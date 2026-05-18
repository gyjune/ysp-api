import base64
import ctypes
import os
import random
import struct
import time
import uuid
import socket
from datetime import datetime, timedelta
import requests
from construct import Struct, Int16ub, Int32ub, Bytes, this
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse, Response
import uvicorn

# ============== 缓存配置 ==============
CACHE_TTL = 80
cache = {}

def get_cache_key(cnlid: str, livepid: str, defn: str) -> str:
    return f"{cnlid}:{livepid}:{defn}"

def get_cached_url(cnlid: str, livepid: str, defn: str):
    key = get_cache_key(cnlid, livepid, defn)
    if key in cache:
        cached_time, url = cache[key]
        if datetime.now() - cached_time < timedelta(seconds=CACHE_TTL):
            return url
        del cache[key]
    return None

def set_cached_url(cnlid: str, livepid: str, defn: str, url: str):
    key = get_cache_key(cnlid, livepid, defn)
    cache[key] = (datetime.now(), url)

# ============== 复用值（关键优化）==============
# 固定 ck_guard_time（与 PHP 版一致）
CK_GUARD_TIME = "1907CEBB43DD91205C0AA24CAA050DCE0EA64FEA1AB8F3D20C45B08B35952308456EE297396350DAA26DDC14"

# 复用 GUID
_guid_cache = None
_guid_cache_time = 0

def get_guid():
    global _guid_cache, _guid_cache_time
    now = time.time()
    if _guid_cache is None or now - _guid_cache_time > CACHE_TTL:
        _guid_cache = ''.join(random.choice('0123456789ABCDEF') for _ in range(32))
        _guid_cache_time = now
    return _guid_cache

# 复用 randFlag
_reusable_randflag = None
_reusable_randflag_time = 0

def get_randflag():
    global _reusable_randflag, _reusable_randflag_time
    now = time.time()
    if _reusable_randflag is None or now - _reusable_randflag_time > CACHE_TTL:
        _reusable_randflag = base64.b64encode(os.urandom(18)).decode()
        _reusable_randflag_time = now
    return _reusable_randflag

# 复用 uuid4
_uuid4_cache = None
_uuid4_cache_time = 0

def get_uuid4():
    global _uuid4_cache, _uuid4_cache_time
    now = time.time()
    if _uuid4_cache is None or now - _uuid4_cache_time > CACHE_TTL:
        _uuid4_cache = str(uuid.uuid4())
        _uuid4_cache_time = now
    return _uuid4_cache

# ============== 构造体定义 ==============
int16_str_struct = Struct(
    "length" / Int16ub,
    "value" / Bytes(this.length)
)

ckey_struct = Struct(
    "header" / Bytes(12),
    "Platform" / Bytes(4),
    "signature" / Bytes(4),
    "Timestamp" / Bytes(4),
    "Sdtfrom" / int16_str_struct,
    "randFlag" / int16_str_struct,
    "appVer" / int16_str_struct,
    "vid" / int16_str_struct,
    "guid" / int16_str_struct,
    "part1" / Int32ub,
    "isDlna" / Int32ub,
    "uid" / int16_str_struct,
    "bundleID" / int16_str_struct,
    "uuid4" / int16_str_struct,
    "bundleID1"/ int16_str_struct,
    "ckeyVersion" / int16_str_struct,
    "packageName" / int16_str_struct,
    "platform_str" / int16_str_struct,
    "ex_json_bus"/ int16_str_struct,
    "ex_json_vs" / int16_str_struct,
    "ck_guard_time" / int16_str_struct
)

# ============== 常量定义 ==============
DELTA = 0x9e3779b9
ROUNDS = 16
LOG_ROUNDS = 4
SALT_LEN = 2
ZERO_LEN = 7
TEA_CKEY = bytes.fromhex('59b2f7cf725ef43c34fdd7c123411ed3')
XOR_KEY = [0x84, 0x2E, 0xED, 0x08, 0xF0, 0x66, 0xE6, 0xEA, 0x48, 0xB4, 0xCA, 0xA9, 0x91, 0xED, 0x6F, 0xF3]
STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
CUSTOM_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-='

class Size_t:
    def __init__(self, value):
        self.value = value

# ============== TEA加密算法 ==============
def TeaEncryptECB(pInBuf: bytes, pKey: bytes, pOutBuf: bytearray) -> None:
    k = list(struct.unpack("!IIII", pKey))
    y, z = struct.unpack("!II", pInBuf[:8])

    sum_val = 0
    for _ in range(ROUNDS):
        sum_val += DELTA
        sum_val = ctypes.c_uint32(sum_val).value
        y += ((z << 4) + k[0]) ^ (z + sum_val) ^ ((z >> 5) + k[1])
        y = ctypes.c_uint32(y).value
        z += ((y << 4) + k[2]) ^ (y + sum_val) ^ ((y >> 5) + k[3])
        z = ctypes.c_uint32(z).value

    pOutBuf.clear()
    pOutBuf.extend(struct.pack("!II", y, z))

def TeaDecryptECB(pInBuf: bytes, pKey: bytes, pOutBuf: bytearray) -> None:
    k = list(struct.unpack("!IIII", pKey))
    y, z = struct.unpack("!II", pInBuf[:8])

    sum_val = ctypes.c_uint32(DELTA << LOG_ROUNDS).value
    for _ in range(ROUNDS):
        z -= ((y << 4) + k[2]) ^ (y + sum_val) ^ ((y >> 5) + k[3])
        z = ctypes.c_uint32(z).value
        y -= ((z << 4) + k[0]) ^ (z + sum_val) ^ ((z >> 5) + k[1])
        y = ctypes.c_uint32(y).value
        sum_val -= DELTA

    pOutBuf.clear()
    pOutBuf.extend(struct.pack("!II", y, z))

def encrypt(key: bytes, sIn: bytes, iLength: int, buffer: bytearray) -> None:
    outlen = Size_t(oi_symmetry_encrypt2_len(iLength))
    oi_symmetry_encrypt2(sIn, iLength, key, buffer, outlen)
    while len(buffer) > outlen.value:
        buffer.pop()

def oi_symmetry_encrypt2_len(nInBufLen: int) -> int:
    nPadSaltBodyZeroLen = nInBufLen + 1 + 2 + 7
    nPadlen = nPadSaltBodyZeroLen % 8
    if nPadlen:
        nPadlen = 8 - nPadlen
    return nPadSaltBodyZeroLen + nPadlen

def oi_symmetry_encrypt2(pInBuf: bytes, nInBufLen: int, pKey: bytes, pOutBuf: bytearray, pOutBufLen: Size_t) -> None:
    nPadSaltBodyZeroLen = nInBufLen + 1 + 2 + 7
    nPadlen = nPadSaltBodyZeroLen % 8
    if nPadlen:
        nPadlen = 8 - nPadlen

    src_buf = bytearray([0] * 8)
    src_buf[0] = (random.randint(0, 255) & 0xf8) | nPadlen
    src_i = 1

    while nPadlen:
        src_buf[src_i] = random.randint(0, 255)
        src_i += 1
        nPadlen -= 1

    iv_plain = bytearray([0] * 8)
    iv_crypt = bytearray(iv_plain)
    pOutBufLen.value = 0

    i = 1
    while i <= 2:
        if src_i < 8:
            src_buf[src_i] = random.randint(0, 255)
            src_i += 1
            i += 1
        if src_i == 8:
            for j in range(8):
                src_buf[j] ^= iv_crypt[j]

            temp_pOutBuf = bytearray()
            TeaEncryptECB(src_buf, pKey, temp_pOutBuf)

            for j in range(8):
                temp_pOutBuf[j] ^= iv_plain[j]

            iv_plain = bytearray(src_buf)
            src_i = 0
            iv_crypt = bytearray(temp_pOutBuf)
            pOutBufLen.value += 8
            pOutBuf.extend(temp_pOutBuf)

    pInBufIndex = 0
    while nInBufLen:
        if src_i < 8:
            src_buf[src_i] = pInBuf[pInBufIndex]
            pInBufIndex += 1
            src_i += 1
            nInBufLen -= 1
        if src_i == 8:
            for j in range(8):
                src_buf[j] ^= iv_crypt[j]

            temp_pOutBuf = bytearray()
            TeaEncryptECB(src_buf, pKey, temp_pOutBuf)

            for j in range(8):
                temp_pOutBuf[j] ^= iv_plain[j]

            iv_plain = bytearray(src_buf)
            src_i = 0
            iv_crypt = bytearray(temp_pOutBuf)
            pOutBufLen.value += 8
            pOutBuf.extend(temp_pOutBuf)

    i = 1
    while i <= 7:
        if src_i < 8:
            src_buf[src_i] = 0
            src_i += 1
            i += 1
        if src_i == 8:
            for j in range(8):
                src_buf[j] ^= iv_crypt[j]

            temp_pOutBuf = bytearray()
            TeaEncryptECB(src_buf, pKey, temp_pOutBuf)

            for j in range(8):
                temp_pOutBuf[j] ^= iv_plain[j]

            iv_plain = bytearray(src_buf)
            src_i = 0
            iv_crypt = temp_pOutBuf
            pOutBufLen.value += 8
            pOutBuf.extend(temp_pOutBuf)

def tc_tea_encrypt(keys: bytes, message: bytes) -> bytes:
    data = bytearray()
    encrypt(keys, message, len(message), data)
    return bytes(data)

# ============== CKEY生成函数 ==============
def CalcSignature(decArray):
    signature = 0
    for byte in decArray:
        signature = (0x83 * signature + byte)
    return signature & 0x7FFFFFFF

def XOR_Array(byteArray):
    retArray = bytearray(byteArray)
    for i in range(len(retArray)):
        retArray[i] ^= XOR_KEY[i & 0xF]
    return retArray

def custom_encode(text):
    return base64.b64encode(text).decode().translate(str.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET))

def create_str_data(value):
    if value is None:
        value = ""
    if isinstance(value, int):
        value = str(value)
    return {"length": len(value), "value": value.encode('utf-8')}

def ckey42(Platform, Timestamp, Sdtfrom="fcgo", vid="600002264", guid=None, appVer="V8.22.1035.3031"):
    header = b'\x00\x00\x00\x42\x00\x00\x00\x04\x00\x00\x04\xd2'
    data = {
        "header": header,
        "Platform": int(Platform).to_bytes(4, 'big'),
        "signature": b'\x00\x00\x00\x00',
        "Timestamp": Timestamp.to_bytes(4, 'big'),
        "Sdtfrom": create_str_data(Sdtfrom),
        "randFlag": create_str_data(get_randflag()),
        "appVer": create_str_data(appVer),
        "vid": create_str_data(vid),
        "guid": create_str_data(guid),
        "part1": 1,
        "isDlna": 1,
        "uid": create_str_data("2622783A"),
        "bundleID": create_str_data("nil"),
        "uuid4": create_str_data(get_uuid4()),  # 复用 uuid4
        "bundleID1": create_str_data("nil"),
        "ckeyVersion": create_str_data("v0.1.000"),
        "packageName": create_str_data("com.cctv.yangshipin.app.iphone"),
        "platform_str": create_str_data(str(Platform)),
        "ex_json_bus": create_str_data("ex_json_bus"),
        "ex_json_vs": create_str_data("ex_json_vs"),
        "ck_guard_time": create_str_data(CK_GUARD_TIME),  # 固定值
    }
    Buffer = ckey_struct.build(data)
    BufferLenHex = hex(len(Buffer))[2:].zfill(4)
    BufferHead = [int(BufferLenHex[i:i+2], 16) for i in range(0, len(BufferLenHex), 2)]
    Buffer = BufferHead + list(Buffer)
    encrypt_data = tc_tea_encrypt(TEA_CKEY, bytes(Buffer))
    encrypt_data = bytearray(encrypt_data)
    CheckSum = CalcSignature(Buffer)
    encrypt_data.extend(struct.pack('>I', CheckSum))
    result = XOR_Array(encrypt_data)
    return "--01" + custom_encode(result).replace('=', '')

# ============== 完整频道列表 ==============
def generate_channel_list(host):
    if ':' in host:
        server_ip = host.split(':')[0]
        server_port = host.split(':')[1]
    else:
        server_ip = host
        server_port = "9006"
    server_address = f"{server_ip}:{server_port}"

    return f"""央视,#genre#
CCTV1,http://{server_address}/ysp?cnlid=2024078201&livepid=600001859&defn=fhd
CCTV2,http://{server_address}/ysp?cnlid=2024075401&livepid=600001800&defn=fhd
CCTV3,http://{server_address}/ysp?cnlid=2024068501&livepid=600001801&defn=fhd
CCTV4,http://{server_address}/ysp?cnlid=2029797101&livepid=600001814&defn=fhd
CCTV5,http://{server_address}/ysp?cnlid=2024078401&livepid=600001818&defn=fhd
CCTV5+,http://{server_address}/ysp?cnlid=2024078001&livepid=600001817&defn=fhd
CCTV6,http://{server_address}/ysp?cnlid=2013693901&livepid=600108442&defn=fhd
CCTV7,http://{server_address}/ysp?cnlid=2024072001&livepid=600004092&defn=fhd
CCTV8,http://{server_address}/ysp?cnlid=2029793001&livepid=600001803&defn=fhd
CCTV9,http://{server_address}/ysp?cnlid=2024078601&livepid=600004078&defn=fhd
CCTV10,http://{server_address}/ysp?cnlid=2024078701&livepid=600001805&defn=fhd
CCTV11,http://{server_address}/ysp?cnlid=2027248701&livepid=600001806&defn=fhd
CCTV12,http://{server_address}/ysp?cnlid=2027248801&livepid=600001807&defn=fhd
CCTV13,http://{server_address}/ysp?cnlid=2029797201&livepid=600001811&defn=fhd
CCTV14,http://{server_address}/ysp?cnlid=2027248901&livepid=600001809&defn=fhd
CCTV15,http://{server_address}/ysp?cnlid=2027249001&livepid=600001815&defn=fhd
CCTV16,http://{server_address}/ysp?cnlid=2027249101&livepid=600098637&defn=fhd
CCTV16(4K),http://{server_address}/ysp?cnlid=2027249301&livepid=600099502&defn=4k
CCTV17,http://{server_address}/ysp?cnlid=2027249401&livepid=600001810&defn=fhd
CCTV4K,http://{server_address}/ysp?cnlid=2029810301&livepid=600002264&defn=4k
CCTV8K,http://{server_address}/ysp?cnlid=2026774101&livepid=600156816&defn=8k
CGTN,http://{server_address}/ysp?cnlid=2024181701&livepid=600014550&defn=fhd
央视VIP,#genre#
CCTV风云剧场,http://{server_address}/ysp?cnlid=2025637103&livepid=600099658&defn=fhd
CCTV第一剧场,http://{server_address}/ysp?cnlid=2026874203&livepid=600099655&defn=fhd
CCTV怀旧剧场,http://{server_address}/ysp?cnlid=2026874303&livepid=600099620&defn=fhd
CCTV世界地理,http://{server_address}/ysp?cnlid=2026874403&livepid=600099637&defn=fhd
CCTV风云音乐,http://{server_address}/ysp?cnlid=2026874503&livepid=600099660&defn=fhd
CCTV兵器科技,http://{server_address}/ysp?cnlid=2026874603&livepid=600099649&defn=fhd
CCTV风云足球,http://{server_address}/ysp?cnlid=2026966203&livepid=600099636&defn=fhd
CCTV高尔夫网球,http://{server_address}/ysp?cnlid=2026874703&livepid=600099659&defn=fhd
卫视,#genre#
北京卫视,http://{server_address}/ysp?cnlid=2024052703&livepid=600002309&defn=fhd
东方卫视,http://{server_address}/ysp?cnlid=2024054503&livepid=600002483&defn=fhd
江苏卫视,http://{server_address}/ysp?cnlid=2024171103&livepid=600002521&defn=fhd
浙江卫视,http://{server_address}/ysp?cnlid=2024054703&livepid=600002520&defn=fhd
湖南卫视,http://{server_address}/ysp?cnlid=2024054803&livepid=600002475&defn=fhd
湖北卫视,http://{server_address}/ysp?cnlid=2024171203&livepid=600002508&defn=fhd
广东卫视,http://{server_address}/ysp?cnlid=2024060903&livepid=600002485&defn=fhd
广西卫视,http://{server_address}/ysp?cnlid=2024060703&livepid=600002509&defn=fhd
黑龙江卫视,http://{server_address}/ysp?cnlid=2024061003&livepid=600002498&defn=fhd
海南卫视,http://{server_address}/ysp?cnlid=2024055603&livepid=600002506&defn=fhd
重庆卫视,http://{server_address}/ysp?cnlid=2024061103&livepid=600002531&defn=fhd
深圳卫视,http://{server_address}/ysp?cnlid=2024061303&livepid=600002481&defn=fhd
四川卫视,http://{server_address}/ysp?cnlid=2024061403&livepid=600002516&defn=fhd
河南卫视,http://{server_address}/ysp?cnlid=2024059703&livepid=600002525&defn=fhd
东南卫视,http://{server_address}/ysp?cnlid=2024061503&livepid=600002484&defn=fhd
贵州卫视,http://{server_address}/ysp?cnlid=2024061603&livepid=600002490&defn=fhd
江西卫视,http://{server_address}/ysp?cnlid=2024061703&livepid=600002503&defn=fhd
辽宁卫视,http://{server_address}/ysp?cnlid=2024171303&livepid=600002505&defn=fhd
安徽卫视,http://{server_address}/ysp?cnlid=2024171403&livepid=600002532&defn=fhd
河北卫视,http://{server_address}/ysp?cnlid=2024171503&livepid=600002493&defn=fhd
山东卫视,http://{server_address}/ysp?cnlid=2024171603&livepid=600002513&defn=fhd
天津卫视,http://{server_address}/ysp?cnlid=2019927003&livepid=600152137&defn=fhd
吉林卫视,http://{server_address}/ysp?cnlid=2025561503&livepid=600190405&defn=fhd
陕西卫视,http://{server_address}/ysp?cnlid=2025561103&livepid=600190400&defn=fhd
宁夏卫视,http://{server_address}/ysp?cnlid=2025608503&livepid=600190737&defn=fhd
内蒙古卫视,http://{server_address}/ysp?cnlid=2025561203&livepid=600190401&defn=fhd
云南卫视,http://{server_address}/ysp?cnlid=2025561303&livepid=600190402&defn=fhd
山西卫视,http://{server_address}/ysp?cnlid=2025560803&livepid=600190407&defn=fhd
青海卫视,http://{server_address}/ysp?cnlid=2025559103&livepid=600190406&defn=fhd
西藏卫视,http://{server_address}/ysp?cnlid=2025558003&livepid=600190403&defn=fhd
新疆卫视,http://{server_address}/ysp?cnlid=2019927403&livepid=600152138&defn=fhd
甘肃卫视,http://{server_address}/ysp?cnlid=2025561703&livepid=600190408&defn=fhd
中国教育,http://{server_address}/ysp?cnlid=2022823801&livepid=600171827&defn=fhd"""

# ============== FastAPI应用 ==============
app = FastAPI()

def get_current_host(request: Request):
    host = request.headers.get('host')
    if host:
        return host
    return "localhost:9006"

@app.get("/")
async def root(request: Request):
    host = get_current_host(request)
    return Response(content=generate_channel_list(host), media_type="text/plain; charset=utf-8")

@app.get("/ysp")
def ysp(cnlid: str, livepid: str, defn: str = "fhd"):
    try:
        # 查缓存
        cached_url = get_cached_url(cnlid, livepid, defn)
        if cached_url:
            return RedirectResponse(url=cached_url)

        # 请求新地址
        url = "https://liveinfo.ysp.cctv.cn"
        params = {
            "atime": "120",
            "livepid": livepid,
            "cnlid": cnlid,
            "appVer": "V8.22.1035.3031",
            "app_version": "300090",
            "caplv": "1",
            "cmd": "2",
            "defn": defn,
            "device": "iPhone",
            "encryptVer": "4.2",
            "getpreviewinfo": "0",
            "hevclv": "33",
            "lang": "zh-Hans_JP",
            "livequeue": "0",
            "logintype": "1",
            "nettype": "1",
            "newnettype": "1",
            "newplatform": "4330403",
            "platform": "4330403",
            "playbacktime": "0",
            "sdtfrom": "v3021",
            "spacode": "23",
            "spaudio": "1",
            "spdemuxer": "6",
            "spdrm": "2",
            "spdynamicrange": "7",
            "spflv": "1",
            "spflvaudio": "1",
            "sphdrfps": "60",
            "sphttps": "0",
            "spvcode": "MSgzMDoyMTYwLDYwOjIxNjB8MzA6MjE2MCw2MDoyMTYwKTsyKDMwOjIxNjAsNjA6MjE2MHwzMDoyMTYwLDYwOjIxNjAp",
            "spvideo": "4",
            "stream": "1",
            "system": "1",
            "sysver": "ios18.2.1",
            "uhd_flag": "4",
        }
        headers = {
            'User-Agent': "qqlive",
            'Connection': "Keep-Alive",
        }

        Timestamp = int(time.time())
        ckey = ckey42(4330403, Timestamp, "dcgh", cnlid, get_guid(), params['appVer'])
        params.update({"cKey": ckey})

        response = requests.get(url, params=params, headers=headers, timeout=15)
        data = response.json()

        play_url = data.get('playurl')
        if not play_url:
            return JSONResponse(content={"error": "获取失败", "detail": data}, status_code=404)

        set_cached_url(cnlid, livepid, defn, play_url)
        return RedirectResponse(url=play_url)

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=9006)