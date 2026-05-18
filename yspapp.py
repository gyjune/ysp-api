import base64
import ctypes
import os
import random
import struct
import time
import uuid
from datetime import datetime, timedelta
from functools import lru_cache
import hashlib

import requests
from construct import Struct, Int16ub, Int32ub, Bytes, this
from fastapi import FastAPI
from fastapi.responses import RedirectResponse, JSONResponse
import uvicorn

# ==================== 缓存配置 ====================
CACHE_TTL = 80  # 缓存80秒，与PHP版一致
cache = {}

def get_cache_key(cnlid: str, livepid: str, defn: str, playseek: str = None) -> str:
    """生成缓存键"""
    if playseek:
        return f"playback:{cnlid}:{livepid}:{defn}:{playseek}"
    return f"live:{cnlid}:{livepid}:{defn}"

def get_cached_url(cnlid: str, livepid: str, defn: str, playseek: str = None):
    """获取缓存的播放地址"""
    key = get_cache_key(cnlid, livepid, defn, playseek)
    if key in cache:
        cached_time, url = cache[key]
        if datetime.now() - cached_time < timedelta(seconds=CACHE_TTL):
            return url
        # 过期则删除
        del cache[key]
    return None

def set_cached_url(cnlid: str, livepid: str, defn: str, url: str, playseek: str = None):
    """缓存播放地址"""
    key = get_cache_key(cnlid, livepid, defn, playseek)
    cache[key] = (datetime.now(), url)

def clear_cache(cnlid: str = None, livepid: str = None, defn: str = None):
    """清空缓存（可选）"""
    global cache
    if cnlid is None:
        cache = {}
    else:
        prefix = f"live:{cnlid}"
        keys_to_delete = [k for k in cache if k.startswith(prefix)]
        for k in keys_to_delete:
            del cache[k]

# ==================== 原有加解密代码 ====================
# ... 保持你原有的所有加解密函数不变 ...
# (int16_str_struct, ckey_struct, DELTA, ROUNDS, TEA_CKEY, XOR_KEY,
#  STANDARD_ALPHABET, CUSTOM_ALPHABET, TeaEncryptECB, TeaDecryptECB,
#  oi_symmetry_encrypt2, oi_symmetry_decrypt2, tc_tea_encrypt,
#  tc_tea_decrypt, CalcSignature, RandomHexStr, XOR_Array,
#  custom_encode, custom_decode, create_str_data, ckey42 等)

# 为了完整性，这里列出你需要保留的函数（从你的原代码复制）：
# - int16_str_struct, int32_str_struct, ckey_struct, ckey42_struct
# - DELTA, ROUNDS, LOG_ROUNDS, SALT_LEN, ZERO_LEN
# - TEA_CKEY, XOR_KEY, STANDARD_ALPHABET, CUSTOM_ALPHABET
# - Size_t 类
# - encrypt(), decrypt()
# - TeaEncryptECB(), TeaDecryptECB()
# - oi_symmetry_encrypt2_len(), oi_symmetry_encrypt2(), oi_symmetry_decrypt2()
# - tc_tea_encrypt(), tc_tea_decrypt()
# - CalcSignature(), RandomHexStr(), XOR_Array()
# - custom_encode(), custom_decode()
# - create_str_data()
# - ckey42()

# ==================== 优化后的 ckey42（复用部分随机值） ====================
# 缓存一些可复用的值，减少随机数生成开销
_reusable_randflag = None
_reusable_randflag_time = 0

def get_randflag():
    """复用 randFlag，每80秒刷新一次"""
    global _reusable_randflag, _reusable_randflag_time
    now = time.time()
    if _reusable_randflag is None or now - _reusable_randflag_time > CACHE_TTL:
        _reusable_randflag = base64.b64encode(os.urandom(18)).decode()
        _reusable_randflag_time = now
    return _reusable_randflag

def ckey42_optimized(Platform, Timestamp, Sdtfrom="fcgo", vid="600002264", guid=None, appVer="V8.22.1035.3031"):
    """优化版 ckey42，复用部分随机值"""
    header = b'\x00\x00\x00\x42\x00\x00\x00\x04\x00\x00\x04\xd2'
    
    # 使用复用的 randFlag
    randflag = get_randflag()
    
    data = {
        "header": header,
        "Platform": int(Platform).to_bytes(4, 'big'),
        "signature": b'\x00\x00\x00\x00',
        "Timestamp": Timestamp.to_bytes(4, 'big'),
        "Sdtfrom": create_str_data(Sdtfrom),
        "randFlag": create_str_data(randflag),
        "appVer": create_str_data(appVer),
        "vid": create_str_data(vid),
        "guid": create_str_data(guid),
        "part1": 1,
        "isDlna": 1,
        "uid": create_str_data("2622783A"),
        "bundleID": create_str_data("nil"),
        "uuid4": create_str_data(str(uuid.uuid4())),
        "bundleID1": create_str_data("nil"),
        "ckeyVersion": create_str_data("v0.1.000"),
        "packageName": create_str_data("com.cctv.yangshipin.app.iphone"),
        "platform_str": create_str_data(str(Platform)),
        "ex_json_bus": create_str_data("ex_json_bus"),
        "ex_json_vs": create_str_data("ex_json_vs"),
        "ck_guard_time": create_str_data(RandomHexStr(66)),
    }
    Buffer = ckey_struct.build(data)
    BufferLenHex = hex(len(Buffer))[2:].zfill(4)
    BufferHead = [int(BufferLenHex[i:i+2], 16) for i in range(0, len(BufferLenHex), 2)]
    Buffer = BufferHead + list(Buffer)
    encrypt_data = tc_tea_encrypt(TEA_CKEY, bytes(Buffer))
    encrypt_data = bytearray(encrypt_data)
    CheckSum = CalcSignature(Buffer)
    CheckSumBytes = struct.pack('>I', CheckSum)
    encrypt_data.extend(CheckSumBytes)
    result = XOR_Array(encrypt_data)
    return "--01" + custom_encode(result).replace('=', '')

# ==================== FastAPI 应用（带缓存） ====================
app = FastAPI()

@app.get("/ysp")
def ysp(cnlid: str, livepid: str, defn: str = "auto", playseek: str = None):
    """
    获取央视频播放地址
    - cnlid: 频道ID
    - livepid: 直播ID
    - defn: 清晰度 (auto/fhd/4k等)
    - playseek: 回看时间 (可选，格式: YYYYMMDDHHMMSS-YYYYMMDDHHMMSS)
    """
    try:
        # 1. 先查缓存
        cached_url = get_cached_url(cnlid, livepid, defn, playseek)
        if cached_url:
            # 直播模式直接返回m3u8内容，点播模式跳转
            if playseek:
                return RedirectResponse(url=cached_url)
            else:
                # 直播模式：获取并处理m3u8内容
                m3u8_content = fetch_m3u8_content(cached_url, cached=True)
                if m3u8_content:
                    from fastapi.responses import Response
                    return Response(content=m3u8_content, media_type="application/vnd.apple.mpegurl")
                # 缓存失效，继续请求
        
        # 2. 缓存未命中，生成新的请求
        url = "https://liveinfo.ysp.cctv.cn" if not playseek else "https://bkliveinfo.ysp.cctv.cn"
        
        # 生成 GUID
        guid = RandomHexStr(32)
        timestamp = int(time.time())
        sdtfrom = 'dcgh' if not playseek else 'v3021'
        
        # 生成 cKey
        ckey = ckey42_optimized(4330403, timestamp, sdtfrom, cnlid, guid, "V8.22.1035.3031")
        
        params = {
            "atime": "120",
            "livepid": livepid,
            "cnlid": cnlid,
            "appVer": "V8.22.1035.3031",
            "app_version": "300090",
            "caplv": "1",
            "cmd": "2",
            "defn": defn if defn != 'auto' else 'fhd',
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
            "sdtfrom": sdtfrom,
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
            "cKey": ckey,
            "guid": guid,
            "fntick": timestamp,
            "flowid": f"{uuid.uuid4()}_{4330403}",
        }
        
        # 回看模式添加 playbacktime
        if playseek:
            parts = playseek.split('-')
            if len(parts) == 2:
                start_time = datetime.strptime(parts[0], '%Y%m%d%H%M%S')
                params["playbacktime"] = int(start_time.timestamp())
        
        headers = {
            'User-Agent': "qqlive",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip"
        }
        
        response = requests.get(url, params=params, headers=headers, timeout=15)
        data = response.json()
        
        # 处理响应
        if defn == "auto" and not playseek:
            formats = data.get('formats', [])
            return JSONResponse(content={"formats": formats})
        
        playurl = data.get('playurl')
        if not playurl:
            return JSONResponse(content={"error": "获取播放地址失败", "detail": data}, status_code=404)
        
        # 缓存结果
        set_cached_url(cnlid, livepid, defn, playurl, playseek)
        
        # 返回结果
        if playseek:
            return RedirectResponse(url=playurl)
        else:
            # 直播模式：获取并处理 m3u8
            m3u8_content = fetch_m3u8_content(playurl, cached=False)
            if m3u8_content:
                from fastapi.responses import Response
                return Response(content=m3u8_content, media_type="application/vnd.apple.mpegurl")
            return RedirectResponse(url=playurl)
            
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


def fetch_m3u8_content(playurl: str, cached: bool = False) -> str | None:
    """获取 M3U8 内容并补全 TS 路径"""
    try:
        response = requests.get(playurl, timeout=10, headers={'User-Agent': 'qqlive'})
        if response.status_code != 200:
            return None
        
        m3u8_content = response.text
        
        # 补全 TS 路径（与 PHP 版一致）
        if not m3u8_content.startswith('#EXTM3U'):
            return None
        
        base_url = playurl[:playurl.rfind('/') + 1]
        
        # 处理 TS 文件路径
        lines = m3u8_content.split('\n')
        processed_lines = []
        for line in lines:
            if line and not line.startswith('#') and not line.startswith('http'):
                processed_lines.append(base_url + line)
            else:
                processed_lines.append(line)
        
        return '\n'.join(processed_lines)
    except Exception:
        return None


if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=9006)