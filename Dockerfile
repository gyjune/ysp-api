FROM python:3.10-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用文件
COPY yspapp.py .
COPY ysp.txt .

# 暴露端口
EXPOSE 9006

# 运行应用
CMD ["python", "yspapp.py"]