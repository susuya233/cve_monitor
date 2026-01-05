FROM python:3.9-slim

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制源代码
COPY . .

# 创建必要的目录
RUN mkdir -p log cache archive RSS

# 暴露数据卷
VOLUME ["/app/log", "/app/cache", "/app/archive", "/app/RSS"]

# 启动命令
CMD ["python", "CVE_monitor.py"]
