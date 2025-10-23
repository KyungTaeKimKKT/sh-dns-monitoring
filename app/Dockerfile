### docker build -t shinwoohipo/web_dns_monitor:1.3.0 .
### docker run -d -p 5000:5000 shinwoohipo/web_dns_monitor:1.2.0
FROM python:3.10-slim

# 필수 패키지 설치 (ping용 + curl)
RUN apt-get update && apt-get install -y iputils-ping curl && rm -rf /var/lib/apt/lists/*

# 작업 디렉터리
WORKDIR /app

# 의존성 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 앱 소스 복사
COPY . .

# Flask 환경 변수
ENV FLASK_APP=main.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000

EXPOSE 5000

CMD ["python", "main.py"]