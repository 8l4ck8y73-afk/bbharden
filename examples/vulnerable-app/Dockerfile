FROM python:latest

ENV API_TOKEN=sk-live-abc123def456ghi789jkl012mno345

RUN curl -sSL https://example.com/install.sh | bash
ADD https://example.com/payload.tar.gz /tmp/

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

CMD ["python", "app.py"]
