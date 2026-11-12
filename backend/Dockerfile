FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY voidsentinel ./voidsentinel
COPY tests ./tests
ENV PYTHONUNBUFFERED=1 VS_DATA_DIR=/data
EXPOSE 8000
CMD ["uvicorn", "voidsentinel.api:app", "--host", "0.0.0.0", "--port", "8000"]
