FROM alpine:latest

RUN apk update && \
    apk add --no-cache python3 py3-pip && \
    pip3 install --upgrade pip

RUN adduser --disabled-password --gecos "Standard user" app && mkdir /app && chown app:app /app
WORKDIR /app

COPY app.py /app/app.py
RUN chown -R app:app /app
COPY requirements.txt /app/requirements.txt

USER app
RUN pip3 install -r /app/requirements.txt

CMD ["python3", "app.py"]

