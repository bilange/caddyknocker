FROM alpine:latest

RUN apk update && \
    apk add --no-cache python3 py3-pip && \
    pip3 install --upgrade pip

RUN adduser --disabled-password --gecos "Standard user" app && mkdir /app && chown app:app /app
WORKDIR /app

COPY requirements.txt /app/requirements.txt
USER app
RUN pip3 install -r /app/requirements.txt
USER root

RUN echo "Forcing update2"
COPY app.py /app/app.py
# COPY configuration.yaml /app/configuration.yaml
#RUN chmod 600 /app/configuration.yaml && chown -R app:app /app
RUN chown -R app:app /app


USER app
CMD ["python3", "app.py"]

