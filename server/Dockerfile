FROM python:3.11-alpine

RUN pip3 install --no-cache-dir Flask PyYAML requests waitress

RUN mkdir -p /server
WORKDIR /server

COPY . /server

ENTRYPOINT ["python3", "app.py"]
