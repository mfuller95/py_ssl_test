FROM python:3.10.13-slim-bullseye

RUN pip3 install requests

COPY ./src/ssl_test.py /ssl_test.py

ENTRYPOINT ["python3", "/ssl_test.py"]