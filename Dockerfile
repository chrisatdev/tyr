FROM python:3.11-slim

WORKDIR /opt/tyr

COPY tyr.py ./
COPY plugins ./plugins

RUN pip install --no-cache-dir requests

ENTRYPOINT ["python", "/opt/tyr/tyr.py"]
