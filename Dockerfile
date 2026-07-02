FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY scripts/run_runtime_container.sh /app/scripts/run_runtime_container.sh
COPY scripts/run_dashboard_container.sh /app/scripts/run_dashboard_container.sh
RUN chmod +x /app/scripts/run_runtime_container.sh /app/scripts/run_dashboard_container.sh

COPY . /app

CMD ["python", "-m", "nids", "run", "--pcap-dir", "pcaps", "--rules", "rules/rules.yml"]
