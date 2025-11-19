FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    whois \
    traceroute \
    dnsutils \
    masscan \
    iputils-ping \
    bind9-host \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY bot.py /app/

RUN mkdir -p /app/logs

# RUN AS ROOT (to avoid permission issues)
# USER botuser  <-- removed

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('https://api.telegram.org').raise_for_status()" || exit 1

CMD ["python", "-u", "bot.py"]
