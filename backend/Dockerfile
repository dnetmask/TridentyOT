# TridentyOT backend image.
#
# Live packet capture needs raw-socket privileges at *runtime* (NET_RAW /
# NET_ADMIN capabilities, granted via docker-compose.yml), not at build time.
# Analyzing uploaded .pcap files works with no special privileges at all.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRIDENTYOT_DATA_DIR=/data

WORKDIR /app

# libpcap0.8: runtime library scapy/libpcap-based tools link against.
# tcpdump: handy for debugging capture issues from inside the container.
# curl: used by the compose healthcheck.
# nmap: active discovery's port/service/OS scan (app/capture/nmap_discovery.py)
# shells out to the real nmap binary rather than a Python wrapper around it.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        tcpdump \
        curl \
        nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fs http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
