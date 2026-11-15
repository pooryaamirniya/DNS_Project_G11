FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
  python3 build-essential git binutils pkg-config libjson-c-dev ca-certificates \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /work
ENV PYTHONPATH=/work PATCHGUARD_ISOLATED=1
ENTRYPOINT ["python3", "-m", "patchguard"]
