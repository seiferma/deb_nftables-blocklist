FROM mcr.microsoft.com/devcontainers/go:1-1.23-bookworm

RUN apt-get update && \
    apt-get install -y socat && \
    rm -rf /var/lib/{apt,dpkg,cache,log}/
