FROM mcr.microsoft.com/devcontainers/base:debian@sha256:a07f1804d8e665ff64bf6adcd60f4d9b9223dc52ee18a1f1a7a8e1ee1a134d34

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends mkcert openssl \
    && rm -rf /var/lib/apt/lists

COPY --chmod=0755 generate-certificates.sh /usr/local/bin/generate-certificates

ENTRYPOINT ["/usr/local/bin/generate-certificates"]
