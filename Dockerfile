# Dockerfile
FROM debian:bookworm-slim

# COPY install.sh /install.sh
EXPOSE 8443

COPY . /workdir
WORKDIR /workdir
RUN chmod +x install.sh
RUN chmod +x scripts/*
RUN ./install.sh docker

ENTRYPOINT [ "bash", "./scripts/exec.sh" ]