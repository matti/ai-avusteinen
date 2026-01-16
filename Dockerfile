
FROM ubuntu:24.04
ARG TARGETARCH

RUN apt-get update && apt-get install -y wget xz-utils ca-certificates \
    && wget -O /tmp/pandoc.deb "https://github.com/jgm/pandoc/releases/download/3.8.3/pandoc-3.8.3-1-${TARGETARCH}.deb" \
    && dpkg -i /tmp/pandoc.deb \
    && rm /tmp/pandoc.deb

RUN case "${TARGETARCH}" in \
        "arm64") arch="ARM64" ;; \
        "amd64") arch="X64" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}"; exit 1 ;; \
    esac \
    && url="https://github.com/lierdakil/pandoc-crossref/releases/download/v0.3.22b/pandoc-crossref-Linux-${arch}.tar.xz" \
    && wget -O /tmp/pandoc-crossref.tar.xz "$url" \
    && mkdir -p /opt/pandoc-crossref \
    && tar -xJf /tmp/pandoc-crossref.tar.xz -C /opt/pandoc-crossref \
    && rm /tmp/pandoc-crossref.tar.xz

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
