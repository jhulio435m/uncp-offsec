# syntax=docker/dockerfile:1
# OCI image for the complete, reproducible web and mail assessment environment.
ARG SUBFINDER_VERSION=v2.7.1
ARG HTTPX_VERSION=v1.7.1
ARG NAABU_VERSION=v2.3.4
ARG NUCLEI_VERSION=v3.4.10
ARG NUCLEI_TEMPLATES_REF=v10.4.8
ARG KATANA_VERSION=v1.2.0
ARG TESTSSL_REF=3.2
ARG SECLISTS_REF=2026.1
ARG SEMGREP_VERSION=1.176.0

FROM golang:1.24-bookworm AS go-tools
ARG SUBFINDER_VERSION
ARG HTTPX_VERSION
ARG NAABU_VERSION
ARG NUCLEI_VERSION
ARG KATANA_VERSION
ENV GOBIN=/out
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    apt-get update && apt-get install -y --no-install-recommends gcc libpcap-dev \
    && rm -rf /var/lib/apt/lists/* \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
    && go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION} \
    && go install github.com/ffuf/ffuf/v2@v2.1.0

FROM aquasec/trivy:0.74.0 AS trivy

FROM python:3.12-slim-bookworm
ARG TESTSSL_REF
ARG SECLISTS_REF
ARG NUCLEI_TEMPLATES_REF
ARG SEMGREP_VERSION
ENV PATH=/opt/uncp-tools/bin:${PATH} \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash bsdextrautils ca-certificates curl dnsutils git nmap openssl procps ruby whatweb \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/uncp-tools/bin \
    && git clone --depth 1 --branch ${TESTSSL_REF} https://github.com/testssl/testssl.sh.git /opt/uncp-tools/testssl \
    && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/uncp-tools/sqlmap \
    && ln -s /opt/uncp-tools/sqlmap/sqlmap.py /opt/uncp-tools/bin/sqlmap \
    && mkdir -p /opt/uncp-tools/wordlists \
    && curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_REF}/Discovery/Web-Content/raft-medium-directories.txt" \
       -o /opt/uncp-tools/wordlists/raft-medium-directories.txt \
    && mkdir -p /opt/uncp-tools/nuclei-templates \
    && curl -fsSL "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/${NUCLEI_TEMPLATES_REF}/http/technologies/tech-detect.yaml" \
       -o /opt/uncp-tools/nuclei-templates/tech-detect.yaml \
    && ln -s /opt/uncp-tools/testssl/testssl.sh /opt/uncp-tools/bin/testssl.sh \
    && useradd --create-home --uid 10001 uncp
COPY --from=go-tools /out/ /opt/uncp-tools/bin/
COPY --from=trivy /usr/local/bin/trivy /opt/uncp-tools/bin/trivy

WORKDIR /app
COPY requirements.lock ./
RUN pip install -r requirements.lock bandit==1.8.6 pip-audit==2.9.0 semgrep==${SEMGREP_VERSION}
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps .

USER uncp
ENTRYPOINT ["uncp_offsec"]
CMD ["--help"]
