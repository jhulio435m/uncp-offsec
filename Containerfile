# syntax=docker/dockerfile:1
# OCI image for the complete, reproducible web and mail assessment environment.
ARG SUBFINDER_VERSION=v2.7.1
ARG HTTPX_VERSION=v1.7.1
ARG NAABU_VERSION=v2.3.4
ARG NUCLEI_VERSION=v3.4.10
ARG NUCLEI_TEMPLATES_REF=v10.4.8
ARG NUCLEI_TEMPLATES_SHA256=53ae80d9bcfff638fbff62c4b730c436564b6bf5e05cf4f86a7eefe37c7ecc47
ARG KATANA_VERSION=v1.2.0
ARG TESTSSL_REF=6555311656639356c212af364b6ded1c14faf6f5
ARG TESTSSL_SHA256=1e1d96259e76ac10c246bfdcb6b6307f56a0da4db7a206f2ea133e830afef107
ARG SQLMAP_REF=5f6c303f8aaeb588402ef2f61197e2a67e0da10b
ARG SQLMAP_SHA256=44cb4fe9c89662500e889e79f55aa1d53ace9dc7072fd4f9906579691182b4ed
ARG SECLISTS_REF=2026.1
ARG SECLISTS_SHA256=a9626959f818d9e198259665c5a88053b7b061c538f46da215d172bcba305fe9
ARG VULNERS_REF=ad39f89aaa06972d18c51ed2f484785cd9a46432
ARG VULNERS_SHA256=96ab184c1c2da56a184f2a6e156614c9daf9e7d35142ee6c210bd54a1b312cd4
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
ARG TESTSSL_SHA256
ARG SQLMAP_REF
ARG SQLMAP_SHA256
ARG SECLISTS_REF
ARG SECLISTS_SHA256
ARG NUCLEI_TEMPLATES_REF
ARG NUCLEI_TEMPLATES_SHA256
ARG VULNERS_REF
ARG VULNERS_SHA256
ARG SEMGREP_VERSION
ENV PATH=/opt/uncp-tools/bin:${PATH} \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash bsdextrautils ca-certificates curl dnsutils libpcap0.8 nmap openssl procps ruby tar whatweb \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/uncp-tools/bin \
    && curl -fsSL "https://github.com/testssl/testssl.sh/archive/${TESTSSL_REF}.tar.gz" -o /tmp/testssl.tar.gz \
    && echo "${TESTSSL_SHA256}  /tmp/testssl.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/uncp-tools/testssl \
    && tar -xzf /tmp/testssl.tar.gz -C /opt/uncp-tools/testssl --strip-components=1 \
    && curl -fsSL "https://github.com/sqlmapproject/sqlmap/archive/${SQLMAP_REF}.tar.gz" -o /tmp/sqlmap.tar.gz \
    && echo "${SQLMAP_SHA256}  /tmp/sqlmap.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/uncp-tools/sqlmap \
    && tar -xzf /tmp/sqlmap.tar.gz -C /opt/uncp-tools/sqlmap --strip-components=1 \
    && ln -s /opt/uncp-tools/sqlmap/sqlmap.py /opt/uncp-tools/bin/sqlmap \
    && mkdir -p /opt/uncp-tools/wordlists \
    && curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_REF}/Discovery/Web-Content/raft-medium-directories.txt" \
       -o /opt/uncp-tools/wordlists/raft-medium-directories.txt \
    && echo "${SECLISTS_SHA256}  /opt/uncp-tools/wordlists/raft-medium-directories.txt" | sha256sum -c - \
    && curl -fsSL "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_REF}.tar.gz" \
       -o /tmp/nuclei-templates.tar.gz \
    && echo "${NUCLEI_TEMPLATES_SHA256}  /tmp/nuclei-templates.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/uncp-tools/nuclei-safe \
    && tar -xzf /tmp/nuclei-templates.tar.gz -C /opt/uncp-tools/nuclei-safe --strip-components=1 \
       nuclei-templates-10.4.8/http/technologies/tech-detect.yaml \
       nuclei-templates-10.4.8/http/misconfiguration/http-missing-security-headers.yaml \
       nuclei-templates-10.4.8/http/misconfiguration/cookies-without-httponly.yaml \
       nuclei-templates-10.4.8/http/misconfiguration/cookies-without-secure.yaml \
       nuclei-templates-10.4.8/http/misconfiguration/missing-cookie-samesite-strict.yaml \
       nuclei-templates-10.4.8/http/miscellaneous/directory-listing.yaml \
       nuclei-templates-10.4.8/http/vulnerabilities/generic/cors-misconfig.yaml \
       nuclei-templates-10.4.8/http/exposures/apis/openapi.yaml \
       nuclei-templates-10.4.8/http/exposures/apis/swagger-api.yaml \
       nuclei-templates-10.4.8/ssl/deprecated-tls.yaml \
       nuclei-templates-10.4.8/ssl/insecure-cipher-suite-detect.yaml \
       nuclei-templates-10.4.8/ssl/mismatched-ssl-certificate.yaml \
       nuclei-templates-10.4.8/ssl/weak-cipher-suites.yaml \
    && curl -fsSL "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/${VULNERS_REF}/vulners.nse" \
       -o /usr/share/nmap/scripts/vulners.nse \
    && echo "${VULNERS_SHA256}  /usr/share/nmap/scripts/vulners.nse" | sha256sum -c - \
    && nmap --script-updatedb \
    && ln -s /opt/uncp-tools/testssl/testssl.sh /opt/uncp-tools/bin/testssl.sh \
    && rm -f /tmp/testssl.tar.gz /tmp/sqlmap.tar.gz /tmp/nuclei-templates.tar.gz \
    && useradd --create-home --uid 10001 uncp
COPY --from=go-tools /out/ /opt/uncp-tools/bin/
COPY --from=trivy /usr/local/bin/trivy /opt/uncp-tools/bin/trivy

WORKDIR /app
COPY requirements.lock ./
RUN pip install -r requirements.lock bandit==1.8.6 pip-audit==2.9.0 semgrep==${SEMGREP_VERSION}
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps .
COPY scope.uncp.json /opt/uncp-tools/scopes/scope.uncp.json

USER uncp
ENTRYPOINT ["uncp_offsec"]
CMD ["--help"]
