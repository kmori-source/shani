# Dockerfile for Shani Vulnerability Judge
#
# Shani evaluates vulnerability scan results and produces a signed audit trail.
# It does NOT bundle a scanner — pass scan results from Grype, Trivy, or OSV-Scanner.
#
# Usage:
#   docker build -t shani/vuln-judge .
#
#   # Step 1: Run your scanner (outside this container)
#   grype dir:. -o json > grype.json
#
#   # Step 2: Shani judgment
#   docker run --rm \
#     -v $(pwd):/workspace \
#     -e SHANI_HITL_AUTO=1 \
#     shani/vuln-judge \
#     --grype /workspace/grype.json \
#     --output /workspace/shani-audit.json
#
#   # With multiple scanners
#   docker run --rm \
#     -v $(pwd):/workspace \
#     -e SHANI_HITL_AUTO=1 \
#     shani/vuln-judge \
#     --grype /workspace/grype.json \
#     --trivy /workspace/trivy.json \
#     --osv /workspace/osv.json \
#     --output /workspace/shani-audit.json \
#     --fail-on-denied

FROM python:3.12-slim

LABEL org.opencontainers.image.title="Shani Vulnerability Judge" \
      org.opencontainers.image.description="Decision governance layer for vulnerability scan results. Pass JSON from Grype, Trivy, or OSV-Scanner." \
      org.opencontainers.image.source="https://github.com/kmori-source/shani" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Copy Shani source and install
COPY . /app
RUN pip install --no-cache-dir -e ".[core]"

# Default policy for vuln judgment
ENV SHANI_POLICY=/app/examples/vuln_remediation/policy.yaml

ENTRYPOINT ["python", "/app/examples/vuln_remediation/shani_vuln_judge.py"]
CMD ["--help"]
