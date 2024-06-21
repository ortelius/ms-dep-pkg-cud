FROM cgr.dev/chainguard/python:latest-dev@sha256:fd845b48e52dd2925b1f2df375520706319189a88f574df02c284205e4af2754 AS builder

ENV PATH=$PATH:/home/nonroot/.local/bin

COPY . /app
WORKDIR /app

RUN python -m pip install --no-cache-dir -r requirements.txt  --no-warn-script-location;

FROM cgr.dev/chainguard/python:latest@sha256:7ae818a3d32ecc4c747637a7c2baba5f6e0ba75b2d0ceb6744c3fb0ca8d208d1
USER nonroot
ENV DB_HOST localhost
ENV DB_NAME postgres
ENV DB_USER postgres
ENV DB_PASS postgres
ENV DB_PORT 5432

COPY --from=builder /app /app
COPY --from=builder /home/nonroot/.local /home/nonroot/.local

WORKDIR /app

EXPOSE 8080
ENV PATH=$PATH:/home/nonroot/.local/bin

HEALTHCHECK CMD curl --fail http://localhost:8080/health || exit 1

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
