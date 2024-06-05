FROM cgr.dev/chainguard/python:latest-dev@sha256:245ebbae834ab2c1cfeb57d3255a6a26e70f0581b6c01d70c78303a68eccc89f AS builder

ENV PATH=$PATH:/home/nonroot/.local/bin

COPY . /app
WORKDIR /app

RUN python -m pip install --no-cache-dir -r requirements.txt  --no-warn-script-location;

FROM cgr.dev/chainguard/python:latest@sha256:b0feb5ef76e7306fe54d6a472053a3dc929e19a5f7d5b10dfd606d2f7104029d
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
