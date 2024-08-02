FROM cgr.dev/chainguard/python:latest-dev@sha256:39d3b461ec14222f7eadb6cf5c64153291c03aca514e09b307b77aa60d0f0a3b AS builder

ENV PATH=$PATH:/home/nonroot/.local/bin

COPY . /app
WORKDIR /app

RUN python -m pip install --no-cache-dir -r requirements.txt  --no-warn-script-location;

FROM cgr.dev/chainguard/python:latest@sha256:5b0aef78beea1a889c0f656b46009ffc63214f06014ec51df7a219d78cd961dc
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
