FROM cgr.dev/chainguard/python:latest-dev@sha256:5ba92d0eb4410ac5963adc7aedc8bd7662e3c1d437eedcce1a7f874a184d62e9 AS builder

ENV PATH=$PATH:/home/nonroot/.local/bin

COPY . /app
WORKDIR /app

RUN python -m pip install --no-cache-dir -r requirements.txt  --no-warn-script-location;

FROM cgr.dev/chainguard/python:latest@sha256:8ffe47b9158f5908ebaad5bba092913ca8de8ea3df6b5caefb8818629cc5b5f1
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
