FROM cgr.dev/chainguard/python:latest-dev@sha256:80e9bf37c59c9ac927491f4933e4d5c414028a42a5ba4240f8a5af01136b35df AS builder

#force build

COPY . /app

WORKDIR /app
RUN python -m pip install --no-cache-dir -r requirements.txt  --require-hashes --no-warn-script-location;

FROM cgr.dev/chainguard/python:latest@sha256:3938b12f0756715f6ee7c0a27dd9ef2763bcd2dfff2673c17761eaa3c2cb1b84
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
