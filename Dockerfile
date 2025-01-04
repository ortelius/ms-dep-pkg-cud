FROM cgr.dev/chainguard/python:latest-dev@sha256:e183cb003066fd5ccc9c5f76140e5d840262720e7653bc5bde07f1c318e8ce8c AS builder

ENV PATH=$PATH:/home/nonroot/.local/bin

COPY . /app
WORKDIR /app
ENV PATH=/home/nonroot/.local/bin:$PATH

# hadolint ignore=DL4006
RUN wget -q -O - https://install.python-poetry.org | python -
RUN poetry install --no-root;

FROM cgr.dev/chainguard/python:latest@sha256:e57e10d5d66dffa858fabd4cebdb8a0b5a3d02a40c76e87ec2d13a87de51e521
USER nonroot
ENV DB_HOST localhost
ENV DB_NAME postgres
ENV DB_USER postgres
ENV DB_PASS postgres
ENV DB_PORT 5432

COPY --from=builder /app /app
COPY --from=builder /home/nonroot /home/nonroot

WORKDIR /app

EXPOSE 8080
ENV PATH=$PATH:/home/nonroot/.local/bin

HEALTHCHECK CMD curl --fail http://localhost:8080/health || exit 1

ENTRYPOINT ["poetry", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
