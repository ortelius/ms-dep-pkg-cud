FROM public.ecr.aws/amazonlinux/amazonlinux:2023.8.20250818.0@sha256:ae7ee9bf8436e1750ca7effe5a3e6fc3546003775ba169b93cc7b9901bcf1aa1

EXPOSE 8080

COPY . /app
WORKDIR /app
ENV PATH=/root/.local/bin:$PATH

# hadolint ignore=DL3041,DL4006
RUN dnf install -y python3.12 wget git; \
    wget -q -O - https://install.python-poetry.org | python3.12 -; \
    poetry env use python3.12; \
    poetry install --no-root; \
    dnf upgrade -y; \
    dnf clean all;

ENV DB_HOST=localhost
ENV DB_NAME=postgres
ENV DB_USER=postgres
ENV DB_PASS=postgres
ENV DB_PORT=5432

HEALTHCHECK CMD curl --fail http://localhost:8080/health || exit 1

ENTRYPOINT ["poetry", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
