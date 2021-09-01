FROM quay.io/ortelius/ms-python-base:fastapi-1.0 as base

ENV DB_HOST localhost
ENV DB_NAME postgres
ENV DB_USER postgres
ENV DB_PASS postgres
ENV DB_POST 5432

WORKDIR /app

# Copy example sbom json
COPY *.json /app/

# Copy main app
COPY main.py /app
COPY requirements.txt /app

# install deps and remove pip for CVE
RUN pip install -r requirements.txt; \
python -m pip uninstall -y pip;
