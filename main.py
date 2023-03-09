# Copyright (c) 2021 Linux Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
import os
import socket
from time import sleep
from typing import Optional

import requests
import uvicorn
from fastapi import Body, FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import sql, create_engine
from sqlalchemy.exc import OperationalError, StatementError, InterfaceError

# Init Globals
service_name = "ortelius-ms-dep-pkg-cud"
db_conn_retry = 3

# Init FastAPI
app = FastAPI(title=service_name, description=service_name)


# Init db connection
db_host = os.getenv("DB_HOST", "localhost")
db_name = os.getenv("DB_NAME", "postgres")
db_user = os.getenv("DB_USER", "postgres")
db_pass = os.getenv("DB_PASS", "postgres")
db_port = os.getenv("DB_PORT", "5432")
validateuser_url = os.getenv("VALIDATEUSER_URL", None)

if validateuser_url is None:
    validateuser_host = os.getenv("MS_VALIDATE_USER_SERVICE_HOST", "127.0.0.1")
    host = socket.gethostbyaddr(validateuser_host)[0]
    validateuser_url = "http://" + host + ":" + str(os.getenv("MS_VALIDATE_USER_SERVICE_PORT", 80))

url = requests.get("https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json")
safety_db = json.loads(url.text)

engine = create_engine("postgresql+psycopg2://" + db_user + ":" + db_pass + "@" + db_host + ":" + db_port + "/" + db_name, pool_pre_ping=True)


# health check endpoint
class StatusMsg(BaseModel):
    status: str
    service_name: Optional[str] = None


@app.get("/health")
async def health(response: Response) -> StatusMsg:
    try:
        with engine.connect() as connection:
            conn = connection.connection
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            if cursor.rowcount > 0:
                return StatusMsg(status="UP", service_name=service_name)
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return StatusMsg(status="DOWN", service_name=service_name)

    except Exception as err:
        print(str(err))
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return StatusMsg(status="DOWN", service_name=service_name)


# end health check

# validate user endpoint


def example(filename):
    text = ""
    with open(filename, "r") as f:
        text = f.read()
    return text


@app.post("/msapi/deppkg/cyclonedx")
async def cyclonedx(request: Request, response: Response, compid: int, cyclonedx_json: dict = Body(..., example=example("cyclonedx.json"), description="JSON output from running CycloneDX")):
    print(json.dumps(cyclonedx_json))
    components_data = []
    components = cyclonedx_json.get("components", [])

    # Parse CycloneDX BOM for licenses
    bomformat = "license"
    for component in components:
        packagename = component.get("name")
        packageversion = component.get("version", "")
        purl = component.get("purl", "")
        pkgtype = ""
        if ":" in purl:
            pkgtype = purl.split("/")[0][4:]

        summary = ""
        license_url = ""
        license_name = ""
        licenses = component.get("licenses", None)
        if licenses is not None and len(licenses) > 0:
            license = licenses[0].get("license", {})
            if license.get("id", None) is not None:
                license_name = license.get("id")
            elif license.get("name", None) is not None:
                license_name = license.get("name")

            if len(license_name) > 0:
                license_url = "https://spdx.org/licenses/" + license_name + ".html"
        component_data = (compid, packagename, packageversion, bomformat, license_name, license_url, summary, purl, pkgtype)
        components_data.append(component_data)

    return saveComponentsData(response, compid, bomformat, components_data)


@app.post("/msapi/deppkg/spdx")
async def spdx(request: Request, response: Response, compid: int, spdx_json: dict = Body(..., example=example("spdx.json"), description="JSON output from running SPDX")):
    try:
        result = requests.get(validateuser_url + "/msapi/validateuser", cookies=request.cookies)
        if result is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed")

        if result.status_code != status.HTTP_200_OK:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed status_code=" + str(result.status_code))
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed:" + str(err)) from None

    components_data = []
    components = spdx_json.get("packages", [])

    # Parse SPDX BOM for licenses
    bomformat = "spdx_json"
    for component in components:
        packagename = component.get("name")
        packageversion = component.get("versionInfo", "")
        extpkgs = component.get("externalRefs", [])
        purl = ""
        pkgtype = ""

        for pkgref in extpkgs:
            reftype = pkgref.get("referenceType", None)
            if reftype is not None and reftype == "purl":
                purl = pkgref.get("referenceLocator", "")

                if ":" in purl:
                    pkgtype = purl.split("/")[0][4:]

        summary = ""
        license_url = ""
        license_name = ""
        license = component.get("licenseDeclared")
        if license != "NOASSERTION":
            license_name = license
            license_url = "https://spdx.org/licenses/" + license_name + ".html"
        component_data = (compid, packagename, packageversion, bomformat, license_name, license_url, summary, purl, pkgtype)
        components_data.append(component_data)

    return saveComponentsData(response, compid, bomformat, components_data)


@app.post("/msapi/deppkg/safety")
async def safety(request: Request, response: Response, compid: int, safety_json: list = Body(..., example=example("safety.json"), description="JSON output from running safety")):
    result = requests.get(validateuser_url + "/msapi/validateuser", cookies=request.cookies)
    if result is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed")

    if result.status_code != status.HTTP_200_OK:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed status_code=" + str(result.status_code))

    components_data = []
    bomformat = "cve"
    for component in safety_json:
        packagename = component[0]  # name
        packageversion = component[2]  # version
        summary = component[3]
        safety_id = component[4]  # cve id
        cve_url = ""
        cve_name = safety_id
        cve_detail = safety_db.get(packagename, None)
        if cve_detail is not None:
            for cve in cve_detail:
                if cve["id"] == "pyup.io-" + safety_id:
                    cve_name = cve["cve"]
                    if cve_name.startswith("CVE"):
                        cve_url = "https://nvd.nist.gov/vuln/detail/" + cve_name
                    break

        component_data = (compid, packagename, packageversion, bomformat, cve_name, cve_url, summary)
        components_data.append(component_data)
    return saveComponentsData(response, compid, bomformat, components_data)


def saveComponentsData(response, compid, bomformat, components_data):
    try:
        if len(components_data) == 0:
            return {"detail": "components not updated"}

        # remove dups
        components_data = list(set(components_data))

        # Retry logic for failed query
        no_of_retry = db_conn_retry
        attempt = 1
        while True:
            try:
                with engine.connect() as connection:
                    conn = connection.connection
                    conn.set_session(autocommit=False)
                    cursor = conn.cursor()
                    records_list_template = ",".join(["%s"] * len(components_data))

                    # delete old licenses
                    sqlstmt = "DELETE from dm_componentdeps where compid=%s and deptype=%s"
                    params = (
                        compid,
                        bomformat,
                    )
                    cursor.execute(sqlstmt, params)

                    # insert into database
                    sqlstmt = "INSERT INTO dm_componentdeps(compid, packagename, packageversion, deptype, name, url, summary, purl, pkgtype) VALUES {} ON CONFLICT ON CONSTRAINT dm_componentdeps_pkey DO NOTHING".format(
                        records_list_template
                    )

                    cursor.execute(sqlstmt, components_data)

                    rows_inserted = cursor.rowcount
                    # Commit the changes to the database
                    conn.commit()
                    if rows_inserted > 0:
                        response.status_code = status.HTTP_201_CREATED
                        return {"detail": "components updated succesfully"}

                return {"detail": "components not updated"}

            except (InterfaceError, OperationalError) as ex:
                if attempt < no_of_retry:
                    sleep_for = 0.2
                    logging.error("Database connection error: {} - sleeping for {}s" " and will retry (attempt #{} of {})".format(ex, sleep_for, attempt, no_of_retry))
                    # 200ms of sleep time in cons. retry calls
                    sleep(sleep_for)
                    attempt += 1
                    continue
                else:
                    raise

    except HTTPException:
        raise
    except Exception as err:
        print(str(err))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)) from None


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5003)
