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

# pylint: disable=E0401,E0611
# pyright: reportMissingImports=false,reportMissingModuleSource=false

import json
import logging
import os
import socket
import threading
from time import sleep

import requests
import uvicorn
from fastapi import Body, FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel  # pylint: disable=E0611
from sqlalchemy import create_engine
from sqlalchemy.exc import InterfaceError, OperationalError

# Init Globals
service_name = "ortelius-ms-dep-pkg-cud"  # pylint: disable=C0103
db_conn_retry = 3  # pylint: disable=C0103

tags_metadata = [
    {
        "name": "health",
        "description": "health check end point",
    },
    {
        "name": "cyclonedx",
        "description": "CycloneDX Upload end point",
    },
    {
        "name": "spdx",
        "description": "SPDX Upload end point",
    },
    {
        "name": "safety",
        "description": "Python Safety Upload end point",
    },
]

# Init FastAPI
app = FastAPI(
    title=service_name,
    description="RestAPI endpoint for adding SBOM data to a component",
    version="10.0.0",
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
    servers=[{"url": "http://localhost:5003", "description": "Local Server"}],
    contact={
        "name": "Ortelius Open Source Project",
        "url": "https://github.com/ortelius/ortelius/issues",
        "email": "support@ortelius.io",
    },
    openapi_tags=tags_metadata,
)


# Init db connection
db_host = os.getenv("DB_HOST", "localhost")
db_name = os.getenv("DB_NAME", "postgres")
db_user = os.getenv("DB_USER", "postgres")
db_pass = os.getenv("DB_PASS", "postgres")
db_port = os.getenv("DB_PORT", "5432")
validateuser_url = os.getenv("VALIDATEUSER_URL", "")
safety_db = None

if len(validateuser_url) == 0:
    validateuser_host = os.getenv("MS_VALIDATE_USER_SERVICE_HOST", "127.0.0.1")
    host = socket.gethostbyaddr(validateuser_host)[0]
    validateuser_url = "http://" + host + ":" + str(os.getenv("MS_VALIDATE_USER_SERVICE_PORT", "80"))

engine = create_engine("postgresql+psycopg2://" + db_user + ":" + db_pass + "@" + db_host + ":" + db_port + "/" + db_name, pool_pre_ping=True)


def calculate_cvss_score(cvss_vector):
    try:
        # Define metric weights for CVSS v2
        cvss2_metric_weights = {
            "AV": {"N": 0.85, "A": 0.62, "L": 0.55},
            "AC": {"H": 0.44, "M": 0.77},
            "Au": {"N": 0.704, "S": 0.56},
            "C": {"N": 0.0, "P": 0.275, "C": 0.660},
            "I": {"N": 0.0, "P": 0.275, "C": 0.660},
            "A": {"N": 0.0, "P": 0.275, "C": 0.660},
        }

        # Define metric weights for CVSS v3
        cvss3_metric_weights = {
            "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
            "AC": {"H": 0.44, "L": 0.77},
            "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
            "UI": {"N": 0.85, "R": 0.62},
            "S": {"U": 6.42, "C": 7.52},
            "C": {"N": 0.0, "L": 0.22, "H": 0.56},
            "I": {"N": 0.0, "L": 0.22, "H": 0.56},
            "A": {"N": 0.0, "L": 0.22, "H": 0.56},
        }

        # Determine the CVSS version
        if cvss_vector.startswith("CVSS:2"):
            metric_weights = cvss2_metric_weights
        elif cvss_vector.startswith("CVSS:3"):
            metric_weights = cvss3_metric_weights
        else:
            raise ValueError("Invalid CVSS vector format")

        # Parse the CVSS vector
        vector_parts = cvss_vector.split("/")
        if len(vector_parts) != 3:
            raise ValueError("Invalid CVSS vector format")

        base_vector = vector_parts[1]

        # Calculate the base score
        base_score = 0.0
        for metric in base_vector.split(":"):
            metric_name, metric_value = metric.split("=")
            if metric_name in metric_weights and metric_value in metric_weights[metric_name]:
                base_score += metric_weights[metric_name][metric_value]

        base_score = min(10, base_score)
        return round(base_score, 1)

    except Exception as ex:
        print(f"Error calculating CVSS score: {ex}")
        return None


def get_vulns(payload):
    vulns = []
    url = "https://api.osv.dev/v1/query"
    try:
        response = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "vulns" in data:
                vulns = data["vulns"]
    except Exception as ex:
        print(ex)

    return vulns


def update_vulns():
    # Retry logic for failed query
    no_of_retry = db_conn_retry
    attempt = 1
    while True:
        try:
            sqlstmt = """
                select distinct packagename, packageversion, purl
                from dm.dm_componentdeps where deptype = 'license'
            """

            with engine.connect() as connection:
                conn = connection.connection
                cursor = conn.cursor()
                cursor.execute(sqlstmt)
                results = cursor.fetchall()

                for result in results:
                    packagename, packageversion, purl = result

                    if purl is None or purl.strip() == "":
                        payload = {"package": {"name": packagename.lower()}, "version": packageversion.lower()}
                    else:
                        if "?" in purl:
                            purl = purl.split("?")[0]
                        payload = {"package": {"purl": purl.lower()}}

                    vulns = get_vulns(payload)

                    for obj in vulns:
                        vulnid = obj.get("id", "")
                        desc = obj.get("summary", "")

                        if "aliases" in obj:
                            aliases = " ".join(obj["aliases"])
                            if desc:
                                desc = f"{aliases}: {desc}"
                            else:
                                desc = aliases

                        risklevel = ""
                        cvss = ""
                        if "severity" in obj:
                            sevlist = obj.get("severity", [])
                            sev = sevlist.get(0)
                            cvss = sev.get("score", None)

                            if cvss is not None:
                                base = calculate_cvss_score(cvss)
                                if base is not None:
                                    if base == 0.0:
                                        risklevel = "None"
                                    elif 0.1 <= base <= 3.9:
                                        risklevel = "Low"
                                    elif 4.0 <= base <= 6.9:
                                        risklevel = "Medium"
                                    elif 7.0 <= base <= 8.9:
                                        risklevel = "High"
                                    elif base >= 9.0:
                                        risklevel = "Critical"

                            if not risklevel and "database_specific" in obj:
                                sec = obj["database_specific"]
                                if "severity" in sec:
                                    risklevel = sec["severity"]

                        risklevel = risklevel.capitalize()
                        if risklevel == "Moderate":
                            risklevel = "Medium"

                        try:
                            sqlstmt = """
                                insert into dm.dm_vulns (packagename, packageversion, purl, id, summary, risklevel, cvss)
                                values (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT ON CONSTRAINT dm_vulns_pkey DO NOTHING
                            """
                            params = tuple([packagename, packageversion, purl, vulnid, desc, risklevel, cvss])
                            cursor.execute(sqlstmt, params)
                            conn.commit()
                        except Exception:
                            print(f"Duplicate Vuln: {packagename}, {packageversion}, {vulnid}, {desc}, {risklevel}, {cvss}")
        except (InterfaceError, OperationalError) as ex:
            if attempt < no_of_retry:
                sleep_for = 0.2
                logging.error("Database connection error: %s - sleeping for %d seconds and will retry (attempt #%d of %d)", ex, sleep_for, attempt, no_of_retry)
                # 200ms of sleep time in cons. retry calls
                sleep(sleep_for)
                attempt += 1
                continue
            else:
                raise


# health check endpoint
class StatusMsg(BaseModel):
    status: str
    service_name: str


@app.get("/health", tags=["health"])
async def health(response: Response) -> StatusMsg:
    """
    This health check end point used by Kubernetes
    """
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
    example_dict = {}
    with open(filename, mode="r", encoding="utf-8") as example_file:
        example_dict = json.load(example_file)
    return example_dict


@app.post("/msapi/deppkg/cyclonedx", tags=["cyclonedx"])
async def cyclonedx(request: Request, response: Response, compid: int, cyclonedx_json: dict = Body(..., example=example("cyclonedx.json"), description="JSON output from running CycloneDX")):
    """
    This is the end point used to upload a CycloneDX SBOM
    """
    try:
        result = requests.get(validateuser_url + "/msapi/validateuser", cookies=request.cookies, timeout=5)
        if result is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed")

        if result.status_code != status.HTTP_200_OK:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed status_code=" + str(result.status_code))
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed:" + str(err)) from None

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
            current_license = licenses[0].get("license", {})
            if current_license.get("id", None) is not None:
                license_name = current_license.get("id")
            elif current_license.get("name", None) is not None:
                license_name = current_license.get("name")
                if "," in license_name:
                    license_name = license_name.split(",")[0]

            if len(license_name) > 0:
                license_url = "https://spdx.org/licenses/" + license_name + ".html"
        component_data = (compid, packagename, packageversion, bomformat, license_name, license_url, summary, purl, pkgtype)
        components_data.append(component_data)

    return save_components_data(response, compid, bomformat, components_data)


@app.post("/msapi/deppkg/spdx", tags=["spdx"])
async def spdx(request: Request, response: Response, compid: int, spdx_json: dict = Body(..., example=example("spdx.json"), description="JSON output from running SPDX")):
    """
    This is the end point used to upload a SPDX SBOM
    """
    try:
        result = requests.get(validateuser_url + "/msapi/validateuser", cookies=request.cookies, timeout=5)
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
        current_license = component.get("licenseDeclared")
        if current_license != "NOASSERTION":
            license_name = current_license
            license_url = "https://spdx.org/licenses/" + license_name + ".html"

        if "," in license_name:
            license_name = license_name.split(",", maxsplit=1)[0]

        component_data = (compid, packagename, packageversion, bomformat, license_name, license_url, summary, purl, pkgtype)
        components_data.append(component_data)

    threading.Thread(target=update_vulns).start()

    return save_components_data(response, compid, bomformat, components_data)


@app.post("/msapi/deppkg/safety", tags=["safety"])
async def safety(request: Request, response: Response, compid: int, safety_json: list = Body(..., example=example("safety.json"), description="JSON output from running safety")):
    """
    This is the end point used to upload a Python Safety SBOM
    """
    global safety_db  # pylint: disable=W0603
    result = requests.get(validateuser_url + "/msapi/validateuser", cookies=request.cookies, timeout=5)
    if result is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed")

    if result.status_code != status.HTTP_200_OK:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed status_code=" + str(result.status_code))

    if safety_db is None:
        url = requests.get("https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json", timeout=5)
        safety_db = json.loads(url.text)

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
    return save_components_data(response, compid, bomformat, components_data)


def save_components_data(response, compid, bomformat, components_data):
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
                    cursor = conn.cursor()

                    # delete old licenses
                    sqlstmt = "DELETE from dm.dm_componentdeps where compid=%s and deptype=%s"
                    params = (
                        compid,
                        bomformat,
                    )
                    cursor.execute(sqlstmt, params)

                    # insert into database
                    sqlstmt = """
                        INSERT INTO dm.dm_componentdeps(compid, packagename, packageversion, deptype, name, url, summary, purl, pkgtype)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT ON CONSTRAINT dm_componentdeps_pkey DO NOTHING
                    """

                    cursor.executemany(sqlstmt, components_data)

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
                    logging.error("Database connection error: %s - sleeping for %d seconds and will retry (attempt #%d of %d)", ex, sleep_for, attempt, no_of_retry)
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
    uvicorn.run(app, port=5003)
