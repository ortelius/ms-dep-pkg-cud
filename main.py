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
import re
import socket
import subprocess  # nosec B404
import sys
import tempfile
import threading
import traceback
import urllib.parse
import warnings
from pprint import pprint
from time import sleep

import requests
import uvicorn
from cvss import CVSS2, CVSS3, CVSS4
from defusedxml import ElementTree as ET
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from packageurl import PackageURL
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

dhurl = ""
cookies = {}  # type: ignore

warnings.filterwarnings("ignore", message="Invalid HTTP request received", category=UserWarning)

desc = """
RestAPI endpoint for adding SBOM data to a component

![Release](https://img.shields.io/github/v/release/ortelius/ms-dep-pkg-cud?sort=semver)
![license](https://img.shields.io/github/license/ortelius/ms-dep-pkg-cud)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/ms-dep-pkg-cud/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/ms-dep-pkg-cud/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/ms-dep-pkg-cud/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/ms-dep-pkg-cud/workflows/CodeQL/badge.svg)
[![OpenSSF
-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-dep-pkg-cud/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-dep-pkg-cud)


![Discord](https://img.shields.io/discord/722468819091849316)
"""

# Init FastAPI
app = FastAPI(
    title=service_name,
    description=desc,
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


# Add global exception handler for 502 errors
@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    """
    Custom exception handler that prints stack trace for 502 errors
    """
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    # Check if it's a connection/gateway error that would result in 502
    if isinstance(exc, (requests.exceptions.ConnectionError,
                       requests.exceptions.Timeout,
                       TimeoutError)):
        status_code = status.HTTP_502_BAD_GATEWAY

        # Print stack trace to stdout
        print("\n" + "="*80, flush=True)
        print("502 BAD GATEWAY ERROR OCCURRED", flush=True)
        print("="*80, flush=True)
        print(f"Request URL: {request.url}", flush=True)
        print(f"Request Method: {request.method}", flush=True)
        print(f"Exception Type: {type(exc).__name__}", flush=True)
        print(f"Exception Message: {str(exc)}", flush=True)
        print("\nFull Stack Trace:", flush=True)
        print("-"*80, flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)

    return JSONResponse(
        status_code=status_code,
        content={"detail": str(exc)}
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

    # Retry 60 times with a 5-second delay (60 * 5s = 300s = 5 minutes)
    for attempt in range(60):
        try:
            host = socket.gethostbyaddr(validateuser_host)[0]
            print(f"Successfully resolved host on attempt #{attempt + 1}.")
            break  # Exit the loop on success
        except socket.herror:
            print("DNS lookup failed. Retrying in 5 seconds...")
            sleep(5)
    else:
        # This 'else' block runs ONLY if the 'for' loop finishes without a 'break'.
        # This means all 60 retries have failed.
        raise TimeoutError(f"Could not resolve host '{validateuser_host}' after 5 minutes.")

    # If the loop succeeded, 'host' is now defined.
    port = os.getenv("MS_VALIDATE_USER_SERVICE_PORT", "80")
    validateuser_url = f"http://{host}:{port}"
    print(f"Service URL is ready: {validateuser_url}")

engine = create_engine(
    "postgresql+psycopg2://" + db_user + ":" + db_pass + "@" + db_host + ":" + db_port + "/" + db_name,
    pool_pre_ping=True,
)


def is_empty(my_string):
    """
    Is the string empty.

    Args:
        my_string (string): string to check emptyness on

    Returns:
        boolean: True if the string is None or blank, otherwise False.
    """
    if isinstance(my_string, int):
        my_string = str(my_string)
    return not (my_string and my_string.strip())


def is_not_empty(my_string):
    """
    Is the string NOT empty.

    Args:
        my_string (string): string to check emptyness on

    Returns:
        boolean: False if the string is None or blank, otherwise True.
    """
    if isinstance(my_string, int):
        my_string = str(my_string)

    return bool(my_string and my_string.strip())


def get_json(url, cookies):
    """
    Get URL as json string.

    Args:
        url (string): url to server
        cookies (string) - login cookies

    Returns:
        string: The json string.

    """
    try:
        res = requests.get(url, cookies=cookies, timeout=300)
        if res is None:
            return None
        if res.status_code == 502:
            print("\n" + "="*80, flush=True)
            print(f"502 BAD GATEWAY response from: {url}", flush=True)
            print("="*80, flush=True)
            print("Stack trace:", flush=True)
            traceback.print_stack(file=sys.stdout)
            sys.stdout.flush()
            print("="*80 + "\n", flush=True)
        if res.status_code != 200:
            return None
        return res.json()
    except requests.exceptions.ConnectionError as conn_error:
        print("\n" + "="*80, flush=True)
        print("502 CONNECTION ERROR in get_json", flush=True)
        print(f"URL: {url}", flush=True)
        print(f"Error: {str(conn_error)}", flush=True)
        print("-"*80, flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)
    except Exception as err:
        print(f"Other error occurred: {err}", flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
    return None


def post_json(url, payload, cookies):
    """
    Post URL as json string.

    Args:
        url (string): url to server
        payload (string): json payload to post
        cookies (string): login cookies

    Returns:
        string: The json string.
    """
    try:
        if "/import" in url:
            res = requests.post(
                url,
                data=payload,
                cookies=cookies,
                headers={"Content-Type": "application/json"},
                timeout=1800,
            )
        else:
            res = requests.post(
                url,
                data=payload,
                cookies=cookies,
                headers={
                    "Content-Type": "application/json",
                    "host": "console.deployhub.com",
                },
                timeout=300,
            )

        if res is None:
            return None

        if res.status_code == 502:
            print("\n" + "="*80, flush=True)
            print(f"502 BAD GATEWAY response from POST: {url}", flush=True)
            print("="*80, flush=True)
            print("Stack trace:", flush=True)
            traceback.print_stack(file=sys.stdout)
            sys.stdout.flush()
            print("="*80 + "\n", flush=True)

        if res.status_code < 200 and res.status_code > 299:
            return None
        return res.json()
    except requests.exceptions.ConnectionError as conn_error:
        print("\n" + "="*80, flush=True)
        print("502 CONNECTION ERROR in post_json", flush=True)
        print(f"URL: {url}", flush=True)
        print(f"Error: {str(conn_error)}", flush=True)
        print("-"*80, flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)
    return None


def get_component(dhurl, cookies, compname, compvariant, compversion, id_only, latest):
    """
    Get the component json string.

    Args:
        dhurl (string): url to the server
        cookies (string): cookies from login
        compname (string): name of the component including domain name
        compvariant (string): variant of the component, optional
        compversion (string): version of the component, optional
        id_only (boolean): return just the id and not the whole json string
        latest (boolean): return the latest version

    Returns:
        int: if id_only = True
        string: if id_only = False. If latest = True then latest version json is returned otherwise current version json string is returned.
    """
    compvariant = clean_name(compvariant)
    compversion = clean_name(compversion)

    if (compvariant == "" or compvariant is None) and compversion is not None and compversion != "":
        compvariant = compversion
        compversion = None

    component = ""

    if compvariant is not None and compvariant != "" and compversion is not None and compversion != "":
        component = compname + ";" + compvariant + ";" + compversion
    elif compvariant is not None and compvariant != "":
        component = compname + ";" + compvariant
    else:
        component = compname

    check_compname = ""
    short_compname = ""

    if "." in compname:
        short_compname = compname.split(".")[-1]

    if compvariant is not None and compvariant != "" and compversion is not None and compversion != "":
        check_compname = short_compname + ";" + compvariant + ";" + compversion
    elif compvariant is not None and compvariant != "":
        check_compname = short_compname + ";" + compvariant
    else:
        check_compname = short_compname

    param = ""
    if id_only:
        param = "&idonly=Y"

    if latest:
        param = param + "&latest=Y"

    data = get_json(
        dhurl + "/dmadminweb/API/component/?name=" + urllib.parse.quote(component) + param,
        cookies,
    )

    if data is None:
        return [-1, ""]

    if data["success"]:
        compid = data["result"]["id"]
        name = data["result"]["name"]

        if name != check_compname and "versions" in data["result"]:
            vers = data["result"]["versions"]
            for ver in vers:
                if ver["name"] == check_compname:
                    compid = ver["id"]
                    name = ver["name"]
                    break

        return [compid, name]

    return [-1, ""]


def new_component_version(
    dhurl,
    cookies,
    compname,
    compvariant,
    compversion,
    kind,
    component_items,
    compautoinc,
):
    """
    Create a new component version and base version if needed.

    Args:
        dhurl (string): url to the server
        cookies (string): cookies from login
        compname (string): name of the component including domain
        compvariant (string): variant of the component, optional
        compversion (string): version of the component, optional
        kind (string): docker or file
        component_items (list): component items for the file type
        compautoinc (boolean): auto increment an existing version to the new version
    Returns:
        int: id of the new component, -1 if an error occurred.
    """
    compvariant = clean_name(compvariant)
    compversion = clean_name(compversion)

    if (compvariant == "" or compvariant is None) and compversion is not None and compversion != "":
        compvariant = compversion
        compversion = None

    compname = compname.rstrip(";")
    compvariant = compvariant.rstrip(";")
    if compversion is not None:
        compversion = compversion.rstrip(";")

    # Get latest version of compnent variant
    data = get_component(dhurl, cookies, compname, compvariant, compversion, False, True)
    if data[0] == -1:
        data = get_component(dhurl, cookies, compname, compvariant, None, False, True)
        if data[0] == -1:
            data = get_component(dhurl, cookies, compname, "", None, False, True)

    latest_compid = data[0]
    found_compname = data[1]
    check_compname = ""
    compid = latest_compid

    short_compname = ""

    if "." in compname:
        short_compname = compname.split(".")[-1]

    if compvariant is not None and compvariant != "" and compversion is not None and compversion != "":
        check_compname = short_compname + ";" + compvariant + ";" + compversion
    elif compvariant is not None and compvariant != "":
        check_compname = short_compname + ";" + compvariant
    else:
        check_compname = short_compname

    # Create base component variant
    # if one is not found
    # Get the new compid of the new component variant
    if compvariant is None:
        compvariant = ""

    if compversion is None:
        compversion = ""

    if latest_compid < 0:
        if kind.lower() == "docker":
            compid = new_docker_component(dhurl, cookies, compname, compvariant, compversion, -1)
        else:
            compid = new_file_component(dhurl, cookies, compname, compvariant, compversion, -1, None)
    else:
        # Create component items for the component
        if compautoinc is None:
            if found_compname == "" or found_compname != check_compname:
                if kind.lower() == "docker":
                    compid = new_docker_component(dhurl, cookies, compname, compvariant, compversion, compid)
                else:
                    compid = new_file_component(
                        dhurl,
                        cookies,
                        compname,
                        compvariant,
                        compversion,
                        compid,
                        component_items,
                    )

            if compid > 0:
                if kind.lower() == "docker":
                    new_component_item(dhurl, cookies, compid, "docker", None)
                else:
                    new_component_item(dhurl, cookies, compid, "file", component_items)
    return compid


def new_docker_component(dhurl, cookies, compname, compvariant, compversion, parent_compid):
    """
    Create a new docker component.

    Args:
        dhurl (string): url to the server
        cookies (string): cookies from login
        compname (string): name of the component including domain
        compvariant (string): variant of the component, optional
        compversion (string): version of the component, optional
        parent_compid (int): parent component version for the new component
    Returns:
        int: id of the new component, -1 if an error occurred.
    """
    compvariant = clean_name(compvariant)
    compversion = clean_name(compversion)

    if (compvariant is None or compvariant == "") and compversion is not None and compversion != "":
        compvariant = compversion
        compversion = None

    compid = 0
    # Create base version
    if parent_compid < 0:
        if is_empty(compvariant):
            data = get_json(
                dhurl + "/dmadminweb/API/new/compver/?name=" + urllib.parse.quote(compname),
                cookies,
            )
        else:
            data = get_json(
                dhurl + "/dmadminweb/API/new/compver/?name=" + urllib.parse.quote(compname + ";" + compvariant),
                cookies,
            )
        if data is not None:
            result = data.get("result", {})
            compid = int(result.get("id", "0"))
    else:
        data = get_json(dhurl + "/dmadminweb/API/new/compver/" + str(parent_compid), cookies)
        if data is not None:
            if data is not None:
                result = data.get("result", {})
                compid = int(result.get("id", "0"))

        update_name(dhurl, cookies, compname, compvariant, compversion, compid)

    new_component_item(dhurl, cookies, compid, "docker", None)

    return compid


def new_file_component(dhurl, cookies, compname, compvariant, compversion, parent_compid, component_items):
    """
    Create a new file component.

    Args:
        dhurl (string): url to the server
        cookies (string): cookies from login
        compname (string): name of the component including domain
        compvariant (string): variant of the component, optional
        compversion (string): version of the component, optional
        parent_compid (int): parent component version for the new component
        component_items (list):  list of items for the component
    Returns:
        int: id of the new component, -1 if an error occurred.
    """
    compvariant = clean_name(compvariant)
    compversion = clean_name(compversion)

    if (compvariant is None or compvariant == "") and compversion is not None and compversion != "":
        compvariant = compversion
        compversion = None

    compid = 0

    # Create base version
    if parent_compid < 0:
        if is_empty(compvariant):
            data = get_json(
                dhurl + "/dmadminweb/API/new/compver/?name=" + urllib.parse.quote(compname),
                cookies,
            )
        else:
            data = get_json(
                dhurl + "/dmadminweb/API/new/compver/?name=" + urllib.parse.quote(compname + ";" + compvariant),
                cookies,
            )
        if data is not None:
            if data is not None:
                result = data.get("result", {})
                compid = int(result.get("id", "0"))
    else:
        data = get_json(dhurl + "/dmadminweb/API/new/compver/" + str(parent_compid), cookies)
        if data is not None:
            if data is not None:
                result = data.get("result", {})
                compid = int(result.get("id", "0"))
        update_name(dhurl, cookies, compname, compvariant, compversion, compid)

    new_component_item(dhurl, cookies, compid, "file", component_items)

    return compid


def new_component_item(dhurl, cookies, compid, kind, component_items):
    """
    Create a new component item for the component.

    Args:
        dhurl (string): url to the server
        cookies (string): cookies from login
        compname (string): name of the component including domain
        compvariant (string): variant of the component, optional
        compversion (string): version of the component, optional
        kind (string): docker or file for the component kind
    Returns:
        int: id of the new component item, -1 if an error occurred.
    """
    data = None
    # Get compId
    if kind.lower() == "docker" or component_items is None:
        data = get_json(
            dhurl + "/dmadminweb/UpdateAttrs?f=inv&c=" + str(compid) + "&xpos=100&ypos=100&kind=" + kind + "&removeall=Y",
            cookies,
        )
    else:
        ypos = 100

        i = 0
        parent_item = -1

        for item in component_items:
            tmpstr = ""
            ciname = ""
            for entry in item:
                if entry["key"].lower() == "name":
                    ciname = entry["value"]
                else:
                    tmpstr = tmpstr + "&" + urllib.parse.quote(entry["key"]) + "=" + urllib.parse.quote(entry["value"])

            if i == 0:
                tmpstr = tmpstr + "&removeall=Y"

            data = get_json(
                dhurl + "/dmadminweb/API/new/compitem/" + urllib.parse.quote(ciname) + "?component=" + str(compid) + "&xpos=100&ypos=" + str(ypos) + "&kind=" + kind + tmpstr,
                cookies,
            )

            if data is not None:
                if data.get("result", None) is not None:
                    result = data.get("result", {})
                    workid = result.get("id", -1)
                    if parent_item > 0:
                        get_json(
                            dhurl + "/dmadminweb/UpdateAttrs?f=iad&c=" + str(compid) + "&fn=" + str(parent_item) + "&tn=" + str(workid),
                            cookies,
                        )
                    parent_item = workid

            ypos = ypos + 100
            i = i + 1
    return data


def clean_name(name):
    """
    Remove periods and dashes from the name.

    Args:
        name (string): string to clean

    Returns:
        string: the name with periods and dashes changed to userscores.
    """
    if name is None:
        return name

    name = name.replace(".", "_")
    name = name.replace("-", "_")
    name = name.replace("/", ".")
    name = name.replace("+", "_")
    name = name.replace(":", "_")
    name = name.replace("~", "_")
    name = name.replace("(", "")
    name = name.replace(")", "")
    name = name.replace("#", "_")
    name = name.replace("@", "")
    return name


def update_name(dhurl, cookies, compname, compvariant, compversion, compid):
    """
    Update the name of the component for the compid to the new name.

    Args:
        dhurl (string): url to the server
        cookies (string): cookies from login
        compname (string): name of the component including domain
        compvariant (string): variant of the component, optional
        compversion (string): version of the component, optional
        compid (int): id to the component to update the name of
    Returns:
        string: json string of the component update.
    """
    compvariant = clean_name(compvariant)
    compversion = clean_name(compversion)

    if (compvariant is None or compvariant == "") and compversion is not None and compversion != "":
        compvariant = compversion
        compversion = None

    if "." in compname:
        compname = compname.split(".")[-1]

    if compvariant is not None and compvariant != "" and compversion is not None and compversion != "":
        data = get_json(
            dhurl + "/dmadminweb/UpdateSummaryData?objtype=23&id=" + str(compid) + "&change_1=" + urllib.parse.quote(compname + ";" + compvariant + ";" + compversion),
            cookies,
        )
    elif compvariant is not None and compvariant != "":
        data = get_json(
            dhurl + "/dmadminweb/UpdateSummaryData?objtype=23&id=" + str(compid) + "&change_1=" + urllib.parse.quote(compname + ";" + compvariant),
            cookies,
        )
    else:
        data = get_json(
            dhurl + "/dmadminweb/UpdateSummaryData?objtype=23&id=" + str(compid) + "&change_1=" + urllib.parse.quote(compname),
            cookies,
        )

    return data


def new_component(dhurl, cookies, compname, compvariant, compversion, kind, parent_compid):
    """
    Create the component object based on the component name and variant.

    Args:
        dhurl (string): url to the server
        cookies (string): cookies from login
        compname (string): name of the component including domain
        compvariant (string): variant of the component, optional
        compversion (string): version of the component, optional
        kind (string): docker or file for the kind of component
        parent_compid: id of the parent component version

    Returns:
        int: component id of the new component otherwise None.
    """
    compid = -1

    # Create base version
    if parent_compid is None:
        data = get_json(
            dhurl + "/dmadminweb/API/new/compver/?name=" + urllib.parse.quote(compname + ";" + compvariant),
            cookies,
        )
        if data is not None:
            if data is not None:
                result = data.get("result", {})
                compid = int(result.get("id", -1))
    else:
        data = get_json(dhurl + "/dmadminweb/API/new/compver/" + str(parent_compid), cookies)
        if data is not None:
            if data is not None:
                result = data.get("result", {})
                compid = int(result.get("id", -1))
    update_name(dhurl, cookies, compname, compvariant, compversion, compid)

    if kind is not None:
        new_component_item(dhurl, cookies, compid, kind, None)

    return compid


def get_component_name(dhurl, cookies, compid):
    """
    Get the full component name.

    Args:
        dhurl (string): url to the server
        cookies (string): cookies from login
        compid (int): id of the component

    Returns:
        string: full name of the component
    """
    name = ""
    data = get_json(dhurl + "/dmadminweb/API/component/" + str(compid) + "?idonly=Y", cookies)

    if data is None:
        return name

    if data["success"]:
        name = data["result"]["domain"] + "." + data["result"]["name"]
    return name


def update_component_attrs(dhurl, cookies, compname, compvariant, compversion, attrs):
    """
    Update the attributes, key/value pairs, for the component and CR list.

    Args:
        dhurl (string): url to the server
        cookies (string): cookies from login
        compname (string): name of the component including domain
        compvariant (string): variant of the component, optional
        compversion (string): version of the component, optional
        attrs (dict): key/value dictionary

    Returns:
        list: [True for success, otherwise False, json string of update, url for update].
    """
    # Get latest version of compnent variant
    data = get_component(dhurl, cookies, compname, compvariant, compversion, True, False)
    compid = data[0]

    if compid < 0:
        return

    payload = json.dumps(attrs)

    data = post_json(dhurl + "/dmadminweb/API/setvar/component/" + str(compid), payload, cookies)
    if data is None:
        return [False, "Could not update attributes on '" + compname + "'"]

    return [True, data, dhurl + "/dmadminweb/API/setvar/component/" + str(compid)]


def create_compver(dhurl, cookies, purl):
    if purl is None or purl.strip() == "":
        return

    try:
        purl_parts = PackageURL.from_string(purl)
    except ValueError:
        return

    domain = ""
    if purl_parts.namespace is None:
        domain = "GLOBAL.Open Source." + purl_parts.type
    else:
        domain = "GLOBAL.Open Source." + purl_parts.type + "." + purl_parts.namespace.replace(".", "_")

    domain = domain.replace("/", ".").replace("-", "_").replace("+", "_").replace("@", "")

    compname = ""
    version = ""
    if purl_parts.version is None:
        compname = clean_name(purl_parts.name.replace(".", "_"))
    else:
        compname = clean_name(purl_parts.name.replace(".", "_") + ";" + purl_parts.version)
        version = clean_name(purl_parts.version)

    package = clean_name(purl_parts.name).replace(".", "_")

    try:
        with engine.connect() as connection:
            conn = connection.connection
            cursor = conn.cursor()

            params = tuple([domain, compname])
            cursor.execute(
                "select count(*) from dm.dm_component a, dm.dm_domain b where a.domainid = b.id and b.fullname = %s and a.name = %s",
                params,
            )
            count_result = cursor.fetchone()[0]
            cursor.close

            if count_result == 0:
                compvariant = ""
                compautoinc = None
                kind = "file"
                compname = domain + "." + package
                compversion = version

                data = get_component(dhurl, cookies, compname, "", "", True, True)
                parent_compid = data[0]

                # create component version
                if parent_compid < 0:
                    print("Creating Parent Component")
                    parent_compid = new_component_version(
                        dhurl,
                        cookies,
                        compname,
                        compvariant,
                        "",
                        kind,
                        None,
                        compautoinc,
                    )

                print("Creating Component")
                shortname = compname
                if "." in shortname:
                    shortname = shortname.split(".")[-1]

                compid = new_component_version(dhurl, cookies, compname, compversion, "", kind, None, compautoinc)
            else:
                compvariant = ""
                compautoinc = None
                kind = "file"
                compname = domain + "." + package
                compversion = version

                compid = get_component(dhurl, cookies, compname, compvariant, compversion, True, False)

            compname = get_component_name(dhurl, cookies, compid)
            compversion = ""
            compvariant = ""

            print("Creation Done: " + compname)
            attrs = {}
            org = ""
            repo_project = ""
            gitcommit = None
            giturl = None

            results = getCommitFromPurl(
                purl_parts.type,
                purl_parts.namespace,
                purl_parts.name,
                purl_parts.version,
                purl,
            )

            giturl = results.get("repo_url", None)
            gitcommit = results.get("commit_sha", None)

            print(f"Purl: {purl}, Url: {giturl}, Commit: {gitcommit}")
            if gitcommit is not None:
                attrs["GitCommit"] = gitcommit

            if giturl is not None and giturl != "":
                giturl = giturl.replace(".git", "")
                path_segments = giturl.strip("/").replace("https://", "").replace("http://", "").split("/")
                # Extract org and repo from the path segments
                if len(path_segments) >= 3:
                    org = path_segments[1]
                    repo_project = path_segments[2]

                attrs["Purl"] = purl
                attrs["GitUrl"] = giturl
                attrs["GitOrg"] = org
                attrs["GitRepo"] = org + "/" + repo_project
                attrs["GitRepoProject"] = repo_project
                if purl_parts.version is not None:
                    attrs["GitTag"] = purl_parts.version

                data = update_component_attrs(dhurl, cookies, compname, compvariant, compversion, attrs)
                print("Attribute Update Done")
                return
    except Exception as err:
        print(str(err))
        return


def get_commit_sha(repo_url, package_version):
    if repo_url is None:
        return None

    cwd = os.getcwd()

    # Create a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_url = repo_url.replace("http://github.com", "https://github.com")
        repo_url = repo_url.replace("git://github.com", "https://github.com")
        repo_url = repo_url.replace("git+https://", "https://github.com")
        repo_url = repo_url.replace("git+ssh://git@", "https://")
        repo_url = repo_url.replace("git+", "")

        # Clone the repository without checking out the files
        # print(f"Clone {repo_url}")

        try:
            subprocess.run(
                ["git", "clone", repo_url, "--no-checkout", temp_dir],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )  # nosec B602, B603, B607
        except subprocess.TimeoutExpired:
            os.chdir(cwd)
            return None

        # Change into the cloned repository directory
        os.chdir(temp_dir)

        if not os.path.exists(".git"):
            os.chdir(cwd)
            return None

        commit_sha = None
        try:
            commit_sha = subprocess.check_output(
                ["git", "rev-list", "-n", "1", package_version],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()  # nosec B602, B603, B607
        except subprocess.CalledProcessError:
            pass

        if commit_sha is None:
            try:
                commit_sha = subprocess.check_output(
                    ["git", "rev-list", "-n", "1", "v" + package_version],
                    stderr=subprocess.DEVNULL,
                    text=True,
                ).strip()  # nosec B602, B603, B607
            except subprocess.CalledProcessError:
                pass

        # print(f"Commit {commit_sha}")
        os.chdir(cwd)
        return commit_sha


def get_deb_info(package_name, version):
    repo_url = None
    dscfile = f"https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/{package_name}/{version}/{package_name}_{version}.dsc"

    try:
        response = requests.get(dscfile, allow_redirects=True, timeout=2)
        # Check if the request was successful (status code 200)
        if response.status_code == 502:
            print("\n" + "="*80, flush=True)
            print(f"502 BAD GATEWAY from get_deb_info: {dscfile}", flush=True)
            print("="*80, flush=True)
            traceback.print_stack(file=sys.stdout)
            sys.stdout.flush()
            print("="*80 + "\n", flush=True)

        if response.status_code == 200:
            dsc_content = response.text

            # Find the value for vcs-git using regular expression
            vcs_git_match = re.search(r"^Vcs-Git:\s*(.*)", dsc_content, re.MULTILINE)
            repo_url = vcs_git_match.group(1) if vcs_git_match else None
    except requests.exceptions.ConnectionError as conn_error:
        print("\n" + "="*80, flush=True)
        print("502 CONNECTION ERROR in get_deb_info", flush=True)
        print(f"URL: {dscfile}", flush=True)
        print(f"Error: {str(conn_error)}", flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)

    if repo_url is None:
        return "", None

    if "git://git.debian.org/git" in repo_url:
        repo_url = repo_url.replace("git://git.debian.org/git", "https://salsa.debian.org").replace(".git", "")

    if "git://git.debian.org/users" in repo_url:
        repo_url = repo_url.replace("git://git.debian.org/users", "https://salsa.debian.org").replace(".git", "")

    if "git://anonscm.debian.org/users" in repo_url:
        repo_url = repo_url.replace("git://anonscm.debian.org/users", "https://salsa.debian.org").replace(".git", "")

    if "git://git.debian.org" in repo_url:
        repo_url = repo_url.replace("git://git.debian.org", "https://salsa.debian.org").replace(".git", "")

    if "git://anonscm.debian.org" in repo_url:
        repo_url = repo_url.replace("git://anonscm.debian.org", "https://salsa.debian.org").replace(".git", "")

    # Define the pattern to match "pkg-*"
    pattern = re.compile(r"pkg-(\w+)")

    # Use a lambda function in the sub method to transpose "pkg-*" to "*-team"
    repo_url = pattern.sub(lambda match: f"{match.group(1)}-team", repo_url)

    print(f"DSC: {repo_url}")
    commit_sha = get_commit_sha(repo_url, version)
    return repo_url, commit_sha


def get_pypi_info(package_name, version):
    url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 502:
            print("\n" + "="*80, flush=True)
            print(f"502 BAD GATEWAY from get_pypi_info: {url}", flush=True)
            print("="*80, flush=True)
            traceback.print_stack(file=sys.stdout)
            sys.stdout.flush()
            print("="*80 + "\n", flush=True)

        data = response.json()
        info = data.get("info", {})
        project_urls = info.get("project_urls", {})

        repo_url = None
        for key, value in project_urls.items():
            if "source" in key.lower():
                repo_url = value
                break
        commit_sha = get_commit_sha(repo_url, version)
        return repo_url, commit_sha
    except requests.exceptions.ConnectionError as conn_error:
        print("\n" + "="*80, flush=True)
        print("502 CONNECTION ERROR in get_pypi_info", flush=True)
        print(f"URL: {url}", flush=True)
        print(f"Error: {str(conn_error)}", flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)
        return None, None


def get_npm_info(package_name, version):
    url = f"https://registry.npmjs.org/{package_name}/{version}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 502:
            print("\n" + "="*80, flush=True)
            print(f"502 BAD GATEWAY from get_npm_info: {url}", flush=True)
            print("="*80, flush=True)
            traceback.print_stack(file=sys.stdout)
            sys.stdout.flush()
            print("="*80 + "\n", flush=True)

        if response.status_code == 200:
            data = response.json()
            repo_url = data.get("repository", {}).get("url", "")
        else:
            return "", None

        commit_sha = get_commit_sha(repo_url, version)
        return repo_url, commit_sha
    except requests.exceptions.ConnectionError as conn_error:
        print("\n" + "="*80, flush=True)
        print("502 CONNECTION ERROR in get_npm_info", flush=True)
        print(f"URL: {url}", flush=True)
        print(f"Error: {str(conn_error)}", flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)
        return "", None


def get_golang_info(domain, module_name, version):
    repo_url = ""
    commit_sha = None

    url = f"https://proxy.golang.org/{domain}/{module_name}/@v/{version}.info"
    print("Version URL: " + url)
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 502:
            print("\n" + "="*80, flush=True)
            print(f"502 BAD GATEWAY from get_golang_info: {url}", flush=True)
            print("="*80, flush=True)
            traceback.print_stack(file=sys.stdout)
            sys.stdout.flush()
            print("="*80 + "\n", flush=True)

        if response.status_code == 200:
            data = response.json()
            origin = data.get("Origin", None)
            if origin is not None:
                repo_url = origin.get("URL", None)
                commit_sha = origin.get("Hash", None)
    except requests.exceptions.ConnectionError as conn_error:
        print("\n" + "="*80, flush=True)
        print("502 CONNECTION ERROR in get_golang_info", flush=True)
        print(f"URL: {url}", flush=True)
        print(f"Error: {str(conn_error)}", flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)

    return repo_url, commit_sha


def get_java_info(group, artifact, version):
    url = url = f'https://repo1.maven.org/maven2/{group.replace(".", "/")}/{artifact}/{version}/{artifact}-{version}.pom'

    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 502:
            print("\n" + "="*80, flush=True)
            print(f"502 BAD GATEWAY from get_java_info: {url}", flush=True)
            print("="*80, flush=True)
            traceback.print_stack(file=sys.stdout)
            sys.stdout.flush()
            print("="*80 + "\n", flush=True)

        if response.status_code != 200:
            return "", None

        # Parse the POM file
        pom_tree = ET.fromstring(response.text)

        repo_url = None
        # Extract SCM information
        scm_element = pom_tree.find(".//{http://maven.apache.org/POM/4.0.0}scm")
        if scm_element is not None:
            url_elem = scm_element.find(".//{http://maven.apache.org/POM/4.0.0}url")
            if url_elem is not None:
                repo_url = url_elem.text

        if repo_url is None:
            return None, None

        commit_sha = get_commit_sha(repo_url, version)
        return repo_url, commit_sha
    except requests.exceptions.ConnectionError as conn_error:
        print("\n" + "="*80, flush=True)
        print("502 CONNECTION ERROR in get_java_info", flush=True)
        print(f"URL: {url}", flush=True)
        print(f"Error: {str(conn_error)}", flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)
        return "", None


def get_rust_info(crate_name, version):
    url = f"https://crates.io/api/v1/crates/{crate_name}/{version}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 502:
            print("\n" + "="*80, flush=True)
            print(f"502 BAD GATEWAY from get_rust_info: {url}", flush=True)
            print("="*80, flush=True)
            traceback.print_stack(file=sys.stdout)
            sys.stdout.flush()
            print("="*80 + "\n", flush=True)

        data = response.json()
        repo_url = data.get("crate", {}).get("repository", "")
        commit_sha = get_commit_sha(repo_url, version)
        return repo_url, commit_sha
    except requests.exceptions.ConnectionError as conn_error:
        print("\n" + "="*80, flush=True)
        print("502 CONNECTION ERROR in get_rust_info", flush=True)
        print(f"URL: {url}", flush=True)
        print(f"Error: {str(conn_error)}", flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)
        return None, None


def getCommitFromPurl(package_type, package_namespace, package_name, package_version, purl):
    repo_url = None
    commit_sha = None

    if package_type is None or len(package_type) == 0:
        return {"repo_url": repo_url, "commit_sha": commit_sha}
    elif package_type == "pypi":
        repo_url, commit_sha = get_pypi_info(package_name, package_version)
    elif package_type == "npm":
        repo_url, commit_sha = get_npm_info(package_name, package_version)
    elif package_type == "golang":
        repo_url, commit_sha = get_golang_info(package_namespace, package_name, package_version)
    elif package_type == "maven":
        repo_url, commit_sha = get_java_info(package_namespace, package_name, package_version)
    elif package_type == "cargo":
        repo_url, commit_sha = get_rust_info(package_name, package_version)
    elif package_type == "deb":
        repo_url, commit_sha = get_deb_info(package_name, package_version)
    else:
        print(f"Unsupported package type: {package_type}")

    return {"repo_url": repo_url, "commit_sha": commit_sha}


def example(filename):
    example_dict = {}
    with open(filename, mode="r", encoding="utf-8") as example_file:
        example_dict = json.load(example_file)
    return example_dict


def calculate_cvss_score(cvss_vector):
    try:
        # Determine the CVSS version
        if cvss_vector.startswith("CVSS:3"):
            c = CVSS3(cvss_vector)
            return c.scores()[0]
        elif cvss_vector.startswith("CVSS:4"):
            c = CVSS4(cvss_vector)
            return c.scores()[0]
        else:
            c = CVSS2(cvss_vector)
            return c.scores()[0]

    except Exception as ex:
        print(f"Error calculating CVSS score: {ex}")
        return None


def get_vulns(payload):
    vulns = []
    url = "https://api.osv.dev/v1/query"
    try:
        response = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        if response.status_code == 502:
            print("\n" + "="*80, flush=True)
            print(f"502 BAD GATEWAY from get_vulns: {url}", flush=True)
            print("="*80, flush=True)
            traceback.print_stack(file=sys.stdout)
            sys.stdout.flush()
            print("="*80 + "\n", flush=True)

        if response.status_code == 200:
            data = response.json()
            if "vulns" in data:
                vulns = data["vulns"]
    except requests.exceptions.ConnectionError as conn_error:
        print("\n" + "="*80, flush=True)
        print("502 CONNECTION ERROR in get_vulns", flush=True)
        print(f"URL: {url}", flush=True)
        print(f"Error: {str(conn_error)}", flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)
    except Exception as ex:
        print(ex)

    return vulns


def login(dhurl, user, password, errors):
    """
    Login to DeployHub using the DH Url, userid and password.

    Args:
        dhurl (string): url to server
        user (string): username to login with
        password (string): password for login
        errors (list): list to return any errors back to the caller

    Returns:
        string: the cookies to be used in subsequent API calls.
    """
    try:
        result = requests.post(
            dhurl + "/dmadminweb/API/login",
            data={"user": user, "pass": password},
            timeout=300,
        )
        if result.status_code == 502:
            print("\n" + "="*80, flush=True)
            print(f"502 BAD GATEWAY from login: {dhurl}/dmadminweb/API/login", flush=True)
            print("="*80, flush=True)
            traceback.print_stack(file=sys.stdout)
            sys.stdout.flush()
            print("="*80 + "\n", flush=True)

        cookies = result.cookies
        if result.status_code == 200:
            data = result.json()
            if not data.get("success", False):
                errors.append(data.get("error", ""))
                return None
            return cookies
    except requests.exceptions.ConnectionError as conn_error:
        print("\n" + "="*80, flush=True)
        print("502 CONNECTION ERROR in login", flush=True)
        print(f"URL: {dhurl}/dmadminweb/API/login", flush=True)
        print(f"Error: {str(conn_error)}", flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)
        errors.append(str(conn_error))
    return None


def update_vulns():
    """
    Thread to update vulnerabilities

    Global:
        dhurl (string): url to server
        cookies (string): cookies from login
    """

    global dhurl  # noqa: F824
    global cookies  # noqa: F824

    # dhurl = "http://localhost:8181"
    # errors = []
    # cookies = login(dhurl, "admin", "admin", errors)

    # Retry logic for failed query
    no_of_retry = db_conn_retry
    attempt = 1
    while True:
        try:
            sqlstmt = """
                select distinct packagename, packageversion, purl
                from dm.dm_componentdeps where deptype = 'license' and purl is not null
            """

            with engine.connect() as connection:
                conn = connection.connection
                cursor = conn.cursor()
                cursor.execute(sqlstmt)
                results = cursor.fetchall()

                for result in results:
                    packagename, packageversion, purl = result

                    create_compver(dhurl, cookies, purl)

                    if purl is None or purl.strip() == "":
                        payload = {
                            "package": {"name": packagename.lower()},
                            "version": packageversion.lower(),
                        }
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
                            sev = sevlist[0]
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
                            params = tuple(
                                [
                                    packagename,
                                    packageversion,
                                    purl,
                                    vulnid,
                                    desc,
                                    risklevel,
                                    cvss,
                                ]
                            )
                            cursor.execute(sqlstmt, params)
                            conn.commit()
                        except Exception:
                            print(f"Duplicate Vuln: {packagename}, {packageversion}, {vulnid}, {desc}, {risklevel}, {cvss}")
                return
        except (InterfaceError, OperationalError) as ex:
            if attempt < no_of_retry:
                sleep_for = 0.2
                logging.error(
                    "Database connection error: %s - sleeping for %d seconds and will retry (attempt #%d of %d)",
                    ex,
                    sleep_for,
                    attempt,
                    no_of_retry,
                )
                # 200ms of sleep time in cons. retry calls
                sleep(sleep_for)
                attempt += 1
                continue
            else:
                raise


# health check endpoint
class StatusMsg(BaseModel):
    status: str = ""
    service_name: str = ""


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


@app.get("/msapi/deppkg")
def sbom_type():
    """
    This is the end point used determine the type of SBOM format this microservice can handle
    """
    # Return a JSON response with SBOMType: 'preparsed'
    return {"SBOMType": "preparsed"}


@app.post("/msapi/deppkg/cyclonedx", tags=["cyclonedx"])
async def cyclonedx(request: Request, response: Response, compid: int):
    """
    This is the end point used to upload a CycloneDX SBOM
    """

    global dhurl
    global cookies

    dhurl = f"{request.base_url.scheme}://{request.base_url.netloc}".replace("http:", "https:")

    try:
        resp = requests.head(dhurl, timeout=1)

        if resp is None or resp.status_code != 200:
            dhurl = f"{request.base_url.scheme}://{request.base_url.netloc}"
    except Exception:
        dhurl = f"{request.base_url.scheme}://{request.base_url.netloc}"

    cookies = request.cookies

    try:
        result = requests.get(validateuser_url + "/msapi/validateuser", cookies=request.cookies, timeout=5)
        if result is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed")

        if result.status_code != status.HTTP_200_OK:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization Failed status_code=" + str(result.status_code),
            )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization Failed:" + str(err),
        ) from None

    cyclonedx_json = await request.json()
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
        component_data = (
            compid,
            packagename,
            packageversion,
            bomformat,
            license_name,
            license_url,
            summary,
            purl,
            pkgtype,
        )
        components_data.append(component_data)

    return save_components_data(response, compid, bomformat, components_data)


@app.post("/msapi/deppkg/spdx", tags=["spdx"])
async def spdx(request: Request, response: Response, compid: int):
    """
    This is the end point used to upload a SPDX SBOM
    """

    global dhurl
    global cookies

    dhurl = f"{request.base_url.scheme}://{request.base_url.netloc}".replace("http:", "https:")

    try:
        resp = requests.head(dhurl, timeout=1)

        if resp is None or resp.status_code != 200:
            dhurl = f"{request.base_url.scheme}://{request.base_url.netloc}"
    except Exception:
        dhurl = f"{request.base_url.scheme}://{request.base_url.netloc}"

    cookies = request.cookies

    spdx_json = await request.json()
    components_data = []
    components = spdx_json.get("packages", [])

    # Parse SPDX BOM for licenses
    bomformat = "license"
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
        current_license = component.get("licenseDeclared", "NOASSERTION")

        if current_license != "NOASSERTION":
            license_name = current_license
            license_url = "https://spdx.org/licenses/" + license_name + ".html"

        if "," in license_name:
            license_name = license_name.split(",", maxsplit=1)[0]

        component_data = (
            compid,
            packagename,
            packageversion,
            bomformat,
            license_name,
            license_url,
            summary,
            purl,
            pkgtype,
        )
        components_data.append(component_data)

    threading.Thread(target=update_vulns).start()

    return save_components_data(response, compid, bomformat, components_data)


@app.post("/msapi/deppkg/safety", tags=["safety"])
async def safety(request: Request, response: Response, compid: int):
    """
    This is the end point used to upload a Python Safety SBOM
    """
    global safety_db  # pylint: disable=W0603

    try:
        result = requests.get(validateuser_url + "/msapi/validateuser", cookies=request.cookies, timeout=5)
        if result is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed")

        if result.status_code != status.HTTP_200_OK:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization Failed status_code=" + str(result.status_code),
            )
    except requests.exceptions.ConnectionError as conn_error:
        print("\n" + "="*80, flush=True)
        print("502 CONNECTION ERROR in safety endpoint", flush=True)
        print(f"Error: {str(conn_error)}", flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        print("="*80 + "\n", flush=True)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Connection error")

    if safety_db is None:
        try:
            url = requests.get(
                "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json",
                timeout=5,
            )
            if url.status_code == 502:
                print("\n" + "="*80, flush=True)
                print("502 BAD GATEWAY when fetching safety database", flush=True)
                print("="*80, flush=True)
                traceback.print_stack(file=sys.stdout)
                sys.stdout.flush()
                print("="*80 + "\n", flush=True)
            safety_db = json.loads(url.text)
        except requests.exceptions.ConnectionError as conn_error:
            print("\n" + "="*80, flush=True)
            print("502 CONNECTION ERROR fetching safety database", flush=True)
            print(f"Error: {str(conn_error)}", flush=True)
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            print("="*80 + "\n", flush=True)

    safety_json = await request.json()
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

        component_data = (
            compid,
            packagename,
            packageversion,
            bomformat,
            cve_name,
            cve_url,
            summary,
        )
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
                    logging.error(
                        "Database connection error: %s - sleeping for %d seconds and will retry (attempt #%d of %d)",
                        ex,
                        sleep_for,
                        attempt,
                        no_of_retry,
                    )
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


@app.post("/msapi/purl2comp")
async def purl2comp(request: Request, response: Response):
    """
    This is the end point used to create a component from a purl
    """

    global dhurl
    global cookies

    dhurl = f"{request.base_url.scheme}://{request.base_url.netloc}".replace("http:", "https:")

    try:
        resp = requests.head(dhurl, timeout=1)

        if resp is None or resp.status_code != 200:
            dhurl = f"{request.base_url.scheme}://{request.base_url.netloc}"
    except Exception:
        dhurl = f"{request.base_url.scheme}://{request.base_url.netloc}"

    # dhurl = "http://localhost:8181"
    cookies = request.cookies

    pprint(dhurl)

    try:
        result = requests.get(validateuser_url + "/msapi/validateuser", cookies=request.cookies, timeout=5)
        if result is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization Failed")

        if result.status_code != status.HTTP_200_OK:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization Failed status_code=" + str(result.status_code),
            )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization Failed:" + str(err),
        ) from None

    purl_json = await request.json()
    purl = purl_json.get("purl", None)

    if purl is None:
        return

    create_compver(dhurl, cookies, purl)
    return


if __name__ == "__main__":
    uvicorn.run(app, port=5003)
