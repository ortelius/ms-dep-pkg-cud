# ortelius-ms-dep-pkg-cud

![Release](https://img.shields.io/github/v/release/ortelius/ms-dep-pkg-cud?sort=semver)
![license](https://img.shields.io/github/license/ortelius/ms-dep-pkg-cud)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/ms-dep-pkg-cud/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/ms-dep-pkg-cud/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/ms-dep-pkg-cud/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/ms-dep-pkg-cud/workflows/CodeQL/badge.svg)
[![OpenSSF
-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-dep-pkg-cud/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-dep-pkg-cud)


![Discord](https://img.shields.io/discord/722468819091849316)
Dependency Package Data Microservice - Create, Update and Delete

HELM_CHART

- port:8080
- package name : deppkg

postgress [test database docker image](https://github.com/ortelius/test-database)
Pull and run the above image

Create Table [Componentdep SQL Query](https://github.com/ortelius/ortelius/blob/main/dmadminweb/WebContent/WEB-INF/schema/2021122706.sql)

Microservice

- url: localhost:5000/msapi/deppkg

methods:

- POST

  sample call:

   ```bash
   curl -X POST - -H "Content-Type: application/json" -d @FILENAME DESTINATION http://localhost:5000/msapi/deppkg?compid=1234
   ```

- DELETE

  Deletes component by component id passed as query Parameter

  sample call:

  ```bash
  curl -X DELETE localhost:5000/msapi/compitem?comp_id=1
  ```

## Fixed CVEs

- 2/27/23 - [CVE-2023-25139](https://www.openwall.com/lists/oss-security/2023/02/10/1)
