# ortelius-ms-dep-pkg-cud

![Release](https://img.shields.io/github/v/release/ortelius/ms-dep-pkg-cud?sort=semver)
![license](https://img.shields.io/github/license/ortelius/.github)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/ms-dep-pkg-cud/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/ms-dep-pkg-cud/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/ms-dep-pkg-cud/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/ms-dep-pkg-cud/workflows/CodeQL/badge.svg)
[![OpenSSF
-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-dep-pkg-cud/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-dep-pkg-cud)


![Discord](https://img.shields.io/discord/722468819091849316)

> Version 10.0.0


RestAPI endpoint for adding SBOM data to a component

![Release](https://img.shields.io/github/v/release/ortelius/ms-dep-pkg-cud?sort=semver)
![license](https://img.shields.io/github/license/ortelius/ms-dep-pkg-cud)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/ms-dep-pkg-cud/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/ms-dep-pkg-cud/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/ms-dep-pkg-cud/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/ms-dep-pkg-cud/workflows/CodeQL/badge.svg)
[![OpenSSF
-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-dep-pkg-cud/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-dep-pkg-cud)


![Discord](https://img.shields.io/discord/722468819091849316)


## Path Table

| Method | Path | Description |
| --- | --- | --- |
| GET | [/health](#gethealth) | Health |
| GET | [/msapi/deppkg](#getmsapideppkg) | Sbom Type |
| POST | [/msapi/deppkg/cyclonedx](#postmsapideppkgcyclonedx) | Cyclonedx |
| POST | [/msapi/deppkg/spdx](#postmsapideppkgspdx) | Spdx |
| POST | [/msapi/deppkg/safety](#postmsapideppkgsafety) | Safety |
| POST | [/msapi/purl2comp](#postmsapipurl2comp) | Purl2Comp |

## Reference Table

| Name | Path | Description |
| --- | --- | --- |
| HTTPValidationError | [#/components/schemas/HTTPValidationError](#componentsschemashttpvalidationerror) |  |
| StatusMsg | [#/components/schemas/StatusMsg](#componentsschemasstatusmsg) |  |
| ValidationError | [#/components/schemas/ValidationError](#componentsschemasvalidationerror) |  |

## Path Details

***

### [GET]/health

- Summary  
Health

- Description  
This health check end point used by Kubernetes

#### Responses

- 200 Successful Response

`application/json`

```ts
{
  status?: string
  service_name?: string
}
```

***

### [GET]/msapi/deppkg

- Summary  
Sbom Type

- Description  
This is the end point used determine the type of SBOM format this microservice can handle

#### Responses

- 200 Successful Response

`application/json`

```ts
{}
```

***

### [POST]/msapi/deppkg/cyclonedx

- Summary  
Cyclonedx

- Description  
This is the end point used to upload a CycloneDX SBOM

#### Parameters(Query)

```ts
compid: integer
```

#### Responses

- 200 Successful Response

`application/json`

```ts
{}
```

- 422 Validation Error

`application/json`

```ts
{
  detail: {
    loc?: Partial(string) & Partial(integer)[]
    msg: string
    type: string
  }[]
}
```

***

### [POST]/msapi/deppkg/spdx

- Summary  
Spdx

- Description  
This is the end point used to upload a SPDX SBOM

#### Parameters(Query)

```ts
compid: integer
```

#### Responses

- 200 Successful Response

`application/json`

```ts
{}
```

- 422 Validation Error

`application/json`

```ts
{
  detail: {
    loc?: Partial(string) & Partial(integer)[]
    msg: string
    type: string
  }[]
}
```

***

### [POST]/msapi/deppkg/safety

- Summary  
Safety

- Description  
This is the end point used to upload a Python Safety SBOM

#### Parameters(Query)

```ts
compid: integer
```

#### Responses

- 200 Successful Response

`application/json`

```ts
{}
```

- 422 Validation Error

`application/json`

```ts
{
  detail: {
    loc?: Partial(string) & Partial(integer)[]
    msg: string
    type: string
  }[]
}
```

***

### [POST]/msapi/purl2comp

- Summary  
Purl2Comp

- Description  
This is the end point used to create a component from a purl

#### Responses

- 200 Successful Response

`application/json`

```ts
{}
```

## References

### #/components/schemas/HTTPValidationError

```ts
{
  detail: {
    loc?: Partial(string) & Partial(integer)[]
    msg: string
    type: string
  }[]
}
```

### #/components/schemas/StatusMsg

```ts
{
  status?: string
  service_name?: string
}
```

### #/components/schemas/ValidationError

```ts
{
  loc?: Partial(string) & Partial(integer)[]
  msg: string
  type: string
}
```
