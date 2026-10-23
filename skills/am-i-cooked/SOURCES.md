# Data sources

Used by `scripts/scan.mjs`. Read this only to debug the scanner or query by hand.

## Matching: OSV.dev

`POST https://api.osv.dev/v1/querybatch`

```json
{"queries":[{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}]}
```

Returns, per query, the vulnerability ids that affect that exact version. Ecosystem names are case-sensitive: `npm`, `PyPI`, `Pub`.

Fallback details for one id: `GET https://api.osv.dev/v1/vulns/<id>`.

## Enrichment: cve.now

No key needed. Merges the CVE List, GitHub Advisory Database, OSV, NVD, ENISA EUVD, CISA KEV, FIRST EPSS and Exploit-DB.

| Endpoint | Use |
| --- | --- |
| `GET https://cve.now/api/v1/entries/<id>` | One entry by CVE, GHSA or OSV id: `severity.cvss`, `exploitation.kev`, `exploitation.epssReached`, `affected[].ranges[].fixed` |
| `GET https://cve.now/api/v1/entries` | Newest entries first, cursor pagination |
| `GET https://cve.now/api/v1/status` | Polling health of each upstream source |
| `GET https://cve.now/feed?filter=kev&ecosystem=npm` | RSS (or `format=atom` / `format=json`) |

Coverage by ecosystem: npm, pypi, go, maven, crates.io, packagist, rubygems, hex, nuget. It does not cover pub, so the scanner falls back to OSV.dev data for Dart/Flutter (severity then comes from the advisory label, with no KEV or exploit signal).

Rate limits are not documented. The scanner sends at most 10 concurrent requests.

## Known blind spots

- A vulnerability with no affected-version data cannot match a package.
- Vendor advisories without a CVE or GHSA record are not covered.
- Private registries and git dependencies are not resolved.
- OSV `querybatch` pages are not followed. A package with more than 1000 advisories is truncated.
