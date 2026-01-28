# TLSCertHound

TLSCertHound is a crt.sh collector focused on large-scale domain discovery from TLS
certificates. It supports recursive expansion, cache-backed resumable runs, and
OpenGraph export for BloodHound CE using the `bhopengraph` library.

Feel free to open issues if anything doesn't work (PR are more than welcome as well!)

## Features

- Query crt.sh for certificates related to a domain or keyword.
- Recursive subdomain discovery with optional depth limit.
- Automatic throttling that adapts to HTTP 5xx responses.
- Resumable runs (state persisted per domain).
- Cache reuse and offline OpenGraph generation.
- Multi-domain runs from a file with a single combined output.
- OpenGraph export with Search, TLSCertificate, CA, and domain nodes.
- Blacklist support (simple patterns with `^`, `$`, and `*`).

## Installation

Recommended (from PyPI):

```
pip install tls_cert_hound
```

From source using requirements.txt:

```
pip install -r requirements.txt
```

This installs the `tls_cert_hound` console script and the `bhopengraph`
dependency.

## Quick start

Single domain:

```
tls_cert_hound example.com
```

Recursive discovery (unlimited depth):

```
tls_cert_hound example.com --recursive
```

Recursive with depth 3:

```
tls_cert_hound example.com --recursive --depth 3
```

Multi-domain from file:

```
tls_cert_hound --domain-file domains.txt --recursive --depth 2
```

Generate OpenGraph only (offline mode):

```
tls_cert_hound --offline --input-data .tls_cert_hound_data/example.com/example.com_all_cert_data.json
```

## Outputs

### Cache and state

- Cache (per queried domain):
  `.tls_cert_hound_cache/<domain>/<domain>.json`
- State (per root domain, for resume):
  `.tls_cert_hound_cache/<domain>/.tls_cert_hound_state_<domain>.json`

### Compiled data

Single-domain default:

```
.tls_cert_hound_data/<domain>/<domain>_all_cert_data.json
```

Multi-domain default (domain file named `domain_list.txt`):

```
.tls_cert_hound_data/domain_list_results/domain_list_all_cert_data.json
```

Override with `--output-data`.

### OpenGraph

By default, OpenGraph output is placed alongside compiled data:

```
.../<base>_opengraph.json
```

Override with `--opengraph-output`.

## OpenGraph model

Nodes:

- `CertIssuerCA`
- `TLSCertificate`
- `WebDomainName`
- `Search`

Edges:

- `Issued` (CA -> TLSCertificate)
- `IsCommonName` (TLSCertificate -> WebDomainName)
- `IsInSAN` (TLSCertificate -> WebDomainName)
- `Discovered` (Search -> WebDomainName)

## Resume and recovery

- Runs save a state file per root domain.
- If a request fails after all retries, the current domain is re-queued so a
  resume will retry it.
- `--ignore-state` ignores saved state while still using cache files.
- `--show-result` generates outputs from saved state/cache without querying.

## Blacklist

Provide a blacklist file with one entry per line:

```
example.com
*.example.com
^internal\..*$
```

Only `^`, `$`, and `*` are supported. Matching domains are skipped and not
included in results or OpenGraph output.

## CLI reference

```
usage: tls_cert_hound [domain] [options]

positional arguments:
  domain                  Domain name to query (e.g. example.com) or keyword.

options:
  --domain-file FILE      Read domains from file (one per line).
  --recursive             Enable recursive subdomain discovery.
  --depth N               Max recursion depth (default: unlimited).
  --throttle SECONDS      Initial delay between requests (default: 1.0).
  --no-auto-throttle      Disable adaptive throttling on HTTP 5xx responses.
  --timeout SECONDS       HTTP timeout per request (default: 30).
  --retries N             Retry count for temporary errors (default: 2).
  --blacklist-file FILE   Skip domains matching entries in blacklist file.
  --force-data-refresh    Ignore cached JSON and re-fetch from crt.sh.
  --ignore-state          Ignore saved state files but keep cache reuse.
  --show-result           Generate outputs from saved state/cache only.
  --output-data PATH      Override compiled data output path.
  --input-data PATH       Compiled data input (required with --offline).
  --opengraph-output PATH Override OpenGraph output path.
  --offline               No crt.sh queries; uses --input-data.
  --subdomain-discovery   Output discovered domain names only.
  --pretty                Pretty-print JSON output.
  --no-disk-write         Disable cache/state/data/OpenGraph writes.
  --no-colorized-output   Disable ANSI colors.
  --no-banner             Disable ASCII banner.
  --verbose               Verbose logs.
```

## Notes

- crt.sh can return transient HTTP 5xx responses; auto-throttle adapts delay
  and retries.
- Wildcard SAN/CN entries are preserved as distinct domain nodes (e.g. `*.example.com`).

## License

MIT. See `LICENSE`.
