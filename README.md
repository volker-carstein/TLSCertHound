# TLSCertHound

<p>
  TLSCertHound is a crt.sh collector focused on large-scale domain discovery from TLS certificates.
  It supports recursive expansion, cache-backed resumable runs, and OpenGraph export for BloodHound CE using the <a href="https://github.com/p0dalirius/bhopengraph">bhopengraph</a> library.
</p>
<p align="center">
  <a href="https://pypi.org/project/tls_cert_hound"><img alt="PyPI" src="https://img.shields.io/pypi/v/tls_cert_hound"></a>
  <a href="https://github.com/volker-carstein/TLSCertHound/releases"><img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/TLSCertHound/releases"></a>
  <a href="https://twitter.com/intent/follow?screen_name=volker_carstein" title="Follow"><img src="https://img.shields.io/twitter/follow/volker_carstein?label=volker_carstein&style=social"></a>
  <br>
  <img height=21px src="https://img.shields.io/badge/Get bloodhound:-191646"> <a href="https://specterops.io/bloodhound-enterprise/" title="Get BloodHound Enterprise"><img alt="Get BloodHound Enterprise" height=21px src="https://mintlify.s3.us-west-1.amazonaws.com/specterops/assets/enterprise-edition-pill-tag.svg"></a>
  <a href="https://specterops.io/bloodhound-community-edition/" title="Get BloodHound Community"><img alt="Get BloodHound Community" height=21px src="https://mintlify.s3.us-west-1.amazonaws.com/specterops/assets/community-edition-pill-tag.svg"></a>
  <br>
</p>

Feel free to open issues if anything doesn't work (PR are more than welcome as well!)

## Features

- Query [crt.sh](https://crt.sh) for certificates related to a domain or keyword.
- Recursive subdomain discovery with optional depth limit.
- Automatic throttling that adapts to HTTP 5xx responses.
- Resumable runs (state persisted per domain) with `--show-result` to generate outputs from saved state/cache without querying.
- Cache reuse and offline OpenGraph generation with `--offline` and `--input-data`.
- Multi-domain runs from a file with a single combined output with `--domain-file`.
- OpenGraph export with Search, TLSCertificate, CA, and domain nodes with `--opengraph-output` (produced by default).
- Blacklist support (simple patterns with `^`, `$`, and `*`) with `--blacklist-file`.

## Installation

Recommended (from PyPI):

```
pip install tls_cert_hound
```

From source using requirements.txt:

```
pip install -r requirements.txt
```

This installs the `tls_cert_hound` console script and the [bhopengraph](https://github.com/p0dalirius/bhopengraph) dependency.

## Quick start

### Single domain:

```bash
tls_cert_hound example.com
```

### Recursive discovery (unlimited depth):

```bash
tls_cert_hound example.com --recursive
```

### Recursive with depth 3:

```bash
tls_cert_hound example.com --recursive --depth 3
```

### Multi-domain from file:

```bash
tls_cert_hound --domain-file domains.txt --recursive --depth 2
```

### Generate OpenGraph only (offline mode):

```bash
tls_cert_hound --offline --input-data .tls_cert_hound_data/example.com/example.com_all_cert_data.json
```

## Outputs

### Cache and state

- Cache (per queried domain):
  `.tls_cert_hound_cache/<domain>/<domain>.json`
- State (per root domain, for resume):
  `.tls_cert_hound_cache/<domain>/.tls_cert_hound_state_<domain>.json`

### Compiled data

#### Single-domain default:

```bash
.tls_cert_hound_data/<domain>/<domain>_all_cert_data.json
```

#### Multi-domain default (domain file named `domain_list.txt`):

```bash
.tls_cert_hound_data/domain_list_results/domain_list_all_cert_data.json
```

Override with `--output-data`.

### OpenGraph

By default, OpenGraph output is placed alongside result data:

```bash
.tls_cert_hound_data/<domain|domain file name>/<domain|domain file name>_opengraph.json
```

Override with `--opengraph-output`.

## OpenGraph model

### Nodes:

- `CertIssuerCA`
- `TLSCertificate`
- `WebDomainName`
- `Search`

### Edges:

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
$ python3 ./tls_cert_hound.py -h
usage: tls_cert_hound.py [-h] [--recursive] [--depth DEPTH] [--no-disk-write] [--blacklist-file BLACKLIST_FILE] [--force-data-refresh]
                         [--input-data INPUT_DATA] [--offline] [--domain-file DOMAIN_FILE] [--show-result] [--ignore-state]
                         [--throttle THROTTLE] [--no-auto-throttle] [--timeout TIMEOUT] [--retries RETRIES]
                         [--opengraph-output OPENGRAPH_OUTPUT] [--subdomain-discovery] [--verbose] [--pretty] [--no-colorized-output]
                         [--no-banner] [--output-data OUTPUT_DATA]
                         [domain]

Query crt.sh for certificates related to a domain. Supports recursive subdomain discovery, adaptive throttling, and resumable runs.

positional arguments:
  domain                Domain name to query (e.g. example.com) or keyword (e.g. "google"). Used for query / as root for recursion. Ignored if --domain-file is present

options:
  -h, --help            show this help message and exit

Recursive mode options:
  --recursive           Enable recursive subdomain discovery from certificate data.
  --depth DEPTH         Max recursion depth when --recursive is set (default: unlimited).

Advanced options:
  --no-disk-write       Disable saving state, cache, compiled data, and OpenGraph outputs.
  --blacklist-file BLACKLIST_FILE
                        Path to a blacklist file with domains or simple patterns (supports only ^, $, and *). Matching domains are skipped.
  --force-data-refresh  Ignore cached per-domain JSON and re-fetch from crt.sh.
  --input-data INPUT_DATA
                        Read compiled cert data from this path (required with --offline).
  --offline             Do not query crt.sh; requires --input-data to generate OpenGraph.
  --domain-file DOMAIN_FILE
                        Read a list of domains (one per line) instead of a single domain. Empty lines and comments (#) are ignored.

Saved state options:
  --show-result         Use saved state file to generate outputs without new queries.
  --ignore-state        Ignore saved state files but still use cached JSON responses.

Requests options:
  --throttle THROTTLE   Initial seconds between requests (default: 1.0).
  --no-auto-throttle    Disable adaptive throttling on HTTP 5xx responses.
  --timeout TIMEOUT     HTTP timeout in seconds for each request (default: 30).
  --retries RETRIES     Retry count for timeouts/temporary errors (default: 2).

Output options:
  --opengraph-output OPENGRAPH_OUTPUT
                        Write OpenGraph output to this path (default: alongside compiled data, with _opengraph.json suffix).
  --subdomain-discovery
                        Output only discovered domain names, one per line.
  --verbose             Enable verbose progress logging to stderr.
  --pretty              Pretty-print JSON output instead of JSONL.
  --no-colorized-output
                        Disable ANSI color output in status messages.
  --no-banner           Disable the startup ASCII banner.
  --output-data OUTPUT_DATA
                        Write compiled cert data to this path (default: .tls_cert_hound_data/<domain>/<domain>_all_cert_data.json or
                        .tls_cert_hound_data/<domain_file>_results/<domain_file>_all_cert_data.json when --domain-file is used).
```

## Notes

- crt.sh can return transient HTTP 5xx responses; auto-throttle adapts delay
  and retries.
- Wildcard SAN/CN entries are preserved as distinct domain nodes (e.g. `*.example.com`).

## License

MIT. See [LICENSE](LICENSE).
