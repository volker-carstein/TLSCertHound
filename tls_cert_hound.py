#!/usr/bin/env python3
import argparse
import json
import sys
import os
import re
import time
import urllib.error
from datetime import datetime
from urllib.parse import urlencode
from urllib.request import Request, urlopen


CRT_SH_BASE = "https://crt.sh/"
COLOR_ENABLED = True


def banner_text():
    return (
        """
 _____ _      _____     _____           _       _   _                       _ 
|_   _| |    /  ___|   /  __ \         | |     | | | |                     | |
  | | | |    \ `--.    | /  \/ ___ _ __| |_    | |_| | ___  _   _ _ __   __| |
  | | | |     `--. \   | |    / _ \ '__| __|   |  _  |/ _ \| | | | '_ \ / _` |
  | | | |____/\__/ /   | \__/\  __/ |  | |_    | | | | (_) | |_| | | | | (_| |
  \_/ \_____/\____/     \____/\___|_|   \__|   \_| |_/\___/ \__,_|_| |_|\__,_|
                                                                              
            v1.0 by Volker Carstein (@volker_carstein) @ 2026
        """
    )


def colorize(message: str, color: str):
    if not COLOR_ENABLED:
        return message
    return f"{color}{message}\033[0m"


def log_message(message: str, verbose: bool, force: bool = False):
    if not (verbose or force):
        return
    if message.startswith("[!]"):
        message = colorize(message, "\033[31m")
    elif message.startswith("[*]"):
        message = colorize(message, "\033[36m")
    print(message, file=sys.stderr)


class ThrottleController:
    def __init__(self, delay: float, auto: bool, verbose: bool):
        self.delay = max(delay, 0.0)
        self.auto = auto
        self.verbose = verbose
        self.success_streak = 0
        self.last_request_time = None

    def wait(self, force: bool = False):
        if self.delay <= 0:
            return
        now = time.time()
        if self.last_request_time is not None:
            remaining = self.delay - (now - self.last_request_time)
            if remaining > 0:
                log_message(
                    f"[*] Throttling: sleeping {remaining:.2f}s before next request.",
                    self.verbose,
                    force=force,
                )
                time.sleep(remaining)
        self.last_request_time = time.time()

    def record_success(self):
        if not self.auto:
            return
        self.success_streak += 1
        if self.success_streak >= 5 and self.delay > 0:
            old_delay = self.delay
            self.delay = max(self.delay / 2.0, 0.1)
            self.success_streak = 0
            if old_delay != self.delay:
                log_message(
                    f"[*] Auto-throttle: 5 successful requests, delay now {self.delay:.2f}s.",
                    self.verbose,
                    force=True,
                )

    def record_503(self):
        if not self.auto:
            return
        self.delay = max(self.delay * 3.0, 0.1)
        self.success_streak = 0
        log_message(
            f"[!] Auto-throttle: HTTP 503 received, delay now {self.delay:.2f}s.",
            self.verbose,
            force=True,
        )

    def snapshot(self):
        return {
            "delay": self.delay,
            "success_streak": self.success_streak,
        }

    def restore(self, state):
        self.delay = float(state.get("delay", self.delay))
        self.success_streak = int(state.get("success_streak", 0))


def state_path(cache_dir: str, domain: str):
    safe = "".join(ch if ch.isalnum() else "_" for ch in domain.lower())
    return os.path.join(cache_dir, f".tls_cert_hound_state_{safe}.json")


def load_state(path: str):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None


def save_state(path: str, state, verbose: bool, force: bool = False):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)

def cache_dir_path(domain: str):
    safe = "".join(ch if ch.isalnum() else "_" for ch in domain.lower())
    return os.path.join(".tls_cert_hound_cache", safe)


def cache_file_path(cache_dir: str, domain: str):
    safe = "".join(ch if ch.isalnum() else "_" for ch in domain.lower())
    return os.path.join(cache_dir, f"{safe}.json")


def read_cache(domain: str, cache_dir: str, verbose: bool):
    path = cache_file_path(cache_dir, domain)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        log_message(f"[*] Cache hit for {domain}: {path}.", verbose)
        return data
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        log_message(f"[!] Cache file is invalid JSON: {path}.", True, force=True)
        return None


def write_cache(
    domain: str, results, cache_dir: str, verbose: bool, no_disk_write: bool
):
    if no_disk_write:
        return
    os.makedirs(cache_dir, exist_ok=True)
    path = cache_file_path(cache_dir, domain)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(results, handle)
    log_message(f"[*] Cached {len(results)} entries to {path}.", verbose)


def data_output_path(domain: str):
    safe = "".join(ch if ch.isalnum() else "_" for ch in domain.lower())
    filename = f"{safe}_all_cert_data.json"
    return os.path.join(".tls_cert_hound_data", safe, filename)


def write_compiled_data(
    domain: str,
    results,
    output_path: str,
    verbose: bool,
    no_disk_write: bool,
    metadata: dict,
):
    if no_disk_write:
        return
    path = output_path or data_output_path(domain)
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"meta": metadata, "results": results}, handle)
    log_message(f"[*] Wrote compiled data to {path}.", verbose)


def load_compiled_data(path: str, verbose: bool):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        log_message(f"[!] Compiled data file not found: {path}.", True, force=True)
        return None, None
    if isinstance(data, list):
        return data, {}
    if isinstance(data, dict):
        return data.get("results", []), data.get("meta", {})
    log_message(f"[!] Unsupported compiled data format: {path}.", True, force=True)
    return None, None


def cert_key(entry):
    cert_id = entry.get("id")
    if cert_id is not None:
        return f"id:{cert_id}"
    stable = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return f"raw:{stable}"


def dedupe_results(results):
    deduped = []
    seen_keys = set()
    for entry in results:
        key = cert_key(entry)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(entry)
    return deduped


def compile_blacklist(path: str, verbose: bool):
    if not path:
        return [], []
    patterns = []
    raw_entries = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                regex = _pattern_to_regex(raw)
                patterns.append(re.compile(regex, re.IGNORECASE))
                raw_entries.append(raw)
        log_message(f"[*] Loaded {len(patterns)} blacklist entries.", verbose)
    except FileNotFoundError:
        log_message(f"[!] Blacklist file not found: {path}.", True, force=True)
    return patterns, raw_entries


def _pattern_to_regex(pattern: str):
    value = pattern.strip().lower()
    prefix = "^" if value.startswith("^") else ""
    suffix = "$" if value.endswith("$") else ""
    if prefix:
        value = value[1:]
    if suffix:
        value = value[:-1]
    escaped = re.escape(value).replace(r"\*", ".*")
    if not prefix and not suffix:
        return f"^{escaped}$"
    return f"{prefix}{escaped}{suffix}"


def is_blacklisted(domain: str, patterns):
    if not patterns:
        return False
    value = domain.lower()
    variants = {value}
    if value.startswith("*."):
        variants.add(value[2:])
    else:
        variants.add(f"*.{value}")
    if "." in value:
        parent = value.split(".", 1)[1]
        variants.add(parent)
        variants.add(f"*.{parent}")
    return any(regex.search(candidate) for regex in patterns for candidate in variants)


def filter_entries_by_blacklist(entries, patterns, verbose: bool):
    if not patterns:
        return entries
    filtered = []
    skipped = 0
    for entry in entries:
        domains = []
        name_value = entry.get("name_value") or ""
        common_name = entry.get("common_name") or ""
        for item in name_value.split():
            domain = normalize_domain(item, keep_wildcard=True)
            if domain:
                domains.append(domain)
        cn_domain = normalize_domain(common_name, keep_wildcard=True)
        if cn_domain:
            domains.append(cn_domain)
        if any(is_blacklisted(domain, patterns) for domain in domains):
            skipped += 1
            continue
        filtered.append(entry)
    if skipped:
        log_message(f"[*] Skipped {skipped} entries due to blacklist.", verbose)
    return filtered


def opengraph_output_path(domain: str, output_data_path: str):
    base_path = output_data_path or data_output_path(domain)
    if base_path.endswith("_all_cert_data.json"):
        return base_path.replace("_all_cert_data.json", "_opengraph.json")
    return f"{base_path}.opengraph.json"


def build_opengraph_nodes(
    results, search_term, search_depth, blacklist_entries, search_date=None
):
    try:
        from bhopengraph import OpenGraph, Node, Properties, Edge
    except Exception as exc:
        log_message(
            f"[!] Failed to import bhopengraph: {exc}. Install it with pip.",
            True,
            force=True,
        )
        return None

    graph = OpenGraph(source_kind="TLSCertBase")

    issuer_nodes = {}
    cert_nodes = {}
    domain_nodes = {}
    domain_flags = {}

    for entry in results:
        issuer_id = entry.get("issuer_ca_id")
        issuer_name = entry.get("issuer_name")
        if issuer_id is not None and issuer_id not in issuer_nodes:
            issuer_nodes[issuer_id] = Node(
                id=str(issuer_id),
                kinds=["CertIssuerCA"],
                properties=Properties(displayname=issuer_name or ""),
            )

        cert_id = entry.get("id")
        if cert_id is not None and cert_id not in cert_nodes:
            cert_nodes[cert_id] = Node(
                id=str(cert_id),
                kinds=["TLSCertificate"],
                properties=Properties(
                    entry_timestamp=entry.get("entry_timestamp"),
                    not_valid_before=entry.get("not_before"),
                    not_valid_after=entry.get("not_after"),
                    serial_number=entry.get("serial_number"),
                ),
            )

        common_name = normalize_domain(entry.get("common_name") or "", keep_wildcard=True)
        if common_name:
            flags = domain_flags.setdefault(
                common_name, {"is_cn": False, "is_san": False}
            )
            flags["is_cn"] = True

        name_value = entry.get("name_value") or ""
        for item in name_value.splitlines():
            domain = normalize_domain(item, keep_wildcard=True)
            if not domain:
                continue
            flags = domain_flags.setdefault(domain, {"is_cn": False, "is_san": False})
            flags["is_san"] = True

    for domain, flags in domain_flags.items():
        domain_nodes[domain] = Node(
            id=domain,
            kinds=["Domain"],
            properties=Properties(
                fqdn=domain,
                is_cn=str(flags["is_cn"]),
                is_san=str(flags["is_san"]),
            ),
        )

    if not search_date:
        search_date = datetime.utcnow().date().isoformat()
    search_node = Node(
        id=f"search:{{{search_term}}}",
        kinds=["Search"],
        properties=Properties(
            search=search_term,
            search_date=search_date,
            search_depth=str(search_depth),
            is_recursive=str(search_depth != 0),
            blacklisted_elements=blacklist_entries,
        ),
    )

    for node in issuer_nodes.values():
        graph.add_node(node)
    for node in cert_nodes.values():
        graph.add_node(node)
    for node in domain_nodes.values():
        graph.add_node(node)
    graph.add_node(search_node)

    edge_keys = set()
    for domain in domain_nodes:
        end_node_id = domain_nodes[domain].id
        key = (search_node.id, end_node_id, "Discovered")
        if key in edge_keys:
            continue
        graph.add_edge(
            Edge(
                start_node=search_node.id,
                end_node=end_node_id,
                kind="Discovered",
            )
        )
        edge_keys.add(key)
    for entry in results:
        cert_id = entry.get("id")
        if cert_id is None:
            continue
        cert_node_id = str(cert_id)
        issuer_id = entry.get("issuer_ca_id")
        if issuer_id is not None:
            issuer_node_id = str(issuer_id)
            key = (issuer_node_id, cert_node_id, "Issued")
            if key not in edge_keys:
                graph.add_edge(
                    Edge(
                        start_node=issuer_node_id,
                        end_node=cert_node_id,
                        kind="Issued",
                    )
                )
                edge_keys.add(key)
        cn_domain = normalize_domain(entry.get("common_name") or "", keep_wildcard=True)
        if cn_domain and cn_domain in domain_nodes:
            key = (cert_node_id, cn_domain, "IsCommonName")
            if key not in edge_keys:
                graph.add_edge(
                    Edge(
                        start_node=cert_node_id,
                        end_node=cn_domain,
                        kind="IsCommonName",
                    )
                )
                edge_keys.add(key)
        name_value = entry.get("name_value") or ""
        for item in name_value.splitlines():
            san_domain = normalize_domain(item, keep_wildcard=True)
            if not san_domain or san_domain not in domain_nodes:
                continue
            key = (cert_node_id, san_domain, "IsInSAN")
            if key in edge_keys:
                continue
            graph.add_edge(
                Edge(
                    start_node=cert_node_id,
                    end_node=san_domain,
                    kind="IsInSAN",
                )
            )
            edge_keys.add(key)

    return graph


def fetch_crtsh(
    domain: str,
    timeout: float,
    retries: int,
    throttle: ThrottleController,
    verbose: bool,
    cache_dir: str,
    no_disk_write: bool,
    force_data_refresh: bool,
    blacklist_patterns,
):
    if not no_disk_write and not force_data_refresh:
        cached = read_cache(domain, cache_dir, verbose)
        if cached is not None:
            cached = filter_entries_by_blacklist(
                dedupe_results(cached), blacklist_patterns, verbose
            )
            return cached, True
    params = {"q": domain, "output": "json"}
    url = f"{CRT_SH_BASE}?{urlencode(params)}"
    req = Request(url, headers={"User-Agent": "TLSCertHound/1.0"})
    attempt = 0
    while True:
        if verbose:
            print(
                f"[*] Querying crt.sh for {domain} (attempt {attempt + 1}).",
                file=sys.stderr,
            )
        try:
            if throttle is not None:
                throttle.wait()
            with urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
            if not raw.strip():
                if throttle is not None:
                    throttle.record_success()
                write_cache(domain, [], cache_dir, verbose, no_disk_write)
                return [], False
            if throttle is not None:
                throttle.record_success()
            results = dedupe_results(json.loads(raw))
            results = filter_entries_by_blacklist(results, blacklist_patterns, verbose)
            write_cache(domain, results, cache_dir, verbose, no_disk_write)
            return results, False
        except urllib.error.HTTPError as exc:
            if exc.code == 503 and throttle is not None:
                throttle.record_503()
                throttle.wait(force=True)
            attempt += 1
            if attempt > retries:
                raise exc
            log_message(
                f"[!] HTTP error from crt.sh: {exc}. Retrying...",
                verbose,
                force=True,
            )
        except (urllib.error.URLError, TimeoutError) as exc:
            attempt += 1
            if attempt > retries:
                raise exc
            log_message(
                f"[!] Network error contacting crt.sh: {exc}. Retrying...",
                verbose,
                force=True,
            )


def normalize_domain(value: str, keep_wildcard: bool = False):
    if not value:
        return None
    domain = value.strip().lower()
    if domain.startswith("*.") and not keep_wildcard:
        domain = domain[2:]
    if "." not in domain:
        return None
    return domain


def extract_domains(entry):
    candidates = []
    name_value = entry.get("name_value") or ""
    common_name = entry.get("common_name") or ""
    candidates.extend(name_value.split())
    candidates.append(common_name)
    domains = []
    for item in candidates:
        domain = normalize_domain(item, keep_wildcard=False)
        if domain:
            domains.append(domain)
    return domains


def fetch_recursive(
    domain: str,
    max_depth,
    timeout: float,
    retries: int,
    throttle: ThrottleController,
    verbose: bool,
    state_file: str,
    cache_dir: str,
    no_disk_write: bool,
    force_data_refresh: bool,
    blacklist_patterns,
):
    state = None if no_disk_write else load_state(state_file)
    seen = set()
    queue = [(domain, 0)]
    results = []
    seen_cert_keys = set()
    if state and state.get("domain") == domain and state.get("depth") == max_depth:
        log_message(f"[*] Resuming from {state_file}.", verbose, force=True)
        seen = set(state.get("seen", []))
        queue = [tuple(item) for item in state.get("queue", [])]
        results = state.get("results", [])
        seen_cert_keys = set(state.get("seen_cert_keys", []))
        if throttle is not None:
            throttle.restore(state.get("throttle", {}))
        if not seen_cert_keys:
            seen_cert_keys = set(cert_key(entry) for entry in results)
    else:
        seen_cert_keys = set(cert_key(entry) for entry in results)

    if blacklist_patterns:
        queue = [
            item for item in queue if not is_blacklisted(item[0], blacklist_patterns)
        ]
        results = filter_entries_by_blacklist(results, blacklist_patterns, verbose)
        seen_cert_keys = set(cert_key(entry) for entry in results)

    while queue:
        current, depth = queue.pop(0)
        if is_blacklisted(current, blacklist_patterns):
            log_message(f"[*] Skipping blacklisted domain {current}.", verbose)
            continue
        if current in seen or (max_depth is not None and depth > max_depth):
            continue
        seen.add(current)
        try:
            fetched, from_cache = fetch_crtsh(
                current,
                timeout,
                retries,
                throttle,
                verbose,
                cache_dir,
                no_disk_write,
                force_data_refresh,
                blacklist_patterns,
            )
        except Exception:
            if not no_disk_write:
                save_state(
                    state_file,
                    {
                        "domain": domain,
                        "depth": max_depth,
                        "seen": sorted(seen),
                        "queue": queue,
                        "results": results,
                        "seen_cert_keys": sorted(seen_cert_keys),
                        "throttle": throttle.snapshot() if throttle else {},
                    },
                    verbose,
                    force=True,
                )
            raise
        if from_cache:
            log_message(
                f"[*] Using cached data for {current}; merging into state.",
                verbose,
            )
        for entry in fetched:
            key = cert_key(entry)
            if key in seen_cert_keys:
                continue
            seen_cert_keys.add(key)
            results.append(entry)
        for entry in fetched:
            for sub in extract_domains(entry):
                if sub not in seen:
                    if not is_blacklisted(sub, blacklist_patterns):
                        queue.append((sub, depth + 1))
                    else:
                        log_message(
                            f"[*] Skipping blacklisted domain {sub}.", verbose
                        )
        if not no_disk_write:
            save_state(
                state_file,
                {
                    "domain": domain,
                    "depth": max_depth,
                    "seen": sorted(seen),
                    "queue": queue,
                    "results": results,
                    "seen_cert_keys": sorted(seen_cert_keys),
                    "throttle": throttle.snapshot() if throttle else {},
                },
                verbose,
            )

    if not no_disk_write and os.path.exists(state_file):
        os.remove(state_file)
        log_message(f"[*] Removed state file {state_file}.", verbose, force=True)

    return results


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Query crt.sh for certificates related to a domain. Supports recursive "
            "subdomain discovery, adaptive throttling, and resumable runs."
        )
    )
    parser.add_argument(
        "domain",
        help="Domain name to query (e.g. example.com) or keyword (e.g. \"google\"). Used as root for recursion.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Enable recursive subdomain discovery from certificate data.",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=None,
        help="Max recursion depth when --recursive is set (default: unlimited).",
    )
    parser.add_argument(
        "--throttle",
        type=float,
        default=1.0,
        help="Initial seconds between requests (default: 1.0).",
    )
    parser.add_argument(
        "--no-auto-throttle",
        action="store_true",
        help="Disable adaptive throttling on HTTP 503 responses.",
    )
    parser.add_argument(
        "--no-disk-write",
        action="store_true",
        help="Disable saving state and per-domain cache to disk.",
    )
    parser.add_argument(
        "--blacklist-file",
        help=(
            "Path to a blacklist file with domains or simple patterns "
            "(supports only ^, $, and *). Matching domains are skipped."
        ),
    )
    parser.add_argument(
        "--force-data-refresh",
        action="store_true",
        help="Ignore cached per-domain JSON and re-fetch from crt.sh.",
    )
    parser.add_argument(
        "--output-data",
        help=(
            "Write compiled cert data to this path "
            "(default: .tls_cert_hound_data/<domain>/<domain>_all_cert_data.json)."
        ),
    )
    parser.add_argument(
        "--input-data",
        help=(
            "Read compiled cert data from this path (required with --offline)."
        ),
    )
    parser.add_argument(
        "--opengraph-output",
        help=(
            "Write OpenGraph output to this path "
            "(default: alongside compiled data, with _opengraph.json suffix)."
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Do not query crt.sh; requires --input-data to generate OpenGraph.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP timeout in seconds for each request (default: 30).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retry count for timeouts/temporary errors (default: 2).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose progress logging to stderr.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output instead of JSONL.",
    )
    parser.add_argument(
        "--subdomain-discovery",
        action="store_true",
        help="Output only discovered domain names, one per line.",
    )
    parser.add_argument(
        "--no-colorized-output",
        action="store_true",
        help="Disable ANSI color output in status messages.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable the startup ASCII banner.",
    )
    args = parser.parse_args()
    global COLOR_ENABLED
    COLOR_ENABLED = not args.no_colorized_output
    if not args.no_banner:
        print(colorize(banner_text(), "\033[36m"), file=sys.stderr)

    try:
        throttle = ThrottleController(
            delay=args.throttle,
            auto=not args.no_auto_throttle,
            verbose=args.verbose,
        )
        blacklist_patterns, blacklist_entries = compile_blacklist(
            args.blacklist_file, args.verbose
        )
        if args.blacklist_file and not blacklist_patterns:
            log_message("[!] No valid blacklist entries loaded.", True, force=True)
        cache_dir = cache_dir_path(args.domain)
        log_message(
            f"[*] Starting run for {args.domain}. Recursive={args.recursive}, "
            f"Depth={args.depth}, Timeout={args.timeout}s, Retries={args.retries}, "
            f"Throttle={args.throttle}s, AutoThrottle={not args.no_auto_throttle}, "
            f"DiskWrite={not args.no_disk_write}.",
            args.verbose,
        )
        search_term = args.domain
        search_date = None
        search_depth_override = None
        if args.offline:
            if not args.input_data:
                log_message(
                    "[!] --offline requires --input-data pointing to a compiled data file.",
                    True,
                    force=True,
                )
                return 1
            compiled_path = args.input_data
            results, meta = load_compiled_data(compiled_path, args.verbose)
            if results is None:
                return 1
            if meta:
                blacklist_entries = meta.get("blacklisted_elements", blacklist_entries)
                search_term = meta.get("search", search_term)
                search_date = meta.get("search_date", None)
                if meta.get("search_depth") is not None:
                    try:
                        search_depth_override = int(meta.get("search_depth"))
                        args.depth = search_depth_override
                    except (TypeError, ValueError):
                        pass
            log_message(
                f"[*] Offline mode: loaded {len(results)} entries from {compiled_path}.",
                args.verbose,
            )
        else:
            if is_blacklisted(args.domain, blacklist_patterns):
                log_message(
                    f"[!] Root domain {args.domain} is blacklisted. Nothing to do.",
                    True,
                    force=True,
                )
                return 0
            if args.recursive:
                if args.no_disk_write:
                    log_message(
                        "[!] --no-disk-write disables resume and caching functionnalities.",
                        True,
                        force=True,
                    )
                results = fetch_recursive(
                    args.domain,
                    args.depth,
                    args.timeout,
                    args.retries,
                    throttle,
                    args.verbose,
                    state_path(cache_dir, args.domain),
                    cache_dir,
                    args.no_disk_write,
                    args.force_data_refresh,
                    blacklist_patterns,
                )
            else:
                results, _from_cache = fetch_crtsh(
                    args.domain,
                    args.timeout,
                    args.retries,
                    throttle,
                    args.verbose,
                    cache_dir,
                    args.no_disk_write,
                    args.force_data_refresh,
                    blacklist_patterns,
                )
    except Exception as exc:
        log_message(f"[!] Failed to query crt.sh: {exc}", True, force=True)
        return 1

    log_message(f"[*] Retrieved {len(results)} certificate entries.", args.verbose)

    search_depth = 0
    if args.recursive:
        search_depth = args.depth if args.depth is not None else -1
    if args.offline and search_depth_override is not None:
        search_depth = search_depth_override
    metadata = {
        "search": search_term,
        "search_date": datetime.utcnow().date().isoformat(),
        "search_depth": search_depth,
        "is_recursive": search_depth != 0,
        "blacklisted_elements": blacklist_entries,
    }
    if not args.offline:
        write_compiled_data(
            args.domain,
            results,
            args.output_data,
            args.verbose,
            args.no_disk_write,
            metadata,
        )

    if not args.no_disk_write:
        og_path = args.opengraph_output or opengraph_output_path(
            args.domain, args.output_data
        )
        graph = build_opengraph_nodes(
            results,
            search_term,
            search_depth,
            blacklist_entries,
            search_date=search_date,
        )
        if graph is not None:
            graph.export_to_file(og_path)
            log_message(f"[*] OpenGraph written to {og_path}.", args.verbose)

    if args.subdomain_discovery:
        discovered = set()
        for entry in results:
            for domain in extract_domains(entry):
                if not is_blacklisted(domain, blacklist_patterns):
                    discovered.add(domain)
        discovered.add(args.domain.lower())
        for name in sorted(discovered):
            print(name)
        return 0

    if args.pretty:
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0

    for entry in results:
        print(json.dumps(entry, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
