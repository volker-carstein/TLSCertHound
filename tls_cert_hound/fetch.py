import json
import os
import urllib.error
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .blacklist import filter_entries_by_blacklist, is_blacklisted
from .cache import read_cache, write_cache
from .domain import extract_domains, normalize_domain
from .logging_utils import log_message
from .state import load_state, save_state

CRT_SH_BASE = "https://crt.sh/"


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


def fetch_crtsh(
    domain: str,
    timeout: float,
    retries: int,
    throttle,
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
            log_message(
                f"[*] Querying crt.sh for {domain} (attempt {attempt + 1}).",
                verbose,
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
            if exc.code >= 500 and exc.code < 600 and throttle is not None:
                throttle.record_5XX(exc.code)
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


def fetch_recursive(
    domain: str,
    max_depth,
    timeout: float,
    retries: int,
    throttle,
    verbose: bool,
    state_file: str,
    cache_dir: str,
    no_disk_write: bool,
    force_data_refresh: bool,
    blacklist_patterns,
    ignore_state: bool = False,
):
    if not no_disk_write:
        os.makedirs(cache_dir, exist_ok=True)
    state = None if (no_disk_write or ignore_state) else load_state(state_file)
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
            # Re-queue the current domain so a resume will retry it.
            if current in seen:
                seen.remove(current)
            queue.insert(0, (current, depth))
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
            )

    if not no_disk_write and os.path.exists(state_file):
        os.remove(state_file)
        log_message(f"[*] Removed state file {state_file}.", verbose, force=True)

    return results
