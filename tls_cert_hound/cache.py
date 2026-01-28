import json
import os

from .logging_utils import log_message


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


def write_cache(domain: str, results, cache_dir: str, verbose: bool, no_disk_write: bool):
    if no_disk_write:
        return
    os.makedirs(cache_dir, exist_ok=True)
    path = cache_file_path(cache_dir, domain)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(results, handle)
    log_message(f"[*] Cached {len(results)} entries to {path}.", verbose)


def data_output_path(domain: str):
    base = domain or "multi"
    safe = "".join(ch if ch.isalnum() else "_" for ch in base.lower())
    filename = f"{safe}_all_cert_data.json"
    return os.path.join(".tls_cert_hound_data", safe, filename)


def data_output_path_for_domain_file(domain_file: str):
    base = os.path.splitext(os.path.basename(domain_file))[0] or "multi"
    safe = "".join(ch if ch.isalnum() else "_" for ch in base.lower())
    filename = f"{safe}_all_cert_data.json"
    return os.path.join(".tls_cert_hound_data", f"{safe}_results", filename)


def write_compiled_data(domain: str, results, output_path: str, verbose: bool, no_disk_write: bool, metadata: dict):
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


def opengraph_output_path(domain: str, output_data_path: str):
    base_path = output_data_path or data_output_path(domain)
    if base_path.endswith("_all_cert_data.json"):
        return base_path.replace("_all_cert_data.json", "_opengraph.json")
    return f"{base_path}.opengraph.json"
