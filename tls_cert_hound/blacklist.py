import re

from .logging_utils import log_message
from .domain import normalize_domain


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
