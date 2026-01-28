from .logging_utils import log_message


def normalize_domain(value: str, keep_wildcard: bool = False):
    if not value:
        return None
    domain = value.strip().lower()
    domain = domain.rstrip(".)$,;")
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


def load_domain_list(path: str, verbose: bool):
    domains = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                domain = normalize_domain(raw, keep_wildcard=False)
                if domain:
                    domains.append(domain)
                else:
                    log_message(
                        f"[!] Skipping invalid domain in input file: {raw}",
                        verbose,
                    )
    except FileNotFoundError:
        log_message(f"[!] Input file not found: {path}.", True, force=True)
    return domains
