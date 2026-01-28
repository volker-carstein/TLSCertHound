import json
import os


def state_path(cache_dir: str, domain: str):
    safe = "".join(ch if ch.isalnum() else "_" for ch in domain.lower())
    return os.path.join(cache_dir, f".tls_cert_hound_state_{safe}.json")


def load_state(path: str):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None


def save_state(path: str, state):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
