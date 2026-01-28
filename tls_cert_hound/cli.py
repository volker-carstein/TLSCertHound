import argparse
import json
from datetime import datetime

from .blacklist import compile_blacklist, is_blacklisted
from .cache import (
    cache_dir_path,
    data_output_path,
    data_output_path_for_domain_file,
    load_compiled_data,
    opengraph_output_path,
    read_cache,
    write_compiled_data,
)
from .domain import extract_domains, load_domain_list
from .fetch import fetch_crtsh, fetch_recursive, cert_key
from .logging_utils import banner_text, log_message, set_color_enabled, colorize
from .opengraph import build_opengraph_nodes
from .state import state_path, load_state
from .throttle import ThrottleController


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Query crt.sh for certificates related to a domain. Supports recursive "
            "subdomain discovery, adaptive throttling, and resumable runs."
        )
    )
    parser.add_argument(
        "domain",
        nargs="?",
        default=None,
        help="Domain name to query (e.g. example.com) or keyword (e.g. \"google\"). Used as root for recursion.",
    )


    group = parser.add_argument_group("Advanced options")
    group.add_argument(
        "--recursive",
        action="store_true",
        help="Enable recursive subdomain discovery from certificate data.",
    )
    group.add_argument(
        "--depth",
        type=int,
        default=None,
        help="Max recursion depth when --recursive is set (default: unlimited).",
    )

    group_advanced_options = parser.add_argument_group("Advanced options")
    group_advanced_options.add_argument(
        "--no-disk-write",
        action="store_true",
        help="Disable saving state, cache, compiled data, and OpenGraph outputs.",
    )
    group_advanced_options.add_argument(
        "--blacklist-file",
        help=(
            "Path to a blacklist file with domains or simple patterns "
            "(supports only ^, $, and *). Matching domains are skipped."
        ),
    )
    group_advanced_options.add_argument(
        "--force-data-refresh",
        action="store_true",
        help="Ignore cached per-domain JSON and re-fetch from crt.sh.",
    )
    group_advanced_options.add_argument(
        "--input-data",
        help=(
            "Read compiled cert data from this path (required with --offline)."
        ),
    )
    group_advanced_options.add_argument(
        "--offline",
        action="store_true",
        help="Do not query crt.sh; requires --input-data to generate OpenGraph.",
    )
    group_advanced_options.add_argument(
        "--domain-file",
        help=(
            "Read a list of domains (one per line) instead of a single domain. "
            "Empty lines and comments (#) are ignored."
        ),
    )

    group_saved_state = parser.add_argument_group("Saved state options")
    group_saved_state.add_argument(
        "--show-result",
        action="store_true",
        help="Use saved state file to generate outputs without new queries.",
    )
    group_saved_state.add_argument(
        "--ignore-state",
        action="store_true",
        help="Ignore saved state files but still use cached JSON responses.",
    )

    group_requests = parser.add_argument_group("Requests options")
    group_requests.add_argument(
        "--throttle",
        type=float,
        default=1.0,
        help="Initial seconds between requests (default: 1.0).",
    )
    group_requests.add_argument(
        "--no-auto-throttle",
        action="store_true",
        help="Disable adaptive throttling on HTTP 5xx responses.",
    )
    group_requests.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP timeout in seconds for each request (default: 30).",
    )
    group_requests.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retry count for timeouts/temporary errors (default: 2).",
    )

    group_output = parser.add_argument_group("Output options")
    group_output.add_argument(
        "--opengraph-output",
        help=(
            "Write OpenGraph output to this path "
            "(default: alongside compiled data, with _opengraph.json suffix)."
        ),
    )
    group_output.add_argument(
        "--subdomain-discovery",
        action="store_true",
        help="Output only discovered domain names, one per line.",
    )
    group_output.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose progress logging to stderr.",
    )
    group_output.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output instead of JSONL.",
    )
    group_output.add_argument(
        "--no-colorized-output",
        action="store_true",
        help="Disable ANSI color output in status messages.",
    )
    group_output.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable the startup ASCII banner.",
    )
    group_output.add_argument(
        "--output-data",
        help=(
            "Write compiled cert data to this path "
            "(default: .tls_cert_hound_data/<domain>/<domain>_all_cert_data.json "
            "or .tls_cert_hound_data/<domain_file>_results/<domain_file>_all_cert_data.json "
            "when --domain-file is used)."
        ),
    )

    args = parser.parse_args()

    set_color_enabled(not args.no_colorized_output)
    if not args.no_banner:
        print(colorize(banner_text(), "\033[36m"))

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

    if not args.domain and not args.domain_file:
        log_message(
            "[!] Either a domain argument or --domain-file is required.",
            True,
            force=True,
        )
        return 1

    domains = [args.domain] if args.domain else []
    if args.domain_file:
        domains = load_domain_list(args.domain_file, args.verbose)
        if not domains:
            log_message(
                "[!] No domains found in --domain-file.",
                True,
                force=True,
            )
            return 1

    if args.offline and args.domain_file:
        log_message(
            "[!] --offline cannot be combined with --domain-file.",
            True,
            force=True,
        )
        return 1

    log_message(
        f"[*] Starting run for {', '.join(domains)}. Recursive={args.recursive}, "
        f"Depth={args.depth}, Timeout={args.timeout}s, Retries={args.retries}, "
        f"Throttle={args.throttle}s, AutoThrottle={not args.no_auto_throttle}, "
        f"DiskWrite={not args.no_disk_write}.",
        args.verbose,
    )

    all_results = []
    seen_cert_keys = set()
    searches = []
    all_discovered = set()
    search_depth_override = None

    if args.show_result and args.offline:
        log_message("[!] --show-result cannot be combined with --offline.", True, force=True)
        return 1

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
            searches = meta.get("searches", [])
            if not searches and "search" in meta:
                searches = [
                    {
                        "search": meta.get("search"),
                        "search_date": meta.get("search_date"),
                        "search_depth": meta.get("search_depth", 0),
                        "is_recursive": meta.get("is_recursive", False),
                        "discovered_domains": meta.get("discovered_domains", []),
                    }
                ]
        log_message(
            f"[*] Offline mode: loaded {len(results)} entries from {compiled_path}.",
            args.verbose,
        )
        all_results = results
    elif args.show_result:
        if args.domain_file:
            compiled_path = args.output_data or data_output_path_for_domain_file(
                args.domain_file
            )
            results, meta = load_compiled_data(compiled_path, args.verbose)
            if results is None:
                return 1
            searches = meta.get("searches", []) if meta else []
            if not searches:
                discovered = set()
                for entry in results:
                    for d in extract_domains(entry):
                        if not is_blacklisted(d, blacklist_patterns):
                            discovered.add(d)
                searches = [
                    {
                        "search": "multi",
                        "search_date": datetime.utcnow().date().isoformat(),
                        "search_depth": -1,
                        "is_recursive": True,
                        "discovered_domains": sorted(discovered),
                    }
                ]
            all_results = results
            for entry in results:
                key = cert_key(entry)
                if key in seen_cert_keys:
                    continue
                seen_cert_keys.add(key)
            for search in searches:
                for d in search.get("discovered_domains", []):
                    all_discovered.add(d)
        else:
            # show-result uses state for single domain, falls back to cache if needed
            for domain in domains:
                cache_dir = cache_dir_path(domain)
                state_file = state_path(cache_dir, domain)
                state = load_state(state_file)
                results = []
                queued_domains = []
                search_depth = None
                if state:
                    results = state.get("results", [])
                    queued_domains = [
                        d for d, _depth in state.get("queue", [])
                        if d and not is_blacklisted(d, blacklist_patterns)
                    ]
                    search_depth = state.get("depth")
                else:
                    cached = read_cache(domain, cache_dir, args.verbose)
                    if cached is None:
                        log_message(
                            f"[!] No state/cache found for --show-result: {domain}.",
                            True,
                            force=True,
                        )
                        return 1
                    results = cached
                discovered = set()
                for entry in results:
                    for d in extract_domains(entry):
                        if not is_blacklisted(d, blacklist_patterns):
                            discovered.add(d)
                discovered.update(queued_domains)
                discovered.add(domain.lower())
                searches.append(
                    {
                        "search": domain,
                        "search_date": datetime.utcnow().date().isoformat(),
                        "search_depth": search_depth if search_depth is not None else -1,
                        "is_recursive": True,
                        "discovered_domains": sorted(discovered),
                    }
                )
                all_discovered.update(discovered)
                for entry in results:
                    key = cert_key(entry)
                    if key in seen_cert_keys:
                        continue
                    seen_cert_keys.add(key)
                    all_results.append(entry)
    else:
        if args.no_disk_write:
            log_message(
                "[!] --no-disk-write disables resume and caching functionnalities.",
                True,
                force=True,
            )
        for domain in domains:
            if is_blacklisted(domain, blacklist_patterns):
                log_message(
                    f"[!] Root domain {domain} is blacklisted. Skipping.",
                    True,
                    force=True,
                )
                continue
            cache_dir = cache_dir_path(domain)
            if args.recursive:
                try:
                    results = fetch_recursive(
                        domain,
                        args.depth,
                        args.timeout,
                        args.retries,
                        throttle,
                    args.verbose,
                    state_path(cache_dir, domain),
                    cache_dir,
                    args.no_disk_write,
                    args.force_data_refresh,
                    blacklist_patterns,
                    args.ignore_state,
                )
                except Exception as exc:
                    log_message(
                        f"[!] Failed to query crt.sh for {domain}: {exc}",
                        True,
                        force=True,
                    )
                    return 1
            else:
                try:
                    results, _from_cache = fetch_crtsh(
                        domain,
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
                    log_message(
                        f"[!] Failed to query crt.sh for {domain}: {exc}",
                        True,
                        force=True,
                    )
                    return 1

            discovered = set()
            for entry in results:
                for d in extract_domains(entry):
                    if not is_blacklisted(d, blacklist_patterns):
                        discovered.add(d)
            discovered.add(domain.lower())
            search_depth = 0
            if args.recursive:
                search_depth = args.depth if args.depth is not None else -1
            searches.append(
                {
                    "search": domain,
                    "search_date": datetime.utcnow().date().isoformat(),
                    "search_depth": search_depth,
                    "is_recursive": search_depth != 0,
                    "discovered_domains": sorted(discovered),
                }
            )
            all_discovered.update(discovered)
            for entry in results:
                key = cert_key(entry)
                if key in seen_cert_keys:
                    continue
                seen_cert_keys.add(key)
                all_results.append(entry)

    results = all_results
    log_message(f"[*] Retrieved {len(results)} certificate entries.", args.verbose)

    search_depth = 0
    if args.recursive:
        search_depth = args.depth if args.depth is not None else -1
    if args.offline and search_depth_override is not None:
        search_depth = search_depth_override

    if not searches:
        searches = [
            {
                "search": args.domain or "",
                "search_date": datetime.utcnow().date().isoformat(),
                "search_depth": search_depth,
                "is_recursive": search_depth != 0,
                "discovered_domains": sorted(all_discovered) if all_discovered else [],
            }
        ]

    metadata = {
        "searches": searches,
        "blacklisted_elements": blacklist_entries,
    }

    if not args.offline:
        default_output_data = args.output_data
        if not default_output_data and args.domain_file:
            default_output_data = data_output_path_for_domain_file(args.domain_file)
        write_compiled_data(
            args.domain,
            results,
            default_output_data,
            args.verbose,
            args.no_disk_write,
            metadata,
        )

    if not args.no_disk_write:
        output_data_path = args.output_data
        if not output_data_path and args.domain_file:
            output_data_path = data_output_path_for_domain_file(args.domain_file)
        og_path = args.opengraph_output or opengraph_output_path(
            args.domain, output_data_path
        )
        graph = build_opengraph_nodes(
            results,
            searches,
            blacklist_entries,
        )
        if graph is not None:
            export_fn = getattr(graph, "exportToFile", None)
            if export_fn is None:
                export_fn = getattr(graph, "export_to_file", None)
            if export_fn is None:
                log_message(
                    "[!] OpenGraph export method not found on graph object.",
                    True,
                    force=True,
                )
                return 1
            export_fn(og_path)
            log_message(f"[*] OpenGraph written to {og_path}.", args.verbose)

    if args.subdomain_discovery:
        discovered = set()
        for entry in results:
            for domain in extract_domains(entry):
                if not is_blacklisted(domain, blacklist_patterns):
                    discovered.add(domain)
        for search in searches:
            for domain in search.get("discovered_domains", []):
                discovered.add(domain)
        if args.domain:
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
