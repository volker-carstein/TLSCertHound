from datetime import datetime

from .domain import normalize_domain
from .logging_utils import log_message


def build_opengraph_nodes(results, searches, blacklist_entries):
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
            kinds=["WebDomainName"],
            properties=Properties(
                fqdn=domain,
                is_cn=str(flags["is_cn"]),
                is_san=str(flags["is_san"]),
            ),
        )

    extra_domains = set()
    for search in searches:
        for domain in search.get("discovered_domains", []):
            extra_domains.add(domain)
    for domain in extra_domains:
        if domain in domain_nodes:
            continue
        domain_nodes[domain] = Node(
            id=domain,
            kinds=["WebDomainName"],
            properties=Properties(
                fqdn=domain,
                is_cn="False",
                is_san="False",
            ),
        )

    if searches is None:
        searches = []

    for node in issuer_nodes.values():
        graph.add_node(node)
    for node in cert_nodes.values():
        graph.add_node(node)
    for node in domain_nodes.values():
        graph.add_node(node)

    edge_keys = set()
    for search in searches:
        search_term = search.get("search", "")
        search_date = search.get("search_date") or datetime.utcnow().date().isoformat()
        search_depth = search.get("search_depth", 0)
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
        graph.add_node(search_node)
        for domain in search.get("discovered_domains", []):
            if domain not in domain_nodes:
                continue
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
