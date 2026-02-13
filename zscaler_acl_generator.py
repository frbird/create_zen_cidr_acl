#!/usr/bin/env python3
"""
Zscaler Data Center ACL Generator for Policy-Based Routing (PBR).

Fetches Zscaler endpoint JSON from a configurable URL, filters by continent/city
via environment variables, and generates ACL/prefix-list config for Arista, Juniper,
or Cisco to exclude traffic destined for Zscaler ranges from normal routing (e.g.
send to Zscaler tunnel via PBR).

Configuration (environment variables or CLI flags; flags override env):
  ZS_URL / --url                    - JSON URL (default: Zscaler CENR endpoint)
  ZS_CONTINENTS / --continents      - Comma-separated continents to include (default: all)
  ZS_CITIES / --cities              - Comma-separated cities to include (default: all)
  ZS_CACHE_MAX_AGE_SECONDS / --cache-max-age  - Max cache age in seconds (default: 86400)
  ZS_CHECK_INTERVAL_HOURS / --check-interval-hours - Refresh interval in hours (overrides above)
  ZS_DEVICE / --device              - Output format: auto | arista | juniper | cisco
  ZS_ACL_NAME / --acl-name          - ACL/filter name (default: ZSCALER-PBR)
  ZS_CACHE_FILE / --cache-file      - Path to cache file (default: .zs_dc_cache.json)
  ZS_OUTPUT_FILE / --output-file    - Write config to file instead of stdout (optional)
"""

from __future__ import annotations

import json
import os
import re
import sys
from ipaddress import ip_network
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# -----------------------------------------------------------------------------
# Defaults and env
# -----------------------------------------------------------------------------

DEFAULT_URL = "https://config.zscaler.com/api/zscalerthree.net/cenr/json"
DEFAULT_ACL_NAME = "ZSCALER-PBR"
DEFAULT_CACHE_FILE = ".zs_dc_cache.json"
DEFAULT_CACHE_MAX_AGE_SECONDS = 86400  # 24 hours

CONTINENT_PREFIX = "continent : "
CITY_PREFIX = "city : "


def env(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, default)


def env_int(key: str, default: int) -> int:
    v = os.environ.get(key)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default


# -----------------------------------------------------------------------------
# Fetch and cache
# -----------------------------------------------------------------------------


def fetch_json(url: str) -> dict[str, Any]:
    # Local file for testing (path or file://)
    if url.startswith("file://"):
        path = Path(url[7:].lstrip("/"))
    elif Path(url).exists():
        path = Path(url)
    else:
        path = None
    if path is not None and path.exists():
        return json.loads(path.read_text())
    req = Request(url, headers={"User-Agent": "ZS-ACL-Generator/1.0"})
    with urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def load_cached(cache_path: Path, max_age_seconds: int) -> tuple[dict[str, Any] | None, bool]:
    """Return (data, from_cache). data is None if cache miss or stale."""
    if not cache_path.exists():
        return None, False
    try:
        with open(cache_path) as f:
            blob = json.load(f)
        ts = blob.get("_cached_at")
        if ts is None:
            return None, False
        age = __import__("time").time() - ts
        if age > max_age_seconds:
            return None, False
        return blob.get("data"), True
    except (json.JSONDecodeError, OSError):
        return None, False


def save_cache(cache_path: Path, data: dict[str, Any]) -> None:
    import time
    with open(cache_path, "w") as f:
        json.dump({"_cached_at": time.time(), "data": data}, f, indent=2)


def get_json(url: str, cache_path: Path, max_age_seconds: int) -> dict[str, Any]:
    is_local = url.startswith("file://") or Path(url).exists()
    if not is_local:
        cached, from_cache = load_cached(cache_path, max_age_seconds)
        if from_cache and cached is not None:
            return cached
    try:
        data = fetch_json(url)
        if not is_local:
            save_cache(cache_path, data)
        return data
    except (URLError, HTTPError) as e:
        if not is_local:
            cached, _ = load_cached(cache_path, max_age_seconds=2**31)
            if cached is not None:
                return cached
        raise SystemExit(f"Failed to fetch {url}: {e}") from e


# -----------------------------------------------------------------------------
# Parse and filter
# -----------------------------------------------------------------------------


def parse_continents_cities(data: dict[str, Any]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """
    Input: raw JSON (e.g. {"zscalerthree.net": { "continent : EMEA": { "city : Amsterdam II": [...] } } })
    Output: { "EMEA": { "Amsterdam II": [ { "range": "1.2.3.0/24", ... }, ... ] }, ... }
    """
    out: dict[str, dict[str, list[dict[str, Any]]]] = {}
    # Top level is usually one key (domain name)
    for domain_key, domain_val in data.items():
        if not isinstance(domain_val, dict):
            continue
        for cont_key, cont_val in domain_val.items():
            if not cont_key.strip().lower().startswith("continent"):
                continue
            if not isinstance(cont_val, dict):
                continue
            # "continent : EMEA" -> "EMEA"
            cont_name = cont_key.split(":", 1)[-1].strip() if ":" in cont_key else cont_key.strip()
            out.setdefault(cont_name, {})
            for city_key, city_val in cont_val.items():
                if not isinstance(city_val, list):
                    continue
                city_name = city_key.split(":", 1)[-1].strip() if ":" in city_key else city_key.strip()
                out[cont_name][city_name] = city_val
    return out


def collect_ranges(
    data: dict[str, Any],
    continents: list[str] | None,
    cities: list[str] | None,
) -> tuple[set[str], bool]:
    """
    Return (unique CIDR set, used_flat_format).
    Supports two JSON shapes:
    - Flat: {"prefixes": ["1.2.3.0/24", ...]} (live API; continent/city ignored)
    - Hierarchical: {"zscalerthree.net": {"continent : X": {"city : Y": [{"range": "..."}]}}}
    """
    # Flat format (e.g. .../future/json has no hierarchy; .../cenr/json has continent/city)
    if "prefixes" in data and isinstance(data["prefixes"], list):
        used_flat = bool(continents or cities)
        return {str(p).strip() for p in data["prefixes"] if p and isinstance(p, str)}, used_flat

    # Hierarchical format (e.g. ZS_DCs.json with continent/city)
    cc = parse_continents_cities(data)
    cont_set = {c.strip().lower() for c in continents} if continents else None
    city_set = {c.strip().lower() for c in cities} if cities else None
    selected = set()
    for cont_name, cities_map in cc.items():
        if cont_set is not None and cont_name.strip().lower() not in cont_set:
            continue
        for city_name, entries in cities_map.items():
            if city_set is not None and city_name.strip().lower() not in city_set:
                continue
            for entry in entries:
                if isinstance(entry, dict) and "range" in entry:
                    r = entry["range"]
                    if r and isinstance(r, str):
                        selected.add(r.strip())
    return selected, False


def normalize_filters(s: str | None) -> list[str] | None:
    if s is None or not s.strip():
        return None
    return [x.strip() for x in re.split(r"[,;]", s) if x.strip()]


# -----------------------------------------------------------------------------
# Device detection
# -----------------------------------------------------------------------------


def detect_device() -> str:
    """
    Attempt to detect network OS from the current system.
    Returns one of: arista, juniper, cisco
    """
    # Explicit override (ZS_DEVICE=arista|juniper|cisco|eos|junos|ios|ios-xe|nxos)
    d = (env("ZS_DEVICE") or "").strip().lower()
    if d in ("arista", "eos"):
        return "arista"
    if d in ("juniper", "junos"):
        return "juniper"
    if d in ("cisco", "ios", "ios-xe", "nxos"):
        return "cisco"

    # Auto-detect from filesystem (when script runs on the device or a known env)
    eos_release = Path("/etc/Eos-release")
    if eos_release.exists():
        return "arista"

    junos_markers = [
        Path("/usr/share/junos"),
        Path("/etc/junos"),
    ]
    for p in junos_markers:
        if p.exists():
            return "juniper"

    # Cisco: common on IOS-XE (Linux), NX-OS; no single canonical path
    cisco_markers = [
        Path("/etc/ios.conf"),
        Path("/usr/bin/Cisco"),
    ]
    for p in cisco_markers:
        if p.exists():
            return "cisco"

    # NAPALM / automation env
    napalm = (env("NAPALM_DEVICE_TYPE") or "").strip().lower()
    if "eos" in napalm or "arista" in napalm:
        return "arista"
    if "junos" in napalm or "juniper" in napalm:
        return "juniper"
    if "ios" in napalm or "nxos" in napalm or "cisco" in napalm:
        return "cisco"

    return "cisco"  # safe default


# -----------------------------------------------------------------------------
# ACL generators (destination-based permit for PBR)
# -----------------------------------------------------------------------------


def cidr_to_wildcard(cidr: str) -> tuple[str, str] | None:
    """Convert IPv4 CIDR to (network, wildcard). Returns None for IPv6 or invalid."""
    try:
        net = ip_network(cidr, strict=False)
        if net.version != 4:
            return None
        addr = str(net.network_address)
        mask = net.netmask
        # wildcard = 255.255.255.255 - mask
        wc = ".".join(str(255 - int(b)) for b in mask.compressed.split("."))
        return addr, wc
    except Exception:
        return None


def is_ipv6(cidr: str) -> bool:
    try:
        return ip_network(cidr, strict=False).version == 6
    except Exception:
        return False


def generate_cisco_acl(name: str, ranges: set[str]) -> list[str]:
    lines = []
    ipv4 = sorted(r for r in ranges if not is_ipv6(r))
    ipv6 = sorted(r for r in ranges if is_ipv6(r))

    if ipv4:
        lines.append(f"ip access-list extended {name}")
        for cidr in ipv4:
            pair = cidr_to_wildcard(cidr)
            if pair:
                net, wc = pair
                lines.append(f" permit ip any {net} {wc}")
        lines.append("!")

    if ipv6:
        lines.append(f"ipv6 access-list {name}-v6")
        for cidr in ipv6:
            lines.append(f" permit ipv6 any {cidr}")
        lines.append("!")
    return lines


def generate_arista_acl(name: str, ranges: set[str]) -> list[str]:
    # Arista EOS uses same extended ACL syntax as Cisco for IPv4; IPv6 similar
    return generate_cisco_acl(name, ranges)


def generate_juniper_acl(name: str, ranges: set[str]) -> list[str]:
    lines = []
    ipv4 = sorted(r for r in ranges if not is_ipv6(r))
    ipv6 = sorted(r for r in ranges if is_ipv6(r))

    if ipv4 or ipv6:
        lines.append("firewall {")
        lines.append(f"  filter {name} {{")
        lines.append("    term permit-zscaler-destinations {")
        lines.append("      from {")
        if ipv4:
            lines.append("        destination-address {")
            for cidr in ipv4:
                lines.append(f"          {cidr};")
            lines.append("        }")
        lines.append("      }")
        lines.append("      then accept;")
        lines.append("    }")
        lines.append("  }")
        lines.append("}")

    if ipv6:
        lines.append("")
        lines.append("firewall {")
        lines.append(f"  filter {name}-v6 {{")
        lines.append("    term permit-zscaler-destinations {")
        lines.append("      from {")
        lines.append("        destination-address {")
        for cidr in ipv6:
            lines.append(f"          {cidr};")
        lines.append("        }")
        lines.append("      }")
        lines.append("      then accept;")
        lines.append("    }")
        lines.append("  }")
        lines.append("}")
    return lines


def generate_acl(device: str, name: str, ranges: set[str]) -> list[str]:
    if device == "arista":
        return generate_arista_acl(name, ranges)
    if device == "juniper":
        return generate_juniper_acl(name, ranges)
    return generate_cisco_acl(name, ranges)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def _resolve(key: str, flag_val: str | int | None, default: str | None = None) -> str | None:
    """Return flag value if set, else env value, else default."""
    if flag_val is not None and flag_val != "":
        return str(flag_val)
    return env(key) or default


def _resolve_int(key: str, flag_val: int | None, default: int) -> int:
    """Return flag value if set (>0 or explicitly 0), else env value, else default."""
    if flag_val is not None:
        return flag_val
    return env_int(key, default)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Generate PBR ACL from Zscaler DC JSON. "
        "All options can be set via environment variables or CLI flags; flags override env."
    )
    parser.add_argument("--list", action="store_true", help="List continents and cities then exit")
    parser.add_argument("--list-continents", action="store_true", help="List continents only")
    parser.add_argument("--list-cities", action="store_true", help="List cities only (optionally filtered by --continents)")
    parser.add_argument("--url", metavar="URL", help="JSON endpoint or local path (overrides ZS_URL)")
    parser.add_argument("--continents", metavar="LIST", help="Comma-separated continents (overrides ZS_CONTINENTS)")
    parser.add_argument("--cities", metavar="LIST", help="Comma-separated cities (overrides ZS_CITIES)")
    parser.add_argument("--cache-max-age", type=int, metavar="SEC", help="Cache max age in seconds (overrides ZS_CACHE_MAX_AGE_SECONDS)")
    parser.add_argument("--check-interval-hours", type=int, metavar="HRS", help="Refresh interval in hours (overrides ZS_CHECK_INTERVAL_HOURS)")
    parser.add_argument("--device", choices=["auto", "arista", "eos", "juniper", "junos", "cisco", "ios", "ios-xe", "nxos"],
                        help="Output format (overrides ZS_DEVICE)")
    parser.add_argument("--acl-name", metavar="NAME", help="ACL/filter name (overrides ZS_ACL_NAME)")
    parser.add_argument("--cache-file", metavar="PATH", help="Path to cache file (overrides ZS_CACHE_FILE)")
    parser.add_argument("--output-file", "-o", metavar="PATH", help="Write config to file (overrides ZS_OUTPUT_FILE)")
    args = parser.parse_args()

    url = _resolve("ZS_URL", args.url, DEFAULT_URL)
    cache_file = Path(_resolve("ZS_CACHE_FILE", args.cache_file, DEFAULT_CACHE_FILE))
    hours = _resolve_int("ZS_CHECK_INTERVAL_HOURS", args.check_interval_hours, 0)
    if hours > 0:
        max_age = hours * 3600
    else:
        max_age = _resolve_int("ZS_CACHE_MAX_AGE_SECONDS", args.cache_max_age, DEFAULT_CACHE_MAX_AGE_SECONDS)

    data = get_json(url, cache_file, max_age)
    cc = parse_continents_cities(data)

    if args.list or args.list_continents:
        for c in sorted(cc.keys()):
            print(c)
        if args.list_continents:
            return
    if args.list or args.list_cities:
        continents_filter = normalize_filters(_resolve("ZS_CONTINENTS", args.continents))
        for cont_name, cities_map in sorted(cc.items()):
            if continents_filter and cont_name.strip().lower() not in {c.lower() for c in continents_filter}:
                continue
            for city_name in sorted(cities_map.keys()):
                print(f"  {cont_name}: {city_name}")
        if args.list or args.list_cities:
            return

    continents = normalize_filters(_resolve("ZS_CONTINENTS", args.continents))
    cities = normalize_filters(_resolve("ZS_CITIES", args.cities))

    ranges, used_flat_format = collect_ranges(data, continents, cities)
    if not ranges:
        print("No ranges selected. Check --continents and --cities (or ZS_CONTINENTS and ZS_CITIES).", file=sys.stderr)
        sys.exit(1)
    if used_flat_format:
        print(
            "Note: This feed uses a flat prefix list; --continents/--cities are ignored and all prefixes are included.",
            file=sys.stderr,
        )

    device_raw = (_resolve("ZS_DEVICE", args.device) or "auto").strip().lower()
    if device_raw == "auto":
        device = detect_device()
    else:
        device = (
            "arista" if device_raw in ("arista", "eos")
            else "juniper" if device_raw in ("juniper", "junos")
            else "cisco" if device_raw in ("cisco", "ios", "ios-xe", "nxos")
            else "cisco"
        )

    acl_name = _resolve("ZS_ACL_NAME", args.acl_name, DEFAULT_ACL_NAME)
    lines = generate_acl(device, acl_name, ranges)
    output = "\n".join(lines)

    out_path = _resolve("ZS_OUTPUT_FILE", args.output_file)
    if out_path:
        Path(out_path).write_text(output)
        print(f"Wrote {len(ranges)} ranges ({device}) to {out_path}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
