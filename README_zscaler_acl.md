# Zscaler PBR ACL Generator

Generates ACL (access-list / firewall filter) configuration for **policy-based routing (PBR)** so you can exclude Zscaler ZCC traffic destined to Zscaler data center CIDRs from your Zscaler tunnel.

Supports **Arista EOS**, **Juniper Junos**, and **Cisco IOS-XE/NX-OS**. Device type can be set via `ZS_DEVICE` or auto-detected when the script runs on the device (or in an environment that exposes the NOS).

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

## Usage

```bash
# Generate Cisco-style ACL (default) from live URL; cache used for 24h
python3 zscaler_acl_generator.py

# Use local JSON file (e.g. for testing)
ZS_URL=./ZS_DCs.json python3 zscaler_acl_generator.py

# Limit to specific continents and cities
ZS_CONTINENTS=EMEA,Americas ZS_CITIES="Amsterdam II,London III,New York III" python3 zscaler_acl_generator.py

# Juniper output
ZS_DEVICE=juniper python3 zscaler_acl_generator.py

# Arista output
ZS_DEVICE=arista python3 zscaler_acl_generator.py

# Write config to file
ZS_OUTPUT_FILE=zscaler_acl.txt python3 zscaler_acl_generator.py

# List available continents and cities
python3 zscaler_acl_generator.py --list-continents
ZS_CONTINENTS=EMEA python3 zscaler_acl_generator.py --list-cities
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|--------|
| `ZS_URL` | JSON endpoint or local path / `file://` URL | `https://config.zscaler.com/api/zscalerthree.net/cenr/json` |
| `ZS_CONTINENTS` | Comma-separated continents (e.g. `EMEA,Americas,APAC`) | all |
| `ZS_CITIES` | Comma-separated cities (e.g. `Amsterdam II,London III`) | all |
| `ZS_CACHE_MAX_AGE_SECONDS` | Seconds after which cache is refreshed | `86400` (24h) |
| `ZS_CHECK_INTERVAL_HOURS` | Alternative refresh interval in hours (overrides above if set) | — |
| `ZS_DEVICE` | `auto` \| `arista` \| `juniper` \| `cisco` (or `eos`, `junos`, `ios`, `ios-xe`, `nxos`) | `auto` |
| `ZS_ACL_NAME` | ACL / filter name | `ZSCALER-PBR` |
| `ZS_CACHE_FILE` | Path to cache file | `.zs_dc_cache.json` |
| `ZS_OUTPUT_FILE` | If set, write config to this file instead of stdout | — |

## Cache and refresh

- The script caches the JSON fetched from `ZS_URL`. Next run within the cache window uses the cache.
- Default: refresh after **24 hours** (`ZS_CACHE_MAX_AGE_SECONDS=86400`).
- To refresh every 12 hours: `ZS_CHECK_INTERVAL_HOURS=12`.
- Local files (`file://` or path) are not cached.

## Device auto-detection

When `ZS_DEVICE=auto` (default), the script tries to detect the platform:

- **Arista**: `/etc/Eos-release` present
- **Juniper**: `/usr/share/junos` or `/etc/junos` present
- **Cisco**: `/etc/ios.conf` or `/usr/bin/Cisco` present, or `NAPALM_DEVICE_TYPE` contains `ios`/`nxos`/`cisco`
- **NAPALM**: `NAPALM_DEVICE_TYPE` (e.g. `eos`, `junos`, `ios`) is used if set

If nothing is detected, output defaults to **Cisco** format.

## Output

- **Cisco / Arista**: `ip access-list extended ZSCALER-PBR` (IPv4) and `ipv6 access-list ZSCALER-PBR-v6` (IPv6) with `permit ip any <destination>` ACEs.
- **Juniper**: `firewall { filter ZSCALER-PBR { ... } }` for IPv4 and `ZSCALER-PBR-v6` for IPv6.

Use the generated ACL/filter in your PBR/route-map/firewall policy to match traffic destined to Zscaler and send it to the appropriate next-hop or interface.
