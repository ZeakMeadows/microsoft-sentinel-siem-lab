# Microsoft Sentinel SIEM Lab — Brute Force Detection & GeoIP Attack Map

A self-built Security Operations Center (SOC) lab using **Microsoft Sentinel**
and the broader **Microsoft security stack** to detect, enrich, and visualize
brute-force login attempts against an exposed VM in near real time.

## Microsoft Tools Used

| Tool | Role |
|---|---|
| **Microsoft Sentinel** | Cloud-native SIEM — detection logic, workbooks, alerting |
| **Microsoft Defender** portal | Unified security operations console |
| **Log Analytics Workspace** | Log ingestion & KQL query engine |
| **Azure Monitor Workbooks** | Custom attack-map visualization |
| **KQL (Kusto Query Language)** | Detection query authoring, GeoIP enrichment |
| **Sentinel Watchlists** | GeoIP CIDR lookup table for `ipv4_lookup()` |
| **Azure NSG** | Network security boundary / controlled attack surface |
| **Azure VNet** | Isolated network for the target VM |

## Architecture

![Architecture Diagram](./architecture.png)

**Flow:**
1. A VM sits behind an NSG in an Azure VNet, deliberately exposed to capture
   real inbound connection attempts from the public internet.
2. Windows Security Events (EventID 4625 — failed logon) are collected into a
   **Log Analytics Workspace**.
3. **Microsoft Sentinel**, acting as the SIEM, runs a custom KQL detection query
   that enriches failed login source IPs with geolocation data via a Sentinel
   watchlist.
4. Results render on a live **Sentinel workbook attack map**, showing attacker
   origin, volume, and location as it happens.

## Detection Query (KQL
