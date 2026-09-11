# Telecom PCAP Analyzer

A script to simplify packet capture analysis for telecom protocols: NGAP, E1AP, F1AP, XnAP, PFCP, GTP, ICMP, ICMPv6, and SCTP.

## Versions

Two versions are included — both produce identical output.

| File | Use case |
|---|---|
| `pcap_analyzer.py` | No asyncio. Works on older/standard Python setups where pyshark manages its own event loop internally. |
| `pcap_analyzer_asyncio.py` | Uses asyncio. Required on Python 3.10+ on Windows. |

## Features

- **Protocol-specific message extraction** — reads directly from packet field structure to identify exact message names
- **File size display** — shows PCAP file size in KB/MB/GB
- **Message filtering** — search for specific messages by name
- **Size anomaly detection** — flags packets whose size deviates from the expected size for that message type
- **Request-response tracking** — verifies every request received a response, tracked per UE session using transaction IDs
- **Log size limiting** — stops collection after a user-defined byte limit, for large capture files

## Why use this over manual Wireshark inspection

- Analyzes packets instantly, no manual scrolling
- Differentiates request/response from packet structure — no hardcoding
- Detects size anomalies and missing responses
- Simple to run, minimal setup

## Limitations

- Only supports the protocols listed above — adding new ones needs code changes
- Message names appear lowercase, not camelCase
- Size anomaly detection is based on common packet sizes observed in the file, not a fixed spec

## Requirements

- `tshark` and `pyshark` installed
- The PCAP file placed in the same folder as the script

## Usage

```bash
pip install pyshark
python pcap_analyzer.py <capture_file>.pcap
```

(On Python 3.10+ on Windows, use `pcap_analyzer_asyncio.py` instead.)
