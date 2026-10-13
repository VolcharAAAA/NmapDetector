# NmapDetector

A Python prototype for detecting port-scanning indicators in PCAP files using PyShark.

## Features

- Extracts IPv4 addresses, protocols, destination ports, timestamps, and TCP flags.
- Calculates the number of unique destination ports in a selected time window.
- Calculates SYN and RST packet ratios.
- Uses a simple rule-based approach to identify potential port-scanning activity.

## Requirements

- Python 3
- Wireshark/TShark
- PyShark

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Place the PCAP files in the project directory and run:

```bash
python main.py
```

## Limitations

This is an educational prototype tested on a small set of PCAP captures. Detection thresholds are experimental and may produce false positives or false negatives. The tool does not guarantee detection of all port-scanning techniques.
