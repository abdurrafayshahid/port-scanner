# Port Scanner

A multithreaded Python port scanner that identifies open ports, running services, and grabs banners across local and remote targets.

## Features

- **Local interface detection**: Auto-detects local IPv4 addresses and network interfaces.
- **Open port counting**: Counts open common ports during target selection.
- **Scan types**:
  - **TCP connect**: Standard socket-based scanning.
  - **SYN scan**: Half-open scanning via Scapy.
- **Multithreading**: Uses a thread pool to scan multiple ports concurrently.
- **Banner grabbing**: Reads initial data packets on open ports to identify running services.

## Prerequisites

- Python 3.8+
- [Scapy](https://scapy.net/)
- [psutil](https://github.com/giampaolo/psutil)

## Installation

1. Clone the repository.
2. Install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Launch the interactive menu to select a local interface or enter a manual target:

```bash
python scanner.py
```

> [!IMPORTANT]
> **Stealth (SYN) scanning** requires root or administrator privileges to craft raw packets. On Unix-based systems, use `sudo`:
> ```bash
> sudo python scanner.py
> ```

### Menu Navigation

```
█▀█ █▀█ █▀█ ▀█▀   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
█▀▀ █▄█ █▀▄ ░█░   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄
    
0. Manual input
1. 127.0.0.1 (lo0) [1 common ports open]
2. 192.168.4.45 (en0) [1 common ports open]
```

1. **Target selection**: Pick from local active IPs or enter a remote target manually.
2. **Port configuration**: Enter a range (`1-1000`) or specific ports (`12,34,567`).
3. **Method selection**: Choose between a TCP connect scan or a SYN scan.

## Technical Details

- **Concurrency**: Uses a thread pool and a shared queue for non-blocking I/O.
- **Service mapping**: Uses `socket.getservbyport` and banner grabbing to identify software.
- **Network discovery**: Uses `psutil` to list local interfaces.

> [!WARNING]
> This tool is for authorized security testing only. Do not scan networks without explicit permission.
