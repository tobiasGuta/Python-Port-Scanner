# Python Port Scanner

A lightweight, fast, and clean TCP/UDP port scanner written in Python.

This is **not** meant to replace Nmap.  
It is a minimal reconnaissance tool designed to quickly identify open ports with a modern CLI interface.

---

## Features

- TCP scanning (`-sT`)
- UDP scanning (`-sU`)
- Combined TCP + UDP scans
- Multi-threaded scanning
- Timing profiles (`-T1` to `-T5`)
- Live progress bar with spinner
- Real-time open port detection
- Clean Rich-based CLI interface
- Final formatted results table
- Hostname resolution support

---

## Requirements

- Python 3.8+
- rich
- pyfiglet

Install dependencies:

```bash
pip install rich pyfiglet
```

Usage
--------

### Basic TCP Scan (Default)

`python scanner.py 192.168.1.1`

### TCP Scan Explicitly

`python scanner.py 192.168.1.1 -sT`

### UDP Scan

`python scanner.py 192.168.1.1 -sU`

### TCP + UDP Scan

`python scanner.py 192.168.1.1 -sT -sU`

### Scan Specific Ports

`python scanner.py 192.168.1.1 -p 22,80,443`

### Scan Port Range

`python scanner.py 192.168.1.1 -p 1-1024`

### Scan All Ports

`python scanner.py 192.168.1.1 -p -`

### Use Timing Profiles

`python scanner.py 192.168.1.1 -T 5`

Timing levels:

| Level | Description |
| --- | --- |
| T1 | Slow / stealthier |
| T2 | Polite |
| T3 | Normal (default) |
| T4 | Fast |
| T5 | Aggressive |

How It Works
-------------

### TCP Scanning

Uses standard TCP connect scanning (`socket.connect_ex()`).

If the connection succeeds → port is considered **OPEN**.

### UDP Scanning

Sends a UDP packet and waits for a response.

-   Response received → likely **OPEN**

-   No response → **OPEN or FILTERED**

-   ICMP unreachable → **CLOSED**

> Note: UDP scanning is inherently less reliable without raw sockets.

### Why They Behave Differently
TCP has a handshake:

`Client → SYN
Server → SYN-ACK (if open)`

When you use:

`sock.connect_ex((ip, port))`

The OS tells you clearly:

-   `0` → port is OPEN

-   error → CLOSED

So TCP scanning in Python is very reliable.

* * * * *

UDP (No Handshake = Ambiguous Results)
-----------------------------------------

UDP has **no handshake**.

You just send a packet:

`Client → UDP packet`

Then one of three things happens:

| Situation | What You Receive | What It Means |
| --- | --- | --- |
| Port closed | ICMP Port Unreachable | Closed |
| Port open | Usually nothing | Could be open |
| Firewalled | Nothing | Could be filtered |

<img width="1919" height="542" alt="image" src="https://github.com/user-attachments/assets/4168763e-75b8-4b7b-b916-e3e8f33419c9" />
<img width="1919" height="542" alt="image" src="https://github.com/user-attachments/assets/4168763e-75b8-4b7b-b916-e3e8f33419c9" />

