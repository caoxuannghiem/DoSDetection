DoS Detection Software (Python)

This Python script provides real-time monitoring and detection of potential Denial of Service (DoS) attacks using the `scapy` library. Designed to run in a terminal interface, it tracks various network traffic types and triggers alerts when thresholds are exceeded, indicating potential attack patterns.

Key Features:
- Packet Analysis: Monitors and analyzes network packets (ICMP, TCP, UDP) using `scapy`.
- Predefined Thresholds: Detects anomalies such as ICMP Echo requests (ping flood), TCP SYN floods, UDP floods, and other attack vectors.
- Real-Time Detection: Utilizes a curses-based interface to provide live updates on packet counts and alert statuses.
- Customizable Settings: Adjustable thresholds and time windows for tailored network monitoring.

Usage:
Run this script with elevated privileges (e.g., using `sudo`) to access network interfaces for sniffing.
