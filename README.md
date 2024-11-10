**DoS Detection Software (Python)**

Description:

This Python script is designed to detect potential Denial of Service (DoS) attacks 
by monitoring network traffic in real-time using the Scapy library. It tracks various 
packet types (ICMP, TCP, UDP) and triggers alerts when abnormal traffic patterns are detected.
    
Tested Environment:

- This script has been tested and verified to work on the following setups:
1. **GNS3 (Graphical Network Simulator 3)**:
   - Used for network simulation to test packet capturing and DoS detection.
   - Recommended to set up a network with multiple nodes to simulate attack scenarios.
        
2. **Ubuntu 20.04 LTS**:
   - Operating System: Linux (Ubuntu)
   - Python Version: 3.x
   - Required Packages:
     * scapy
     * curses (pre-installed on most Linux systems)
3. Requirements:
   - Python 3.x
   - scapy library
   - Network packet capturing tool (like Npcap on Windows or libpcap on Linux)

Setup Instructions:
1. **On Ubuntu**:
$ sudo apt update
$ sudo apt install python3-pip
$ pip3 install scapy

3. **For GNS3 Simulation**:
- Configure network nodes and connect a Linux VM (like Ubuntu) for testing.
- Use the script to monitor and detect potential DoS attacks on simulated networks.
        
Usage:
    Run the script with root or administrator privileges for network packet sniffing:
        $ sudo python3 detectionfinal1_0.py
        
Key Features:
- Packet Analysis: Monitors and analyzes network packets (ICMP, TCP, UDP) using `scapy`.
- Predefined Thresholds: Detects anomalies such as ICMP Echo requests (ping flood), TCP SYN floods, UDP floods, and other attack vectors.
- Real-Time Detection: Utilizes a curses-based interface to provide live updates on packet counts and alert statuses.
- Customizable Settings: Adjustable thresholds and time windows for tailored network monitoring.
