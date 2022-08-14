# Ransomware Detection and Mitigation in SDN
Pox Controller modules to detect ransomwares using Software Defined Networking (SDN) techniques and set OpenFlow rules to stop them from spreading in a network.

## 1. Shallow Packet Inspection (SPI)
Analyses the tcp packet headers to block the host.

### 1.1. packet_header_inspect.py
Detects malicious strings in packet headers to block the host.

### 1.2. packet_size_inspect.py
Detects malicious tcp packets based on their size to block the host.
<br/><br/>

## 2. Deep Packet Inspection (DPI)

### 2.1. deep_packet_inspect.py
Analyses tcp packet for unique malicious strings to block the host.

### 2.2. dns_monitor.py
Analyses dns requests to malicious urls and blocks the host.
<br/><br/>

## 3. Network Scan Based
Analyses network traffic scans to block the host.

### 3.1. arp_scan_monitor.py
Detects arp scan with a threshold by keeping a log of number of arp request packets and reply packets and blocks the host.

### 3.2. honeypot_monitor.py
Detects connections over specific ports to a honeypot in the network and blocks the host.

### TODO: HTTP IOC based detection 