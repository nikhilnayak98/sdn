# Ransomware Detection and Mitigation in SDN
Pox Controller modules to detect ransomwares using Software Defined Networking (SDN) techniques and set OpenFlow rules to stop them from spreading in a network.

## 1. Shallow Packet Inspection (SPI)
Analyses the tcp packet headers to block the host.

### 1.1. packet_header_inspect.py
Detects malicious strings in packet headers to block the host.

### 1.2. packet_size_inspect.py
Detects malicious tcp packets based on their size to block the host.

## 2. Deep Packet Inspection (DPI)
Analyses tcp packet for unique malicious strings to block the host.