# 🔥 PackCap Tool

PackCap Tool is an advanced network and packet analysis tool designed for cybersecurity enthusiasts and network analysts. It provides a comprehensive set of features for capturing, analyzing, and managing network packets and Bluetooth HCI logs. Built with Python, Scapy, and PyShark, and featuring a stylish UI with Rich.

## 🚀 Key Features

PackCap Tool is packed with robust features designed to simplify and enhance network and packet analysis. Here’s what it offers:

- **Project Management:**
  - Create, manage, and organize multiple projects efficiently.
  - Dynamically create and select projects, with default settings tied to each project.
  - Auto-save captures and analysis results within the selected project directory.
  - Manage multiple projects with ease.
  - Create and select projects dynamically.
  - Default settings are tied to the selected project.
- **Network Packet Capture:**
  - Capture live network traffic across multiple interfaces with customizable filters.
  - Apply advanced filters by source IP, destination IP, protocol type, and custom ports.
  - Auto-generate filenames using UTC timestamps if no filename is provided.
  - Capture live network traffic with custom filters.
  - Save captures to project-specific directories.
  - Auto-generate filenames with UTC timestamps.
- **Trace File Analysis:**
  - Analyze PCAP and LOG files from project directories.
  - Extract detailed protocol distribution, top talkers, and packet statistics.
  - Resolve domain names for external IPs using DNS data from captured packets.
  - Analyze PCAP and LOG files within project directories.
  - Extract detailed protocol distribution and top talkers.
- **Flow Analysis:**
  - Group packets by flow, identifying unique sessions using source IP, destination IP, ports, and protocol.
  - Visualize flow statistics including packet counts, byte sizes, and bandwidth usage.
  - Identify suspicious flows or anomalies by comparing session patterns.
  - Group packets by flow (src IP, dst IP, src port, dst port, protocol).
  - Display flow statistics including packet counts and byte sizes.
- **Bluetooth HCI Log Analysis:**
  - Supports Bluetooth HCI logs exported from Android devices in both PCAP and LOG formats.
  - Detects encrypted packets, extracts Link Keys and Long Term Keys (LTK).
  - Group packets by sessions showing Source and Destination MAC addresses and Connection Handles.
  - Displays encryption status per session and pinpoints the packet numbers for key exchanges.
  - Supports Bluetooth HCI logs exported from Android.
  - Identifies encrypted packets and extracts Link Keys and Long Term Keys (LTK).
  - Groups packets by sessions, displaying MAC addresses and connection handles.

## 🧰 Requirements

- Python 3.x
- Required Python Packages:
  - scapy
  - pyshark
  - rich
  - netifaces (optional for detailed network info)
- TShark (for Bluetooth HCI log analysis)

## ⚙️ Installation and Setup

To get started with JDZ Tools, follow the steps below to install the required dependencies and set up the environment.

1. Install Python dependencies:

```bash
pip install scapy pyshark rich netifaces
```

2. Install TShark:

- On Ubuntu/Debian:

```bash
sudo apt install tshark
```

- On macOS (Homebrew):

```bash
brew install wireshark
```

- On Windows: [Download from Wireshark.org](https://www.wireshark.org/download.html) and ensure TShark is added to PATH.

## 🎬 Getting Started

Launch tool using the command below and follow the on-screen instructions to select a project or create a new one, modify default settings, and perform network captures or analysis.

```bash
python3 jdz_tools.py
```

1. Select a project or create a new one.
2. Modify default settings as needed.
3. Capture network packets or analyze existing trace files.
4. Perform flow analysis or advanced Bluetooth HCI log analysis.

## 📚 Practical Examples

Here are some practical examples to help you get started with JDZ Tools:

```bash
# Start PackCap Tools
python3 packcap.py

# Capture network packets and save to a project
- Select 'Capture Network Packets'
- Apply filters as needed (e.g., source IP, destination IP, protocol)
- File saved with UTC timestamp if no name is given

# Analyze Bluetooth HCI log
- Select 'Bluetooth Trace File Analysis'
- Choose a .log or .pcap file from the project folder
- View sessions, encryption status, and key details
```

## 📜 License

This project is licensed under the MIT License. Feel free to modify and distribute it under the terms of the license.

## 🚧 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Feel free to reach out for any queries or suggestions!
