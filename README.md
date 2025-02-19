# 🕵️ PacketCap - TCPDump Packet Capture

## 📌 Overview

Cybersecurity tool to easily capture network packets (and analyze). This script allows you to capture network packets using `tcpdump` and organize them into project-based folders. It provides functionality to:

- Create and manage packet capture projects.
- Select network interfaces for monitoring.
- Filter packets by source and destination IP.
- Save packet captures into project folders.
- Stop live captures gracefully using `CTRL+C`.

---

## 🚀 Installation

### Prerequisites

Ensure you have the following installed:

- **Linux/macOS** (or Windows with WSL)
- `tcpdump` installed (`sudo apt install tcpdump` for Debian-based systems)

### Clone Repository

```sh
 git clone https://github.com/johndzilva/PacketCap.git
 cd PacketCap
 chmod +x packetcap_script.sh
```

---

## 🔧 Usage

### 1️⃣ Run the Script

```sh
python3 packetcap_script.sh
```

### 2️⃣ Select an Option

Once the script starts, you can:

1. **Create a new project**: Organize packet captures by project.
2. **Select an existing project**: Choose a project folder to save captures.
3. **Start a live capture**: Specify an interface, source, and destination IP for filtering.
4. **Stop Capture**: Press `CTRL+C` anytime to stop capturing packets.
5. **Exit**: Quit the script.

### 3️⃣ Create a Project

- Enter a unique name for the project.
- A folder will be created inside the script directory (`projects/<ProjectName>`).

### 4️⃣ Start Capturing

- Choose an interface (e.g., `eth0`, `wlan0`).
- Specify an optional source and destination IP for filtering.
- Packets will be saved as `capture_YYYYMMDD_HHMMSS.pcap` in the selected project folder.

### 5️⃣ Stop Capturing

- Press `CTRL+C` to stop live capture and return to the menu.
- Captured packets remain in the project folder.

---

## 🛠 Features & Customization

- **Modify Capture Filters**: Edit the script to change `tcpdump` options for more advanced filtering.
- **Change Save Location**: Adjust `capture_file_path` to store captures in a different directory.
- TODO: **Packet Analyzer**.

---

## ❓ Troubleshooting

- **Permission Denied**: Run the script with `sudo` (`sudo ./capture_script.sh`).
- **tcpdump Not Found**: Install using `sudo apt install tcpdump` or `brew install tcpdump` (Mac).
- **No Network Interfaces Found**: Ensure your system has active network interfaces (`ip a` or `ifconfig`).

---

## 📜 License

This project is licensed under the MIT License.

---

## 📬 Contact

For issues or improvements, open an issue in this repository.


