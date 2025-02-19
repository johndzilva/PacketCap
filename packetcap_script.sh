#!/bin/bash

# Trap SIGINT (Control+C)
trap ctrl_c SIGINT

ctrl_c() {
    if [ ! -z "$TCPDUMP_PID" ]; then
        echo -e "\n${YELLOW}Control+C detected. Stopping capture and returning to menu...${NC}"
        stop_capture
        # Return to the main loop (do not exit the script)
        return 0
    else
        echo -e "\n${YELLOW}Control+C detected. Exiting...${NC}"
        exit 0
    fi
}

# Default settings
INTERFACE="eth0"    # Default interface
DEFAULT_FILTER="port 53 or port 5353 or port 443"
ADDITIONAL_FILTER=""
SRC_IP=""
DST_IP=""
CAPTURE_FILE="capture.pcap"
TCPDUMP_PID=""
PROJECT_NAME=""
PROJECT_LIST=()

# Color codes for a beautiful UI
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[1;35m'
NC='\033[0m'  # No Color

# Function to create a new project (folder) inside the script's directory
create_project() {
    echo -e "${CYAN}Enter a name for the new project:${NC}"
    read -p "Project Name: " project_name

    # Define the directory path where the project will be created (inside the script's folder)
    PROJECT_DIR="$(pwd)/$project_name"

    # Check if the directory already exists
    if [ -d "$PROJECT_DIR" ]; then
        echo -e "${RED}Project '$project_name' already exists. Please choose a different name.${NC}"
    else
        # Create the directory
        mkdir "$PROJECT_DIR"
        echo -e "${GREEN}Project '$project_name' created at $PROJECT_DIR${NC}"

        # Set the capture file to be inside the newly created project directory
        UTC_TIMESTAMP=$(date -u +%Y%m%d%H%M%S)  # UTC timestamp for unique file name
        CAPTURE_FILE="$PROJECT_DIR/capture_$UTC_TIMESTAMP.pcap"
        echo -e "${GREEN}Capture file will be saved as: $CAPTURE_FILE${NC}"
    fi
    sleep 1
}



# Function to list existing projects (folders) inside the script's directory
select_project() {
    echo -e "${CYAN}Existing Projects in Script Directory:${NC}"
    # List directories (projects) inside the current directory (script directory)
    PROJECTS=()
    index=1
    for dir in $(pwd)/*/; do
        # Only consider directories (projects)
        if [ -d "$dir" ]; then
            project_name=$(basename "$dir")
            echo -e "${MAGENTA}$index. $project_name${NC}"
            PROJECTS+=("$dir")
            index=$((index + 1))
        fi
    done

    # If no projects are found
    if [ ${#PROJECTS[@]} -eq 0 ]; then
        echo -e "${RED}No existing projects found in the script directory. Please create a new one.${NC}"
        return
    fi

    # Prompt the user to select a project
    read -p "Select a project by index: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#PROJECTS[@]}" ]; then
        # Set the selected project directory and capture file path
        SELECTED_PROJECT="${PROJECTS[$((choice - 1))]}"
        UTC_TIMESTAMP=$(date -u +%Y%m%d%H%M%S)  # UTC timestamp for unique file name
        CAPTURE_FILE="$SELECTED_PROJECT/capture_$UTC_TIMESTAMP.pcap"
        echo -e "${GREEN}Selected project: $(basename "$SELECTED_PROJECT")${NC}"
        echo -e "${GREEN}Capture file will be saved as: $CAPTURE_FILE${NC}"
    else
        echo -e "${RED}Invalid choice. Please select a valid index.${NC}"
    fi
    sleep 1
}



# Function to display the main menu
show_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}          🚀 TCPDUMP CAPTURE MENU          ${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${YELLOW} Interface: ${GREEN}$INTERFACE${NC}"
    echo -e "${YELLOW} Source IP: ${GREEN}${SRC_IP:-Any}${NC}"
    echo -e "${YELLOW} Destination IP: ${GREEN}${DST_IP:-Any}${NC}"
    echo -e "${YELLOW} Additional Protocols: ${GREEN}${ADDITIONAL_FILTER:-None}${NC}"
    echo -e "${YELLOW} Capture File: ${GREEN}$CAPTURE_FILE${NC}"
    echo -e "${YELLOW} Project: ${GREEN}${PROJECT_NAME:-None}${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${BLUE} 1. Select Interface${NC}"
    echo -e "${BLUE} 2. Set Source IP${NC}"
    echo -e "${BLUE} 3. Set Destination IP${NC}"
    echo -e "${BLUE} 4. Add Protocol${NC}"
    echo -e "${BLUE} 5. Remove Protocol${NC}"
    echo -e "${BLUE} 6. Start Capture${NC}"
    echo -e "${BLUE} 7. Create Project${NC}"
    echo -e "${BLUE} 8. Select Project${NC}"
    echo -e "${BLUE} 9. Exit${NC}"
    echo -e "${CYAN}========================================${NC}"
}

# Function to list and select network interfaces with IP and MAC addresses
select_interface() {
    echo -e "${CYAN}Available Network Interfaces:${NC}"
    interfaces=()
    index=1
    echo -e "${MAGENTA}Index | Interface        | IP Address        | MAC Address${NC}"
    echo -e "${MAGENTA}------------------------------------------------------------${NC}"
    # Loop through each interface name (remove trailing colon)
    for iface in $(ifconfig | awk '/^[a-zA-Z0-9]/ {print $1}' | sed 's/://'); do
         # Get IP address (if any)
         ip=$(ifconfig "$iface" | grep -E "inet " | awk '{print $2}' | head -n 1)
         if [ -z "$ip" ]; then
            ip="None"
         fi
         # Get MAC address (if any)
         mac=$(ifconfig "$iface" | grep -E "ether " | awk '{print $2}' | head -n 1)
         if [ -z "$mac" ]; then
            mac="None"
         fi
         printf "${YELLOW} %-5s ${GREEN}| %-15s ${BLUE}| %-17s ${CYAN}| %-17s${NC}\n" "$index" "$iface" "$ip" "$mac"
         interfaces+=("$iface")
         index=$((index + 1))
    done
    echo -e "${MAGENTA}------------------------------------------------------------${NC}"
    read -p "Select an interface by index: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#interfaces[@]}" ]; then
         INTERFACE="${interfaces[$((choice - 1))]}"
         echo -e "${GREEN}Selected interface: $INTERFACE${NC}"
    else
         echo -e "${RED}Invalid choice. Please select a valid index.${NC}"
    fi
    sleep 1
}

# Function to list connected IPs on the network using nmap
list_connected_ips() {
    echo -e "${CYAN}Scanning for connected devices in your network...${NC}"
    local connected_ips
    # Try using nmap to find local network IPs
    connected_ips=$(sudo nmap -sn 192.168.0.0/24 | grep 'Nmap scan report for' | awk '{print $5}')
    echo -e "${MAGENTA}Connected IP Addresses:${NC}"
    echo -e "${MAGENTA}--------------------------${NC}"
    if [ -z "$connected_ips" ]; then
        echo -e "${RED}No IPs found in the local network. Make sure you are connected to the network.${NC}"
        return
    fi
    local index=1
    for ip in $connected_ips; do
        echo -e "${YELLOW}$index. $ip${NC}"
        connected_ips_array+=("$ip")
        index=$((index + 1))
    done
    echo -e "${MAGENTA}--------------------------${NC}"
}

# Function to set source IP filter
set_src_ip() {
    list_connected_ips
    echo -e "${CYAN}Would you like to select an IP from the list above or manually enter one?${NC}"
    echo -e "${GREEN}1. Select from list${NC}"
    echo -e "${GREEN}2. Manually enter IP${NC}"
    read -p "Enter your choice: " choice
    case $choice in
        1) 
            read -p "Select IP index: " ip_choice
            if [[ "$ip_choice" =~ ^[0-9]+$ ]] && [ "$ip_choice" -ge 1 ] && [ "$ip_choice" -le "${#connected_ips_array[@]}" ]; then
                SRC_IP="${connected_ips_array[$((ip_choice - 1))]}"
                echo -e "${GREEN}Source IP set to $SRC_IP${NC}"
            else
                echo -e "${RED}Invalid IP index.${NC}"
            fi
            ;;
        2) 
            read -p "Enter Source IP: " SRC_IP
            echo -e "${GREEN}Source IP set to $SRC_IP${NC}"
            ;;
        *)
            echo -e "${RED}Invalid choice. Please select either 1 or 2.${NC}"
            ;;
    esac
    sleep 1
}

# Function to set destination IP filter
set_dst_ip() {
    list_connected_ips
    echo -e "${CYAN}Would you like to select an IP from the list above or manually enter one?${NC}"
    echo -e "${GREEN}1. Select from list${NC}"
    echo -e "${GREEN}2. Manually enter IP${NC}"
    read -p "Enter your choice: " choice
    case $choice in
        1) 
            read -p "Select IP index: " ip_choice
            if [[ "$ip_choice" =~ ^[0-9]+$ ]] && [ "$ip_choice" -ge 1 ] && [ "$ip_choice" -le "${#connected_ips_array[@]}" ]; then
                DST_IP="${connected_ips_array[$((ip_choice - 1))]}"
                echo -e "${GREEN}Destination IP set to $DST_IP${NC}"
            else
                echo -e "${RED}Invalid IP index.${NC}"
            fi
            ;;
        2) 
            read -p "Enter Destination IP: " DST_IP
            echo -e "${GREEN}Destination IP set to $DST_IP${NC}"
            ;;
        *)
            echo -e "${RED}Invalid choice. Please select either 1 or 2.${NC}"
            ;;
    esac
    sleep 1
}

# Function to add an additional protocol (port)
add_protocol() {
    echo -e "${CYAN}Select protocols to add (use space to toggle):${NC}"
    protocols=("HTTP (80)" "HTTPS (443)" "DNS (53)" "mDNS (5353)" "FTP (21)" "SSH (22)" "SMTP (25)" "POP3 (110)" "IMAP (143)" "Telnet (23)")
    choices=()
    index=1
    for protocol in "${protocols[@]}"; do
        echo -e "[ ] $index. $protocol"
        choices+=("0")  # All choices are initially unchecked
        index=$((index + 1))
    done
    echo -e "[ ] $index. Manually enter port"
    
    read -p "Select protocol numbers to add (separate with spaces): " selected_protocols

    # Process selected protocols
    for num in $selected_protocols; do
        if [ "$num" -ge 1 ] && [ "$num" -le "${#protocols[@]}" ]; then
            case $num in
                1) ADDITIONAL_FILTER="$ADDITIONAL_FILTER or port 80" ;;
                2) ADDITIONAL_FILTER="$ADDITIONAL_FILTER or port 443" ;;
                3) ADDITIONAL_FILTER="$ADDITIONAL_FILTER or port 53" ;;
                4) ADDITIONAL_FILTER="$ADDITIONAL_FILTER or port 5353" ;;
                5) ADDITIONAL_FILTER="$ADDITIONAL_FILTER or port 21" ;;
                6) ADDITIONAL_FILTER="$ADDITIONAL_FILTER or port 22" ;;
                7) ADDITIONAL_FILTER="$ADDITIONAL_FILTER or port 25" ;;
                8) ADDITIONAL_FILTER="$ADDITIONAL_FILTER or port 110" ;;
                9) ADDITIONAL_FILTER="$ADDITIONAL_FILTER or port 143" ;;
                10) ADDITIONAL_FILTER="$ADDITIONAL_FILTER or port 23" ;;
            esac
        fi
    done

    # Manually add port
    read -p "Enter a custom port (or press Enter to skip): " custom_port
    if [ ! -z "$custom_port" ]; then
        ADDITIONAL_FILTER="$ADDITIONAL_FILTER or port $custom_port"
    fi

    echo -e "${GREEN}Protocols added: $ADDITIONAL_FILTER${NC}"
    sleep 1
}

# Function to remove an additional protocol (port)
remove_protocol() {
    read -p "Enter protocol port to remove: " PORT
    ADDITIONAL_FILTER=$(echo $ADDITIONAL_FILTER | sed "s/or port $PORT//g")
    echo -e "${GREEN}Removed protocol on port $PORT${NC}"
    sleep 1
}

# Function to build the tcpdump filter string
build_filter() {
    FILTER="$DEFAULT_FILTER $ADDITIONAL_FILTER"
    if [ ! -z "$SRC_IP" ]; then
        FILTER="$FILTER and src $SRC_IP"
    fi
    if [ ! -z "$DST_IP" ]; then
        FILTER="$FILTER and dst $DST_IP"
    fi
}

# Function to display live packets (only stoppable by Control+C)
live_capture() {
    while kill -0 $TCPDUMP_PID 2>/dev/null; do
         clear
         echo -e "${CYAN}Live Packet Capture on $INTERFACE${NC}"
         echo -e "${YELLOW}Press Control+C to stop capture and return to menu.${NC}"
         # Display 10 packets at a time using the current filter
         sudo tcpdump -i $INTERFACE "$FILTER" -c 10 -nn 2>/dev/null
         sleep 1
    done
}

# Function to start capturing packets
start_capture() {
    build_filter
    echo -e "${CYAN}Starting tcpdump on $INTERFACE with filter: $FILTER${NC}"
    # Start tcpdump in the background writing to file (with verbose output)
    sudo tcpdump -i $INTERFACE "$FILTER" -w $CAPTURE_FILE -v &
    TCPDUMP_PID=$!
    echo -e "${GREEN}Capture started. PID: $TCPDUMP_PID${NC}"
    sleep 1
    # Enter live capture mode (only stoppable via Control+C)
    live_capture
}

# Function to stop capturing packets
stop_capture() {
    if [ ! -z "$TCPDUMP_PID" ]; then
        echo -e "${YELLOW}Stopping capture...${NC}"
        sudo kill -2 $TCPDUMP_PID
        sleep 1
        if ps -p $TCPDUMP_PID > /dev/null; then
            echo -e "${RED}Force stopping capture...${NC}"
            sudo kill -9 $TCPDUMP_PID
        fi
        sudo pkill -f "tcpdump -i $INTERFACE"
        TCPDUMP_PID=""
        echo -e "${GREEN}Capture stopped. Packets saved to $CAPTURE_FILE${NC}"
        sleep 2
        clear
    else
        echo -e "${RED}No capture is currently running.${NC}"
        sleep 2
    fi
}

# Main loop
while true; do
    # Only show the menu when no capture is running
    if [ -z "$TCPDUMP_PID" ]; then
         show_menu
         read -p "Choose an option: " CHOICE
         case $CHOICE in
              1) select_interface ;;
              2) set_src_ip ;;
              3) set_dst_ip ;;
              4) add_protocol ;;
              5) remove_protocol ;;
              6) start_capture ;;
              7) create_project ;;
              8) select_project ;;
              9) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
              *) echo -e "${RED}Invalid option. Please choose again.${NC}"; sleep 1 ;;
         esac
    else
         # When capture is running, live_capture is active.
         # (The only way to stop capture is by pressing Control+C.)
         sleep 1
    fi
done
