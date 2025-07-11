#!/bin/bash

# --- Configuration ---
# Path to your Xray or V2Ray executable
XRAY_PATH="./xray"
# Path to the Python helper script
HELPER_SCRIPT_PATH="./config_converter.py" 
# The local port for the proxy
LOCAL_PORT=10808 
# Connection timeout for each attempt (in seconds)
CONNECT_TIMEOUT=5
# Maximum number of connection retries
MAX_RETRIES=3
# Temporary file for the generated config
TEMP_CONFIG_FILE="/tmp/proxy_config.json"
# File to store the PID of the Xray process
PID_FILE="/tmp/xray_proxy.pid"
# URL for the delay test
TEST_URL="http://www.google.com/gen_204"

# --- Functions ---

# Function to disconnect the proxy
disconnect() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        echo "🔌 Disconnecting from proxy..."
        kill "$PID" 2>/dev/null
        rm -f "$PID_FILE"
        echo "✅ Proxy process terminated."
        # The temp config file is cleaned up on a full stop or final failure
    else
        echo "ℹ️ No active proxy connection found."
    fi
}

# Function to connect to the proxy
connect() {
    local V2RAY_LINK="$1"

    # If already connected, disconnect first
    if [ -f "$PID_FILE" ]; then
        echo "⚠️ An existing connection is active. Disconnecting it first."
        # Clean up the old config file to avoid confusion with a 'stop' command
        rm -f "$TEMP_CONFIG_FILE"
        disconnect
        sleep 1
    fi

    echo "🔄 Generating Xray config from link..."
    python3 "$HELPER_SCRIPT_PATH" test-config "$V2RAY_LINK" "$LOCAL_PORT" > "$TEMP_CONFIG_FILE"

    if [ ! -s "$TEMP_CONFIG_FILE" ]; then
        echo "❌ Error: Failed to generate config. Check your link or converter script."
        exit 1
    fi
    
    # --- MODIFIED: Change inbound to HTTP proxy and force IPv4 ---
    # This creates a standard HTTP proxy that is widely supported.
    jq '(.inbounds[] | select(.protocol=="socks") | .protocol) = "http" | . + {"dns": {"servers": ["8.8.8.8", "1.1.1.1"]}, "routing": {"domainStrategy": "UseIPv4"}}' "$TEMP_CONFIG_FILE" > "${TEMP_CONFIG_FILE}.tmp" && mv "${TEMP_CONFIG_FILE}.tmp" "$TEMP_CONFIG_FILE"
    
    echo "✅ Config generated for HTTP proxy and routing set to IPv4."

    local connected=false
    for ((i=1; i<=MAX_RETRIES; i++)); do
        echo "🔄 Attempting to connect (Attempt $i of $MAX_RETRIES)..."
        
        # Run Xray in the background
        nohup "$XRAY_PATH" run --config "$TEMP_CONFIG_FILE" > /dev/null 2>&1 &
        XRAY_PID=$!
        echo "$XRAY_PID" > "$PID_FILE"
        
        echo "🚀 Xray process started with PID: $XRAY_PID. Waiting for connection..."
        sleep 2 # Wait a bit for the process to start completely

        # Test the connection and show the delay
        echo "🔍 Testing connection with a ${CONNECT_TIMEOUT}-second timeout..."
        DELAY=$(curl -4 -s -w "%{time_total}" --proxy "http://127.0.0.1:$LOCAL_PORT" --connect-timeout "$CONNECT_TIMEOUT" "$TEST_URL" -o /dev/null)
        
        if [ -n "$DELAY" ] && [ "$(echo "$DELAY > 0.001" | bc -l)" -eq 1 ]; then
            DELAY_MS=$(echo "$DELAY * 1000" | bc | cut -d. -f1)
            echo -e "✅ Connection successful! Latency: \033[0;33m${DELAY_MS}ms\033[0m"
            connected=true
            break # Exit loop on success
        else
            echo "❌ Attempt $i failed. Cleaning up..."
            disconnect # Kill the failed process
            if [ "$i" -lt "$MAX_RETRIES" ]; then
                echo "🔁 Retrying in 2 seconds..."
                sleep 2
            fi
        fi
    done

    if [ "$connected" = false ]; then
        echo "❌ Connection failed after $MAX_RETRIES attempts. Aborting."
        rm -f "$TEMP_CONFIG_FILE" "$PID_FILE" # Final cleanup of temp files
        exit 1
    fi

    # --- MODIFIED: Use standard http:// proxy URLs ---
    echo -e "\nRun this command in your terminal to route traffic through the proxy:"
    PROXY_CMD="export http_proxy=http://127.0.0.1:$LOCAL_PORT https_proxy=http://127.0.0.1:$LOCAL_PORT"
    PROXY_CMD_UPPER="export HTTP_PROXY=\$http_proxy HTTPS_PROXY=\$https_proxy ALL_PROXY=\$http_proxy"
    echo -e "\n\033[0;32m$PROXY_CMD\n$PROXY_CMD_UPPER\033[0m\n"
    echo "To stop the proxy, run: ./proxy_terminal.sh stop"
}


# --- Main Logic ---

# Check if required commands exist
if ! command -v jq &> /dev/null; then
    echo "❌ Error: 'jq' is not installed. Please install it using 'sudo apt update && sudo apt install jq'."
    exit 1
fi
if [ ! -f "$XRAY_PATH" ]; then
    echo "❌ Error: Xray executable not found at '$XRAY_PATH'. Please update the path in the script."
    exit 1
fi
if [ ! -f "$HELPER_SCRIPT_PATH" ]; then
    echo "❌ Error: Python helper script not found at '$HELPER_SCRIPT_PATH'."
    exit 1
fi

case "$1" in
    stop)
        disconnect
        # Also remove the temp config file on stop
        rm -f "$TEMP_CONFIG_FILE"
        echo "Run this command in your terminal to unset proxy:"
        echo -e "\n\033[0;32munset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY\033[0m\n"
        ;;
    "")
        echo "❌ Error: No V2Ray link provided."
        echo "Usage: ./proxy_terminal.sh \"<v2ray_link>\""
        echo "       ./proxy_terminal.sh stop"
        ;;
    *)
        connect "$1"
        ;;
esac