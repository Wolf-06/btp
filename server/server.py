import paho.mqtt.client as mqtt
import os
import json
import time
import logging
import sys

log_level_str = os.environ.get("LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_str, logging.INFO)
logging.basicConfig(
    stream=sys.stdout,  # Log to standard output
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logging.info("Logging has been configured.")

# --- Configuration ---
MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "localhost")
SERVER_ID = "central-server-01"

# --- MQTT Callbacks ---
def on_connect(client, userdata, flags, rc, properties=None):
    """Callback for when the client connects to the broker."""
    if rc == 0:
        print(f"[{SERVER_ID}]: Connected to MQTT Broker successfully.")
        # Subscribe to all data topics from all edge nodes
        client.subscribe("edge/data/#")
        print(f"[{SERVER_ID}]: Subscribed to topic 'edge/data/#'.")
    else:
        print(f"[{SERVER_ID}]: Failed to connect, return code {rc}\n")

def on_message(client, userdata, msg):
    """Callback for when a message is received from an edge node."""
    try:
        payload_str = msg.payload.decode("utf-8")
        data = json.loads(payload_str)
        edge_id = data.get("edgeId", "unknown_edge_node")
        
        print(f"[{SERVER_ID}]: <<< FINAL DATA RECEIVED >>> from Edge Node '{edge_id}': {payload_str}")
        
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"[{SERVER_ID}]: Error decoding message on topic '{msg.topic}': {e}")

# --- Main ---
if __name__ == "__main__":
    print(f"--- Starting Central Server (ID: {SERVER_ID}) ---")
    
    # Use the latest callback API version
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=SERVER_ID)
    
    client.on_connect = on_connect
    client.on_message = on_message
    
    # --- Robust Connection Attempt ---
    connected = False
    retry_count = 0
    while not connected and retry_count < 5:
        try:
            print(f"[{SERVER_ID}]: Attempting to connect to broker at {MQTT_BROKER_HOST}...")
            client.connect(MQTT_BROKER_HOST, 1883, 60)
            connected = True  # Connection successful
        except Exception as e:
            retry_count += 1
            print(f"[{SERVER_ID}]: Connection failed (Attempt {retry_count}). Retrying in 5 seconds... Error: {e}")
            time.sleep(5)

    if not connected:
        print(f"[{SERVER_ID}]: ERROR - Could not connect to MQTT Broker after several attempts. Exiting.")
        exit(1)
        
    # loop_forever() is a blocking call that processes network traffic, dispatches
    # callbacks and handles reconnecting.
    client.loop_forever()