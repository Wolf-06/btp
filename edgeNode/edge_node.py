import os
import paho.mqtt.client as mqtt
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
MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST")
EDGE_ID = os.environ.get("EDGE_ID")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=EDGE_ID)

def on_connect(client, userdata, flags, rc, properties=None):
    """Callback for when the client connects to the broker."""
    if rc == 0:
        print(f"[Edge Node - {EDGE_ID}]: Connected to MQTT Broker successfully.")
        client.subscribe("iot/telemetry/#")
        print(f"[Edge Node - {EDGE_ID}]: Subscribed to topic 'iot/telemetry/#'.")
    else:
        print(f"[Edge Node - {EDGE_ID}]: Failed to connect, return code {rc}\n")

def on_message(client, userdata, msg):
    """Callback for when a message is received from a subscribed topic."""
    try:
        payload_str = msg.payload.decode("utf-8")
        data = json.loads(payload_str)
        device_id = data.get("deviceId", "unknown_device")
        
        print(f"[Edge Node - {EDGE_ID}]: Received message from '{device_id}': {payload_str}")
        
        forward_payload = json.dumps({
            "edgeId": EDGE_ID,
            "originalDeviceId": device_id,
            "data": data 
        })
        
        server_topic = f"edge/data/{EDGE_ID}"
        client.publish(server_topic, forward_payload)
        
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"[Edge Node - {EDGE_ID}]: Error decoding message on topic '{msg.topic}': {e}")


# --- Main ---
if __name__ == "__main__":
    print(f"--- Starting Edge Node (ID: {EDGE_ID}) ---")
    
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=EDGE_ID)
    
    client.on_connect = on_connect
    client.on_message = on_message
    
    # --- Robust Connection Attempt ---
    connected = False
    retry_count = 0
    while not connected and retry_count < 5:
        try:
            print(f"[Edge Node - {EDGE_ID}]: Attempting to connect to broker at {MQTT_BROKER_HOST}...")
            client.connect(MQTT_BROKER_HOST, 1883, 60)
            connected = True
        except Exception as e:
            retry_count += 1
            print(f"[Edge Node - {EDGE_ID}]: Connection failed (Attempt {retry_count}). Retrying in 5 seconds... Error: {e}")
            time.sleep(5)

    if not connected:
        print(f"[Edge Node - {EDGE_ID}]: ERROR - Could not connect to MQTT Broker. Exiting.")
        exit(1)
    
    client.loop_forever()