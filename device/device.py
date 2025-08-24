import paho.mqtt.client as mqtt
import time
import psutil
import threading
import json
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Configuration (from environment variables) ---
MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "localhost")
MQTT_PORT = 1883
NUM_DEVICES = int(os.environ.get("NUM_DEVICES", 5)) 
# IMPROVEMENT: Load PSK from environment variable for better security.
DEVICE_PSK_STR = os.environ.get("DEVICE_PSK", "default_32_byte_key_for_testing!")
# CRITICAL FIX: The key MUST be exactly 32 bytes for AES-256. Slice it to ensure correctness.
DEVICE_PSK = DEVICE_PSK_STR.encode()[:32] 

# --- Graceful Shutdown Event ---
# IMPROVEMENT: Add an event to signal threads to stop gracefully.
shutdown_event = threading.Event()

def encrypt_message(key: bytes, plaintext: str) -> bytes:
    """Encrypts a message using AES-GCM."""
    header = b'data'
    # The nonce is generated randomly by PyCryptodome for each message.
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    # We send nonce, header, tag, and ciphertext together.
    return cipher.nonce + header + tag + ciphertext

def device_thread(device_id: int):
    """Simulates a single IoT device with robust connection and reconnection logic."""
    client_id = f"iot-device-{device_id}"
    topic = f"iot/telemetry/{client_id}"

    def on_connect(client, userdata, flags, rc, properties=None):
        if rc == 0:
            print(f"[Device {device_id}]: Connected successfully.")
        else:
            print(f"[Device {device_id}]: Failed to connect, return code {rc}")

    # IMPROVEMENT: Add a disconnect callback to handle network interruptions.
    def on_disconnect(client, userdata, rc, properties=None):
        print(f"[Device {device_id}]: Disconnected with result code {rc}. Will attempt to reconnect...")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect

    # IMPROVEMENT: Main connection and publishing loop with reconnection logic.
    while not shutdown_event.is_set():
        try:
            if not client.is_connected():
                print(f"[Device {device_id}]: Attempting to connect to broker at {MQTT_BROKER_HOST}...")
                client.connect(MQTT_BROKER_HOST, MQTT_PORT, 60)
                client.loop_start() # Start the network loop in a background thread.
            
            # Wait a moment to ensure the connection is established before publishing.
            time.sleep(1) 

            if client.is_connected():
                cpu_usage = psutil.cpu_percent()
                payload_json = json.dumps({
                    "deviceId": client_id,
                    "messageId": userdata['message_counter'],
                    "cpuUsage": cpu_usage
                })
                
                encrypted_payload = encrypt_message(DEVICE_PSK, payload_json)
                client.publish(topic, encrypted_payload)
                userdata['message_counter'] += 1
            
            # Wait for the next interval, but check shutdown event periodically.
            shutdown_event.wait(5)

        except Exception as e:
            print(f"[Device {device_id}]: An error occurred: {e}. Retrying in 5 seconds...")
            client.loop_stop() # Stop the loop to clean up before retrying.
            time.sleep(5)

    # Cleanup on shutdown
    print(f"[Device {device_id}]: Shutdown signal received. Disconnecting.")
    client.loop_stop()
    client.disconnect()

# --- Main ---
if __name__ == "__main__":
    threads = []
    print(f"--- Starting {NUM_DEVICES} IoT Device Simulations (Press Ctrl+C to stop) ---")
    
    try:
        for i in range(NUM_DEVICES):
            # Pass a simple dictionary as userdata to maintain the message counter per device.
            userdata = {'message_counter': 0}
            thread = threading.Thread(target=device_thread, args=(i,), name=f"Device-{i}")
            # Attach userdata to the client before starting the thread
            thread.daemon = True # Allows main thread to exit even if children are blocking
            threads.append(thread)
            thread.start()
            time.sleep(0.5) # Stagger device startups slightly

        # Keep the main thread alive, waiting for the shutdown event
        while not shutdown_event.is_set():
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n--- KeyboardInterrupt received. Shutting down all devices... ---")
        shutdown_event.set()

    for thread in threads:
        thread.join() # Wait for all threads to finish cleanly.

    print("--- All devices have shut down. ---")
