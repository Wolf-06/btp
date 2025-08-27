import paho.mqtt.client as mqtt
import time
import threading
import json
import os
import logging
import hashlib
from Crypto.Cipher import AES

# --- Configuration (from environment variables) ---
MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "localhost")
MQTT_PORT = int(os.environ.get("MQTT_PORT", 1883))
DEVICE_PSK_STR = os.environ.get("DEVICE_PSK", "default_32_byte_key_for_testing!")

# Ensure a stable 32-byte key for AES-256 (avoid slicing that can produce invalid lengths)
def derive_32byte_key(psk_str: str) -> bytes:
    return hashlib.sha256(psk_str.encode("utf-8")).digest()

DEVICE_PSK = derive_32byte_key(DEVICE_PSK_STR)  # 32 bytes for AES-256

# --- Device Profiles for Heterogeneous Simulation ---
DEVICE_PROFILES = {
    "ECG": {"interval_sec": 2, "payload_size_bytes": 128},
    "BloodPressure": {"interval_sec": 300, "payload_size_bytes": 256},
    "InfusionPump": {"interval_sec": 60, "payload_size_bytes": 64}
}

# --- Graceful Shutdown Event ---
shutdown_event = threading.Event()

# --- Logging setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("iot-sim")

def encrypt_message(key: bytes, plaintext: str) -> bytes:
    """Encrypts a message using AES-GCM and returns: nonce | header | tag | ciphertext"""
    # Ensure key is 16/24/32 bytes; here we use 32 bytes already
    header = b"data"
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return cipher.nonce + header + tag + ciphertext

def device_thread(device_id: int, profile: dict, initial_userdata: dict):
    """Simulates a single IoT device with a specific profile."""
    # copy profile to avoid mutating shared dicts across threads
    profile_local = profile.copy()
    device_type = profile_local["type"]
    client_id = f"iot-device-{device_type}-{device_id}"
    topic = f"iot/telemetry/{client_id}"

    # prepare per-client userdata; keep message counter local and pass as MQTT userdata as well
    userdata = {"message_counter": initial_userdata.get("message_counter", 0)}

    def on_connect(client, userdata_cb, flags, rc, properties=None):
        if rc == 0:
            log.info(f"[{client_id}] Connected to broker.")
        else:
            log.error(f"[{client_id}] Connect failed with rc={rc}")

    # Use MQTT v5 explicitly (modern paho)
    try:
        client = mqtt.Client(client_id=client_id, userdata=userdata, protocol=mqtt.MQTTv5)
    except Exception:
        client = mqtt.Client(client_id=client_id, userdata=userdata)

    client.on_connect = on_connect

    try:
        log.info(f"[{client_id}] Connecting to {MQTT_BROKER_HOST}:{MQTT_PORT} ...")
        client.connect(MQTT_BROKER_HOST, MQTT_PORT, 60)
    except Exception as e:
        log.error(f"[{client_id}] Connection failed: {e}")
        return

    client.loop_start()

    try:
        while not shutdown_event.is_set():
            dummy_data = "x" * profile_local["payload_size_bytes"]
            payload_json = json.dumps({
                "deviceId": client_id,
                "deviceType": device_type,
                "messageId": userdata["message_counter"],
                "data": dummy_data,
                "timestamp": time.time()
            })

            try:
                encrypted_payload = encrypt_message(DEVICE_PSK, payload_json)
            except Exception as e:
                log.exception(f"[{client_id}] Encryption failed: {e}")
                break

            # publish as bytes; use QoS=0 by default (change if you need delivery guarantees)
            try:
                result = client.publish(topic, encrypted_payload, qos=0)
                # Optionally wait for publish acknowledgement for QoS>0
                # result.wait_for_publish()
                if result.rc != mqtt.MQTT_ERR_SUCCESS:
                    log.warning(f"[{client_id}] Publish returned rc={result.rc}")
            except Exception as e:
                log.exception(f"[{client_id}] Publish failed: {e}")
                break

            userdata["message_counter"] += 1

            # Wait for the next interval or shutdown
            shutdown_event.wait(profile_local["interval_sec"])
    finally:
        log.info(f"[{client_id}] Shutdown signal received. Disconnecting.")
        try:
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            log.debug(f"[{client_id}] Error during disconnect: {e}")

# --- Main ---
if __name__ == "__main__":
    # Define the mix of devices you want to simulate
    device_mix = [
        {"type": "ECG", "count": 5},
        {"type": "BloodPressure", "count": 2},
        {"type": "InfusionPump", "count": 3}
    ]

    threads = []
    log.info("--- Starting Heterogeneous IoT Device Simulations (Press Ctrl+C to stop) ---")

    try:
        for device_spec in device_mix:
            device_type = device_spec["type"]
            base_profile = DEVICE_PROFILES.get(device_type)
            if not base_profile:
                log.warning(f"Unknown profile for device type '{device_type}', skipping.")
                continue

            for i in range(device_spec["count"]):
                # Prepare a thread-local copy of profile and add type to it
                profile_copy = dict(base_profile)
                profile_copy["type"] = device_type

                userdata = {"message_counter": 0}
                # Use i as device_id for each device type, so IDs are unique per type
                thread = threading.Thread(target=device_thread, args=(i, profile_copy, userdata))
                thread.daemon = True
                threads.append(thread)
                thread.start()
                time.sleep(0.2)  # Stagger startups

        # Main thread waits until Ctrl+C
        while not shutdown_event.is_set():
            time.sleep(1)

    except KeyboardInterrupt:
        log.info("KeyboardInterrupt received. Shutting down all devices...")
        shutdown_event.set()

    # Wait for threads to finish
    for thread in threads:
        thread.join()

    log.info("--- All devices have shut down. ---")
