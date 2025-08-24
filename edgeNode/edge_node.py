import paho.mqtt.client as mqtt
import os
import json
import time
import oqs
import base64
from Crypto.Cipher import AES

# --- Library Sanity Check ---
# Ensures the correct 'liboqs-python' is being used.
if not hasattr(oqs, 'KeyEncapsulation') or not hasattr(oqs, 'Signature'):
    print("--- FATAL ERROR: Incorrect 'oqs' Library Detected ---")
    print("Please follow the official guide to build and install 'liboqs' and 'liboqs-python' from source.")
    print("   (Official Repository: https://github.com/open-quantum-safe/liboqs-python)")
    print("-" * 55)
    exit(1)

# --- Configuration ---
MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "localhost")
EDGE_ID = os.environ.get("EDGE_ID", "edge-node-default")
DEVICE_PSK_STR = os.environ.get("DEVICE_PSK", "default_32_byte_key_for_testing!")
DEVICE_PSK = DEVICE_PSK_STR.encode()[:32] # Ensure key is 32 bytes

# --- PQC Algorithm Selection ---
# IMPROVEMENT: Centralized algorithm names to prevent mismatches.
KEM_ALG = "ML-KEM-512"
SIG_ALG = "ML-DSA-44"

# --- Crypto Functions ---
def decrypt_device_message(key: bytes, encrypted_payload: bytes) -> str:
    """Decrypts an AES-GCM message from a device."""
    try:
        # Extract components: nonce (16 bytes), header (4), tag (16)
        nonce = encrypted_payload[:16]
        header = encrypted_payload[16:20]
        tag = encrypted_payload[20:36]
        ciphertext = encrypted_payload[36:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError) as e:
        # IMPROVEMENT: Consistent logging.
        print(f"[Edge Node - {EDGE_ID}]: Decryption failed! Error: {e}")
        return None

def encrypt_server_message(key: bytes, plaintext: str) -> bytes:
    """Encrypts a message for the server using the established session key."""
    header = b'data'
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return cipher.nonce + header + tag + ciphertext

# --- MQTT Callbacks ---
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"[Edge Node - {EDGE_ID}]: Connected to MQTT Broker.")
        client.subscribe("iot/telemetry/#")
        client.subscribe(f"edge/handshake/response/{EDGE_ID}")
        print(f"[Edge Node - {EDGE_ID}]: Subscribed to device and handshake topics.")
        
        # --- Initiate PQC Handshake ---
        try:
            kem = oqs.KeyEncapsulation(KEM_ALG)
            sig = oqs.Signature(SIG_ALG)
        except oqs.Error as e:
            print(f"[Edge Node - {EDGE_ID}]: CRITICAL ERROR: PQC algorithm not supported: {e}")
            client.disconnect()
            return

        # Generate KEM keys. We need to store the secret key for use in on_message.
        userdata["kem_public_key"] = kem.generate_keypair()
        userdata["kem_secret_key"] = kem.export_secret_key()
        
        # Generate Signature keys. The secret key is stored inside the `sig` object.
        userdata["sig_public_key"] = sig.generate_keypair()

        handshake_payload = {
            "edgeId": EDGE_ID,
            "kem_pub_key_b64": base64.b64encode(userdata["kem_public_key"]).decode('utf-8'),
            "sig_pub_key_b64": base64.b64encode(userdata["sig_public_key"]).decode('utf-8')
        }
        
        # Sign the KEM public key. The sign() method uses the secret key stored internally.
        signature = sig.sign(userdata["kem_public_key"])
        handshake_payload["signature_b64"] = base64.b64encode(signature).decode('utf-8')

        # Clean up the C objects.
        sig.free()
        kem.free()

        client.publish(f"edge/handshake/initiate/{EDGE_ID}", json.dumps(handshake_payload))
        print(f"[Edge Node - {EDGE_ID}]: PQC Handshake initiated using {KEM_ALG} and {SIG_ALG}.")
    else:
        print(f"[Edge Node - {EDGE_ID}]: Failed to connect, return code {rc}")

def on_message(client, userdata, msg):
    topic = msg.topic
    
    if topic.startswith("iot/telemetry/"):
        decrypted_payload = decrypt_device_message(DEVICE_PSK, msg.payload)
        if decrypted_payload:
            print(f"[Edge Node - {EDGE_ID}]: Decrypted data from device: {decrypted_payload}")
            # IMPROVEMENT: Check state from the userdata dictionary.
            if userdata.get("handshake_complete", False):
                server_payload = encrypt_server_message(userdata["session_key"], decrypted_payload)
                client.publish(f"edge/data/{EDGE_ID}", server_payload)
            else:
                print(f"[Edge Node - {EDGE_ID}]: Handshake not complete. Buffering/dropping data.")

    elif topic.startswith("edge/handshake/response/"):
        print(f"[Edge Node - {EDGE_ID}]: Received PQC handshake response.")
        
        # IMPROVEMENT: Added robust error handling for the entire response block.
        try:
            response = json.loads(msg.payload.decode('utf-8'))
            
            # Decode the data from the server
            ciphertext = base64.b64decode(response['ciphertext_b64'])
            server_signature = base64.b64decode(response['signature_b64'])
            server_sig_pub_key = base64.b64decode(response['server_sig_pub_key_b64'])
            
            # 1. Verify the server's signature on the ciphertext
            verifier = oqs.Signature(SIG_ALG)
            is_valid = verifier.verify(ciphertext, server_signature, server_sig_pub_key)
            verifier.free()
            
            if not is_valid:
                print(f"[Edge Node - {EDGE_ID}]: SERVER SIGNATURE INVALID! Aborting handshake.")
                return
                
            print(f"[Edge Node - {EDGE_ID}]: Server signature verified successfully.")
            
            # 2. Decapsulate the ciphertext to get the shared secret
            kem = oqs.KeyEncapsulation(KEM_ALG)
            shared_secret = kem.decap_secret(ciphertext, userdata["kem_secret_key"])
            kem.free()

            # IMPROVEMENT: Store session state in the userdata dictionary.
            userdata["session_key"] = shared_secret[:32] # Use first 32 bytes for AES-256
            userdata["handshake_complete"] = True
            
            print(f"[Edge Node - {EDGE_ID}]: Handshake complete! Session key established with server.")

        except (json.JSONDecodeError, KeyError, base64.binascii.Error) as e:
            print(f"[Edge Node - {EDGE_ID}]: Failed to process handshake response. Invalid format: {e}")


# --- Main ---
def initialize_client_state():
    """Initializes the state dictionary that will be passed as userdata."""
    return {
        "kem_public_key": None,
        "kem_secret_key": None,
        "sig_public_key": None,
        "session_key": None,
        "handshake_complete": False,
    }

if __name__ == "__main__":
    print(f"--- Starting Edge Node (ID: {EDGE_ID}) ---")
    
    client_userdata = initialize_client_state()
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=EDGE_ID, userdata=client_userdata)
    
    client.on_connect = on_connect
    client.on_message = on_message
    
    # Connection retry loop
    connected = False
    while not connected:
        try:
            client.connect(MQTT_BROKER_HOST, 1883, 60)
            connected = True
        except Exception as e:
            print(f"[Edge Node - {EDGE_ID}]: Connection failed. Retrying in 5 seconds... Error: {e}")
            time.sleep(5)
    
    client.loop_forever()
