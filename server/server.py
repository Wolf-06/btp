import paho.mqtt.client as mqtt
import os
import json
import time
import oqs
import base64
from Crypto.Cipher import AES

# --- Configuration ---
MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "localhost")
SERVER_ID = "central-server-01"

# --- State ---
# This dictionary will store session keys for each connected edge node
edge_sessions = {}

# --- Crypto Functions ---
def decrypt_edge_message(key: bytes, encrypted_payload: bytes) -> str:
    """Decrypts an AES-GCM message from an edge node."""
    # Re-using the same AES logic as the edge node
    try:
        nonce = encrypted_payload[:16]
        header = encrypted_payload[16:20]
        tag = encrypted_payload[20:36]
        ciphertext = encrypted_payload[36:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError) as e:
        print(f"[{SERVER_ID}]: Decryption failed for edge message! Error: {e}")
        return None

# --- MQTT Callbacks ---
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"[{SERVER_ID}]: Connected to MQTT Broker.")
        client.subscribe("edge/handshake/initiate/#")
        print(f"[{SERVER_ID}]: Subscribed to handshake topic.")
    else:
        print(f"[{SERVER_ID}]: Failed to connect, return code {rc}")

def on_message(client, userdata, msg):
    topic = msg.topic
    
    if topic.startswith("edge/handshake/initiate/"):
        edge_id = topic.split('/')[-1]
        print(f"[{SERVER_ID}]: Received handshake initiation from '{edge_id}'.")
        
        payload = json.loads(msg.payload.decode('utf-8'))
        
        # Decode the keys and signature from the edge node
        edge_kem_pub_key = base64.b64decode(payload['kem_pub_key_b64'])
        edge_sig_pub_key = base64.b64decode(payload['sig_pub_key_b64'])
        edge_signature = base64.b64decode(payload['signature_b64'])
        
        # 1. Verify the edge node's signature on its KEM public key
        verifier = oqs.SIG("Dilithium2")
        is_valid = verifier.verify(edge_kem_pub_key, edge_signature, edge_sig_pub_key)
        
        if not is_valid:
            print(f"[{SERVER_ID}]: SIGNATURE FROM EDGE NODE '{edge_id}' IS INVALID! Aborting.")
            return
            
        print(f"[{SERVER_ID}]: Signature from '{edge_id}' verified successfully.")
        
        # 2. Encapsulate a shared secret using the edge node's KEM public key
        kem = oqs.KEM("Kyber512")
        ciphertext, shared_secret = kem.encapsulate_secret(edge_kem_pub_key)
        
        # Store the session key
        edge_sessions[edge_id] = {"key": shared_secret[:32]} # Use first 32 bytes for AES-256
        
        # 3. Sign the ciphertext to prove our identity to the edge node
        server_sig = userdata["sig"]
        server_signature = server_sig.sign(ciphertext)
        
        response_payload = {
            "ciphertext_b64": base64.b64encode(ciphertext).decode('utf-8'),
            "signature_b64": base64.b64encode(server_signature).decode('utf-8'),
            "server_sig_pub_key_b64": base64.b64encode(userdata["sig_public_key"]).decode('utf-8')
        }
        
        client.publish(f"edge/handshake/response/{edge_id}", json.dumps(response_payload))
        print(f"[{SERVER_ID}]: Handshake response sent to '{edge_id}'. Session established.")
        
        # Now subscribe to this edge node's data topic
        client.subscribe(f"edge/data/{edge_id}")
        print(f"[{SERVER_ID}]: Subscribed to data topic for '{edge_id}'.")

    elif topic.startswith("edge/data/"):
        edge_id = topic.split('/')[-1]
        if edge_id in edge_sessions:
            session_key = edge_sessions[edge_id]["key"]
            decrypted_data = decrypt_edge_message(session_key, msg.payload)
            if decrypted_data:
                print(f"[{SERVER_ID}]: <<< FINAL DATA RECEIVED >>> from '{edge_id}': {decrypted_data}")
        else:
            print(f"[{SERVER_ID}]: Received data from unknown/un-keyed edge node '{edge_id}'.")

# --- Main ---
if __name__ == "__main__":
    print(f"--- Starting Central Server (ID: {SERVER_ID}) ---")
    
    # Generate the server's long-term signing keypair
    server_sig = oqs.SIG("Dilithium2")
    server_sig_public_key = server_sig.generate_keypair()
    
    client_userdata = {"sig": server_sig, "sig_public_key": server_sig_public_key}
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=SERVER_ID, userdata=client_userdata)
    
    client.on_connect = on_connect
    client.on_message = on_message
    
    # Connection retry loop
    connected = False
    while not connected:
        try:
            client.connect(MQTT_BROKER_HOST, 1883, 60)
            connected = True
        except Exception as e:
            print(f"[{SERVER_ID}]: Connection failed. Retrying in 5 seconds... Error: {e}")
            time.sleep(5)
            
    client.loop_forever()

