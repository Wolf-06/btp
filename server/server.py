import paho.mqtt.client as mqtt
import os
import json
import time
import oqs
import base64
import logging
import csv
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s')
log = logging.getLogger("CentralServer")

MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "localhost")
SERVER_ID = "central-server-01"
CRYPTO_MODE = os.environ.get("CRYPTO_MODE", "PQC").upper()

# --- Algorithm Selection ---
KEM_ALG = "ML-KEM-512"
SIG_ALG = "ML-DSA-44"
ECC_CURVE = ec.SECP256R1()
ECC_HASH = hashes.SHA256()

# --- State ---
edge_sessions = {}

# --- Crypto & Logging Functions ---
def decrypt_edge_message(key: bytes, encrypted_payload: bytes) -> str | None:
    try:
        nonce, header, tag, ciphertext = encrypted_payload[:16], encrypted_payload[16:20], encrypted_payload[20:36], encrypted_payload[36:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError) as e:
        log.error(f"Decryption failed for an edge message! Error: {e}")
        return None

def log_latency_to_csv(edge_id: str, latency_ms: float):
    network_mode = "ideal" if "mosquitto" in MQTT_BROKER_HOST else "public"
    filename = f"/app/results/latency_{CRYPTO_MODE}_{network_mode}_{edge_id}.csv"
    file_exists = os.path.exists(filename)
    try:
        with open(filename, "a", newline="") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["timestamp", "latency_ms"])
            writer.writerow([time.time(), latency_ms])
    except Exception as e:
        log.error(f"Failed to write latency to CSV: {e}")

# --- Handshake Handler Functions ---
def _handle_pqc_handshake(client: mqtt.Client, userdata: dict, payload: dict, edge_id: str):
    log.info(f"Handling PQC handshake from '{edge_id}'.")
    timings = {}

    edge_kem_pub_key = base64.b64decode(payload['kem_pub_key_b64'])
    edge_sig_pub_key = base64.b64decode(payload['sig_pub_key_b64'])
    edge_signature = base64.b64decode(payload['signature_b64'])

    verifier = oqs.Signature(SIG_ALG)
    start = time.perf_counter()
    is_valid = verifier.verify(edge_kem_pub_key, edge_signature, edge_sig_pub_key)
    timings["verify_ms"] = (time.perf_counter() - start) * 1000
    verifier.free()

    if not is_valid:
        log.warning(f"SIGNATURE FROM EDGE NODE '{edge_id}' IS INVALID! Aborting.")
        return

    kem = oqs.KeyEncapsulation(KEM_ALG)
    start = time.perf_counter()
    ciphertext, shared_secret = kem.encap_secret(edge_kem_pub_key)
    timings["encapsulate_ms"] = (time.perf_counter() - start) * 1000
    kem.free()

    edge_sessions[edge_id] = {"key": shared_secret[:32], "mode": "PQC"}


    # Ensure server_sig is present in userdata, else generate and store
    if "sig" not in userdata or "sig_public_key" not in userdata:
        log.info("Generating PQC (Dilithium) long-term signing key (late)...")
        server_sig = oqs.Signature(SIG_ALG)
        server_sig_public_key = server_sig.generate_keypair()
        userdata["sig"] = server_sig
        userdata["sig_public_key"] = server_sig_public_key
    else:
        server_sig = userdata["sig"]

    start = time.perf_counter()
    server_signature = server_sig.sign(ciphertext)
    timings["sign_ms"] = (time.perf_counter() - start) * 1000

    log.info(f"Server-side PQC computation times (ms): {timings}")

    response_payload = json.dumps({
        "ciphertext_b64": base64.b64encode(ciphertext).decode('utf-8'),
        "signature_b64": base64.b64encode(server_signature).decode('utf-8'),
        "server_sig_pub_key_b64": base64.b64encode(userdata["sig_public_key"]).decode('utf-8')
    })
    client.publish(f"edge/handshake/response/{edge_id}", response_payload)
    log.info(f"PQC Handshake response sent to '{edge_id}'.")
    client.subscribe(f"edge/data/{edge_id}")

def _handle_ecc_handshake(client: mqtt.Client, userdata: dict, payload: dict, edge_id: str):
    log.info(f"Handling ECC handshake from '{edge_id}'.")
    timings = {}

    edge_ec_pub_key_pem = payload['ec_pub_key_pem'].encode('utf-8')
    edge_ec_pub_key = serialization.load_pem_public_key(edge_ec_pub_key_pem)

    start = time.perf_counter()
    server_ec_key = ec.generate_private_key(ECC_CURVE)
    timings["keygen_ms"] = (time.perf_counter() - start) * 1000
    
    server_ec_pub_key = server_ec_key.public_key()
    
    start = time.perf_counter()
    shared_key = server_ec_key.exchange(ec.ECDH(), edge_ec_pub_key)
    timings["key_exchange_ms"] = (time.perf_counter() - start) * 1000

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data')
    session_key = hkdf.derive(shared_key)

    edge_sessions[edge_id] = {"key": session_key, "mode": "ECC"}

    log.info(f"Server-side ECC computation times (ms): {timings}")

    response_payload = json.dumps({
        "server_ec_pub_key_pem": server_ec_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    })
    client.publish(f"edge/handshake/response/{edge_id}", response_payload)
    log.info(f"ECC Handshake response sent to '{edge_id}'.")
    client.subscribe(f"edge/data/{edge_id}")

# --- MQTT Callbacks ---
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        log.info("Connected to MQTT Broker.")
        client.subscribe("edge/handshake/initiate/#")
        log.info("Subscribed to global handshake topic.")
    else:
        log.error(f"Failed to connect, return code {rc}")

def on_message(client, userdata, msg):
    topic = msg.topic
    
    if topic.startswith("edge/handshake/initiate/"):
        edge_id = topic.split('/')[-1]
        payload = json.loads(msg.payload.decode('utf-8'))
        
        # Detect handshake type based on payload content
        if "kem_pub_key_b64" in payload:
            _handle_pqc_handshake(client, userdata, payload, edge_id)
        elif "ec_pub_key_pem" in payload:
            _handle_ecc_handshake(client, userdata, payload, edge_id)
        else:
            log.warning(f"Received unknown handshake format from '{edge_id}'.")

    elif topic.startswith("edge/data/"):
        edge_id = topic.split('/')[-1]
        if session := edge_sessions.get(edge_id):
            if decrypted_data := decrypt_edge_message(session["key"], msg.payload):
                log.info(f"<<< FINAL DATA RECEIVED >>> from '{edge_id}': {decrypted_data}")
                try:
                    data = json.loads(decrypted_data)
                    if "edge_timestamp" in data:
                        latency_ms = (time.time() - data["edge_timestamp"]) * 1000
                        log_latency_to_csv(edge_id, round(latency_ms, 2))
                except json.JSONDecodeError:
                    log.warning("Could not parse JSON from edge node data.")
        else:
            log.warning(f"Received data from unknown/un-keyed edge node '{edge_id}'.")

# --- Main ---
if __name__ == "__main__":
    log.info(f"--- Starting Central Server (ID: {SERVER_ID}) ---")
    
    client_userdata = {}
    # Generate long-term keys based on the primary mode of the server
    if CRYPTO_MODE == "PQC":
        log.info("Generating PQC (Dilithium) long-term signing key...")
        server_sig = oqs.Signature(SIG_ALG)
        server_sig_public_key = server_sig.generate_keypair()
        client_userdata = {"sig": server_sig, "sig_public_key": server_sig_public_key}
    else: # ECC mode does not require a long-term key for this ephemeral handshake
        log.info("Running in ECC mode. No long-term PQC keys generated.")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=SERVER_ID, userdata=client_userdata)
    client.on_connect = on_connect
    client.on_message = on_message
    
    connected = False
    while not connected:
        try:
            client.connect(MQTT_BROKER_HOST, 1883, 60)
            connected = True
        except Exception as e:
            log.error(f"Connection failed. Retrying in 5 seconds... Error: {e}")
            time.sleep(5)
            
    client.loop_forever()