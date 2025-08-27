import paho.mqtt.client as mqtt
import os
import json
import time
import oqs
import base64
import logging
import hashlib
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s')
log = logging.getLogger("EdgeNode")

MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "localhost")
EDGE_ID = os.environ.get("EDGE_ID", "edge-node-default")
DEVICE_PSK_STR = os.environ.get("DEVICE_PSK", "default_32_byte_key_for_testing!")
CRYPTO_MODE = os.environ.get("CRYPTO_MODE", "PQC").upper()  # "PQC" or "ECC"

# Derive a stable 32-byte key for AES from the PSK string (avoids invalid key sizes)
DEVICE_PSK = hashlib.sha256(DEVICE_PSK_STR.encode("utf-8")).digest()  # 32 bytes

# --- Algorithm Selection ---
KEM_ALG = "ML-KEM-512"
SIG_ALG = "ML-DSA-44"
ECC_CURVE = ec.SECP256R1()
ECC_HASH = hashes.SHA256()

# --- Global State ---
metrics = {}

# --- Crypto Functions (AES GCM) ---
def decrypt_device_message(key: bytes, encrypted_payload: bytes) -> str | None:
    """
    Expects: nonce (16 bytes) | header (4 bytes) | tag (16 bytes) | ciphertext (rest)
    Returns UTF-8 plaintext string or None on failure.
    """
    try:
        if not encrypted_payload or len(encrypted_payload) < (16 + 4 + 16):
            log.warning("Encrypted payload too short to parse.")
            return None

        nonce = encrypted_payload[:16]
        header = encrypted_payload[16:20]
        tag = encrypted_payload[20:36]
        ciphertext = encrypted_payload[36:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8")
    except (ValueError, KeyError) as e:
        log.error(f"Decryption failed! Error: {e}")
        return None
    except Exception as e:
        log.exception(f"Unexpected error during decryption: {e}")
        return None


def encrypt_server_message(key: bytes, plaintext: str) -> bytes:
    """
    Produces: nonce (16 bytes) | header (4 bytes) | tag (16 bytes) | ciphertext
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) not in (16, 24, 32):
        # defensively derive a 32-byte key if something odd arrives
        log.warning("Session key invalid length; deriving 32-byte HKDF key from provided value.")
        key = hashlib.sha256(key if isinstance(key, (bytes, bytearray)) else str(key).encode()).digest()

    header = b"data"  # 4-byte header
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return cipher.nonce + header + tag + ciphertext


# --- PQC Handshake Functions ---
def initiate_pqc_handshake(client: mqtt.Client, userdata: dict):
    timings = {}
    try:
        kem = oqs.KeyEncapsulation(KEM_ALG)
        sig = oqs.Signature(SIG_ALG)
    except Exception as e:
        log.exception(f"Failed to initialize OQS objects: {e}")
        return

    # generate KEM keypair
    start = time.perf_counter()
    try:
        kem_pub = kem.generate_keypair()
        # depending on binding, secret key may be obtainable differently; attempt export
        try:
            kem_secret = kem.export_secret_key()
        except Exception:
            # fallback: some bindings return (pub, secret) from generate_keypair; check that
            kem_secret = None
    except Exception as e:
        log.exception(f"KEM key generation failed: {e}")
        kem.free() if hasattr(kem, "free") else None
        return
    timings["kem_keygen_ms"] = (time.perf_counter() - start) * 1000

    # generate signature keypair
    start = time.perf_counter()
    try:
        sig_pub = sig.generate_keypair()
    except Exception as e:
        log.exception(f"Signature key generation failed: {e}")
        try:
            kem.free()
        except Exception:
            pass
        return
    timings["sig_keygen_ms"] = (time.perf_counter() - start) * 1000

    # sign the kem public key
    start = time.perf_counter()
    try:
        signature = sig.sign(kem_pub)
    except Exception as e:
        log.exception(f"Signing failed: {e}")
        try:
            kem.free()
            sig.free()
        except Exception:
            pass
        return
    timings["sign_ms"] = (time.perf_counter() - start) * 1000

    # store values safely in userdata
    userdata["kem_public_key"] = kem_pub
    userdata["kem_secret_key"] = kem_secret
    userdata["sig_public_key"] = sig_pub
    userdata["signature"] = signature

    metrics["computation_times_ms"] = timings

    payload = json.dumps({
        "kem_pub_key_b64": base64.b64encode(kem_pub).decode("utf-8"),
        "sig_pub_key_b64": base64.b64encode(sig_pub).decode("utf-8"),
        "signature_b64": base64.b64encode(signature).decode("utf-8"),
    })

    # free OQS resources if supported (safe-guarded)
    try:
        sig.free()
    except Exception:
        pass
    try:
        kem.free()
    except Exception:
        pass

    metrics["handshake_payload_size_bytes"] = len(payload)
    metrics["handshake_start_time"] = time.time()

    try:
        client.publish(f"edge/handshake/initiate/{EDGE_ID}", payload)
        log.info(f"PQC Handshake initiated using {KEM_ALG} and {SIG_ALG}.")
    except Exception as e:
        log.exception(f"Failed to publish PQC handshake initiate message: {e}")


def handle_pqc_response(client: mqtt.Client, userdata: dict, msg: mqtt.MQTTMessage):
    try:
        response = json.loads(msg.payload.decode("utf-8"))
    except Exception:
        log.exception("Failed to parse PQC handshake response JSON")
        return

    try:
        ciphertext = base64.b64decode(response["ciphertext_b64"])
        server_signature = base64.b64decode(response["signature_b64"])
        server_sig_pub_key = base64.b64decode(response["server_sig_pub_key_b64"])
    except KeyError as e:
        log.error(f"Missing expected field in server response: {e}")
        return
    except Exception as e:
        log.exception(f"Failed to decode base64 fields: {e}")
        return

    timings = metrics.setdefault("computation_times_ms", {})

    # Verify server signature
    try:
        verifier = oqs.Signature(SIG_ALG)
        start = time.perf_counter()
        # WARNING: OQS API ordering might vary across bindings.
        # Most bindings use verify(message, signature, public_key)
        is_valid = verifier.verify(ciphertext, server_signature, server_sig_pub_key)
        timings["verify_ms"] = (time.perf_counter() - start) * 1000
    except Exception as e:
        log.exception(f"Signature verification failed (exception): {e}")
        try:
            verifier.free()
        except Exception:
            pass
        return
    finally:
        try:
            verifier.free()
        except Exception:
            pass

    if not is_valid:
        log.warning("SERVER SIGNATURE INVALID! Aborting handshake.")
        return

    # Decapsulate to obtain shared secret
    try:
        kem = oqs.KeyEncapsulation(KEM_ALG, secret_key=userdata.get("kem_secret_key"))
    except Exception as e:
        log.exception(f"Failed to create KEM object for decapsulation: {e}")
        return

    try:
        start = time.perf_counter()
        shared_secret = kem.decap_secret(ciphertext)
        timings["decapsulate_ms"] = (time.perf_counter() - start) * 1000
    except Exception as e:
        log.exception(f"Decapsulation failed: {e}")
        try:
            kem.free()
        except Exception:
            pass
        return
    finally:
        try:
            kem.free()
        except Exception:
            pass

    if not shared_secret:
        log.error("Decapsulation produced no shared secret.")
        return

    # use first 32 bytes as session key (HKDF could be used instead)
    userdata["session_key"] = shared_secret[:32]
    userdata["handshake_complete"] = True
    metrics["computation_times_ms"] = timings
    log.info("PQC Handshake complete! Session key established with server.")


# --- ECC Handshake Functions ---
def initiate_ecc_handshake(client: mqtt.Client, userdata: dict):
    timings = {}

    start = time.perf_counter()
    ec_key = ec.generate_private_key(ECC_CURVE)
    ec_pub_key = ec_key.public_key()
    timings["keygen_ms"] = (time.perf_counter() - start) * 1000

    userdata["ec_key"] = ec_key

    ec_pub_key_bytes = ec_pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    payload = {"ec_pub_key_pem": ec_pub_key_bytes.decode("utf-8")}

    metrics["computation_times_ms"] = timings
    metrics["handshake_payload_size_bytes"] = len(json.dumps(payload))
    metrics["handshake_start_time"] = time.time()
    try:
        client.publish(f"edge/handshake/initiate/{EDGE_ID}", json.dumps(payload))
        log.info("ECC Handshake initiated using ECDH.")
    except Exception as e:
        log.exception(f"Failed to publish ECC handshake initiate message: {e}")


def handle_ecc_response(client: mqtt.Client, userdata: dict, msg: mqtt.MQTTMessage):
    try:
        response = json.loads(msg.payload.decode("utf-8"))
        server_ec_pub_key_pem = response["server_ec_pub_key_pem"].encode("utf-8")
    except Exception:
        log.exception("Failed to parse ECC handshake response JSON")
        return

    try:
        server_ec_pub_key = serialization.load_pem_public_key(server_ec_pub_key_pem)
    except Exception as e:
        log.exception(f"Failed to load server EC public key: {e}")
        return

    timings = metrics.setdefault("computation_times_ms", {})
    start = time.perf_counter()
    try:
        shared_key = userdata["ec_key"].exchange(ec.ECDH(), server_ec_pub_key)
        timings["key_exchange_ms"] = (time.perf_counter() - start) * 1000
    except Exception as e:
        log.exception(f"EC key exchange failed: {e}")
        return

    # Derive a 32-byte session key (HKDF)
    try:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data")
        session_key = hkdf.derive(shared_key)
    except Exception as e:
        log.exception(f"HKDF derive failed: {e}")
        return

    userdata["session_key"] = session_key
    userdata["handshake_complete"] = True
    metrics["computation_times_ms"] = timings
    log.info("ECC Handshake complete! Session key established with server.")


# --- MQTT Callbacks ---
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        # Normalize CRYPTO_MODE to handle quotes and whitespace
        mode = CRYPTO_MODE.strip().replace('"', '').replace("'", '').upper()
        log.info(f"Connected to MQTT Broker. Starting handshake in {mode} mode.")
        client.subscribe("iot/telemetry/#")
        client.subscribe(f"edge/handshake/response/{EDGE_ID}")

        if mode == "PQC":
            initiate_pqc_handshake(client, userdata)
        elif mode == "ECC":
            initiate_ecc_handshake(client, userdata)
        else:
            log.error(f"Unknown CRYPTO_MODE: {CRYPTO_MODE} (normalized: {mode})")
    else:
        log.error(f"Failed to connect, return code {rc}")


def on_message(client, userdata, msg):
    topic = msg.topic
    log.debug(f"Incoming message on topic: {topic}")

    if topic.startswith("edge/handshake/response/"):
        metrics["response_payload_size_bytes"] = len(msg.payload)
        if "handshake_start_time" in metrics:
            metrics["total_handshake_latency_ms"] = (time.time() - metrics["handshake_start_time"]) * 1000
        else:
            metrics["total_handshake_latency_ms"] = None

        # Use normalized CRYPTO_MODE for correct comparison
        mode = CRYPTO_MODE.strip().replace('"', '').replace("'", '').upper()
        if mode == "PQC":
            handle_pqc_response(client, userdata, msg)
        elif mode == "ECC":
            handle_ecc_response(client, userdata, msg)
        else:
            log.error(f"Unknown CRYPTO_MODE in on_message: {CRYPTO_MODE} (normalized: {mode})")

        if userdata.get("handshake_complete"):
            network_mode = "ideal" if "mosquitto" in MQTT_BROKER_HOST else "public"
            filename = f"/app/results/handshake_{mode}_{network_mode}.json"
            try:
                os.makedirs("/app/results", exist_ok=True)
                with open(filename, "w") as f:
                    json.dump(metrics, f, indent=2)
                log.info(f"Handshake metrics saved to {filename}")
            except Exception as e:
                log.error(f"Failed to write metrics file: {e}")

    elif topic.startswith("iot/telemetry/"):
        decrypted_payload = decrypt_device_message(DEVICE_PSK, msg.payload)
        if decrypted_payload is None:
            log.debug("Could not decrypt device payload; dropping.")
            return

        if not userdata.get("handshake_complete") or not userdata.get("session_key"):
            log.info("Handshake not complete or session key missing. Dropping device data.")
            return

        try:
            data = json.loads(decrypted_payload)
            data["edge_timestamp"] = time.time()
            payload_to_forward = json.dumps(data)
            encrypted_payload = encrypt_server_message(userdata["session_key"], payload_to_forward)
            # publish bytes payload
            client.publish(f"edge/data/{EDGE_ID}", encrypted_payload)
            log.debug("Forwarded encrypted telemetry to edge/data topic.")
        except json.JSONDecodeError:
            log.warning("Could not parse JSON from device.")
        except Exception as e:
            log.exception(f"Failed to forward device data: {e}")


# --- Main ---
if __name__ == "__main__":
    log.info(f"--- Starting Edge Node (ID: {EDGE_ID}) ---")

    # Initialize client correctly and use MQTT v5 (properties param in on_connect)
    client = mqtt.Client(client_id=EDGE_ID, userdata={})
    # Set protocol to MQTT v5 (optional; adjust to environment if you need v3.1.1)
    try:
        client._protocol = mqtt.MQTTv5
    except Exception:
        # fallback: constructing with protocol flag may be different across paho versions
        pass

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

    # Blocking loop - will run callbacks
    client.loop_forever()
