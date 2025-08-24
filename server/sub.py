import paho.mqtt.client as mqtt

# Broker connection details
broker_address = "broker.emqx.io"
port = 1883
topic = "paho/test/topic"

# --- Callback Functions ---

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print("Connected successfully to MQTT Broker!")
        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.
        print(f"Subscribing to topic: {topic}")
        client.subscribe(topic)
    else:
        print(f"Failed to connect, return code {reason_code}\n")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(f"Received message: '{msg.payload.decode()}' on topic '{msg.topic}'")

# --- Main Script ---

# Create a new MQTT client instance
# Using the modern Callback API version is recommended
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="subscriber-1")

# Assign the callback functions
client.on_connect = on_connect
client.on_message = on_message

# Connect to the broker
print(f"Connecting to broker at {broker_address}...")
client.connect(broker_address, port=port)

# Start the blocking network loop
# This will keep the script running and process messages until interrupted.
client.loop_forever()