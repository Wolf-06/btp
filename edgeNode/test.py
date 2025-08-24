import paho.mqtt.client as mqtt
import time

# Broker connection details
broker_address = "broker.emqx.io"
port = 1883
topic = "paho/test/topic"

# Create a new MQTT client instance
# Using the modern Callback API version is recommended
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="publisher-1")

# Connect to the broker
print(f"Connecting to broker at {broker_address}...")
client.connect(broker_address, port=port)

# Start the network loop in a background thread
client.loop_start()

# Publish a message
message = "Hello, MQTT!"
print(f"Publishing message '{message}' to topic '{topic}'")
result = client.publish(topic, message)

# The publish method returns a MQTTMessageInfo object.
# We can check the result code to see if the publish was successful.
status = result.rc
if status == 0:
    print(f"Message sent successfully to topic {topic}")
else:
    print(f"Failed to send message to topic {topic}")

# Wait for a moment to ensure the message is sent
time.sleep(2)

# Stop the loop and disconnect
client.loop_stop()
client.disconnect()
print("Disconnected from broker.")