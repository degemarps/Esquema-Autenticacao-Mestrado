import paho.mqtt.client as mqtt

cont = 0

while cont < 10000:
  client = mqtt.Client()
  client.connect("192.168.30.2", 1883, 60)
  client.publish("topic/test", "Hello world!")
  client.disconnect()

  cont += 1
  