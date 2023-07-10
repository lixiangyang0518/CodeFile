# _*_ coding:utf-8 _*_
import kafka
import json
from kafka import KafkaProducer
from kafka import KafkaConsumer

print(kafka.__version__)

bootstrap_servers="10.0.160.94:9092"
security_protocol="SASL_PLAINTEXT"
sasl_mechanism="SCRAM-SHA-512"
sasl_plain_username="admin"
sasl_plain_password="admin"

flag = 2
if flag == 1:
    topic = "edeepwatch-cloudlog-checkeslbmember-topic" # test-topic 和 edeepwatch-cloudlog-checkeslbmember-topic
else:
    topic = "test-topic"

producer = KafkaProducer(bootstrap_servers=bootstrap_servers,
                         security_protocol=security_protocol,
                         sasl_mechanism=sasl_mechanism,
                         sasl_plain_username=sasl_plain_username,
                         sasl_plain_password=sasl_plain_password,
                         )
# producer = KafkaProducer(bootstrap_servers=bootstrap_servers)
# print("producer:{}".format(producer))
#
# res = producer.send(topic,json.dumps({"id":"1","name":"aaa"}).encode('utf-8'))
# print(res)
# producer.flush()

consumer = KafkaConsumer(topic,
                         bootstrap_servers=bootstrap_servers,
                         security_protocol=security_protocol,
                         sasl_mechanism=sasl_mechanism,
                         sasl_plain_username=sasl_plain_username,
                         sasl_plain_password=sasl_plain_password,
                         auto_offset_reset="earliest",
                         )
# consumer = KafkaConsumer(topic,
#                          bootstrap_servers=bootstrap_servers,
#                          auto_offset_reset="earliest")
print("consumer:{}".format(consumer))
for msg in consumer:
    print msg