#SUBSCRIBER: this code has to be runned in the station

from binascii import unhexlify
from cose.messages import CoseMessage
from cose.keys import CoseKey
from json import loads
import paho.mqtt.client as mqtt
from cryptography.exceptions import InvalidTag
import time
import sys

#COSE KEY STRUCTURE
cose_key = {
    'KTY': 'SYMMETRIC', #key type
    'K': unhexlify(b'000102030405060708090a0b0c0d0e0f')} #key = 128 bit
key = CoseKey.from_dict(cose_key)

def on_connect(client, userdata, flags, rc):
    ''' on_connect function, it is called after the connection '''
    print('Client connected with code: ' + str(rc))
    client.subscribe('data\sensor')
    print('Listening...visit "data.txt" to read messages or press <CTRL+C> to stop')

def on_message(client, userdata, msg):
    ''' on_message function, it is called after the message is received '''
    try:
        received = msg.payload
        decoded = CoseMessage.decode(received) #decoding from CBOR
        decoded.key = key #key to decrypt
        decrypted = decoded.decrypt() #decrypting
        data = loads(decrypted.decode('utf-8'))
        #FILE
        with open('data.txt', 'a') as f1:
            f1.write(str(data) + '\n\n')
    except InvalidTag: #raised if the auth tag is not correct
        t = time.localtime()
        current_time = time.strftime("%H:%M:%S", t)
        with open('log.txt', 'a') as f2:
            f2.write('Attempted attack at {}\n'.format(current_time))
            
def main():
    ''' connects to the broker and calls the function to read and save data '''
    try:
        #MQTT CONNECTION
        broker_address = 'test.mosquitto.org' #broker
        client = mqtt.Client() #random id to be sure that is unique
        client.on_connect = on_connect
        client.on_message = on_message
        client.connect(broker_address)
        client.loop_forever()
    except KeyboardInterrupt: #raised after <CTRL+C>
        print('Ending...')
        client.disconnect()
        client.loop_stop()
        sys.exit()

if __name__ == "__main__":
    main()  
