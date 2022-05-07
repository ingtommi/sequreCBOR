#PUBLISHER: this code simulates the behaviour of a sensor installed in a structure

from binascii import unhexlify
from cose.messages import Enc0Message
from cose.keys import CoseKey
from cose.algorithms import A128GCM
from cose.headers import Algorithm, IV
from json import dumps
from datetime import datetime
import time
from random import randint
import sys
import os
import paho.mqtt.client as mqtt

#COSE KEY STRUCTURE
cose_key = {
    'KTY': 'SYMMETRIC', #key type
    'K': unhexlify('000102030405060708090a0b0c0d0e0e')} #key = 128 bit
key = CoseKey.from_dict(cose_key)

def packgen(numsamp, sps):
    ''' generates a random packet to simulate the measures '''
    tms = 1000*round(datetime.timestamp(datetime.now()))
    samples = []
    for _ in range(numsamp):
        sample = randint(0,pow(2,32)-1)
        samples.append(sample)
    packet= {"E":"enc: int, sps: {}".format(sps),"T":tms,"V":samples}
    return packet

def on_connect(client, userdata, flags, rc):
    ''' on_connect function, it is called after the connection '''
    print('Client connected with code: ' + str(rc))
    print('Publishing will start in 5sec, wait or press <CTRL+C> to stop!')

def main():
    ''' encrypts and encode the packet using COSE protocol and sends it via MQTT'''
    try:
        #COMMAND LINE ARGUMENT
        if len(sys.argv) < 3:
            print('Please select the number and the frequency of the samples!')
            sys.exit()
        numsamp = int(sys.argv[1]) #number of samples in a single packet
        sps = int(sys.argv[2]) #frequency of the samples
        delay = numsamp/sps #delay between packets 
        #MQTT CONNECTION
        broker_address = 'test.mosquitto.org'
        topic = 'data\sensor'
        client = mqtt.Client() #random id to be sure that is unique
        client.on_connect = on_connect
        client.connect(broker_address)
        client.loop_start()
        time.sleep(5) #5sec delay to allow the subscriber to connect without losing the first packets
        while True:
            time.sleep(delay)
            #COSE ENCRYPT0 STRUCTURE
            msg = Enc0Message(
                phdr = {Algorithm: A128GCM, IV: os.urandom(12)}, #protected header with random IV = 12 byte
                payload = dumps(packgen(numsamp,sps)).encode('utf-8')) #payload
            msg.key = key
            encoded = msg.encode() #encrypting and encoding in a single function
            #MQTT PUBLICATION
            client.publish(topic, encoded) #topic, data
    except KeyboardInterrupt: #raised after <CTRL+C>
        print('Ending...')
        client.disconnect()
        client.loop_stop()
        sys.exit()

if __name__ == "__main__":
    main()        
