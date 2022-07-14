#CONFRONTO PAYLOAD TRA NULLA, CBOR E COSE (CBOR + CIFRATURA)

from binascii import unhexlify
from cose.messages import Enc0Message, CoseMessage
from cose.keys import CoseKey
from cose.algorithms import A256GCM
from cose.headers import Algorithm, IV
from json import loads, dumps
from datetime import datetime
from random import randint
from statistics import mean
import cbor2
import csv

def packgen(values):
    tms = 1000*round(datetime.timestamp(datetime.now()))
    sps = 200
    samples = []
    for _ in range(values):
        value = randint(0,pow(2,32)-1)
        samples.append(value)
    packet = {"E":"enc: int, sps: {}".format(sps),"T":tms,"V":samples}
    size = len(dumps(packet))/1024
    return packet, size

def cbor(pack):

    sent = cbor2.dumps(pack)
    size = len(sent)/1024
    return size

def cose(pack):
        
    msg = Enc0Message(
       phdr = {Algorithm: A256GCM, IV: unhexlify('000102030405060708090a0b')},
       payload = dumps(pack).encode('utf-8'))
    cose_key = {
    'KTY': 'SYMMETRIC',
    'K': unhexlify('000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f')} #256 bit
    key = CoseKey.from_dict(cose_key)
    msg.key = key
    sent = msg.encode()
    size = len(sent)/1024
    return size

list_values = [100,250,500,1000,2000,4000,8000,16000]
num = 100
no_size = ['NO']
cbor_size = ['CBOR']
cose_size = ['COSE']

#algoritmo
for step in range(len(list_values)):
   no_size_temp = ['NO']
   cbor_size_temp = ['CBOR']
   cose_size_temp = ['COSE']
   for x in range(num):
       pack, no_dim = packgen(list_values[step]) #genero 100 pacchetti diversi per ogni quantità di campioni da analizzare
       cbor_dim = cbor(pack)
       cose_dim = cose(pack)
       no_size_temp.append(no_dim)
       cbor_size_temp.append(cbor_dim)
       cose_size_temp.append(cose_dim)
   #media
   no_size.append(mean(no_size_temp[1:]))
   cbor_size.append(mean(cbor_size_temp[1:]))
   cose_size.append(mean(cose_size_temp[1:]))
   
#file per grafici
file_header = ['','100','250','500','1000','2000','4000','8000','16000']
with open('size.csv','w',newline="") as f1:
    writer = csv.writer(f1)
    writer.writerow(file_header)
    writer.writerow(no_size)
    writer.writerow(cbor_size)
    writer.writerow(cose_size)

print('Analisi eseguita correttamente!')
