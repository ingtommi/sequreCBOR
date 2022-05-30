#CONFRONTO TRA JOSE E COSE CON A256GCM

from binascii import unhexlify
from cose.messages import Enc0Message, CoseMessage
from cose.keys import CoseKey
from cose.algorithms import A256GCM
from cose.headers import Algorithm, IV
from jose import jwe
from json import loads, dumps
from datetime import datetime
from random import randint
from statistics import mean
import time
import csv

def packgen(values):
    tms = 1000*round(datetime.timestamp(datetime.now()))
    sps = 200
    samples = []
    for _ in range(values):
        value = randint(0,pow(2,32)-1)
        samples.append(value)
    packet= {"E":"enc: int, sps: {}".format(sps),"T":tms,"V":samples}
    return packet

def jose256(pack):
    #PUBLISHER
    msg = dumps(pack)
    key = unhexlify('000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f')
    #--------------------------------------------#
    te0 = time.perf_counter()
    sent = jwe.encrypt(msg, key, algorithm='dir', encryption='A256GCM')
    dt1 = 1000000*(time.perf_counter() - te0)
    #--------------------------------------------#
    size = len(sent)/1024

    #SUBSCRIBER
    #--------------------------------------------#
    td0 = time.perf_counter()
    received = jwe.decrypt(sent, key)
    dt2 = 1000000*(time.perf_counter() - td0)
    #--------------------------------------------#

    return dt1, dt2, size

def cose256(pack):
        #PUBLISHER
    msg = Enc0Message(
       phdr = {Algorithm: A256GCM, IV: unhexlify('000102030405060708090a0b')},
       payload = dumps(pack).encode('utf-8'))

    cose_key = {
    'KTY': 'SYMMETRIC',
    'K': unhexlify('000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f')} #256 bit

    key = CoseKey.from_dict(cose_key)
    msg.key = key
    #--------------------------------------------#
    te0 = time.perf_counter()
    sent = msg.encode()
    dt1 = 1000000*(time.perf_counter() - te0)
    #--------------------------------------------#
    size = len(sent)/1024

    #SUBSCRIBER
    #--------------------------------------------#
    td0 = time.perf_counter()
    decoded = CoseMessage.decode(sent)
    decoded.key = key
    decrypted = decoded.decrypt()
    dt2 = 1000000*(time.perf_counter() - td0)
    #--------------------------------------------#

    return dt1, dt2, size

list_values = [100,250,500,1000,2000,4000,8000,16000]
num = 100
jose256_enc = ['JOSE_256']
jose256_dec = ['JOSE_256']
jose256_size = ['JOSE_256']
cose256_enc = ['COSE_256']
cose256_dec = ['COSE_256']
cose256_size = ['COSE_256']

#file di log
a = ['']
b = list(range(1,100+1))
log_header = a + b
l1 = open('log_enc.csv','w',newline="")
writer1 = csv.writer(l1)
writer1.writerow(log_header)
l2 = open('log_dec.csv','w',newline="")
writer2 = csv.writer(l2)
writer2.writerow(log_header)
l3 = open('log_size.csv','w',newline="")
writer3 = csv.writer(l3)
writer3.writerow(log_header)

#algoritmo
for step in range(len(list_values)):
   jose256_enc_temp = ['JOSE_256']
   jose256_dec_temp = ['JOSE_256']
   jose256_size_temp = ['JOSE_256']
   cose256_enc_temp = ['COSE_256']
   cose256_dec_temp = ['COSE_256']
   cose256_size_temp = ['COSE_256']
   for x in range(num):
       pack = packgen(list_values[step]) #genero 100 pacchetti diversi per ogni quantità di campioni da analizzare
       (jose256_dt1, jose256_dt2, jose256_dim) = jose256(pack)
       (cose256_dt1, cose256_dt2, cose256_dim) = cose256(pack)
       jose256_enc_temp.append(jose256_dt1)
       jose256_dec_temp.append(jose256_dt2)
       jose256_size_temp.append(jose256_dim)
       cose256_enc_temp.append(cose256_dt1)
       cose256_dec_temp.append(cose256_dt2)
       cose256_size_temp.append(cose256_dim)
   writer1.writerow(jose256_enc_temp)
   writer1.writerow(cose256_enc_temp)
   writer1.writerow('\n')
   writer2.writerow(jose256_dec_temp)
   writer2.writerow(cose256_enc_temp)
   writer2.writerow('\n')
   writer3.writerow(jose256_size_temp)
   writer3.writerow(cose256_enc_temp)
   writer3.writerow('\n')
   #media
   jose256_enc.append(mean(jose256_enc_temp[1:]))
   jose256_dec.append(mean(jose256_dec_temp[1:]))
   jose256_size.append(mean(jose256_size_temp[1:]))
   cose256_enc.append(mean(cose256_enc_temp[1:]))
   cose256_dec.append(mean(cose256_dec_temp[1:]))
   cose256_size.append(mean(cose256_size_temp[1:]))
    
l1.close()
l2.close()
l3.close()

#file per grafici
file_header = ['','100','250','500','1000','2000','4000','8000','16000']
with open('encryption.csv','w',newline="") as f1:
    writer = csv.writer(f1)
    writer.writerow(file_header)
    writer.writerow(jose256_enc)
    writer.writerow(cose256_enc)
with open('decryption.csv','w',newline="") as f2:
    writer = csv.writer(f2)
    writer.writerow(file_header)
    writer.writerow(jose256_dec)
    writer.writerow(cose256_dec)
with open('size.csv','w',newline="") as f3:
    writer = csv.writer(f3)
    writer.writerow(file_header)
    writer.writerow(jose256_size)
    writer.writerow(cose256_size)

print('Analisi eseguita correttamente!')
