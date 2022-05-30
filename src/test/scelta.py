#CONFRONTO TRA TUTTI GLI ALGORITMI POSSIBILI

from binascii import unhexlify
from cose.messages import Enc0Message, CoseMessage
from cose.keys import CoseKey
from cose.algorithms import A128GCM, A192GCM, A256GCM, AESCCM64128128, AESCCM64128256, AESCCM16128128, AESCCM16128256
from cose.headers import Algorithm, IV
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

def gcm128(pack):
    #PUBLISHER
    msg = Enc0Message(
       phdr = {Algorithm: A128GCM, IV: unhexlify('000102030405060708090a0b')},
       payload = dumps(pack).encode('utf-8'))

    cose_key = {
    'KTY': 'SYMMETRIC',
    'K': unhexlify('000102030405060708090a0b0c0d0e0f')} #128 bit

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

def gcm192(pack):
    #PUBLISHER
    msg = Enc0Message(
       phdr = {Algorithm: A192GCM, IV: unhexlify('000102030405060708090a0b')},
       payload = dumps(pack).encode('utf-8'))

    cose_key = {
    'KTY': 'SYMMETRIC',
    'K': unhexlify('000102030405060708090a0b0c0d0e0f0001020304050607')} #192 bit

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

def gcm256(pack):
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

def ccm64128(pack):
    #PUBLISHER
    msg = Enc0Message(
       phdr = {Algorithm: AESCCM64128128, IV: unhexlify('000102030405060708090a0b')},
       payload = dumps(pack).encode('utf-8'))

    cose_key = {
    'KTY': 'SYMMETRIC',
    'K': unhexlify('000102030405060708090a0b0c0d0e0f')} #128 bit

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

def ccm64256(pack):
        #PUBLISHER
    msg = Enc0Message(
       phdr = {Algorithm: AESCCM64128256, IV: unhexlify('000102030405060708090a0b')},
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

def ccm16128(pack):
    #PUBLISHER
    msg = Enc0Message(
       phdr = {Algorithm: AESCCM16128128, IV: unhexlify('000102030405060708090a0b')},
       payload = dumps(pack).encode('utf-8'))

    cose_key = {
    'KTY': 'SYMMETRIC',
    'K': unhexlify('000102030405060708090a0b0c0d0e0f')} #128 bit

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

def ccm16256(pack):
        #PUBLISHER
    msg = Enc0Message(
       phdr = {Algorithm: AESCCM16128256, IV: unhexlify('000102030405060708090a0b')},
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
gcm128_enc = ['GCM_128']
gcm128_dec = ['GCM_128']
gcm128_size = ['GCM_128']
gcm192_enc = ['GCM_192']
gcm192_dec = ['GCM_192']
gcm192_size = ['GCM_192']
gcm256_enc = ['GCM_256']
gcm256_dec = ['GCM_256']
gcm256_size = ['GCM_256']
ccm64128_enc = ['CCM_64_128']
ccm64128_dec = ['CCM_64_128']
ccm64128_size = ['CCM_64_128']
ccm64256_enc = ['CCM_64_256']
ccm64256_dec = ['CCM_64_256']
ccm64256_size = ['CCM_64_256']
ccm16128_enc = ['CCM_16_128']
ccm16128_dec = ['CCM_16_128']
ccm16128_size = ['CCM_16_128']
ccm16256_enc = ['CCM_16_256']
ccm16256_dec = ['CCM_16_256']
ccm16256_size = ['CCM_16_256']

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
    gcm128_enc_temp = ['GCM_128']
    gcm128_dec_temp = ['GCM_128']
    gcm128_size_temp = ['GCM_128']
    gcm192_enc_temp = ['GCM_192']
    gcm192_dec_temp = ['GCM_192']
    gcm192_size_temp = ['GCM_192']
    gcm256_enc_temp = ['GCM_256']
    gcm256_dec_temp = ['GCM_256']
    gcm256_size_temp = ['GCM_256']
    ccm64128_enc_temp = ['CCM_64_128']
    ccm64128_dec_temp = ['CCM_64_128']
    ccm64128_size_temp = ['CCM_64_128']
    ccm64256_enc_temp = ['CCM_64_256']
    ccm64256_dec_temp = ['CCM_64_256']
    ccm64256_size_temp = ['CCM_64_256']
    ccm16128_enc_temp = ['CCM_16_128']
    ccm16128_dec_temp = ['CCM_16_128']
    ccm16128_size_temp = ['CCM_16_128']
    ccm16256_enc_temp = ['CCM_16_256']
    ccm16256_dec_temp = ['CCM_16_256']
    ccm16256_size_temp = ['CCM_16_256']
    for x in range(num):
        pack = packgen(list_values[step]) #genero 100 pacchetti diversi per ogni quantità di campioni da analizzare
        (gcm128_dt1, gcm128_dt2, gcm128_dim) = gcm128(pack)
        (gcm192_dt1, gcm192_dt2, gcm192_dim) = gcm192(pack)
        (gcm256_dt1, gcm256_dt2, gcm256_dim) = gcm256(pack)
        (ccm64128_dt1, ccm64128_dt2, ccm64128_dim) = ccm64128(pack)
        (ccm64256_dt1, ccm64256_dt2, ccm64256_dim) = ccm64256(pack)
        (ccm16128_dt1, ccm16128_dt2, ccm16128_dim) = ccm16128(pack)
        (ccm16256_dt1, ccm16256_dt2, ccm16256_dim) = ccm16256(pack)
        gcm128_enc_temp.append(gcm128_dt1)
        gcm128_dec_temp.append(gcm128_dt2)
        gcm128_size_temp.append(gcm128_dim)
        gcm192_enc_temp.append(gcm192_dt1)
        gcm192_dec_temp.append(gcm192_dt2)
        gcm192_size_temp.append(gcm192_dim)
        gcm256_enc_temp.append(gcm256_dt1)
        gcm256_dec_temp.append(gcm256_dt2)
        gcm256_size_temp.append(gcm256_dim)
        ccm64128_enc_temp.append(ccm64128_dt1)
        ccm64128_dec_temp.append(ccm64128_dt2)
        ccm64128_size_temp.append(ccm64128_dim)
        ccm64256_enc_temp.append(ccm64256_dt1)
        ccm64256_dec_temp.append(ccm64256_dt2)
        ccm64256_size_temp.append(ccm64256_dim)
        ccm16128_enc_temp.append(ccm16128_dt1)
        ccm16128_dec_temp.append(ccm16128_dt2)
        ccm16128_size_temp.append(ccm16128_dim)
        ccm16256_enc_temp.append(ccm16256_dt1)
        ccm16256_dec_temp.append(ccm16256_dt2)
        ccm16256_size_temp.append(ccm16256_dim)
    writer1.writerow(gcm128_enc_temp)
    writer1.writerow(ccm64128_enc_temp)
    writer1.writerow(ccm16128_enc_temp)
    writer1.writerow(gcm192_enc_temp)
    writer1.writerow(gcm256_enc_temp)
    writer1.writerow(ccm64256_enc_temp)
    writer1.writerow(ccm16256_enc_temp)
    writer1.writerow('\n')
    writer2.writerow(gcm128_dec_temp)
    writer2.writerow(ccm64128_dec_temp)
    writer2.writerow(ccm16128_dec_temp)
    writer2.writerow(gcm192_dec_temp)
    writer2.writerow(gcm256_dec_temp)
    writer2.writerow(ccm64256_dec_temp)
    writer2.writerow(ccm16256_dec_temp)
    writer2.writerow('\n')
    writer3.writerow(gcm128_size_temp)
    writer3.writerow(ccm64128_size_temp)
    writer3.writerow(ccm16128_size_temp)
    writer3.writerow(gcm192_size_temp)
    writer3.writerow(gcm256_size_temp)
    writer3.writerow(ccm64256_size_temp)
    writer3.writerow(ccm16256_size_temp)
    writer3.writerow('\n')
    #media
    gcm128_enc.append(mean(gcm128_enc_temp[1:]))
    gcm128_dec.append(mean(gcm128_dec_temp[1:]))
    gcm128_size.append(mean(gcm128_size_temp[1:]))
    gcm192_enc.append(mean(gcm192_enc_temp[1:]))
    gcm192_dec.append(mean(gcm192_dec_temp[1:]))
    gcm192_size.append(mean(gcm192_size_temp[1:]))
    gcm256_enc.append(mean(gcm256_enc_temp[1:]))
    gcm256_dec.append(mean(gcm256_dec_temp[1:]))
    gcm256_size.append(mean(gcm256_size_temp[1:]))
    ccm64128_enc.append(mean(ccm64128_enc_temp[1:]))
    ccm64128_dec.append(mean(ccm64128_dec_temp[1:]))
    ccm64128_size.append(mean(ccm64128_size_temp[1:]))
    ccm64256_enc.append(mean(ccm64256_enc_temp[1:]))
    ccm64256_dec.append(mean(ccm64256_dec_temp[1:]))
    ccm64256_size.append(mean(ccm64256_size_temp[1:]))
    ccm16128_enc.append(mean(ccm16128_enc_temp[1:]))
    ccm16128_dec.append(mean(ccm16128_dec_temp[1:]))
    ccm16128_size.append(mean(ccm16128_size_temp[1:]))
    ccm16256_enc.append(mean(ccm16256_enc_temp[1:]))
    ccm16256_dec.append(mean(ccm16256_dec_temp[1:]))
    ccm16256_size.append(mean(ccm16256_size_temp[1:]))
    
l1.close()
l2.close()
l3.close()

#file per grafici
file_header = ['','100','250','500','1000','2000','4000','8000','16000']
with open('encryption.csv','w',newline="") as f1:
    writer = csv.writer(f1)
    writer.writerow(file_header)
    writer.writerow(gcm128_enc)
    writer.writerow(ccm64128_enc)
    writer.writerow(ccm16128_enc)
    writer.writerow(gcm192_enc)
    writer.writerow(gcm256_enc)
    writer.writerow(ccm64256_enc)
    writer.writerow(ccm16256_enc)
with open('decryption.csv','w',newline="") as f2:
    writer = csv.writer(f2)
    writer.writerow(file_header)
    writer.writerow(gcm128_dec)
    writer.writerow(ccm64128_dec)
    writer.writerow(ccm16128_dec)
    writer.writerow(gcm192_dec)
    writer.writerow(gcm256_dec)
    writer.writerow(ccm64256_dec)
    writer.writerow(ccm16256_dec)
with open('size.csv','w',newline="") as f3:
    writer = csv.writer(f3)
    writer.writerow(file_header)
    writer.writerow(gcm128_size)
    writer.writerow(ccm64128_size)
    writer.writerow(ccm16128_size)
    writer.writerow(gcm192_size)
    writer.writerow(gcm256_size)
    writer.writerow(ccm64256_size)
    writer.writerow(ccm16256_size)

print('Analisi eseguita correttamente!')
