#!/usr/bin/env python
"""

Requirements:
* https://github.com/openalias/dnscrypt-python
* https://github.com/warner/python-pure25519/blob/master/misc/djbec.py
* a query file of the form `qname\tqtype`. Example query file https://nominum.com/measurement-tools/


Example usage:
python dnscrypt-fuzzer.py \
    --provider-key XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX \
    --port 8443 \
    -q queryfile-example-current
"""
import argparse
import codecs
import os
import pdb
import random
import socket
import time

import dnscrypt

qtypemap = {
    'A': 1,
    'NS': 2,
    'MD': 3,
    'MF': 4,
    'CNAME': 5,
    'SOA': 6,
    'MB': 7,
    'MG': 8,
    'MR': 9,
    'NULL': 10,
    'WKS': 11,
    'PTR': 12,
    'HINFO': 13,
    'MINFO': 14,
    'MX': 15,
    'TXT': 16,
    'RP': 17,
    'AFSDB': 18,
    'X25': 19,
    'ISDN': 20,
    'RT': 21,
    'NSAP': 22,
    'NSAP-PTR': 23,
    'SIG': 24,
    'KEY': 25,
    'PX': 26,
    'GPOS': 27,
    'AAAA': 28,
    'LOC': 29,
    'NXT': 30,
    'EID': 31,
    'NIMLOC': 32,
    'SRV': 33,
    'ATMA': 34,
    'NAPTR': 35,
    'KX': 36,
    'CERT': 37,
    'A6': 38,
    'DNAME': 39,
    'SINK': 40,
    'OPT': 41,
    'APL': 42,
    'DS': 43,
    'SSHFP': 44,
    'IPSECKEY': 45,
    'RRSIG': 46,
    'NSEC': 47,
    'DNSKEY': 48,
    'DHCID': 49,
    'NSEC3': 50,
    'NSEC3PARAM': 51,
    'TLSA': 52,
    'SMIMEA': 53,
    'Unassigned': 54,
    'HIP': 55,
    'NINFO': 56,
    'RKEY': 57,
    'TALINK': 58,
    'CDS': 59,
    'CDNSKEY': 60,
    'OPENPGPKEY': 61,
    'CSYNC': 62,
    'SPF': 99,
    'UINFO': 100,
    'UID': 101,
    'GID': 102,
    'UNSPEC': 103,
    'NID': 104,
    'L32': 105,
    'L64': 106,
    'LP': 107,
    'EUI48': 108,
    'EUI64': 109,
    'TKEY': 249,
    'TSIG': 250,
    'IXFR': 251,
    'AXFR': 252,
    'MAILB': 253,
    'MAILA': 254,
    '*': 255,
    'URI': 256,
    'CAA': 257,
    'AVC': 258,
    'TA': 32768,
    'DLV': 32769,
}

def flipbit(msg, **kwargs):
    idx = random.randint(0, len(msg)-1)
    bit_idx = random.randint(0,7)
    x = msg[:idx]
    x += chr(ord(msg[idx]) ^ 1<<bit_idx)
    x += msg[idx+1:]
    return x

def flipmanybits(msg, **kwargs):

    x = ''
    for c in msg:
        if random.randint(0, 50) == 25:
            bit_idx = random.randint(0,7)
            x += chr(ord(c) ^ 1<<bit_idx)
        else:
            x += c
    return x

def dropbyte(msg, **kwargs):
    idx = random.randint(0, len(msg)-1)
    return msg[:idx] + msg[idx+1:]

def injectbyte(msg, **kwargs):
    idx = random.randint(0, len(msg)-1)
    x = msg[:idx]
    x += chr(random.randint(0, 255))
    x += msg[idx:]
    return x

def truncatepacket(msg, **kwargs):
    idx = random.randint(kwargs['minint'], len(msg)-1)
    return msg[idx:]

def noop(msg, **kwargs):
    return msg

def mkmsg(magic_query, pk, nonce, encoded_message):
    return magic_query + pk + nonce + encoded_message

def corrupt(magic_query, pk, nonce, nmkey, message):
    c = random.randint(0, 100) % 7
    args = {}
    if c <= 1:
        f = flipmanybits
    elif c == 2:
        f = flipbit
    elif c == 3:
        f = dropbyte
    elif c == 4:
        f = injectbyte
    elif c == 5:
        # 68 is min dnscrypt header size
        args = {'minint': 68}
        f = truncatepacket
    elif c == 6:
        c2 = random.randint(0, 100) % 4
        f = flipmanybits
        if c2 == 0:
            f = flipbit
        elif c2 == 1:
            f = dropbyte
        elif c2 == 2:
            f = injectbyte
        elif c2 == 3:
            # 12 is min dns header size
            args = {'minint': 12}
            f = truncatepacket
        message = f(message, **args)
        args = {}
        f = noop

    encoded_message = dnscrypt.encode_message(message, nonce, nmkey)
    return f(mkmsg(magic_query, pk, nonce, encoded_message), **args)

class DnsCrypt():
    def __init__(self, ip, port, provider_name, provider_key):
        self.ip = ip
        self.port = port
        self.provider_name = provider_name
        self.provider_key = provider_key.replace(':', '')
        self.provider_pk, self.magic_query = dnscrypt.get_public_key(
            self.ip, self.port, self.provider_key, self.provider_name)

        self.pk, self.sk = dnscrypt.generate_keypair()
        self.nmkey = dnscrypt.create_nmkey(self.provider_pk[:32], self.sk)

    def query(self, qname, qtype, corrupted=False,return_packet=True):
        # create dns query
        header = dnscrypt.DnsHeader()

        question = dnscrypt.DnsQuestion()
        question.labels = qname.split('.')
        question.qtype = qtype

        packet = dnscrypt.DnsPacket(header)
        packet.addQuestion(question)

        message = packet.toBinary() + '\x00\x00\x29\x04\xe4' + 6 * '\x00' + '\x80'

        # custom rules for type 48
        if qtype == 48:
            url_part = ''
            for part in question.labels:
                url_part += chr(len(part)) + part
            message = '\x124\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01' + url_part + '\x00\x000\x00\x01\x00\x00)\x05\x00\x00\x00\x80\x00\x00\x00\x80'

        nonce = "%x" % int(time.time()) + os.urandom(4).encode('hex')[4:]
        if corrupted:
            payload = corrupt(self.magic_query, self.pk, nonce, self.nmkey, message)
        else:
            payload = self.magic_query + self.pk + nonce + dnscrypt.encode_message(message, nonce, self.nmkey)

        #poly = poly1305.onetimeauth_poly1305(encoded_message, provider_pk[:32])  not quite sure if that's needed for something...

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        dest = (self.ip, self.port)

        sock.sendto(payload, dest)

def parse_args():
    parser = argparse.ArgumentParser(description='Fuzzer for DNSCrypt')
    parser.add_argument(
        '--provider-name', '-p',
        default='2.dnscrypt-cert.example.com',
        help='Provider name, default: %(default)s',
    )
    parser.add_argument(
        '--provider-key', '-k',
        help='Provider key',
        required=True,
    )
    parser.add_argument(
        '--host', '-H',
        default='127.0.0.1',
        help='DNS host to fuzz, default: %(default)s',
    )
    parser.add_argument(
        '--port', '-P',
        default=443, type=int,
        help='Port the dnscrypt service is running on, default: %(default)s',
    )
    parser.add_argument(
        '--queryfile', '-q',
        required=True,
        help='Path to the file containing query samples. Format: qname\tqtype. Example file available at https://nominum.com/measurement-tools/'
    )
    parser.add_argument(
        '--count', '-c',
        type=int,
        default=1000000,
        help='Number of queries to perform, default: %(default)s',
    )
    parser.add_argument(
        '--non-corrupted', '-C',
        type=int,
        default=1000,
        help='How often to not corrupt a query. 1 query every --non-corrupted query will be sent coorruption free. 0 for always corrupt, default: %(default)s',
    )
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    args.provider_key = args.provider_key.replace(':', '')
    d = DnsCrypt(args.host, args.port, args.provider_name, args.provider_key)

    queries = []
    with open(args.queryfile) as f:
        for l in f:
            qname, qtype = l.split()
            queries.append((codecs.escape_decode(qname)[0], qtypemap[qtype],))

    for i in xrange(args.count):
        corrupted = True
        if args.non_corrupted == 0 or random.randint(0, args.non_corrupted) == 0:
            corrupted = False
        q = random.choice(queries)
        try:
            r = d.query(q[0], q[1], corrupted=corrupted)
        except Exception:
            pdb.set_trace()

