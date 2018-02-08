#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import errno
import traceback
import socket
import logging
import json
import collections
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), './crypto'))

from shadowsocks import common, eventloop, tcprelay, udprelay, asyncdns, shell
BUF_SIZE = 1506
STAT_SEND_LIMIT = 100

def testudp():
    import time
    import threading
    import struct
    from shadowsocks import encrypt

    logging.basicConfig(level=5,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    print("send packet")
    
    header = common.pack_addr(b'127.0.0.1') + struct.pack('>H', 80)
    data = b'\x05\x03\x00\x03\x0ewww.google.com\x00\x50'
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #udp_cli.sendto(json.dumps(data).encode(), ('127.0.0.1', 1082))
    udp.sendto(data, ('127.0.0.1', 1082))
    print("data : ", data)
    udp.close()
    
def testtcp():
    import time
    import threading
    import struct
    from shadowsocks import encrypt

    logging.basicConfig(level=5,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    '''
    1. NEGO.
    client---->ss-local start a connection
    negotiate with sock5 protocal
    +-----+---------------+-----------------+
    | VER |    NMETHODS   |     METHODS     |
    +-----+---------------+-----------------+
    | 1   |      1        |    1 to 255     |
    +-----+---------------+-----------------+
    version is  x05
    nmethods is x01 : methods's length is 1
    methods is  x00 : no authentication required
                x01 : gssapi
                x02 : username/password
                x03 : to x7f IANA assigned
                x04 : to xfe reserved for private methods
                xff : no acceptable methods
    eg:b'\x05\x02\x00\02'  b'\x05\x01\x00'

    the ss-local as server receives the req, selects one of the methods,
    then send the message as response to client. The method here is x00.
    +-----+---------------+
    | VER |     METHOD    |
    +-----+---------------+
    | 1   |      1        |
    +-----+---------------+
    version is  x05
    methods is  x00

    2.client send request
    After Nego, the client sends the request detail. The req as follows:
    +-----+-----+-----+------+----------+----------+
    | VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
    +-----+-----+-----+------+----------+----------+
    |  1  |  1  | X00 |   1  |   Var    |     2    |
    +-----+-----+-----+------+----------+----------+
    VER:  protocol version:x05
    
    CMD
        1.CONNECT       x01
        2.BIND          x02
        3.UDP ASSOCIATE x03
        
    RSV:  reserved
    
    ATYP: address type of following address
        1.IPV4 addr     x01   (4bytes)
        2.domainname    x03   (variable len)
        3.IPV6 addr     x04   (16bytes)
        
    DST.ADDR: desired destination address.(client request dest addr)
        1.ATYP=x01-->ipv4 addr  with a length of 4 octets(4 bytes)
        2.ATYP=x03-->domainname DST.ADDR: len(1 byte) + domain
        +--------------+
        |  DST.ADDR    |
        +--------------+
        | len  |domain |
        +--------------+
        3.ATYP=x04-->ipv6 addr  with a length of 16 octets(16 bytes)
        
    DST.PORT: desired destination port in network octet order. (2bytes)

    3.ss-local(as server) send reply
    when ss-local as server of socks5 receive the request of client,
    it returns a reply formed as follows:
    +-----+-----+-----+------+----------+----------+
    | VER | REP | RSV | ATYP | BND.ADDR | BND.PORT |
    +-----+-----+-----+------+----------+----------+
    |  1  |  1  | X00 |   1  |   Var    |     2    |
    +-----+-----+-----+------+----------+----------+

    VER:  protocol version: x05
    
    REP:
        1.x00: succeeded
        2.x01: general SOCKS server failure
        3.x02: connection not allowed by ruleset
        4.x03: network unreachable
        5.x04: host unreachable
        6.x05: connection refused
        7.x06: TTL expired
        8.x07: command not supported
        9.x08: address type not supported
        10.x09:to xff unassigned
        
    RSV:  reserved
    
    ATYP: address type of following address
        1.IPV4 addr     x01   (4bytes)
        2.domainname    x03   (variable len)
        3.IPV6 addr     x04   (16bytes)
        
    BND.ADDR: server bound address
    BND.PORT: server bound port in network octet order.it contains
              the port that socks server assigned to connect to the
              target host.
    
    '''
    nego_req = b'\x05\x02\x00\x02'
    data_req = b'\x05\x01\x00\x03\x11www.google.com.hk\x01\xbb'
    
    #connect to the ss-local server
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect(('127.0.0.1', 1082))

    #nego
    tcp.send(nego_req)
    time.sleep(1)

    #recv socks server nego reply
    nego_resp = tcp.recv(1024)
    print("nego_resp:", nego_resp)

    #send detail request
    print("send detail request : ", data_req)
    tcp.send(data_req)
    time.sleep(1)

    #recv socks server req reply
    read_server_response = tcp.recv(1024)
    print("ecv socks server req reply: ", read_server_response)

    time.sleep(20)
    #recv socks server req reply
    read_server_response = tcp.recv(1024)
    print("ecv socks server req reply: ", read_server_response)
    tcp.close()
    
if __name__ == '__main__':
    testtcp()
