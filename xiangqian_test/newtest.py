#!/usr/bin/python

import socks
import time
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


SERVER_IP = '127.0.0.1'
SERVER_PORT = 1082


if __name__ == '__main__':
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, SERVER_IP, 1082)
    s.connect((SERVER_IP, SERVER_PORT))
    s.send(b'test')
    time.sleep(30)
    s.close()
