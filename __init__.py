# !/usr/bin/env python3
# -*- coding: utf-8 -*-

import ssl
import socket
import logging
import json
import sys
from time import sleep
from threading import Thread
from queue import Queue
from core import cons
from core import vk


# check json data from client
def valid_json(j):
    if "method" and "params" and "token" in j.keys():
        return True
    return False


# data handler
def handler(_cs, _addr):
    global q
    try:
        data = _cs.recv(cons.BUFF).decode("utf-8")
        j = json.loads(data)
        if valid_json(j):
            q.put((j, _cs))
        else:
            pass
    except socket.timeout:
        logging.warning("{addr} timeout".format(addr=_addr))
    except json.decoder.JSONDecodeError:
        logging.warning("{addr} not a json data".format(addr=_addr))
    logging.info("{addr} closed".format(addr=_addr))


def worker():
    while True:
        item, _cs = q.get()
        api = vk.API(token=item["token"])
        exc = getattr(api, item["method"])(**item["params"])
        _cs.send(json.dumps(exc).encode())
        _cs.close()
        sleep(cons.VTIMEOUT)
        q.task_done()

if __name__ == '__main__':
    # logging
    logging.basicConfig(level=logging.DEBUG, format=cons.LOGFORMAT)
    file_handler = logging.FileHandler('results.log')
    file_handler.setFormatter(logging.Formatter(cons.LOGFORMAT))
    logging.getLogger().addHandler(file_handler)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("requests.packages.urllib3.connectionpool").setLevel(logging.WARNING)

    # socket params
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", cons.LISTEN_PORT))
    sock.listen(cons.MAX_CONN)

    # command list queue
    q = Queue()
    t = Thread(target=worker)
    t.start()

    while 1:
        cs, addr = sock.accept()
        cs.settimeout(cons.FTIMEOUT)
        logging.info("{addr} opened".format(addr=addr))
        try:
            ssl_wrap = ssl.wrap_socket(cs, keyfile=cons.SSL_KEY, certfile=cons.SSL_CRT, server_side=True)
        except Exception as e:
            logging.critical("exception: {e}".format(e=e))
            sys.exit(1)
        t = Thread(target=handler, args=(ssl_wrap, addr,))
        t.start()
        q.join()
        t.join()
