# !/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import logging
import json
from time import sleep
from threading import Thread
from queue import Queue
from lib import cons
from lib import aes
from lib import vk


# check json data from client
def valid_json(j):
    if "method" and "params" and "token" in j.keys():
        return True
    return False


# data handler
def handler(_cs, _addr):
    global q
    try:
        data = _cs.recv(cons.BUFF)
        sdata = data.decode("utf-8").split(" ")
        ldata = ([int(x) for x in sdata])
        decr = cipher.decrypt(ldata, False, cipher.modeOfOperation["OFB"], cons.CKEY,
                              cipher.aes.keySize["SIZE_256"], cons.IV)
        j = json.loads(decr)
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
        mode, orig_len, ciph = cipher.encrypt(json.dumps(exc), cipher.modeOfOperation["OFB"], cons.CKEY,
                                              cipher.aes.keySize["SIZE_256"], cons.IV)
        _cs.send(" ".join(str(x) for x in ciph).encode())
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

    # cipher
    cipher = aes.AESModeOfOperation()

    # command list queue
    q = Queue()
    t = Thread(target=worker)
    t.start()

    while 1:
        cs, addr = sock.accept()
        cs.settimeout(cons.FTIMEOUT)
        logging.info("{addr} opened".format(addr=addr))
        t = Thread(target=handler, args=(cs, addr,))
        t.start()
        q.join()
        t.join()
