# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# server listen port
LISTEN_PORT = 55555

# server max connections
MAX_CONN = 64

# max input length
BUFF = 1024

# logging format
LOGFORMAT = '%(levelname)-10s [%(asctime)s] (%(threadName)-10s) %(message)s'

# force read data timeout
FTIMEOUT = 5.0

# vk api requests timeout
VTIMEOUT = 0.35

# cipher key
CKEY = [209, 29, 254, 94, 11, 249, 63, 126, 79, 224, 139, 81, 11, 192, 56, 24, 90, 78, 125, 41, 118, 152, 135, 186, 135,
        44, 45, 54, 228, 103, 37, 23]

# cipher Initilization Vector
IV = [241, 85, 3, 248, 71, 240, 32, 213, 228, 243, 87, 155, 158, 90, 254, 5]
