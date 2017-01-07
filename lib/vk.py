# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
from urllib.parse import urlencode


class API(object):
    def __init__(self, token=None, version='5.60', **kwargs):
        self.__token = token
        self.__version = version
        self.__method = kwargs.get('method', '')

    def get_url(self, method=None, **kwargs):
        kwargs.setdefault('v', self.__version)

        if self.__token is not None:
            kwargs.setdefault('access_token', self.__token)

        return 'https://api.vk.com/method/{}?{}'.format(
            method or self.__method, urlencode(kwargs)
        )

    def request(self, method, **kwargs):
        kwargs.setdefault('v', self.__version)

        if self.__token is not None:
            kwargs.setdefault('access_token', self.__token)

        return requests.get(self.get_url(method, **kwargs)).json()

    def __getattr__(self, attr):
        method = ('{}.{}'.format(self.__method, attr)).lstrip('.')
        return API(self.__token, version=self.__version, method=method)

    def __call__(self, **kwargs):
        return self.request(self.__method, **kwargs)
