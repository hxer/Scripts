# -*- coding: utf-8 -*-

from ctfs import parseBurpLog

with open('burp.txt') as f:
    text = f.read()
    print parseBurpLog(text)
