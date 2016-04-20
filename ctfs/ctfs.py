# -*- coding: utf-8 -*-

"""
author: janes
date: 2016/04/20

TODO:
[+] proxy
"""

import re

from common import getPublicTypeMembers
from common import filterStringValue
from common import getUnicode
from enums import HTTP_HEADER
from enums import HTTPMETHOD


### BURP ###

# Splitter used between requests in BURP log files
BURP_REQUEST_REGEX = r"={10,}\s+[^=]+={10,}\s(.+?)\s={10,}"

# Regex used for parsing XML Burp saved history items
BURP_XML_HISTORY_REGEX = r'<port>(\d+)</port>.+?<request base64="true"><!\[CDATA\[([^]]+)'

# Extensions
EXTENSIONS = ("gif", "jpg", "jpeg", "image", "jar", "tif", "bmp", "war", "ear", "mpg", "mpeg", "wmv", "mpeg", "scm", "iso", "dmp", "dll", "cab", "so", "avi", "mkv", "bin", "iso", "tar", "png", "pdf", "ps", "wav", "mp3", "mp4", "au", "aiff", "aac", "zip", "rar", "7z", "gz", "flv", "mov", "doc", "docx", "xls", "dot", "dotx", "xlt", "xlsx", "ppt", "pps", "pptx")

class Headers(dict):
    def __init__(self, header=None):
        headers = {
            HTTP_HEADER.ACCEPT_LANGUAGE : u'en-US,en;q=0.5',
            HTTP_HEADER.ACCEPT_ENCODING : u'gzip, deflate',
            HTTP_HEADER.ACCEPT : u'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            HTTP_HEADER.USER_AGENT : u'Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0'
        }
        if header:
            try:
                headers.update(header)
            except ValueError as e:
                print e

        self.update(headers)


def parseBurpLog(content):
    """
    Parses burp logs
    params:
        content[str]: Burp log content
    return:
        {url, method, params, data, cookies, headers}
    """

    if not re.search(BURP_REQUEST_REGEX, content, re.I | re.S):
        # search XML
        if re.search(BURP_XML_HISTORY_REGEX, content, re.I | re.S):
            req_list = []
            for match in re.finditer(BURP_XML_HISTORY_REGEX, content, re.I | re.S):
                port, request = match.groups()
                request = request.decode("base64")
                _ = re.search(r"%s:.+" % re.escape(HTTP_HEADER.HOST), request)
                if _:
                    host = _.group(0).strip()
                    if not re.search(r":\d+\Z", host):
                        request = request.replace(host, "%s:%d" % (host, int(port)))
                req_list.append(request)
        else:
            # the most common sense
            req_list = [content]
            return _parse(content)
    else:
        req_list = re.finditer(BURP_REQUEST_REGEX, content, re.I | re.S)

    print "not common sense"
    for match in req_list:
        print _parse(match)
    return None

def _parse(match):
    request = match if isinstance(match, basestring) else match.group(0)
    request = re.sub(r"\A[^\w]+", "", request)

    # not match HTTP method
    if not re.search(r"^[\n]*(%s).*?\sHTTP\/" % "|".join(getPublicTypeMembers(HTTPMETHOD, True)), request, re.I | re.M):
        return None

    scheme_port = re.search(r"(http[\w]*)\:\/\/.*?\:([\d]+).+?={10,}", request, re.I | re.S)
    if scheme_port:
        scheme = scheme_port.group(1)
        port = scheme_port.group(2)
    else:
        scheme, port = None, None

    url = None
    host = None
    method = None
    cookies = None
    data = None
    params = {}
    headers = {}

    lines = request.split('\n')
    newline = None

    for index in xrange(len(lines)):
        line = lines[index]

        if not line.strip() and index == len(lines) - 1:
            break

        newline = "\r\n" if line.endswith('\r') else '\n'
        line = line.strip('\r')
        match = re.search(r"\A(%s) (.+) HTTP/[\d.]+\Z" % "|".join(getPublicTypeMembers(HTTPMETHOD, True)), line) if not method else None

        if len(line.strip()) == 0 and method and method != HTTPMETHOD.GET and data is None:
            data = ""

        elif match:
            method = match.group(1)
            url = match.group(2)
            if '=' in url and '?' in url:
                url, param = url.split('?', 1)
                params = _parse_params(param)

        # POST parameters
        elif data is not None:
            data += "%s%s" % (line, newline)

        # GET parameters
        elif "?" in line and "=" in line and ": " not in line:
            params = _parse_params(line.split('?', 1)[1])

        # Headers
        elif re.search(r"\A\S+:", line):
            key, value = line.split(":", 1)
            value = value.strip().replace("\r", "").replace("\n", "")

            # Cookie and Host headers
            if key.upper() == HTTP_HEADER.COOKIE.upper():
                cookies = value
            elif key.upper() == HTTP_HEADER.HOST.upper():
                if '://' in value:
                    scheme, value = value.split('://')[:2]
                splitValue = value.split(":")
                host = splitValue[0]

                if len(splitValue) > 1:
                    port = filterStringValue(splitValue[1], "[0-9]")

            # Avoid proxy, static content length  and connection type related headers
            if key not in (HTTP_HEADER.PROXY_CONNECTION, HTTP_HEADER.CONNECTION, HTTP_HEADER.CONTENT_LENGTH):
                headers[getUnicode(key)] = getUnicode(value)

    # post data
    data = data.rstrip("\r\n") if data else data
    if data:
        data = _parse_params(data)
    data = data if data else {}

    if not port and isinstance(scheme, basestring) and scheme.lower() == "https":
        port = "443"
    elif not scheme and port == "443":
        scheme = "https"

    if not host:
        err_msg = "invalid format of a request file"
        print(err_msg)
        return None

    if not url.startswith("http"):
        url = "%s://%s:%s%s" % (scheme or "http", host, port or "80", url)

    ret_dict = {}
    ret_dict['url'] = url
    ret_dict['headers'] = headers
    ret_dict['cookies'] = cookies
    ret_dict['method'] = method
    ret_dict['params'] = params
    ret_dict['data'] = data

    return ret_dict

def _parse_params(data):
    """
    parse get or post data
    params:
        data[str]: get or post parameters' data like "username=a&passowrd=a"
    return:
        data[dict]: { 'username': 'a', 'password': 'a'}
    """
    payload = {}
    for p in data.split('&'):
        try:
            key, value = p.split('=')
            payload[key] = value
        except ValueError:
            err_msg = "parse post data error"
            print err_msg
    return payload
