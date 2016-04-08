#!/bin/bash python
# -*- coding:utf-8 -*-

"""
author: janes
date: 2016/04/08

todo: 高级搜索
"""

import logging
import hashlib
import json
import sys

import requests

from exploit import joomla

reload(sys)
sys.setdefaultencoding("utf-8")

logging.basicConfig(level=logging.INFO, format='%(message)s')


class Shadan(object):
    """
    """
    def __init__(self, user, passwd):
        # login must use https
        self.url = "https://www.oshadan.com/"
        self.session = requests.session()
        self.header = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate br",
        }
        self.login(user, passwd)

    def fetch_cookie(self):
        """get cookie from server's response
        """
        headers = {
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
        }
        headers.update(self.header)
        try:
            resp = self.session.get(self.url, headers=headers)
            if resp.status_code != 200:
                err_msg = "[-] response code is not 200"
                logging.error(err_msg)
        except Exception as e:
            err_msg = "[-] visit shadan error: {}".format(e)
            logging.error(err_msg)

    def login(self, user, passwd):
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.oshadan.com/login",
            "Connection": "keep-alive"
        }
        headers.update(self.header)
        login_url = self.url + 'validateLogin'

        # rand is nouse, can be any in [1-9,A-Z]
        rand = '13BW'
        md5 = hashlib.md5()
        md5.update(passwd)
        passwd = md5.hexdigest()[4:] + rand

        info = {
            "username": user,
            "password": passwd,
            "code": "",
            "autologin": False
        }

        # post data is json
        payload = {
            "info": json.dumps(info)
        }

        # fetch cookie and login
        self.fetch_cookie()
        try:
            resp = self.session.post(login_url, headers=headers, data=payload)
            respjson = resp.json()
        except Exception as e:
            err_msg = "[-] login error: {}".format(e)
        else:
            if respjson['type'] == 'success':
                print("[+] Login success")
            else:
                err_msg = "[-] Login failed: "
                err_msg += "{}".format(respjson['content'].encode('utf-8'))
                logging.error(err_msg)

    def search(self, keyword, page):
        """
        params:
            keyword[str]: search keyword
            page[int]: page of result
        """
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.oshadan.com/main",
            "Connection": "keep-alive"
        }
        headers.update(self.header)
        serch_url = self.url + "search"

        # q=0 全网搜索, 1 监测站点搜索
        # p: page index
        info = {
            "c": keyword,
            "q": 0,
            "clear": False,
            "p": page
        }

        params = {
            "info": json.dumps(info)
        }

        # return the result
        result = None

        try:
            resp = self.session.get(serch_url, headers=headers, params=params)
            respjson = resp.json()
            self.respjson = respjson
        except Exception as e:
            err_msg = "[-]: search {k} error: {e}".format(k=keyword, e=e)
            logging.error(err_msg)
        else:
            if respjson['type'] == 'success':
                result_num = int(respjson['result']['result']['recordNum'])
                if page == 1:
                    print("[*] get {} records".format(result_num))

                if result_num != 0:
                    # result is a list
                    result = respjson['result']['result']['data']

                # has been fetched all result
                if page*10 > result_num:
                    result = None
            else:
                err_msg = "[-] search failed\n\t{}".format(resp.content)
                logging.error(err_msg)

        return result

    def exploit(self, data):
        joomla_rce = joomla.Joomla_rce()
        for raw in data:
            result = self.parse(raw)
            if result:
                url = result[0] + "://" + result[1]
                joomla_rce.check(url)
        joomla_rce.report()

    def savefile(self, filename, data):
        """
        params:
            filename[str]
            data[list]:
        """
        with open(filename, 'a') as f:
            for raw in data:
                result = self.parse(raw)
                if result:
                    f.write("\t".join(result) + "\n")

    def parse(self, data):
        """parse the return data
        params:
            data[dict]
        return:
            [scheme, url, ip, port, country] or None
        """
        msg = data['notcomponentFields']
        # component = data['componentFields']
        ip = msg.get('ip')
        port = msg.get('port')
        if all((ip, port)):
            ip = ip.split(":")[1]
            port = port.split(":")[1]

            host = msg.get('host', 'null')
            if host != 'null':
                scheme = host.split('://')[0]
                url = host.split('://')[1]

            country = msg.get('country', 'null')
            if country != 'null':
                index = msg.get('country').find('>')
                country = country[index+1:]
            return [scheme, url, ip, port, country]
        else:
            return None


if __name__ == "__main__":
    """example
    s = Shadan('username', 'password')
    s.search('key')
    """

    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', dest='uname', required=True,
                help="login shadan, username")
    parser.add_argument('-p', dest='passwd', required=True,
                help="login shadan, password")
    parser.add_argument('-s', '--search', dest='keyword', required=True,
                help="search keyword")
    parser.add_argument('-pg', '--pages', dest='pages', type=int, default=5,
                help="fetch pages of result, 0 denote all pages, default is 5")
    parser.add_argument('--exploit', dest='exploit', action='store_true',
                help="so far, just support exploit joomla remote code exploit")
    args = parser.parse_args()

    username = args.uname
    password = args.passwd
    keyword = args.keyword
    pages = args.pages
    exploit = args.exploit

    s = Shadan(username, password)

    # 0 denote fetch all pages
    if pages == 0:
        pages = 1000000

    for page in xrange(1, pages+1):
        result = s.search(keyword, page)
        if result == None :
            break

        print("[*] save page {} to file ...".format(page))
        s.savefile(keyword+'.txt', result)

        if exploit:
            s.exploit(result)

    print("[+] search finished")
