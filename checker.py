# _*__author__ coding: utf-8 -*-
from compiler.syntax import check
import random
import string

__author__ = 'alexey'

from themis.checker import Server, Result
import struct
import socket
import StringIO
import gzip


def pack_string(str):
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode='w') as f:
        f.write(unicode(str, "utf-8"))
    return out.getvalue()


def INSERT(sock, key, value):
    payload = pack_string(key + ";" + value)
    data = struct.pack("!Bi", 0, len(payload))
    sock.send(data)
    sock.send(payload)
    answer = sock.recv(1)
    return struct.unpack("!B", answer)[0]


def CHECK(sock, key):
    payload = pack_string(key)
    data = struct.pack("!Bi", 1, len(payload))
    sock.send(data)
    sock.send(payload)
    answer = sock.recv(1)
    return struct.unpack("!B", answer)[0]


def DELETE(sock, key):
    payload = pack_string(key)
    data = struct.pack("!Bi", 2, len(payload))
    sock.send(data)
    sock.send(payload)
    answer = sock.recv(1)
    return struct.unpack("!B", answer)[0]


def SELECT(sock, key):
    payload = pack_string(key)
    data = struct.pack("!Bi", 3, len(payload))
    sock.send(data)
    sock.send(payload)
    answer = sock.recv(8192)
    return unicode(answer)


def genkey():
    return ''.join(random.choice(string.ascii_letters) for i in range(random.randint(25, 35)))


class StupidDBChecker(Server):
    def push(self, endpoint, flag_id, flag):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((endpoint, 5010))
            # check full protocol
            key = genkey()
            value = genkey()
            res = INSERT(sock, key, value)
            if res != 0:
                return Result.CORRUPT,""
            res = CHECK(sock, key)
            if res != 0:
                return Result.CORRUPT,""
            res = DELETE(sock,key)
            if res != 0:
                return Result.CORRUPT,""
            res = CHECK(sock,key)
            if res != 1:
                return Result.CORRUPT,""
            flag_key = genkey()
            res = INSERT(sock,flag_key,flag)
            if res != 0:
                return Result.CORRUPT,""
            res = CHECK(sock,flag_key)

            if res !=0:
                return Result.CORRUPT, ""
            else:
                return Result.UP, flag_key
        except socket.error:
            return Result.DOWN, ""
        except:
            return Result.MUMBLE, ""

    def pull(self, endpoint, flag_id, flag):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((endpoint, 5010))
            res = SELECT(sock, flag_id)
            if res == flag:
                return Result.UP
            else:
                return Result.CORRUPT
        except socket.error:
            return Result.DOWN, ""
        except:
            return Result.MUMBLE, ""

checker = StupidDBChecker()
checker.run()
