#!/usr/bin/env python
# -*- coding:utf-8 -*-

from twisted.protocols import basic
from pprint import pprint as pp
import pdb

from twisted.internet import protocol
from twisted.application import service, internet

TTYLOGFILE = "/sys/kernel/security/hp/tty_output/all"

from twisted.internet.protocol import Protocol

class TTYServer(Protocol):
    def connectionMade(self):
        print("Got new client!")
    def connectionLost(self, reason):
        print("Connection lost")
    def dataReceived(self, line):
        l = repr(line)
        print(l)
        if line == "all\r\n":
            try:
                f = open(TTYLOGFILE, 'rb')
            except IOError:
                print("No such file: %s" % TTYLOGFILE)
                return
            while True:
                buf = f.read(64)
                self.transport.write(buf)
                self.transport.doWrite()
    def sendBuffer(self, buf):
        self.transport.write(buf)

factory = protocol.ServerFactory()
factory.protocol = TTYServer
factory.clients = []
factory.rooms = {}

#pdb.set_trace()
application = service.Application("ttyserver")
internet.TCPServer(8801, factory).setServiceParent(application)
