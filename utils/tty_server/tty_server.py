#!/usr/bin/env python
# -*- coding:utf-8 -*-

from twisted.protocols import basic
from pprint import pprint as pp
import pdb

from twisted.internet import protocol
from twisted.application import service, internet

TTYLOGFILE = "/sys/kernel/security/hp/tty_output/all"
SERVER_PORT=8080

from twisted.internet.protocol import Protocol

class TTYServer(Protocol):
    """
    TTY Server
    Reads the logfile from special device TTYLOGFILE and
    sends the data to client directly.
    """
    def connectionMade(self):
        print("Got new client!")
        try:
            self.f = open(TTYLOGFILE, 'rb')
        except IOError:
            print("No such file: %s" % TTYLOGFILE)
            return
        return

    # Never be called
    def connectionLost(self, reason):
        print("Connection lost")
        self.f.close()

    def dataReceived(self, line):
        for i in range(10):
            try:
                buf = self.f.read(64)
                self.sendBuffer(buf)
            except IOError:
                print("IOError when connectionMade");
                break
        l = repr(line)
        print(l)

    def sendBuffer(self, buf):
        self.transport.write(buf)
        self.transport.doWrite()
#        self.printBufferHex(buf)

    def printBufferHex(self, buf):
        s = ""
        for c in buf:
            s += "%2x|" % ord(c)
        print("\n%s" % s)

def printConfig():
    print("Log file %s" % TTYLOGFILE)
    print("Server port %s" % SERVER_PORT)

printConfig()
factory = protocol.ServerFactory()
factory.protocol = TTYServer
factory.clients = []
factory.rooms = {}

print("start server...")
application = service.Application("ttyserver")
internet.TCPServer(SERVER_PORT, factory).setServiceParent(application)

