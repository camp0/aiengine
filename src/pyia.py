"""Example script for integrate the firesql with other systems """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import signal
import sys
import pyiaengine

def loadSignaturesForTcp():
	sm = pyiaengine.SignatureManager()


if __name__ == '__main__':

	st = pyiaengine.StackLan()

	pdis = pyiaengine.PacketDispatcher()



	pdis.setStack(pyiaengine.NetworkStack(st))

	print dir(pdis)
	sys.exit(0)

