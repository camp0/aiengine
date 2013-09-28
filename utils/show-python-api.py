"""Shows the python api for aiengine """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import types
import sys
import inspect
sys.path.append("../src/")

import pyaiengine


if __name__ == '__main__':

	for mod in dir(pyaiengine):
		name = pyaiengine.__dict__.get(mod)
		if((inspect.isclass(name))and(type(name).__module__=="Boost.Python")):
			print name.__name__
			for m in dir(name):
				if(not m.startswith("__")):
					print "   |--->", m
	sys.exit(0)

