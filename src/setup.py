"""
    https://www.cac.cornell.edu/wiki/index.php?title=Python_Distutils_Tips
"""

import os
import sys
import distutils.sysconfig
from distutils.core import setup
from distutils.extension import Extension

""" List of the files of the lib """
head_files =  ["Multiplexer.h","FlowForwarder.h","PacketDispatcher.h","Flow.cc","Protocol.h","Signature.h"]

src_files =  ["Multiplexer.cc","FlowForwarder.cc","PacketDispatcher.cc","Flow.cc","Protocol.cc","Signature.cc","Interpreter.cc"]
src_files += ["./flow/FlowManager.cc","./ethernet/EthernetProtocol.cc","./vlan/VLanProtocol.cc","./mpls/MPLSProtocol.cc"]
src_files += ["./ip/IPProtocol.cc","./ipset/IPSet.cc","./ipset/IPBloomSet.cc","./ipset/IPSetManager.cc"]
src_files += ["./ip6/IPv6Protocol.cc","./icmp/ICMPProtocol.cc","./udp/UDPProtocol.cc","./tcp/TCPProtocol.cc"]
src_files += ["./tcpgeneric/TCPGenericProtocol.cc","./udpgeneric/UDPGenericProtocol.cc"]
src_files += ["./gprs/GPRSProtocol.cc","./http/HTTPProtocol.cc","./ssl/SSLProtocol.cc","./dns/DNSProtocol.cc"]
src_files += ["./regex/Regex.cc","./regex/RegexManager.cc","./frequency/FrequencyProtocol.cc"]
src_files += ["./frequency/FrequencyCounter.cc","./learner/LearnerEngine.cc","./names/DomainNameManager.cc"]
src_files += ["System.cc","StackMobile.cc","StackLan.cc","StackLanIPv6.cc"]
src_files += ["py_wrapper.cc"]

def setup_compiler():
    distutils.sysconfig.get_config_vars()
    config_vars = distutils.sysconfig._config_vars
    
    if sys.platform == 'sunos5':
        config_vars['LDSHARED'] = "gcc -G"
        config_vars['CCSHARED'] = ""

    """
    print config_vars
    for item,val in config_vars.iteritems():
        print item,val 
    print config_vars['CCSHARED']
    print config_vars['PY_CFLAGS']
    print config_vars['CFLAGS']
    """

    os.environ["CC"] = "g++"

aiengine_module = Extension("pyaiengine",
    sources = src_files,
    include_dirs = [".."],
    libraries = ["boost_system","boost_python","pcap","pcre"],
    define_macros = [('HAVE_CONFIG_H','1'),('PYTHON_BINDING','1')],
    extra_compile_args = ["-Wreorder","-std=c++11","-lpthread","-lstdc++"],
    )

if __name__ == "__main__":

    setup_compiler()

    print("Compiling aiengine extension for %s" % sys.platform)
    print("\tOS name %s" % os.name)
    print("\tArchitecture %s" % os.uname()[4])

    setup(name="aiengine",
        version = "0.8",
        author = "Luis Campo Giralte",
        author_email = "luis.camp0.2009 at gmail.com",
        url = "https://bitbucket.org/camp0/aiengine",
        license = "GPLv2",
        package_dir = {'': '.'},
        package_data = {"" : ["*.h","flow/*.h"] },
        description = "Wrapper for the aiengine",
        long_description = open('../README.md').read(),
        ext_modules = [aiengine_module],
        py_modules = ["pyaiengine"],
    )

