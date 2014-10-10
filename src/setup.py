"""
    https://www.cac.cornell.edu/wiki/index.php?title=Python_Distutils_Tips
"""

import os
import sys
import distutils.sysconfig
from distutils.core import setup
from distutils.extension import Extension

""" List of the files of the lib """
src_files =  ["Multiplexer.cc","FlowForwarder.cc","PacketDispatcher.cc","Flow.cc","Protocol.cc"]
src_files += ["Signature.cc","Interpreter.cc","NetworkStack.cc"]
src_files += ["./flow/FlowManager.cc","./ethernet/EthernetProtocol.cc","./vlan/VLanProtocol.cc","./mpls/MPLSProtocol.cc"]
src_files += ["./ip/IPProtocol.cc","./ipset/IPAbstractSet.cc","./ipset/IPSet.cc","./ipset/IPBloomSet.cc","./ipset/IPSetManager.cc"]
src_files += ["./ip6/IPv6Protocol.cc","./icmp6/ICMPv6Protocol.cc","./icmp/ICMPProtocol.cc","./udp/UDPProtocol.cc","./tcp/TCPProtocol.cc"]
src_files += ["./tcpgeneric/TCPGenericProtocol.cc","./udpgeneric/UDPGenericProtocol.cc"]
src_files += ["./gre/GREProtocol.cc","./vxlan/VxLanProtocol.cc"]
src_files += ["./gprs/GPRSProtocol.cc","./http/HTTPProtocol.cc","./ssl/SSLProtocol.cc","./dns/DNSProtocol.cc"]
src_files += ["./regex/Regex.cc","./regex/RegexManager.cc","./frequency/FrequencyProtocol.cc"]
src_files += ["./frequency/FrequencyCounter.cc","./learner/LearnerEngine.cc","./names/DomainNameManager.cc"]
src_files += ["System.cc","StackMobile.cc","StackLan.cc","StackLanIPv6.cc","StackVirtual.cc"]
src_files += ["py_wrapper.cc"]

def setup_compiler():
    distutils.sysconfig.get_config_vars()
    config_vars = distutils.sysconfig._config_vars

    includes = list()
    macros = list()

    macros.append(('PYTHON_BINDING','1'))
    macros.append(('HAVE_LIBPCRE','1'))
    macros.append(('HAVE_ADAPTOR','1'))
    includes.append("..")

    if (sys.platform == 'sunos5'):
        config_vars['LDSHARED'] = "gcc -G"
        config_vars['CCSHARED'] = ""
    elif (sys.platform == 'freebsd10'):
        os.environ["CC"] = "c++"
        includes.append("/usr/local/include")
        macros.append(('__FREEBSD__','1'))
    elif (sys.platform == 'openbsd5'):
        macros.append(('__OPENBSD__','1'))
        os.environ["CC"] = "eg++"
    else:
        os.environ["CC"] = "g++"

    return includes,macros

aiengine_module = Extension("pyaiengine",
    sources = src_files,
    libraries = ["boost_system","boost_python","pcap","pcre"],
#    define_macros = [('__OPENBSD__','1'),('PYTHON_BINDING','1'),('HAVE_LIBPCRE','1')],
    # define_macros = [('PYTHON_BINDING','1'),('HAVE_LIBPCRE','1')],
    extra_compile_args = ["-Wreorder","-std=c++11","-lpthread","-lstdc++"],
    )

if __name__ == "__main__":

    includes,macros = setup_compiler()

    print("Compiling aiengine extension for %s" % sys.platform)
    print("\tOS name %s" % (os.name))
    print("\tArchitecture %s" % os.uname()[4])

    aiengine_module.include_dirs = includes
    aiengine_module.define_macros = macros

    setup(name="aiengine",
        version = "0.10",
        author = "Luis Campo Giralte",
        author_email = "luis.camp0.2009 at gmail.com",
        url = "https://bitbucket.org/camp0/aiengine",
        license = "GPLv2",
        package_dir = {'': '.'},
        description = "Wrapper for the aiengine",
        long_description = open('../README.md').read(),
        ext_modules = [aiengine_module],
        py_modules = ["pyaiengine"],
        classifiers=[
            "Development Status :: 0.10 - Beta",
            "Environment :: Console",
            "Intended Audience :: Information Technology",
            "Intended Audience :: Science/Research",
            "Intended Audience :: System Administrators",
            "Intended Audience :: Telecommunications Industry",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
            "Operating System :: POSIX :: BSD :: FreeBSD",
            "Operating System :: POSIX :: Linux",
            "Programming Language :: C++",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3.3",
            "Programming Language :: Python :: 3.4",
            "Topic :: Internet",
            "Topic :: Scientific/Engineering :: Information Analysis",
            "Topic :: Security",
            "Topic :: System :: Networking",
            "Topic :: System :: Networking :: Monitoring",
          ],
    )

