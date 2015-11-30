"""
    https://www.cac.cornell.edu/wiki/index.php?title=Python_Distutils_Tips
"""

import os
import sys
import distutils.sysconfig
# from distutils.core import Command
from distutils.core import setup, Command
from distutils.extension import Extension
# from setuptools import setup

""" List of the files of the lib """
src_files =  ["Multiplexer.cc","FlowForwarder.cc","PacketDispatcher.cc","Flow.cc","Protocol.cc"]
src_files += ["Callback.cc","Interpreter.cc","NetworkStack.cc","EvidenceManager.cc","CacheManager.cc","AnomalyManager.cc"]
src_files += ["flow/FlowManager.cc"] 
src_files += ["protocols/ethernet/EthernetProtocol.cc"]
src_files += ["protocols/vlan/VLanProtocol.cc"]
src_files += ["protocols/mpls/MPLSProtocol.cc"]
src_files += ["protocols/ip/IPProtocol.cc"]
src_files += ["ipset/IPAbstractSet.cc","ipset/IPSet.cc","ipset/IPBloomSet.cc","ipset/IPSetManager.cc"]
src_files += ["protocols/ip6/IPv6Protocol.cc"]
src_files += ["protocols/icmp6/ICMPv6Protocol.cc"]
src_files += ["protocols/icmp/ICMPProtocol.cc"]
src_files += ["protocols/udp/UDPProtocol.cc","protocols/tcp/TCPProtocol.cc"]
src_files += ["protocols/tcpgeneric/TCPGenericProtocol.cc","protocols/udpgeneric/UDPGenericProtocol.cc"]
src_files += ["protocols/gre/GREProtocol.cc","protocols/vxlan/VxLanProtocol.cc","protocols/openflow/OpenFlowProtocol.cc"]
src_files += ["protocols/gprs/GPRSProtocol.cc"]
src_files += ["protocols/http/HTTPProtocol.cc"]
src_files += ["protocols/http/HTTPUriSet.cc"]
src_files += ["protocols/ssl/SSLProtocol.cc"]
src_files += ["protocols/smtp/SMTPProtocol.cc"]
src_files += ["protocols/imap/IMAPProtocol.cc"]
src_files += ["protocols/pop/POPProtocol.cc"]
src_files += ["protocols/dns/DNSProtocol.cc"]
src_files += ["protocols/sip/SIPProtocol.cc"]
src_files += ["protocols/dhcp/DHCPProtocol.cc"]
src_files += ["protocols/ntp/NTPProtocol.cc"]
src_files += ["protocols/snmp/SNMPProtocol.cc"]
src_files += ["protocols/ssdp/SSDPProtocol.cc"]
src_files += ["regex/Regex.cc","regex/RegexManager.cc","protocols/frequency/FrequencyProtocol.cc"]
src_files += ["protocols/frequency/FrequencyCounter.cc","learner/LearnerEngine.cc"]
src_files += ["names/DomainName.cc","names/DomainNameManager.cc"]
src_files += ["System.cc","StackMobile.cc","StackLan.cc","StackLanIPv6.cc","StackVirtual.cc","StackOpenFlow.cc"]
src_files += ["python_wrapper.cc"]

class SetupBuildCommand(Command):
    """
    Master setup build command to subclass from.
    """

    user_options = []

    def initialize_options(self):
        """
        Setup the current dir.
        """
        self._dir = os.getcwd()

    def finalize_options(self):
        """
        Set final values for all the options that this command supports.
        """
        pass

class TODOCommand(SetupBuildCommand):
    """
    Quick command to show code TODO's.
    """

    description = "prints out TODO's in the code"

    def run(self):
        """
        Prints out TODO's in the code.
        """
        import re

        # The format of the string to print: file_path (line_no): %s line_str
        format_str = "%s (%i): %s"
        # regex to remove whitespace in front of TODO's
        remove_front_whitespace = re.compile("^[ ]*(.*)$")

        # Look at all non pyc files in src/ and bin/
        for rootdir in ['./']:
            # walk down each root directory
            for root, dirs, files in os.walk(rootdir):
                # for each single file in the files
                for afile in files:
                    # if the file doesn't end with .pyc
                    if ((afile.endswith('.cc')) or (afile.endswith('.h'))):
                    #if not afile.endswith('.pyc'):
                        full_path = os.path.join(root, afile)
                        fobj = open(full_path, 'r')
                        line_no = 0
                        # look at each line for TODO's
                        for line in fobj.readlines():
                            if 'todo' in line.lower():
                                nice_line = remove_front_whitespace.match(
                                    line).group(1)
                                # print the info if we have a TODO
                                print(format_str % (
                                    full_path, line_no, nice_line))
                            line_no += 1

def setup_compiler():
    distutils.sysconfig.get_config_vars()
    config_vars = distutils.sysconfig._config_vars

    includes = list()
    macros = list()

    macros.append(('PYTHON_BINDING','1'))
    macros.append(('HAVE_ADAPTOR','1'))
    includes.append(".")
    includes.append("..")
    includes.append("../..")

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
    elif (sys.platform == 'darwin'):
        macros.append(('__DARWIN__','1'))
        os.environ["CC"] = "g++"
    else:
        os.environ["CC"] = "g++"

    return includes,macros

aiengine_module = Extension("pyaiengine",
    sources = src_files,
    libraries = ["boost_system","boost_python","pcap","pcre","boost_iostreams"],
#    define_macros = [('__OPENBSD__','1'),('PYTHON_BINDING','1'),('HAVE_LIBPCRE','1')],
    # define_macros = [('PYTHON_BINDING','1'),('HAVE_LIBPCRE','1')],
    extra_compile_args = ["-O3","-Wreorder","-std=c++11","-lpthread","-lstdc++"],
    )

if __name__ == "__main__":

    includes,macros = setup_compiler()

    print("Compiling aiengine extension for %s" % sys.platform)
    print("\tOS name %s" % (os.name))
    print("\tArchitecture %s" % os.uname()[4])

    aiengine_module.include_dirs = includes
    aiengine_module.define_macros = macros

    setup(name="aiengine",
        version = "1.2",
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
            "Development Status :: 0.11 - Beta",
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
       cmdclass = {'todo': TODOCommand},
    )

