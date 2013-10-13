import sys
import os
sys.path.append("../src/")
import pyaiengine

def callback_troyan_activity(flow):
    ip = str(flow).split(":")[0]

    print "Detected OSX_DocksterTrojan on ip:",ip

def callback_domain(flow):

    ip = str(flow).split(":")[0]

    print "Suspicious Domain (%s) from %s" % (flow.getDNSDomain(),ip)
    print "Add specific regex for OSX_DocksterTrojan"

    reg = pyaiengine.Regex("OSX_DocksterTrojan regex activity",
        "^\xff\xff\xff\xff\xc2\x1f\x96\x9b\x5f\x03\xd3\x3d\x43\xe0\x4f\x8f")

    reg.setCallback(callback_troyan_activity)
    r_mng.addRegex(reg)

    # Something of the references of python are wrong
    # do not remove this call, fix on future.
    st.setTCPRegexManager(r_mng)


if __name__ == '__main__':

    # Load an instance of a Network Stack on Mobile network
    st = pyaiengine.StackLan()

    # Create a instace of a PacketDispatcher
    pdis = pyaiengine.PacketDispatcher()

    # Plug the stack on the PacketDispatcher
    pdis.setStack(st)

    dm = pyaiengine.DomainNameManager()

    dom = pyaiengine.DomainName("OSX_DocksterTrojan suspicious domain",
        "itsec.eicp.net")
    dom.setCallback(callback_domain)
    dm.addDomainName(dom)

    r_mng = pyaiengine.RegexManager()

    st.setDNSDomainNameManager(dm)
    st.setTCPRegexManager(r_mng)

    st.setTotalTCPFlows(327680)
    st.setTotalUDPFlows(163840)

    pdis.openPcapFile("/home/luis/pcapfiles/troyan/OSX_DocksterTrojan.pcap")

    try:
        pdis.runPcap()
    except:
        e = sys.exc_info()[0]
        print "Interrupt during capturing packets:",e

    pdis.closePcapFile()

    # Dump on file the statistics of the stack
    st.setStatisticsLevel(5)
    f = open("statistics.log","w")
    f.write(str(st))
    f.close()

    sys.exit(0)

