require './ruaiengine'
require 'test/unit'

class StackLanUnitTests < Test::Unit::TestCase
  def setup
    @s = StackLan.new
    @pd = PacketDispatcher.new
    @pd.setStack(@s)
    @s.setTotalTCPFlows(32)
    @s.setTotalUDPFlows(32)
  end

  def teardown
  end

  def test_1
    d1 = DomainName.new("Google",".google.com")
    d2 = DomainName.new("Facebook",".facebook.com")
    dmng = DomainNameManager.new
    dmng.addDomainName(d1)
    dmng.addDomainName(d2)

    @s.setDomainNameManager(dmng,"HTTPProtocol")

    @pd.open("../pcapfiles/accessgoogle.pcap")
    @pd.run()
    @pd.close()

    # Verify some values 
    assert_equal(@pd.getTotalBytes(),2922)
    assert_equal(@pd.getTotalPackets(),14)
    assert_equal(d1.getMatchs(), 1)
    assert_equal(d2.getMatchs(), 0)
    assert_equal(dmng.getTotalDomains(), 2)
  end

  def test_2

    @have_been_call = false

    def callback(flow)
      @have_been_call = true 
    end

    @tcp_r = RegexManager.new
    r1 = Regex.new("Get request","^GET.*$")
    r2 = Regex.new("Post request","^POST.*$")

    r1.setCallback(method(:callback))
    @tcp_r.addRegex(r1)
    @tcp_r.addRegex(r2)

    @s.setTCPRegexManager(@tcp_r)
    @s.enableNIDSEngine(true)

    @pd.open("../pcapfiles/accessgoogle.pcap")
    @pd.run()
    @pd.close()

    assert_equal( @have_been_call , true)
    assert_equal(@tcp_r.getTotalRegexs(), 2)
    assert_equal(r1.getMatchs(), 1)
    assert_equal(r2.getMatchs(), 0)
  end

  def test_3
    @s.enableLinkLayerTagging("vlan")
    
    @udp_r = RegexManager.new
    r1 = Regex.new("Netbios","CACACACA")

    @udp_r.addRegex(r1)
    @s.setUDPRegexManager(@udp_r)

    @pd.open("../pcapfiles/flow_vlan_netbios.pcap")
    @pd.run()
    @pd.close()

    assert_equal(r1.getMatchs(), 1)
  end

  def test_4

    @have_been_call_ssl = false
    @have_been_call_ipset = false

    def callback_ssl(flow)
      @have_been_call_ssl = true 
    end
    
    def callback_ipset(flow)
      @have_been_call_ipset = true 
    end

    ip = IPSet.new("Some IPSet")
    print ip.methods
    ip.addIPAddress("74.125.24.189")
    ip.setCallback(method(:callback_ipset))
 
    ipmng = IPSetManager.new()
    ipmng.addIPSet(ip)
 
    d1 = DomainName.new("Google",".google.com")
    d1.setCallback(method(:callback_ssl))
    dmng = DomainNameManager.new
    dmng.addDomainName(d1)

    print @s.methods
    @s.setTCPIPSetManager(ipmng)
    @s.setDomainNameManager(dmng,"SSLProtocol")

    @pd.open("../pcapfiles/sslflow.pcap")
    @pd.run()
    @pd.close()

    assert_equal( d1.getMatchs(), 1)
    assert_equal( @have_been_call_ssl , true)
    assert_equal( @have_been_call_ipset , true)

  end

  def test_5
    # Test the HTTPUriSet functionality

    @have_been_call_uri = false
    @have_been_call_domain = false

    def callback_uri(flow)
      @have_been_call_uri = true
    end

    def callback_domain(flow)
      @have_been_call_domain = true
    end

    d = DomainName.new("Wired",".wired.com")
    d.setCallback(method(:callback_domain))
    dmng = DomainNameManager.new
    dmng.addDomainName(d)

    u = HTTPUriSet.new()
    u.addURI("/images_blogs/gadgetlab/2013/08/AP090714043057-60x60.jpg")
    u.setCallback(method(:callback_uri))

    d.setHTTPUriSet(u)

    @s.setDomainNameManager(dmng,"HTTPProtocol")

    @pd.open("../pcapfiles/two_http_flows_noending.pcap")
    @pd.run()
    @pd.close()

    assert_equal( d.getMatchs(), 1)
    assert_equal( @have_been_call_uri , true)
    assert_equal( @have_been_call_domain , true)

  end

end

class StackMobileUnitTests < Test::Unit::TestCase

  def setup
    @s = StackMobile.new
    @pd = PacketDispatcher.new
    @pd.setStack(@s)
    @s.setTotalTCPFlows(32)
    @s.setTotalUDPFlows(32)
  end

  def teardown
  end

  def test_1
    @pd.open("../pcapfiles/gprs_icmp.pcap")
    @pd.run()
    @pd.close()

    # Verify some values 
    assert_equal(@pd.getTotalBytes(),320)
    assert_equal(@pd.getTotalPackets(),2)
  end

end

class StackLanIPv6UnitTests < Test::Unit::TestCase

  def setup
    @s = StackLanIPv6.new
    @pd = PacketDispatcher.new
    @pd.setStack(@s)
    @s.setTotalTCPFlows(32)
    @s.setTotalUDPFlows(32)
  end

  def teardown
  end

  def test_1

    @have_been_call = false

    def callback_dns(flow)
      @have_been_call = true 
    end

    d1 = DomainName.new("Google",".google.com")
    d1.setCallback(method(:callback_dns))
    dmng = DomainNameManager.new
    dmng.addDomainName(d1)

    @s.setDomainNameManager(dmng,"DNSProtocol")

    @pd.open("../pcapfiles/ipv6_google_dns.pcap")
    @pd.run()
    @pd.close()

    assert_equal( @have_been_call , true)

  end
  
  def test_2

    @tcp_r = RegexManager.new
    r1 = Regex.new("r1","^(No hacker should visit Las Vegas).*$")
    r2 = Regex.new("r2","^POST.*$")
    r3 = Regex.new("r3","^POST.*$")

    @tcp_r.addRegex(r1)
    @tcp_r.addRegex(r2)
    @tcp_r.addRegex(r3)

    @s.setTCPRegexManager(@tcp_r)
    
    @pd.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
    @pd.run()
    @pd.close()

    assert_equal(r1.getMatchs(), 1)
    assert_equal(r2.getMatchs(), 0)
    assert_equal(r3.getMatchs(), 0)

  end

end

class StackVirtualUnitTests < Test::Unit::TestCase

  def setup
    @s = StackVirtual.new
    @pd = PacketDispatcher.new
    @pd.setStack(@s)
    @s.setTotalTCPFlows(32)
    @s.setTotalUDPFlows(32)
  end

  def teardown
  end

  def test_1

    tcp_r = RegexManager.new
    r1 = Regex.new("r1","^bin$")

    tcp_r.addRegex(r1)
    @s.setTCPRegexManager(tcp_r)
    
    @pd.open("../pcapfiles/vxlan_ftp.pcap")
    @pd.run()
    @pd.close()

    # Verify some values
    assert_equal(@pd.getTotalBytes(),900)
    assert_equal(@pd.getTotalPackets(),8)
    assert_equal(r1.getMatchs(), 1)
  end

  def test_2

    tcp_r = RegexManager.new
    r1 = Regex.new("r1","^SSH-2.0.*$")

    tcp_r.addRegex(r1)
    @s.setTCPRegexManager(tcp_r)
    
    @pd.open("../pcapfiles/gre_ssh.pcap")
    @pd.run()
    @pd.close()

    # Verify some values
    assert_equal(r1.getMatchs(), 1)
  end

end

class StackOpenFlowUnitTests < Test::Unit::TestCase

  def setup
    @s = StackOpenFlow.new
    @pd = PacketDispatcher.new
    @pd.setStack(@s)
    @s.setTotalTCPFlows(32)
    @s.setTotalUDPFlows(32)
  end

  def teardown
  end

  def test_1

    tcp_r = RegexManager.new
    r1 = Regex.new("r1","^\x26\x01")

    tcp_r.addRegex(r1)
    @s.setTCPRegexManager(tcp_r)
    
    @pd.open("../pcapfiles/openflow.pcap")
    @pd.run()
    @pd.close()

    # Verify some values
    assert_equal(r1.getMatchs(), 1)
  end

end

