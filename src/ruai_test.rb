require './ruaiengine'
require 'test/unit'

class FileAdaptor < DatabaseAdaptor
  def initialize
  end
end

class StackLanUnitTests < Test::Unit::TestCase
  def setup
    @s = StackLan.new
    @pd = PacketDispatcher.new
    @pd.stack = @s
    @s.total_tcp_flows = 32
    @s.total_udp_flows = 32
  end

  def teardown
  end

  def test_1
    d1 = DomainName.new("Google",".google.com")
    d2 = DomainName.new("Facebook",".facebook.com")
    dmng = DomainNameManager.new
    dmng.add_domain_name(d1)
    dmng.add_domain_name(d2)

    @s.set_domain_name_manager(dmng,"HTTPProtocol")

    @pd.open("../pcapfiles/accessgoogle.pcap")
    @pd.run()
    @pd.close()

    # Verify some values 
    assert_equal(@pd.total_bytes,2922)
    assert_equal(@pd.total_packets,14)
    assert_equal(d1.matchs, 1)
    assert_equal(d2.matchs, 0)
    assert_equal(dmng.getTotalDomains(), 2)
  end

  def test_2
    @have_been_call = false

    def callback(flow)
      assert_equal(flow.l7_protocol_name,"TCPGenericProtocol")
      @have_been_call = true 
    end

    @tcp_r = RegexManager.new
    r1 = Regex.new("Get request","^GET.*$")
    r2 = Regex.new("Post request","^POST.*$")

    r1.callback = method(:callback)
    @tcp_r.add_regex(r1)
    @tcp_r.add_regex(r2)

    @s.tcp_regex_manager = @tcp_r
    @s.enableNIDSEngine(true)

    @pd.open("../pcapfiles/accessgoogle.pcap")
    @pd.run()
    @pd.close()

    assert_equal( @have_been_call , true)
    assert_equal(@tcp_r.getTotalRegexs(), 2)
    assert_equal(r1.matchs, 1)
    assert_equal(r2.matchs, 0)
  end

  def test_3
    @have_been_called_regex = false

    def regex_callback(flow)
      r = flow.regex
      if (r)
        assert_equal(r.matchs, 1)
        assert_equal(r.name,"Netbios")
        @have_been_called_regex = true
      end
    end

    @s.enableLinkLayerTagging("vlan")
    
    udp_r = RegexManager.new
    r1 = Regex.new("Netbios","CACACACA")

    r1.callback = method(:regex_callback)
    udp_r.add_regex(r1)
    @s.udp_regex_manager = udp_r

    @pd.open("../pcapfiles/flow_vlan_netbios.pcap")
    @pd.run()
    @pd.close()

    assert_equal(@have_been_called_regex, true)
    assert_equal(r1.matchs, 1)
  end

  def test_4
    @have_been_call_ssl = false
    @have_been_call_ipset = false

    def callback_ssl(flow)
      assert_equal(flow.l7_protocol_name,"SSLProtocol")
      s = flow.ssl_info
      if (s)
        assert_equal(s.server_name,"0.drive.google.com")
        @have_been_call_ssl = true 
      end
    end
    
    def callback_ipset(flow)
      @have_been_call_ipset = true 
    end

    ip = IPSet.new("Some IPSet")
    ip.add_ip_address("74.125.24.189")
    ip.callback = method(:callback_ipset)
 
    ipmng = IPSetManager.new()
    ipmng.add_ip_set(ip)
 
    d1 = DomainName.new("Google",".google.com")
    d1.callback = method(:callback_ssl)
    dmng = DomainNameManager.new
    dmng.add_domain_name(d1)

    @s.tcpip_set_manager = ipmng
    @s.set_domain_name_manager(dmng,"SSLProtocol")

    @pd.open("../pcapfiles/sslflow.pcap")
    @pd.run()
    @pd.close()

    assert_equal( d1.matchs, 1)
    assert_equal( @have_been_call_ssl , true)
    assert_equal( @have_been_call_ipset , true)

  end

  def test_5
    # Test the HTTPUriSet functionality

    @have_been_call_uri = false
    @have_been_call_domain = false

    def callback_uri(flow)
      assert_equal(flow.l7_protocol_name,"HTTPProtocol")
      h = flow.http_info
      if (h)
        assert_equal(h.uri,"/images_blogs/gadgetlab/2013/08/AP090714043057-60x60.jpg")
      end
      @have_been_call_uri = true
    end

    def callback_domain(flow)
      assert_equal(flow.l7_protocol_name,"HTTPProtocol")
      h = flow.http_info
      assert_not_equal(h,nil)
      assert_equal(h.host_name,"www.wired.com")
      @have_been_call_domain = true
    end

    d = DomainName.new("Wired",".wired.com")
    d.callback = method(:callback_domain)
    dmng = DomainNameManager.new
    dmng.add_domain_name(d)

    u = HTTPUriSet.new()
    u.addURI("/images_blogs/gadgetlab/2013/08/AP090714043057-60x60.jpg")
    u.callback = method(:callback_uri)

    d.setHTTPUriSet(u)

    @s.set_domain_name_manager(dmng,"HTTPProtocol")

    @pd.open("../pcapfiles/two_http_flows_noending.pcap")
    @pd.run()
    @pd.close()

    assert_equal( d.matchs, 1)
    assert_equal( @have_been_call_uri , true)
    assert_equal( @have_been_call_domain , true)
  end

  def test_6
    # Test smtp values on the flow
    @have_been_called_smtp = false

    def callback_smtp(flow)
      s = flow.smtp_info
      if (s)
        assert_equal(s.mail_from,"gurpartap@patriots.in")
        @have_been_called_smtp = true
      end
    end

    d = DomainName.new("Some domain",".patriots.in")
    d.callback = method(:callback_smtp)
    dmng = DomainNameManager.new
    dmng.add_domain_name(d)

    @s.set_domain_name_manager(dmng,"SMTPProtocol")

    @pd.open("../pcapfiles/smtp.pcap")
    @pd.run()
    @pd.close()

    assert_equal( d.matchs, 1)
    assert_equal( @have_been_called_smtp , true)
  end
end

class StackMobileUnitTests < Test::Unit::TestCase

  def setup
    @s = StackMobile.new
    @pd = PacketDispatcher.new
    @pd.stack = @s
    @s.total_tcp_flows = 32
    @s.total_udp_flows = 32
  end

  def teardown
  end

  def test_1
    @pd.open("../pcapfiles/gprs_icmp.pcap")
    @pd.run()
    @pd.close()

    # Verify some values 
    assert_equal(@pd.total_bytes,320)
    assert_equal(@pd.total_packets,2)
  end
end

class StackLanIPv6UnitTests < Test::Unit::TestCase

  def setup
    @s = StackLanIPv6.new
    @pd = PacketDispatcher.new
    @pd.stack = @s
    @s.total_tcp_flows = 32
    @s.total_udp_flows = 32
  end

  def teardown
  end

  def test_1
    @have_been_call = false

    def callback_dns(flow)
      d = flow.dns_info
      # TODO: Make iterable the object dns_info for retrieve the IP address
      if (d)
        assert_equal(flow.l7_protocol_name,"DNSProtocol")
        @have_been_call = true 
      end
    end

    d1 = DomainName.new("Google",".google.com")
    d1.callback = method(:callback_dns)
    dmng = DomainNameManager.new
    dmng.add_domain_name(d1)

    @s.set_domain_name_manager(dmng,"DNSProtocol")

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

    @tcp_r.add_regex(r1)
    @tcp_r.add_regex(r2)
    @tcp_r.add_regex(r3)

    @s.tcp_regex_manager = @tcp_r
    
    @pd.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
    @pd.run()
    @pd.close()

    assert_equal(r1.matchs, 1)
    assert_equal(r2.matchs, 0)
    assert_equal(r3.matchs, 0)
  end
end

class StackVirtualUnitTests < Test::Unit::TestCase

  def setup
    @s = StackVirtual.new
    @pd = PacketDispatcher.new
    @pd.stack = @s
    @s.total_tcp_flows = 32
    @s.total_udp_flows = 32
  end

  def teardown
  end

  def test_1
    tcp_r = RegexManager.new
    r = Regex.new("r1","^bin$")

    tcp_r.add_regex(r)
    @s.tcp_regex_manager = tcp_r
    
    @pd.open("../pcapfiles/vxlan_ftp.pcap")
    @pd.run()
    @pd.close()

    # Verify some values
    assert_equal(@pd.total_bytes,900)
    assert_equal(@pd.total_packets,8)
    assert_equal(r.matchs, 1)
  end

  def test_2
    tcp_r = RegexManager.new
    r1 = Regex.new("r1","^SSH-2.0.*$")

    tcp_r.add_regex(r1)
    @s.tcp_regex_manager = tcp_r
    
    @pd.open("../pcapfiles/gre_ssh.pcap")
    @pd.run()
    @pd.close()

    # Verify some values
    assert_equal(r1.matchs, 1)
  end
end

class StackOpenFlowUnitTests < Test::Unit::TestCase

  def setup
    @s = StackOpenFlow.new
    @pd = PacketDispatcher.new
    @pd.stack = @s
    @s.total_tcp_flows = 32
    @s.total_udp_flows = 32
  end

  def teardown
  end

  def test_1
    tcp_r = RegexManager.new
    r1 = Regex.new("r1","^\x26\x01")

    tcp_r.add_regex(r1)
    @s.tcp_regex_manager = tcp_r
    
    @pd.open("../pcapfiles/openflow.pcap")
    @pd.run()
    @pd.close()

    # Verify some values
    assert_equal(r1.matchs, 1)
  end

  def test_2

  end
end

