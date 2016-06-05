require './ruaiengine'
require 'test/unit'

# Class for verify the DatabaseAdaptor funcionality
class FileAdaptor < DatabaseAdaptor 
  attr_reader :total_inserts 
  attr_reader :total_updates 
  attr_reader :total_removes 

  def initialize
    @total_inserts = 0
    @total_updates = 0
    @total_removes = 0
  end

  def insert(flowid)
    @total_inserts += 1
  end
  def remove(flowid)
    @total_removes += 1
  end
  def update(flowid, data)
    @total_updates += 1
  end
end

class StackLanUnitTests < Test::Unit::TestCase
  def setup
    @s = StackLan.new
    @pd = PacketDispatcher.new
    @pd.stack = @s
    @s.total_tcp_flows = 2048
    @s.total_udp_flows = 1024
  end

  def teardown
    @pd = nil
    @s = nil
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
    assert_equal(dmng.total_domains, 2)
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

    f = method(:callback)
    r1.callback = method(:callback)
    @tcp_r.add_regex(r1)
    @tcp_r.add_regex(r2)

    @s.tcp_regex_manager = @tcp_r
    @s.enable_nids_engine = true

    @pd.open("../pcapfiles/accessgoogle.pcap")
    @pd.run()
    @pd.close()

    assert_equal( @have_been_call , true)
    assert_equal(@tcp_r.total_regex, 2)
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

    @s.link_layer_tag = "vlan"
    
    udp_r = RegexManager.new
    r1 = Regex.new("Netbios","CACACACA")

    r1.callback = method(:regex_callback)
    udp_r.add_regex(r1)
    @s.udp_regex_manager = udp_r

    @s.enable_nids_engine = true

    @pd.open("../pcapfiles/flow_vlan_netbios.pcap")
    @pd.run()
    @pd.close()

    assert_equal(@have_been_called_regex, true)
    assert_equal(r1.matchs, 1)
  end

  def test_4
    @have_been_call_ssl = false
    @have_been_call_ipset = false
    @d1 = DomainName.new("Google",".google.com")

    def callback_ssl(flow)
      assert_equal(flow.l7_protocol_name,"SSLProtocol")
      s = flow.ssl_info
      if (s)
        assert_equal(s.server_name,"0.drive.google.com")
        @have_been_call_ssl = true
        assert_equal(s.matched_domain_name,@d1) 
      end
      # Verify the integrity of the payload 
      s = flow.payload
      # Iterate s.each { |x| puts x }
    end
    
    def callback_ipset(flow)
      @have_been_call_ipset = true 
    end

    ip = IPSet.new("Some IPSet")
    ip.add_ip_address("74.125.24.189")
    ip.callback = method(:callback_ipset)
 
    ipmng = IPSetManager.new()
    ipmng.add_ip_set(ip)
 
    @d1.callback = method(:callback_ssl)
    dmng = DomainNameManager.new
    dmng.add_domain_name(@d1)

    @s.tcpip_set_manager = ipmng
    @s.set_domain_name_manager(dmng,"SSLProtocol")

    @pd.open("../pcapfiles/sslflow.pcap")
    @pd.run()
    @pd.close()

    assert_equal( @d1.matchs, 1)
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
        assert_equal(h.uri,"/js/jquery.hoverIntent.js")
      end
      @have_been_call_uri = true
    end

    def callback_domain(flow)
      assert_equal(flow.l7_protocol_name,"HTTPProtocol")
      h = flow.http_info
      assert_not_equal(h,nil)
      assert_equal(h.host_name,"www.wired.com")
      assert_equal(h.matched_domain_name,@d)
      @have_been_call_domain = true
    end

    @d = DomainName.new("Wired",".wired.com")
    @d.callback = method(:callback_domain)
    dmng = DomainNameManager.new
    dmng.add_domain_name(@d)

    u = HTTPUriSet.new()
    u.add_uri("/js/jquery.hoverIntent.js")
    # u.add_uri("/images_blogs/gadgetlab/2013/08/AP090714043057-60x60.jpg")
    u.callback = method(:callback_uri)

    @d.http_uri_set = u

    @s.set_domain_name_manager(dmng,"HTTPProtocol")

    @pd.open("../pcapfiles/two_http_flows_noending.pcap")
    @pd.run()
    @pd.close()

    assert_equal( @d.matchs, 1)
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

  def test_7
    # Attach a database to the engine and test timeouts on udp flows 
    file_udp = FileAdaptor.new

    @s.flows_timeout = 1
    @s.link_layer_tag = "vlan"
    @s.set_udp_database_adaptor(file_udp,16)

    @pd.open("../pcapfiles/flow_vlan_netbios.pcap")
    @pd.run()
    @pd.close()

    assert_equal(file_udp.total_inserts,1)
    assert_equal(file_udp.total_updates,1)
    assert_equal(file_udp.total_removes,1)

  end

  def test_8
    # Verify the double callback calling on linked regex

    @have_been_call_tcp_1 = false
    @have_been_call_tcp_2 = false
    @have_been_call_tcp_3 = false

    def callback_client_hello(flow)
      p = flow.payload
      assert_equal( p.length, 193)
      assert_equal( p[1], 3)
      @have_been_call_tcp_1 = true
    end

    def callback_server_hello(flow)
      @have_been_call_tcp_2 = true
    end

    def callback_application_data(flow)
      assert_equal( flow.payload.length, 53)
      @have_been_call_tcp_3 = true
    end

    @tcp_r = RegexManager.new
    r1 = Regex.new("clienthello","^\x16\x03\x01.*$")
    r2 = Regex.new("serverhello","^\x16\x03\x02.*$")
    r3 = Regex.new("application data","^\x17\x03\x02.*$")

    # Sets the callbacks
    r1.callback = method(:callback_client_hello)
    r2.callback = method(:callback_server_hello)
    r3.callback = method(:callback_application_data)

    # Link the regex
    r1.next_regex = r2
    r2.next_regex = r3

    @tcp_r.add_regex(r1)

    @s.tcp_regex_manager = @tcp_r

    @s.enable_nids_engine = true

    @pd.open("../pcapfiles/sslflow.pcap")
    @pd.run()
    @pd.close()

    assert_equal( r1.matchs, 1)
    assert_equal( r1.total_evaluates, 1) 
    assert_equal( r2.matchs, 1)
    assert_equal( r2.total_evaluates, 1) 
    assert_equal( r3.matchs, 1)
    assert_equal( r3.total_evaluates, 5) 
    assert_equal( @have_been_call_tcp_1 , true)
    assert_equal( @have_been_call_tcp_2 , true)
    assert_equal( @have_been_call_tcp_3 , true)

  end

  def test_9
    # Verify the functionality of the counters

    @pd.open("../pcapfiles/two_http_flows_noending.pcap")
    @pd.run()
    @pd.close()

    c = @s.get_counters("EthernetProtocol")
    assert_equal( c["bytes"], 910064)

    c = @s.get_counters("TCPProtocol")

    assert_equal( c["bytes"], 879940)
    assert_equal( c["packets"], 886)
    assert_equal( c["syns"], 2)
    assert_equal( c["synacks"], 2)
    assert_equal( c["acks"], 882)
    assert_equal( c["rsts"], 0)
    assert_equal( c["fins"], 0)

    c = @s.get_counters("UnknownProtocol")
    assert_equal( c , nil)

    c = @s.get_counters("HTTPProtocol")
    assert_equal( c["requests"], 42)
  end

  def test_10
    # Verify counters and cache functionality

    @pd.open("../pcapfiles/tor_4flows.pcap")
    @pd.run()
    @pd.close()

    c = @s.get_cache("SSLProtocol")
    assert_equal(c.length, 1)
    assert_equal(c["www.2crtm25flad.com"], 4)

    @s.release_caches()
    
    c = @s.get_cache("SSLProtocol")
    assert_equal(c.length, 0)

    # www.2crtm25flad.com:4
  end

  def test_11
    # Verify the link bettwen IPSets and RegexManagers for complex logic
    @have_been_call_ipset = false 
    @have_been_call_regex = false

    def callback_regex(flow)
      @r = flow.regex 
      if (@r)
        assert_equal(@r.matchs, 1)
        assert_equal(@r.name,"generic http")
        @have_been_call_regex = true
      end
    end

    def callback_ipset(flow)
      @have_been_call_ipset = true
      # TODO: Verify the integrity of the values of the flow
    end

    rm = RegexManager.new
    r = Regex.new("generic http","^GET.*HTTP.*$")
    r.callback = method(:callback_regex)
    rm.add_regex(r)

    ip = IPSet.new("Some IPSet")
    ip.add_ip_address("95.100.96.10")
    ip.callback = method(:callback_ipset)
    ip.regexmanager = rm

    ipmng = IPSetManager.new()
    ipmng.add_ip_set(ip)
   
    @s.tcpip_set_manager = ipmng 
    @s.enable_nids_engine = true

    @pd.open("../pcapfiles/two_http_flows_noending.pcap")
    @pd.run()
    @pd.close()

    assert_equal( @have_been_call_ipset , true)
    assert_equal( @have_been_call_regex , true)

  end
  def test_12
    # @pd.open("../pcapfiles/tor_4flows.pcap")
    @pd.open("../pcapfiles/two_http_flows_noending.pcap")
    @pd.run()
    @pd.close()

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
    assert_equal(@pd.total_bytes,536)
    assert_equal(@pd.total_packets,4)

    c = @s.get_counters("ICMPProtocol")
    assert_not_equal( c, nil)
    assert_equal(c["packets"] , 4)
    assert_equal(c["echo"], 2)
    assert_equal(c["echoreplay"], 2)

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
        assert_equal(d.domain_name,"www.google.com")
        assert_equal(flow.src_ip,"2014:dead:beef::1")
        assert_equal(d.matched_domain_name,@d1)
        @have_been_call = true 
      end
    end

    @d1 = DomainName.new("Google",".google.com")
    @d1.callback = method(:callback_dns)
    dmng = DomainNameManager.new
    dmng.add_domain_name(@d1)

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

  def test_3
    # Verify the get_cache functionality over a IPv6 stack

    @pd.open("../pcapfiles/ipv6_google_dns.pcap")
    @pd.run()
    @pd.close()

    c = @s.get_cache("DNSProtocol")
    assert_not_equal(c, nil)
    assert_equal(c["www.google.com"], 1)
    assert_equal( @s.get_cache("DNSProtocolNoExists"),nil)
   
    @s.release_cache("DNSProtocol")
    c = @s.get_cache("DNSProtocol")
    assert_not_equal(c, nil)
    assert_equal(c.length, 0)
    c = @s.get_cache("SSLProtocol")
    assert_equal(c.length, 0)
    c = @s.get_cache("HTTPProtocol")
    assert_equal(c.length, 0)
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
    # Check the DatabaseAdaptor functionality for external data storages
    storage_tcp = FileAdaptor.new
    storage_udp = FileAdaptor.new

    @s.set_tcp_database_adaptor(storage_tcp,2)
    @s.set_udp_database_adaptor(storage_udp,1)

    @pd.open("../pcapfiles/openflow.pcap")
    @pd.run()
    @pd.close()

    assert_equal(storage_tcp.total_inserts,1)
    assert_equal(storage_tcp.total_updates,1)
    assert_equal(storage_tcp.total_removes,0)
    
    assert_equal(storage_udp.total_inserts,1)
    assert_equal(storage_udp.total_updates,3)
    assert_equal(storage_udp.total_removes,0)
  end

  def test_3
    # Verify the number of parameters on the regex callbacks

    def callback1
    end

    def callback2(one)
    end

    def callback3(owe,two)
    end

    r = Regex.new("test0","")

    assert_raise( RuntimeError ) { r.callback = method(:callback1) }
    assert_raise( RuntimeError ) { r.callback = method(:callback3) }
    assert_nothing_raised( RuntimeError ) { r.callback = method(:callback2) }

  end

end

class StackLanLearningUnitTests < Test::Unit::TestCase

  def setup
    @s = StackLan.new
    @pd = PacketDispatcher.new
    @pd.stack = @s
    @s.total_tcp_flows = 32
    @s.total_udp_flows = 32
    @f = FrequencyGroupString.new
  end

  def teardown
  end

  def test_1

    @s.enable_frequency_engine = true
    @pd.open("../pcapfiles/two_http_flows_noending.pcap")
    @pd.run()
    @pd.close()

    assert_equal(@f.total_process_flows , 0)
    assert_equal(@f.total_computed_frequencies , 0)

    @f.add_flows_by_destination_port(@s.tcp_flow_manager)
    @f.compute()
    
    assert_equal(@f.total_process_flows , 2)
    assert_equal(@f.total_computed_frequencies , 1)

  end
  def test_2

    @s.enable_frequency_engine = true
    @pd.open("../pcapfiles/tor_4flows.pcap")
    @pd.run()
    @pd.close()

    assert_equal(@f.total_process_flows , 0)
    assert_equal(@f.total_computed_frequencies , 0)

    @f.add_flows_by_destination_port(@s.tcp_flow_manager)
    @f.compute()
    
    assert_equal(@f.total_process_flows , 4)
    assert_equal(@f.total_computed_frequencies , 1)

  end

  def test_3
    # Integrate with the learner to generate a regex 

    l = LearnerEngine.new

    @s.enable_frequency_engine = true
    @pd.open("../pcapfiles/tor_4flows.pcap")
    @pd.run()
    @pd.close()

    @f.add_flows_by_destination_port(@s.tcp_flow_manager)
    @f.compute()

    flow_list = @f.reference_flows
    assert_equal(@f.total_computed_frequencies, 1)

    # For print the flows involved
    # flow_list.each { |x| puts x.src_ip }
    
    # Add the flows to the learner engine
    l.agregate_flows(flow_list)
    l.compute()

    assert_equal(l.total_flows_process, 4)
    assert_nothing_raised( RuntimeError ) { r = Regexp.new(l.regex) }

  end
end

