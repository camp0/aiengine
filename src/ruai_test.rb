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

    def callback
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
    print @s.methods
    #assert_equal(@dmng.getTotalDomains(), 3)
  end

end
