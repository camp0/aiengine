require './ruaiengine'
require 'test/unit'

class TC_MyTest < Test::Unit::TestCase
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
    @dmng = DomainNameManager.new
    @dmng.addDomainName(d1)

    @s.setDomainNameManager(@dmng,"HTTPProtocol")

    @pd.open("../pcapfiles/accessgoogle.pcap")
    @pd.run()
    @pd.close()

    print d1.getMatchs()
    @dmng.statistics()    
    # Verify some values on the PacketDispatcher
    assert_equal(@pd.getTotalBytes(),2922)
    assert_equal(@pd.getTotalPackets(),14)
  end

  def test_2
    @tcp_r = RegexManager.new
    r1 = Regex.new("Get request","^GET.*$")
    r2 = Regex.new("Post request","^POST.*$")
    @tcp_r.addRegex(r1)
    @tcp_r.addRegex(r2)

    @s.setTCPRegexManager(@tcp_r)
    @s.enableNIDSEngine(true)

    @pd.open("../pcapfiles/accessgoogle.pcap")
    @pd.run()
    @pd.close()

    assert_equal(@tcp_r.getTotalRegexs(), 2)
    print "value is", r1.getMatchs(),r2.getMatchs(), "\n"
    @tcp_r.statistics()
    # assert_equal(r1.getMatchs(), 1)
    # assert_equal(r2.getMatchs(), 0)
    print @s.methods
    print @tcp_r
    print r1.methods
    @tcp_r.statistics()
  end

  def test_3
    d1 = DomainName.new(".facebool.com","pepe")
    d2 = DomainName.new(".facebook.com","pepe")
    @dmng = DomainNameManager.new
    @dmng.addDomainName(".pepe.net","otro mas")
    print @dmng.methods
    @dmng.addDomainName(d1)
    @dmng.addDomainName(d2)
    assert_equal(@dmng.getTotalDomains(), 3)
  end

end
