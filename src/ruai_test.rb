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

  # def teardown
  # end

  def test1
    @pd.open("../pcapfiles/accessgoogle.pcap")
    @pd.run()
    @pd.close()
    
    # Verify some values on the PacketDispatcher
    assert_equal(@pd.getTotalBytes(),2922)
    assert_equal(@pd.getTotalPackets(),14)
  end

  def test2
    @tcp_r = RegexManager.new
    @r1 = Regex.new("^GET.*$","Get request")
    @r2 = Regex.new("^POST.*$","Post request")
    @tcp_r.addRegex(@r1)
    @tcp_r.addRegex(@r2)

    @s.setTCPRegexManager(@tcp_r)
    @s.enableNIDSEngine(true)

    print @s.methods
    print @tcp_r

    @tcp_r.statistics()
  end

  def test3
    @d1 = DomainName.new(".facebool.com","pepe")
    @d2 = DomainName.new(".facebook.com","pepe")
    @dmng = DomainNameManager.new
    @dmng.addDomainName(@d1)
    @dmng.addDomainName(@d2)
    assert_equal(@dmng.getTotalDomains(), 2)
  end

end
