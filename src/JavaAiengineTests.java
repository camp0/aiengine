import org.junit.*; 

public class JavaAiengineTests { 

    private StackLan s;
    private PacketDispatcher pd;

    @Before
    public void setUp(  ) {
        System.load("/home/luis/c++/aiengine/src/jaaiengine.so");
	
	this.s = new StackLan();
	this.pd = new PacketDispatcher();

	this.pd.setStack(this.s);

	this.s.setTotalTCPFlows(32);
	this.s.setTotalUDPFlows(32);
    }

    @After
    public void tearDown(  ) {
	this.s = null;
	this.pd = null;
    }

    @Test
    public void test01() {
	RegexManager rm = new RegexManager();
	Regex r = new Regex("netbios","CACACACA");

	rm.addRegex(r);

	this.s.setUDPRegexManager(rm);

	this.s.enableLinkLayerTagging("vlan");

       	this.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        this.pd.run();
        this.pd.close();

	Assert.assertEquals(r.getMatchs(), 1);
	Assert.assertEquals(r.getTotalEvaluates(), 1);
    }

    @Test
    public void test02() {
        RegexManager rm = new RegexManager();
        Regex r = new Regex("netbios","CACACACA");

        rm.addRegex(r);

        this.s.setUDPRegexManager(rm);
	this.s.setUDPRegexManager(null);

        this.s.enableLinkLayerTagging("vlan");

        this.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        this.pd.run();
        this.pd.close();

        Assert.assertEquals(r.getMatchs(), 0);
        Assert.assertEquals(r.getTotalEvaluates(), 0);
    }


    @Test
    public void test03() {
  	DomainNameManager dm = new DomainNameManager();
        DomainName d = new DomainName("Google Drive Cert",".drive.google.com");

	dm.addDomainName(d);

	this.s.setDomainNameManager(dm,"SSLProtocol");

	this.pd.open("../pcapfiles/sslflow.pcap");
        this.pd.run();
        this.pd.close();

        FlowManager fm = this.s.getTCPFlowManager();

    }
}
