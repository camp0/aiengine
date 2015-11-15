import org.junit.*; 

public class JavaAiengineTests { 

    public boolean called;
    private StackLan s;
    private PacketDispatcher pd;

    @Before
    public void setUp(  ) {
	
	this.s = new StackLan();
	this.pd = new PacketDispatcher();

	this.pd.setStack(this.s);

	this.s.setTotalTCPFlows(32);
	this.s.setTotalUDPFlows(32);
	this.called = false;
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

	class ExternalCallback extends JaiCallback{
		public void call(Flow flow) {
			SSLInfo s = flow.getSSLInfo();
			System.out.println(called);
			Assert.assertEquals("0.drive.google.com",s.getServerName());
			// this.called = true;
		}
	}
  	DomainNameManager dm = new DomainNameManager();
        DomainName d = new DomainName("Google Drive Cert",".drive.google.com");
	ExternalCallback call = new ExternalCallback();

	d.setCallback(call);
	dm.addDomainName(d);

	this.s.setDomainNameManager(dm,"SSLProtocol");

	this.pd.open("../pcapfiles/sslflow.pcap");
        this.pd.run();
        this.pd.close();

	Assert.assertEquals(d.getMatchs(), 1);
	// Assert.assertEquals(this.called, true);
        FlowManager fm = this.s.getTCPFlowManager();

    }
}
