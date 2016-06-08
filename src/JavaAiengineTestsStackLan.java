import org.junit.*; 
import static org.junit.Assert.*;

public class JavaAiengineTestsStackLan { 

    private StackLan s;
    private PacketDispatcher pd;

    @Before
    public void setUp(  ) {
	
	this.s = new StackLan();
	this.pd = new PacketDispatcher();

	this.pd.setStack(this.s);

	this.s.setTotalTCPFlows(2048);
	this.s.setTotalUDPFlows(1024);
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

        this.s.enableNIDSEngine(true);

	this.s.enableLinkLayerTagging("vlan");

       	this.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        this.pd.run();
        this.pd.close();

	assertEquals(r.getMatchs(), 1);
	assertEquals(r.getTotalEvaluates(), 1);
    }

    @Test
    public void test02() {
        RegexManager rm = new RegexManager();
        Regex r = new Regex("netbios","CACACACA");

        rm.addRegex(r);

	// TODO: this.s.setUDPRegexManager(rm);
	this.s.setUDPRegexManager(null);

        this.s.enableLinkLayerTagging("vlan");

        this.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        this.pd.run();
        this.pd.close();

	// System.out.println("getMatchs:" + r.getMatchs());
	// System.out.println("getTotalEvaluates:" + r.getTotalEvaluates());
        assertEquals(r.getMatchs(), 0);
        assertEquals(r.getTotalEvaluates(), 0);
    }


    @Test
    public void test03() {

        DomainName d = new DomainName("Google Drive Cert",".drive.google.com");
	class ExternalCallback extends JaiCallback{
            public boolean called = false;
	    public void call(Flow flow) {
		SSLInfo s = flow.getSSLInfoObject();
		assertEquals("0.drive.google.com",s.getServerName());
		// assertEquals(s.getMatchedDomainName(),d);
		called = true;
            }
	}
  	DomainNameManager dm = new DomainNameManager();
        // DomainName d = new DomainName("Google Drive Cert",".drive.google.com");
	ExternalCallback call = new ExternalCallback();

	d.setCallback(call);
	dm.addDomainName(d);

	this.s.setDomainNameManager(dm,"SSLProtocol");

	this.pd.open("../pcapfiles/sslflow.pcap");
        this.pd.run();
        this.pd.close();

	assertEquals(d.getMatchs(), 1);
	assertEquals(call.called, true);
        FlowManager fm = this.s.getTCPFlowManager();
    }

    @Test
    public void test04() {

        class ExternalCallbackIpset extends JaiCallback{
           public boolean called = false;
           public void call(Flow flow) {
               IPAbstractSet is = flow.getIPSet();
               called = true;
           }
        }

        class ExternalCallbackDomain extends JaiCallback{
           public boolean called = false;
           public void call(Flow flow) {
                SSLInfo s = flow.getSSLInfoObject();
                assertEquals("SSLProtocol",flow.getL7ProtocolName());
                called = true;
           }
        }

        IPSet ip = new IPSet("Specific IP address");
        ip.addIPAddress("74.125.24.189");
	ExternalCallbackIpset eci = new ExternalCallbackIpset();
        ip.setCallback(eci);

        IPSetManager ipm = new IPSetManager();
        ipm.addIPSet(ip);

        DomainNameManager dm = new DomainNameManager();
        DomainName d = new DomainName("Google All",".google.com");
	ExternalCallbackDomain ecd = new ExternalCallbackDomain();

        d.setCallback(ecd);
        dm.addDomainName(d);

	this.s.setTCPIPSetManager(ipm);
        this.s.setDomainNameManager(dm,"SSLProtocol");

        this.pd.open("../pcapfiles/sslflow.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(d.getMatchs(), 1);
        assertEquals(ecd.called, true);
        assertEquals(eci.called, true);
    }

    @Test
    public void test05() {
        // Verify SMTP traffic with domain callback 

        class ExternalCallbackDomain extends JaiCallback{
           public boolean called = false;
           public void call(Flow flow) {
                SMTPInfo s = flow.getSMTPInfoObject();
                assertEquals("SMTPProtocol",flow.getL7ProtocolName());
                assertEquals("gurpartap@patriots.in",s.getFrom());
                called = true;
           }
        }

        DomainNameManager dm = new DomainNameManager();
        DomainName d = new DomainName("Some domain",".patriots.in");
        ExternalCallbackDomain ecd = new ExternalCallbackDomain();

        d.setCallback(ecd);
        dm.addDomainName(d);
        this.s.setDomainNameManager(dm,"SMTPProtocol");

        this.pd.open("../pcapfiles/smtp.pcap");
        this.pd.run();
        this.pd.close(); 

        //this.s.setStatisticsLevel(4);
        //this.s.statistics();

        assertEquals(d.getMatchs(), 1);
        assertEquals(ecd.called, true);
    }

    @Test
    public void test06() {
        // Test the chains of regex with RegexManagers 

        RegexManager rmbase = new RegexManager();
        RegexManager rm1 = new RegexManager();
        RegexManager rm2 = new RegexManager();
        RegexManager rm3 = new RegexManager();

        Regex r1 = new Regex("smtp1" , "^AUTH LOGIN");
        r1.setNextRegexManager(rm1);
        rmbase.addRegex(r1);

        Regex r2 = new Regex("smtp2" , "^NO MATCHS");
        Regex r3 = new Regex("smtp3" , "^MAIL FROM");

        rm1.addRegex(r2);
        rm1.addRegex(r3);
        r3.setNextRegexManager(rm2);

        Regex r4 = new Regex("smtp4" , "^NO MATCHS");
        Regex r5 = new Regex("smtp5" , "^DATA");

        rm2.addRegex(r4);
        rm2.addRegex(r5);
        r5.setNextRegexManager(rm3);

        Regex r6 = new Regex("smtp6" , "^QUIT");
        rm3.addRegex(r6);

        this.s.setTCPRegexManager(rmbase);
        this.s.enableNIDSEngine(true);

        this.pd.open("../pcapfiles/smtp.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(r1.getMatchs(), 1);
        assertEquals(r2.getMatchs(), 0);
        assertEquals(r3.getMatchs(), 1);
        assertEquals(r4.getMatchs(), 0);
        assertEquals(r5.getMatchs(), 1);
        assertEquals(r6.getMatchs(), 1);
	
    }
    @Test
    public void test07() {
        // Verify the functionatliy of the HTTPUriSets with the callbacks

        class ExternalCallbackDomain extends JaiCallback{
           public boolean called = false;
           public void call(Flow flow) {
                HTTPInfo s = flow.getHTTPInfoObject();
                assertEquals("www.wired.com",s.getHostName());
                called = true;
           }
        }
        class ExternalCallbackUri extends JaiCallback{
           public boolean called = false;
           public void call(Flow flow) {
                HTTPInfo s = flow.getHTTPInfoObject();
	        assertEquals(s.getUri(),"/images_blogs/wiredscience/2013/08/earth-ring-200x100.jpg");
                called = true;
           }
        }

        DomainNameManager dm = new DomainNameManager();
        DomainName d = new DomainName("Some domain",".wired.com");
        ExternalCallbackDomain ecd = new ExternalCallbackDomain();
        ExternalCallbackUri eci = new ExternalCallbackUri();

	HTTPUriSet uset = new HTTPUriSet();
        uset.addURI("/images_blogs/wiredscience/2013/08/earth-ring-200x100.jpg");
        uset.setCallback(eci);

        d.setCallback(ecd);
	d.setHTTPUriSet(uset);

        dm.addDomainName(d);
        this.s.setDomainNameManager(dm,"HTTPProtocol");

        this.pd.open("../pcapfiles/two_http_flows_noending.pcap");
        this.pd.run();
        this.pd.close();
        
	assertEquals(d.getMatchs(), 1);
	assertEquals(ecd.called, true);
	assertEquals(eci.called, true);
    }

    @Test
    public void test08() {
        // Verify the functionatliy of the DatabaseAdaptor with TCP traffic and a DomainManager

        class ExternalCallbackDomain extends JaiCallback{
            public boolean called = false;
            public void call(Flow flow) {
                SSLInfo s = flow.getSSLInfoObject();
	        assertEquals("0.drive.google.com",s.getServerName());
                called = true;
            }
        }

        class BasicAdaptor extends DatabaseAdaptor {
            public int inserts = 0;
            public int updates = 0;
            public int removals = 0;

	    public void connect(String s) { }
	    public void insert(String key) { inserts += 1; } 
            public void update(String key,String data) { 

		boolean value = data.contains("0.drive.google.com");
		assertEquals(value,true);
		updates += 1;
	    }
	    public void remove(String key) { removals +=1; }
        }

        DomainNameManager dm = new DomainNameManager();
        DomainName d = new DomainName("Some domain",".google.com");
	ExternalCallbackDomain ecd = new ExternalCallbackDomain();      
 
	d.setCallback(ecd); 
	dm.addDomainName(d);
        this.s.setDomainNameManager(dm,"SSLProtocol");

	BasicAdaptor ba = new BasicAdaptor();

	this.s.setTCPDatabaseAdaptor(ba,16);

        this.pd.open("../pcapfiles/sslflow.pcap");
        this.pd.run();
        this.pd.close();

	assertEquals(ba.inserts, 1);
	assertEquals(ba.updates, 5);
	assertEquals(ba.removals, 0);
    }

    @Test
    public void test09() {
        // Verify the functionatliy of the DatabaseAdaptor with UDP traffic

        class BasicAdaptor extends DatabaseAdaptor {
            public int inserts = 0;
            public int updates = 0;
            public int removals = 0;

            public void connect(String s) { }
            public void insert(String key) { inserts += 1; }
            public void update(String key,String data) { updates += 1;}
            public void remove(String key) { removals +=1; }
        }

        BasicAdaptor ba = new BasicAdaptor();

        this.s.setUDPDatabaseAdaptor(ba,16);
	this.s.enableLinkLayerTagging("vlan");

        this.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(ba.inserts, 1);
        assertEquals(ba.updates, 1);
        assertEquals(ba.removals, 0);
    }

    @Test
    public void test10() {
        // Attach a database to the engine and test timeouts on udp flows

        class BasicAdaptor extends DatabaseAdaptor {
            public int inserts = 0;
            public int updates = 0;
            public int removals = 0;

            public void connect(String s) { }
            public void insert(String key) { inserts += 1; }
            public void update(String key,String data) { updates += 1;}
            public void remove(String key) { removals +=1; }
        }

        BasicAdaptor ba = new BasicAdaptor();

        this.s.setUDPDatabaseAdaptor(ba,16);
        this.s.enableLinkLayerTagging("vlan");

        this.s.setFlowsTimeout(1);

        this.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(ba.inserts, 1);
        assertEquals(ba.updates, 1);
        assertEquals(ba.removals, 1);
        assertEquals(this.s.getFlowsTimeout(), 1);
    }

    @Test
    public void test11() {
        // Verify the functionatliy of the RegexManager on the HTTP Protocol for analise
        // inside the l7 payload of HTTP 

        class ExternalCallbackDomain extends JaiCallback{
            public boolean called = false;
            public void call(Flow flow) {
                HTTPInfo s = flow.getHTTPInfoObject();
                called = true;
            }
        }

        class ExternalCallbackRegex extends JaiCallback{
            public boolean called = false;
            public void call(Flow flow) {
                HTTPInfo s = flow.getHTTPInfoObject();
                Regex r = flow.getRegex();
                called = true;
            }
        }

	ExternalCallbackDomain ecd = new ExternalCallbackDomain();
	ExternalCallbackRegex ecr = new ExternalCallbackRegex();

        DomainName d = new DomainName("Wired domain",".wired.com");

        RegexManager rm = new RegexManager();
        Regex r1 = new Regex("Regex for analysing the content of HTTP","^\\x1f\\x8b\\x08\\x00\\x00\\x00\\x00.*$");
        Regex r2 = new Regex("Regex for analysing the content of HTTP","^.{3}\\xcd\\x9c\\xc0\\x0a\\x34.*$");
        Regex r3 = new Regex("Regex for analysing the content of HTTP","^.*\\x44\\x75\\x57\\x0c\\x22\\x7b\\xa7\\x6d$");

        r2.setNextRegex(r3);
        r1.setNextRegex(r2);
        rm.addRegex(r1);
        r3.setCallback(ecr);

        // So the flows from wired.com will be analise the regexmanager attached 
        d.setRegexManager(rm);

        DomainNameManager dm = new DomainNameManager();
        d.setCallback(ecd);
        dm.addDomainName(d);

        this.s.setDomainNameManager(dm,"HTTPProtocol");

        this.pd.open("../pcapfiles/two_http_flows_noending.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(r1.getMatchs(), 1);
        assertEquals(r2.getMatchs(), 1);
        assertEquals(r3.getMatchs(), 1);
        assertEquals(d.getMatchs(), 1);
        assertEquals(ecd.called, true);
        assertEquals(ecr.called, true);
    }
    
    @Test
    public void test12() {
        // Verify the correctness of the HTTP Protocol 
        // The filter tcp and port 55354 will filter just one HTTP flow
        // that contains exactly 39 requests and 38 responses 

        this.pd.open("../pcapfiles/two_http_flows_noending.pcap");
	this.pd.setPcapFilter("tcp and port 55354");
        this.pd.run();
        this.pd.close();

        Counters c = this.s.getCounters("HTTPProtocol");
        assertEquals(c.get("requests"), 39);
        assertEquals(c.get("responses"), 38);
    }

    @Test
    public void test13() {
        // Verify the correctness of the HTTP Protocol 
        // The filter tcp and port 49503 will filter just one HTTP flow
        // that contains exactly 3 requests and 3 responses

        this.pd.open("../pcapfiles/two_http_flows_noending.pcap");
        this.pd.setPcapFilter("tcp and port 49503");
        this.pd.run();
        this.pd.close();

        Counters c = this.s.getCounters("HTTPProtocol");

        // this.s.setStatisticsLevel(5);
        // this.s.statistics("HTTPProtocol");
        assertEquals(c.get("requests"), 3);
        assertEquals(c.get("responses"), 3);
    }

    public void test14() {
        // Verify the functionatliy of the RegexManager attach on a IPSet

        class ExternalCallbackIPSet extends JaiCallback{
            public boolean called = false;
            public void call(Flow flow) {
                // TODO: IPSet not retrieve
                called = true;
            }
        }

        class ExternalCallbackRegex extends JaiCallback{
            public boolean called = false;
            public void call(Flow flow) {
                Regex r = flow.getRegex();
                called = true;
            }
        }

        ExternalCallbackIPSet eci = new ExternalCallbackIPSet();
        ExternalCallbackRegex ecr = new ExternalCallbackRegex();
        RegexManager rm = new RegexManager();

        IPSet ip = new IPSet("IPSet address");
        ip.addIPAddress("95.100.96.10");
        ip.setCallback(eci);
        ip.setRegexManager(rm);

        IPSetManager ipm = new IPSetManager();
        ipm.addIPSet(ip);

        Regex r = new Regex("generic http","^GET.*HTTP.*$");

        r.setCallback(ecr);
        rm.addRegex(r);
       
        this.s.setTCPIPSetManager(ipm);
        this.s.enableNIDSEngine(true);
 
        this.pd.open("../pcapfiles/two_http_flows_noending.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(eci.called, true);
        assertEquals(ecr.called, true);
        assertEquals(ip.getTotalLookupsIn() , 1);
        assertEquals(r.getMatchs() , 1);
    }
}

