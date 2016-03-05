import org.junit.*; 
import static org.junit.Assert.*;

public class JavaAiengineTestsStackLanIPv6 { 

    private StackLanIPv6 s;
    private PacketDispatcher pd;

    @Before
    public void setUp(  ) {
	
	this.s = new StackLanIPv6();
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
	Regex r = new Regex("Generic exploit NOP","\\x90\\x90\\x90\\x90\\x90\\x90\\x90");
	rm.addRegex(r);

	this.s.setTCPRegexManager(rm);

       	this.pd.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap");
        this.pd.run();
        this.pd.close();

	assertEquals(r.getMatchs(), 1);
	assertEquals(r.getTotalEvaluates(), 1);
    }

    @Test
    public void test02() {
        class ExternalCallbackIPSet extends JaiCallback{
            public boolean called = false;
            public void call(Flow flow) {
                called = true;
            } 
        }
        ExternalCallbackIPSet eci = new ExternalCallbackIPSet();
        IPSet ipset = new IPSet("IPv6 generic set");
        ipset.addIPAddress("dc20:c7f:2012:11::2");
        ipset.addIPAddress("dc20:c7f:2012:11::1");
        ipset.setCallback(eci);
        
        IPSetManager im = new IPSetManager();

        im.addIPSet(ipset);
        this.s.setTCPIPSetManager(im);

        RegexManager rm = new RegexManager();
        Regex r1 = new Regex("Generic exploit NOP","\\x90\\x90\\x90\\x90\\x90\\x90\\x90");
        Regex r2 = new Regex("other exploit","(this can not match)");
        rm.addRegex(r1);
        rm.addRegex(r2);

        this.s.setTCPRegexManager(rm);

        this.pd.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(r1.getMatchs(), 1);
        assertEquals(r1.getTotalEvaluates(), 1);
        assertEquals(r2.getMatchs(), 0);
        assertEquals(r2.getTotalEvaluates(), 0);
        assertEquals(eci.called, true);
    }

    @Test
    public void test03() {
        // Attach a database to the engine for TCP traffic

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

        this.s.setTCPDatabaseAdaptor(ba,16);

        this.pd.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(ba.inserts, 1);
        assertEquals(ba.updates, 5);
        assertEquals(ba.removals, 1);
    }

    @Test
    public void test04() {
        // Attach a database to the engine for UDP traffic

        class BasicAdaptor extends DatabaseAdaptor {
            public int inserts = 0;
            public int updates = 0;
            public int removals = 0;

            public void connect(String s) { }
            public void insert(String key) { inserts += 1; }
            public void update(String key,String data) { updates += 1;}
            public void remove(String key) { removals +=1; }
        }

        BasicAdaptor ba_udp = new BasicAdaptor();
        BasicAdaptor ba_tcp = new BasicAdaptor();

        this.s.setUDPDatabaseAdaptor(ba_udp,16);
        this.s.setTCPDatabaseAdaptor(ba_tcp);

        this.pd.open("../pcapfiles/ipv6_google_dns.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(ba_udp.inserts, 1);
        assertEquals(ba_udp.updates, 1);
        assertEquals(ba_udp.removals, 0);
        
        assertEquals(ba_tcp.inserts, 0);
        assertEquals(ba_tcp.updates, 0);
        assertEquals(ba_tcp.removals, 0);
    }

    @Test
    public void test05() {
        // Test the functionality of make graphs of regex, for complex detecctions 

        RegexManager rmbase = new RegexManager();
        RegexManager rm2 = new RegexManager();
        Regex r1 = new Regex("r1","^(No hacker should visit Las Vegas).*$");

        rmbase.addRegex(r1);

        r1.setNextRegexManager(rm2);

        Regex r2 = new Regex("r2","(this can not match)");
        Regex r3 = new Regex("r3","^\\x90\\x90\\x90\\x90.*$");
        rm2.addRegex(r2);
        rm2.addRegex(r3);

        this.s.setTCPRegexManager(rmbase);

        this.pd.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(r1.getMatchs(), 1);
        assertEquals(r2.getMatchs(), 0);
        assertEquals(r3.getMatchs(), 1);
    }

    @Test
    public void test06() {
        // Verify the correctness of the HTTP Protocol on IPv6 with the getCounters

        this.pd.open("../pcapfiles/http_over_ipv6.pcap");
        this.pd.run();
        this.pd.close();

        Counters c = this.s.getCounters("HTTPProtocol");
        assertEquals(c.get("requests"), 11);
        assertEquals(c.get("responses"), 11);
    }

    @Test
    public void test07() {
        // Verify the functionatliy of the RegexManager on the HTTP Protocol for analise
        // inside the l7 payload of HTTP on IPv6 traffic 

        class ExternalCallbackDomain extends JaiCallback{
            public boolean called = false;
            public void call(Flow flow) {
                called = true;
            }
        }

        class ExternalCallbackRegex extends JaiCallback{
            public boolean called = false;
            public void call(Flow flow) {
                Regex r = flow.getRegex();
                HTTPInfo h = flow.getHTTPInfoObject();
                assertEquals(r.getName(),"Regex for analysing the content of HTTP");
                assertEquals(h.getHostName(),"media.us.listen.com");
                called = true;
            }
        }

        ExternalCallbackDomain ecd = new ExternalCallbackDomain();
        ExternalCallbackRegex ecr = new ExternalCallbackRegex();
        DomainName d = new DomainName("Music domain",".us.listen.com");

        RegexManager rm = new RegexManager();
        Regex r1 = new Regex("Regex for analysing the content of HTTP","^\\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a.*$");

        rm.addRegex(r1);
        r1.setCallback(ecr);

        // So the flows from listen.com will be analise the regexmanager attached 
        d.setRegexManager(rm);

        DomainNameManager dm = new DomainNameManager();
        d.setCallback(ecd);
        dm.addDomainName(d);

        this.s.setDomainNameManager(dm,"HTTPProtocol");

        this.pd.open("../pcapfiles/http_over_ipv6.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(ecd.called, true);
        assertEquals(ecr.called, true);
        assertEquals(r1.getMatchs(), 1);
        assertEquals(d.getMatchs(), 1);
    }
}

