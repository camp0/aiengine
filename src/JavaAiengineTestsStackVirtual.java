import org.junit.*; 
import static org.junit.Assert.*;

public class JavaAiengineTestsStackVirtual { 

    private StackVirtual s;
    private PacketDispatcher pd;

    @Before
    public void setUp(  ) {
	
	this.s = new StackVirtual();
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
        Regex r = new Regex("Bin directory","^bin$");
        rm.addRegex(r);

        this.s.setTCPRegexManager(rm);

        this.pd.open("../pcapfiles/vxlan_ftp.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(r.getMatchs(), 1);
    }

    @Test
    public void test02() {
        RegexManager rm = new RegexManager();
        Regex r = new Regex("SSH over cloud infraestructure","^SSH-2.0.*$");
        rm.addRegex(r);

        this.s.setTCPRegexManager(rm);

        this.pd.open("../pcapfiles/gre_ssh.pcap");
        this.pd.run();
        this.pd.close();

        assertEquals(r.getMatchs(), 1);
    }

}

