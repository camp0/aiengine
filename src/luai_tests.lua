luaunit = require('luaunit')
luaiengine = require('luaiengine')
local inspect = require 'inspect'

Adaptor = {}

Adaptor.new = function()
    local self = {}
    setmetatable(self,luaiengine.DatabaseAdaptor)
    self.inserts = 0
    self.updates = 0
    self.removes = 0

    self.get_inserts = function() return self.inserts end
    self.get_updates = function() return self.updates end
    self.get_removes = function() return self.removes end

    self.insert = function(key)
        self.inserts = self.inserts + 1
    end
    self.update = function(key,data)
        self.updates = self.updates + 1
    end
    self.remove = function(key)
        self.removes = self.removes + 1
    end
    return self
end

TestStackLan = {} 
    function TestStackLan:setUp() 
        self.st = luaiengine.StackLan()
        self.pd = luaiengine.PacketDispatcher()

        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        -- self.st:tcp_total_flows(1000)
        -- print(self.st.name)
        self.pd:set_stack(self.st)
    end

    function TestStackLan:tearDown() 
    end

    function TestStackLan:test01()
        self.st.link_layer_tag = "vlan"

        rm = luaiengine.RegexManager()
        r = luaiengine.Regex("netbios","CACACACA")

        rm:add_regex(r)

        -- self.st.enable_nids_engine =True
        self.st.udp_regex_manager = rm

        print(inspect(luaiengine.StackLan))

        self.pd:open("../pcapfiles/flow_vlan_netbios.pcap");
        self.pd:run();
        self.pd:close();

        luaunit.assertEquals( r.matchs, 1 )
        -- TODO: luaunit.assertEquals( self.st.udp_regex_manager, rm)
    end

    function TestStackLan:test02()
        local callme = false

        function mycallback (flow)
            luaunit.assertEquals( flow.src_ip, "192.168.1.13")
            luaunit.assertEquals( flow.dst_ip, "74.125.24.189")
            luaunit.assertNotEquals( flow.ssl_info, nill)
            luaunit.assertEquals( flow.http_info, nill)
            luaunit.assertEquals( flow.dns_info, nill)
            luaunit.assertEquals( flow.smtp_info, nill)

            luaunit.assertEquals( flow.ssl_info.server_name, "0.drive.google.com")
            callme = true
        end

        local d = luaiengine.DomainName("Google Drive Cert",".drive.google.com")

        d:set_callback("mycallback")
        dm = luaiengine.DomainNameManager()
        dm:add_domain_name(d)

        self.st:set_domain_name_manager(dm,"SSLProtocol")

        self.pd:open("../pcapfiles/sslflow.pcap");
        self.pd:run();
        self.pd:close();

        luaunit.assertEquals(d.matchs , 1)
        luaunit.assertEquals( callme, true)
    
        local c = self.st:get_counters("SSLProtocol")
        luaunit.assertEquals(c:has_key("packets"), true)
        luaunit.assertEquals(c:get("packets"), 56)
        luaunit.assertEquals(c:get("bytes"), 41821)
        luaunit.assertEquals(c:get("allow hosts"), 1)
        luaunit.assertEquals(c:get("banned hosts"), 0)
        luaunit.assertEquals(c:get("client hellos"), 1)
        luaunit.assertEquals(c:get("server hellos"), 1)
        luaunit.assertEquals(c:get("certificates"), 1)
        luaunit.assertEquals(c:get("records"), 3)
    end  
 
    function TestStackLan:test03()
        -- Verify SSL traffic with domain callback and IPset
        local callme_set = false
        local callme_domain = false

        -- print(inspect(luaiengine.Flow))

        function ipset_callback(flow)
            -- TODO luaunit.assertNotEquals( flow.ipset_info, nill)
            luaunit.assertEquals( flow.ssl_info, nill)
            luaunit.assertEquals( flow.http_info, nill)
            luaunit.assertEquals( flow.dns_info, nill)
            luaunit.assertEquals( flow.smtp_info, nill)

            callme_set = true
        end 

        function domain_callback(flow)
            luaunit.assertNotEquals( flow.ssl_info, nill)
            luaunit.assertEquals( flow.http_info, nill)
            luaunit.assertEquals( flow.dns_info, nill)
            luaunit.assertEquals( flow.smtp_info, nill)
            luaunit.assertEquals( flow.ssl_info.server_name,"0.drive.google.com")
            callme_domain = true
        end
        
        i = luaiengine.IPSet("Specific IP address")
        i:add_ip_address("74.125.24.189")
        i:set_callback("ipset_callback")

        ip = luaiengine.IPSetManager()
        ip:add_ip_set(i)

        d = luaiengine.DomainName("Google All",".google.com")
        d:set_callback("domain_callback")

        dm = luaiengine.DomainNameManager()
        dm:add_domain_name(d)

        self.st.tcp_ip_set_manager = ip
        self.st:set_domain_name_manager(dm,"SSLProtocol")

        self.pd:open("../pcapfiles/sslflow.pcap")
        self.pd:run()
        self.pd:close()

        luaunit.assertEquals( d.matchs , 1)
        luaunit.assertEquals( callme_set, true)
        luaunit.assertEquals( callme_domain, true)
    end

    function TestStackLan:test04()
        -- Verify HTTP traffic with domain callback 
        local callme_domain = false

        -- print(inspect(luaiengine.HTTPInfo))

        function domain_callback(flow)
            luaunit.assertNotEquals (flow.http_info,nill) 
            luaunit.assertEquals( flow.http_info.host_name,"www.wired.com")
            luaunit.assertEquals( flow.http_info.uri, "/css/global.css?v=20121120a")
            callme_domain = true
        end

        local d = luaiengine.DomainName("Wired domain",".wired.com")
        local dm = luaiengine.DomainNameManager()

        d:set_callback("domain_callback")
        dm:add_domain_name(d)

        self.st:set_domain_name_manager(dm,"HTTPProtocol")

        self.pd:open("../pcapfiles/two_http_flows_noending.pcap")
        self.pd:run()
        self.pd:close()
        
        luaunit.assertEquals( d.matchs , 1)
        luaunit.assertEquals( callme_domain, true)
    end

    function TestStackLan:test05()
        -- Verify SMTP traffic with domain callback 
        local callme = false

        function domain_callback(flow)
            s = flow.smtp_info
            luaunit.assertNotEquals(s,nill)
            luaunit.assertEquals(s.mail_from, "gurpartap@patriots.in")
            callme = true
        end 

        d = luaiengine.DomainName("Some domain",".patriots.in")
        d:set_callback("domain_callback")

        dm = luaiengine.DomainNameManager()
        dm:add_domain_name(d)

        self.st:set_domain_name_manager(dm,"SMTPProtocol")

        self.pd:open("../pcapfiles/smtp.pcap")
        self.pd:run()
        self.pd:close()

        local c = self.st:get_counters("SMTPProtocol")
        luaunit.assertEquals(c:has_key("packets"), true)
        luaunit.assertEquals(c:get("packets"), 33)
        luaunit.assertEquals(c:get("bytes"), 21083)
        luaunit.assertEquals(c:get("commands"), 6)
        luaunit.assertEquals(c:get("responses"), 10)
 
        luaunit.assertEquals (d.matchs , 1)
        luaunit.assertEquals (callme,true)
    end
    
    function TestStackLan:test06()

        -- d = luaiengine.DatabaseAdaptor()
        -- print(inspect(d))

        self.st.link_layer_tag  = "vlan"
        -- self.st:set_udp_database_adaptor(d,16)

        self.pd:open("../pcapfiles/flow_vlan_netbios.pcap");
        self.pd:run();
        self.pd:close();

        --self.assertEqual(db.getInserts(), 1)
        --self.assertEqual(db.getUpdates(), 1)
        --self.assertEqual(db.getRemoves(), 0)

        -- d:insert = insert
    end

    function TestStackLan:test07()
        -- Verify the functionatliy of the HTTPUriSets with the callbacks 
        local call_set = false
        local call_domain = false
        local uset = luaiengine.HTTPUriSet()

        -- called on the first request
        function domain_callback(flow)
            luaunit.assertNotEquals(flow.http_info,nill)
            h = flow.http_info
            luaunit.assertEquals(h.host_name, "www.wired.com")
            luaunit.assertEquals(h.uri,"/css/global.css?v=20121120a")
            luaunit.assertNotEquals(h.matched_domain_name,nill)
            luaunit.assertEquals(h.matched_domain_name.name,"Wired domain")
            call_domain = true
        end

        -- called on the request with the macht uri
        function uri_callback(flow)
            luaunit.assertNotEquals(flow.http_info,nill)
            h = flow.http_info
            luaunit.assertEquals(h.host_name, "www.wired.com")
            luaunit.assertEquals(h.uri,"/images_blogs/gadgetlab/2013/08/AP090714043057-60x60.jpg")
            call_set = true
        end

        d = luaiengine.DomainName("Wired domain",".wired.com")

        dm = luaiengine.DomainNameManager()
        d:set_callback("domain_callback")
        dm:add_domain_name(d)

        uset:add_uri("/images_blogs/gadgetlab/2013/08/AP090714043057-60x60.jpg")
        uset:set_callback("uri_callback")

        d:set_http_uri_set(uset)

        self.st:set_domain_name_manager(dm,"HTTPProtocol")

        self.pd:open("../pcapfiles/two_http_flows_noending.pcap");
        self.pd:run();
        self.pd:close();

        luaunit.assertEquals( call_domain, true)
        luaunit.assertEquals( call_set, true)
        luaunit.assertEquals( uset.total_lookups, 39)
        luaunit.assertEquals( uset.total_lookups_in, 1)
        luaunit.assertEquals( uset.total_lookups_out, 38)
    end

    function TestStackLan:test08()
        -- Verify SSL traffic with domain callback and IPset
        local call_set = false
        local call_domain = false

        function ipset_callback(flow)
            s = flow.ssl_info
            luaunit.assertEquals(s,nill)
            call_set = true
        end

        function domain_callback(flow)
            s = flow.ssl_info
            luaunit.assertNotEquals(s,nill)
            luaunit.assertEquals(s.server_name,"0.drive.google.com")
            luaunit.assertEquals(s.matched_domain_name.name,"Google All")
            call_domain = true
        end

        ip = luaiengine.IPSet("Specific IP address")
        ip:add_ip_address("74.125.24.189")
        ip:set_callback("ipset_callback")

        ipm = luaiengine.IPSetManager()
        ipm:add_ip_set(ip)

        d = luaiengine.DomainName("Google All",".google.com")
        d:set_callback("domain_callback")

        dm = luaiengine.DomainNameManager()
        dm:add_domain_name(d)

        self.st.tcp_ip_set_manager = ipm
        self.st:set_domain_name_manager(dm,"SSLProtocol")

        self.pd:open("../pcapfiles/sslflow.pcap");
        self.pd:run();
        self.pd:close();

        luaunit.assertEquals( call_domain, true)
        luaunit.assertEquals( call_set, true)
    end

    function TestStackLan:test09()
        -- Verify the coap protocol functionality with domains matched 
        local callme_domain = false

        function domain_callback(flow)
            luaunit.assertNotEquals(flow.coap_info,nill)
            luaunit.assertEquals(flow.coap_info.host_name,"localhost")
            luaunit.assertEquals(flow.coap_info.uri,"/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time")
            callme_domain = true
        end

        d = luaiengine.DomainName("Localhost domain","localhost")

        dm = luaiengine.DomainNameManager()
        d:set_callback("domain_callback")
        dm:add_domain_name(d)

        self.st:set_domain_name_manager(dm,"CoAPProtocol")

        self.pd:open("../pcapfiles/ipv4_coap_big_uri.pcap");
        self.pd:run();
        self.pd:close();

        luaunit.assertEquals(callme_domain, true)
        luaunit.assertEquals(d.matchs, 1)


    end

TestStackMobile = {} 
    function TestStackMobile:setUp() 
        self.st = luaiengine.StackMobile()
        self.pd = luaiengine.PacketDispatcher()

        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.pd:set_stack(self.st)
    end

    function TestStackMobile:tearDown() 
    end

    function TestStackMobile:test01()
        -- Check functionality for gprs and icmp
        -- gprs_icmp.pcap 
        -- self.st.link_layer_tag = "vlan"

        self.pd:open("../pcapfiles/gprs_icmp.pcap");
        self.pd:run();
        self.pd:close();
        -- print(inspect(luaiengine.StackMobile))

        local c = self.st:get_counters("GPRSProtocol")
        luaunit.assertEquals(c:has_key("packets"), true)
        luaunit.assertEquals(c:get("packets"), 4)
        luaunit.assertEquals(c:get("bytes"), 368)
        luaunit.assertEquals(c:get("create pdp reqs"), 0)
        luaunit.assertEquals(c:get("tpdus"), 4)

        c = self.st:get_counters("ICMPProtocol")
        luaunit.assertEquals(c:has_key("packets"), true)
        luaunit.assertEquals(c:get("packets"), 4)
        luaunit.assertEquals(c:get("echo"), 2)
        luaunit.assertEquals(c:get("echoreplay"), 2)
    end

    function TestStackMobile:test02()
        -- Check functionality for gprs and sip
        -- gprs_icmp.pcap 
        -- self.st.link_layer_tag = "vlan"

        self.pd:open("../pcapfiles/gprs_sip_flow.pcap");
        self.pd:run();
        self.pd:close();
        -- print(inspect(luaiengine.StackMobile))

        local c = self.st:get_counters("GPRSProtocol")
        luaunit.assertEquals(c:has_key("packets"), true)
        luaunit.assertEquals(c:get("packets"), 22)
        luaunit.assertEquals(c:get("bytes"), 15329)
        luaunit.assertEquals(c:get("create pdp reqs"), 0)
        luaunit.assertEquals(c:get("tpdus"), 22)

        c = self.st:get_counters("SIPProtocol")
        luaunit.assertEquals(c:has_key("packets"), true)
        luaunit.assertEquals(c:get("packets"), 22)
        luaunit.assertEquals(c:get("requests"), 7)
        luaunit.assertEquals(c:get("responses"), 7)
        luaunit.assertEquals(c:get("registers"), 2)
    end

TestStackLanIPv6 = {} 
    function TestStackLanIPv6:setUp() 
        self.st = luaiengine.StackLanIPv6()
        self.pd = luaiengine.PacketDispatcher()

        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.pd:set_stack(self.st)
    end

    function TestStackLanIPv6:tearDown() 
    end

    function TestStackLanIPv6:test01()

        rm = luaiengine.RegexManager()
        r = luaiengine.Regex("generic exploit","\x90\x90\x90\x90\x90\x90\x90")
        rm:add_regex(r)

        self.st.tcp_regex_manager = rm

        self.pd:open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.pd:run()
        self.pd:close()

        luaunit.assertEquals(r.matchs, 1)
    end

    function TestStackLanIPv6:test02()

        im = luaiengine.IPSetManager()

        -- print(inspect(luaiengine.IPSetManager))
        -- print(inspect(luaiengine.IPSet))

        i = luaiengine.IPSet("IPv6 generic set")
        i:add_ip_address("dc20:c7f:2012:11::2")
        i:add_ip_address("dc20:c7f:2012:11::1")
        -- ipset.callback = ipset_callback

        im:add_ip_set(i)

        self.st.tcp_ip_set_manager = im

        self.pd:open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.pd:run()
        self.pd:close()

        luaunit.assertEquals(i.total_lookups_in, 1)
        luaunit.assertEquals(i.total_lookups_out, 0)
        -- im:statistics()
    end

    function TestStackLanIPv6:test03()
        -- Verify the get_counters for HTTP

        self.pd:open("../pcapfiles/http_over_ipv6.pcap")
        self.pd:run()
        self.pd:close()

        local c = self.st:get_counters("HTTPProtocol")
        luaunit.assertEquals(c:has_key("packets"), true)
        luaunit.assertEquals(c:get("packets"), 318)
        luaunit.assertEquals(c:get("bytes"), 400490)
        luaunit.assertEquals(c:get("L7 bytes"), 394179)
        -- TODO: this should be 1 ???
        luaunit.assertEquals(c:get("allow hosts"), 11)
        luaunit.assertEquals(c:get("banned hosts"), 0)
        luaunit.assertEquals(c:get("requests"), 11)
        luaunit.assertEquals(c:get("responses"), 11)

    end

    function TestStackLanIPv6:test04()
        -- Verify the functionatliy of the RegexManager on the HTTP Protocol for analise
        -- inside the l7 payload of HTTP on IPv6 traffic 
        local callme_dom = false
        local callme_regex = false

        function callback_domain(flow)
            luaunit.assertEquals( flow.http_info.host_name,"media.us.listen.com")
            callme_dom = true
        end

        function callback_regex(flow)
            luaunit.assertNotEquals( flow.regex,nill)
            luaunit.assertEquals(flow.regex.name,"Regex for analysing the content of HTTP")
            luaunit.assertEquals( flow.http_info.host_name,"media.us.listen.com")
            callme_regex = true
        end

        local d = luaiengine.DomainName("Music domain",".us.listen.com")

        local rm = luaiengine.RegexManager()
        r1 = luaiengine.Regex("Regex for analysing the content of HTTP","^\x89\x50\x4e\x47\x0d\x0a\x1a\x0a.*$")

        rm:add_regex(r1)
        r1:set_callback("callback_regex")

        -- So the flows from listen.com will be analise the regexmanager attached 
        d:setRegexManager(rm)

        dm = luaiengine.DomainNameManager()
        d:set_callback("callback_domain")
        dm:add_domain_name(d)

        self.st:set_domain_name_manager(dm,"HTTPProtocol")
        
        self.pd:open("../pcapfiles/http_over_ipv6.pcap") 
        self.pd:run()
        self.pd:close()

        luaunit.assertEquals( callme_dom , true)
        luaunit.assertEquals( callme_regex, true)
        luaunit.assertEquals( r1.matchs, 1)
        luaunit.assertEquals( d.matchs, 1) 
    end
    
    function TestStackLanIPv6:test05()
        -- Verify the DNS functionality
        local call_domain = false

        function domain_callback(flow)
            dom = flow.dns_info
            luaunit.assertNotEquals(dom,nill)
            luaunit.assertNotEquals(dom.matched_domain_name,nill)
            luaunit.assertEquals(dom.domain_name,"www.google.com")
            luaunit.assertEquals(dom.matched_domain_name.name,"Google domain")
            call_domain = true
        end

        d = luaiengine.DomainName("Google domain",".google.com")

        dm = luaiengine.DomainNameManager()
        d:set_callback("domain_callback")
        dm:add_domain_name(d)

        self.st:set_domain_name_manager(dm,"DNSProtocol")

        self.pd:open("../pcapfiles/ipv6_google_dns.pcap") 
        self.pd:run()
        self.pd:close()

        -- Get the countes of dns
        local c = self.st:get_counters("DNSProtocol")
        luaunit.assertEquals(c:has_key("total allow queries"), true)
        luaunit.assertEquals(c:get("total allow queries"), 1)
        luaunit.assertEquals(c:get("total type NS"), 0)
        luaunit.assertEquals(c:get("total type A"), 0)
        luaunit.assertEquals(c:get("total type AAAA"), 1)

        luaunit.assertEquals(call_domain, true)
        luaunit.assertEquals(d.matchs, 1)
    end

TestStackVirtual = {} 
    function TestStackVirtual:setUp() 
        self.st = luaiengine.StackVirtual()
        self.pd = luaiengine.PacketDispatcher()

        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.pd:set_stack(self.st)
    end

    function TestStackVirtual:tearDown() 
    end

    function TestStackVirtual:test01()
        -- Create a regex for a detect the flow on a virtual network on the GRE side 

        adap = Adaptor:new()
        self.st:set_tcp_database_adaptor("adap")

        local rm = luaiengine.RegexManager()
        r = luaiengine.Regex("Bin directory","^SSH-2.0.*$")
        rm:add_regex(r)
        self.st.tcp_regex_manager = rm

        self.pd:open("../pcapfiles/gre_ssh.pcap")
        self.pd:run()
        self.pd:close()

        luaunit.assertEquals(adap.inserts, 1)
        luaunit.assertEquals(adap.updates, 5)
        luaunit.assertEquals(r.matchs, 1)

    end


luaunit.LuaUnit:run()
