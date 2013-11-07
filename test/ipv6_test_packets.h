#ifndef _ipv6_test_packets_H_
#define _ipv6_test_packets_H_

// ethernet,ipv6,icmpv6, echo request
// srcip = 2001:470:d37b:1:214:2aff:fe33:747e
// dstip = 2001:470:d37b:2::6
// iplenght = 64
static char *raw_packet_ethernet_ipv6_icmpv6_ping_request = 
"\x00\x50\x56\x09\xec\x32\x00\x14\x2a\x33\x74\x7e\x86\xdd\x60\x00"
"\x00\x00\x00\x40\x3a\x40\x20\x01\x04\x70\xd3\x7b\x00\x01\x02\x14"
"\x2a\xff\xfe\x33\x74\x7e\x20\x01\x04\x70\xd3\x7b\x00\x02\x00\x00"
"\x00\x00\x00\x00\x00\x06\x80\x00\x5f\xe9\xe0\x4d\x00\x01\x0f\x2a"
"\x9e\x4c\x0c\x2b\x0b\x00\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"
"\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21"
"\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31"
"\x32\x33\x34\x35\x36\x37";

static int raw_packet_ethernet_ipv6_icmpv6_ping_request_length = 118;


// ethernet,ipv6, tcp,and HTTP GET"

static char *raw_packet_ethernet_ipv6_tcp_http_get=
// ethernet header
"\x00\x90\x1a\x41\x65\x41\x00\x16\xcf\x41\x9c\x20\x86\xdd"		//14
// ipv6 header size 40,payload length 817,x
// srcip = 2002:4637:d5d3::4637:d5d3
// dstip= 2001:4860:0:2001::68
"\x60\x00\x00\x00\x03\x31\x06\x80\x20\x02\x46\x37\xd5\xd3\x00\x00"	//40
"\x00\x00\x00\x00\x46\x37\xd5\xd3\x20\x01\x48\x60\x00\x00\x20\x01"
"\x00\x00\x00\x00\x00\x00\x00\x68"
// tcp header,source port 1287 and dest port 80
"\x05\x07\x00\x50\x22\xec\x55\x11\x3a\xc0\x0d\x61\x50\x18\x41\xcb"	//20
"\x66\x18\x00\x00"
// HTTP GET
"\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a"	//\x797
"\x48\x6f\x73\x74\x3a\x20\x69\x70\x76\x36\x2e\x67\x6f\x6f\x67\x6c"
"\x65\x2e\x63\x6f\x6d\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e"
"\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28"
"\x57\x69\x6e\x64\x6f\x77\x73\x3b\x20\x55\x3b\x20\x57\x69\x6e\x64"
"\x6f\x77\x73\x20\x4e\x54\x20\x35\x2e\x31\x3b\x20\x65\x6e\x2d\x55"
"\x53\x3b\x20\x72\x76\x3a\x31\x2e\x39\x62\x35\x29\x20\x47\x65\x63"
"\x6b\x6f\x2f\x32\x30\x30\x38\x30\x33\x32\x36\x32\x30\x20\x46\x69"
"\x72\x65\x66\x6f\x78\x2f\x33\x2e\x30\x62\x35\x0d\x0a\x41\x63\x63"
"\x65\x70\x74\x3a\x20\x74\x65\x78\x74\x2f\x68\x74\x6d\x6c\x2c\x61"
"\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x68\x74\x6d\x6c"
"\x2b\x78\x6d\x6c\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e"
"\x2f\x78\x6d\x6c\x3b\x71\x3d\x30\x2e\x39\x2c\x2a\x2f\x2a\x3b\x71"
"\x3d\x30\x2e\x38\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x4c\x61\x6e"
"\x67\x75\x61\x67\x65\x3a\x20\x65\x6e\x2d\x75\x73\x2c\x65\x6e\x3b"
"\x71\x3d\x30\x2e\x35\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x45\x6e"
"\x63\x6f\x64\x69\x6e\x67\x3a\x20\x67\x7a\x69\x70\x2c\x64\x65\x66"
"\x6c\x61\x74\x65\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x43\x68\x61"
"\x72\x73\x65\x74\x3a\x20\x49\x53\x4f\x2d\x38\x38\x35\x39\x2d\x31"
"\x2c\x75\x74\x66\x2d\x38\x3b\x71\x3d\x30\x2e\x37\x2c\x2a\x3b\x71"
"\x3d\x30\x2e\x37\x0d\x0a\x4b\x65\x65\x70\x2d\x41\x6c\x69\x76\x65"
"\x3a\x20\x33\x30\x30\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f"
"\x6e\x3a\x20\x6b\x65\x65\x70\x2d\x61\x6c\x69\x76\x65\x0d\x0a\x43"
"\x6f\x6f\x6b\x69\x65\x3a\x20\x50\x52\x45\x46\x3d\x49\x44\x3d\x37"
"\x36\x35\x38\x37\x30\x63\x62\x35\x66\x66\x33\x30\x33\x61\x33\x3a"
"\x54\x4d\x3d\x31\x32\x30\x39\x32\x33\x30\x31\x34\x30\x3a\x4c\x4d"
"\x3d\x31\x32\x30\x39\x32\x35\x35\x33\x35\x38\x3a\x47\x4d\x3d\x31"
"\x3a\x53\x3d\x74\x46\x47\x63\x55\x55\x4b\x64\x5a\x54\x54\x6c\x46"
"\x68\x67\x38\x3b\x20\x72\x65\x6d\x65\x6d\x62\x65\x72\x6d\x65\x3d"
"\x74\x72\x75\x65\x3b\x20\x53\x49\x44\x3d\x44\x51\x41\x41\x41\x48"
"\x63\x41\x41\x41\x44\x79\x6d\x6e\x66\x32\x37\x57\x53\x64\x6d\x71"
"\x38\x56\x4b\x37\x44\x74\x51\x6b\x44\x43\x59\x77\x70\x54\x36\x79"
"\x45\x48\x31\x63\x38\x70\x36\x63\x72\x72\x69\x72\x54\x4f\x33\x48"
"\x73\x58\x4e\x32\x4e\x5f\x70\x4f\x63\x57\x2d\x54\x38\x32\x6c\x63"
"\x4e\x79\x76\x6c\x55\x48\x67\x58\x69\x56\x50\x73\x5a\x59\x72\x48"
"\x36\x54\x6e\x6a\x51\x72\x67\x43\x45\x4f\x4c\x6a\x55\x53\x4f\x43"
"\x72\x6c\x4c\x46\x68\x35\x49\x30\x42\x64\x47\x6a\x69\x6f\x78\x7a"
"\x6d\x6b\x73\x67\x57\x72\x72\x66\x65\x4d\x56\x2d\x79\x37\x62\x78"
"\x31\x54\x31\x4c\x50\x43\x4d\x44\x4f\x57\x30\x57\x6b\x77\x30\x58"
"\x46\x71\x57\x4f\x70\x4d\x6c\x6b\x42\x43\x48\x73\x64\x74\x32\x56"
"\x63\x73\x68\x61\x30\x6a\x32\x30\x56\x70\x49\x61\x77\x36\x79\x67"
"\x3b\x20\x4e\x49\x44\x3d\x31\x30\x3d\x6a\x4d\x59\x57\x4e\x6b\x6f"
"\x7a\x73\x6c\x41\x34\x55\x61\x52\x75\x38\x7a\x79\x46\x53\x4c\x45"
"\x6e\x73\x38\x69\x57\x56\x7a\x34\x47\x64\x6b\x65\x65\x66\x6b\x71"
"\x56\x6d\x35\x64\x46\x53\x30\x46\x30\x7a\x74\x63\x38\x68\x44\x6c"
"\x4e\x4a\x52\x6c\x6c\x62\x5f\x57\x65\x59\x65\x39\x57\x78\x36\x61"
"\x38\x59\x6f\x37\x4d\x6e\x72\x46\x7a\x71\x77\x5a\x63\x7a\x67\x58"
"\x56\x35\x65\x2d\x52\x46\x62\x43\x72\x72\x4a\x39\x64\x66\x55\x35"
"\x67\x73\x37\x39\x4c\x5f\x76\x33\x42\x53\x64\x75\x65\x49\x67\x5f"
"\x4f\x4f\x66\x6a\x70\x53\x63\x53\x68\x0d\x0a\x0d\x0a";

static int raw_packet_ethernet_ipv6_tcp_http_get_length = 14+40+20+797;

// Source ip fe80::9c09:b416:768:ff42
// dest ip: ff02::1:3
// payload length 41 from ip
static char *raw_packet_ethernet_ipv6_udp_llmnr = 
"\x33\x33\x00\x01\x00\x03\x00\x12\x3f\x97\x92\x01\x86\xdd\x60\x00"
"\x00\x00\x00\x29\x11\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x9c\x09"
"\xb4\x16\x07\x68\xff\x42\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x01\x00\x03\xea\x46\x14\xeb\x00\x29\xbf\xfa\x49\xe2"
"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0f\x63\x68\x6d\x75\x74"
"\x68\x75\x2d\x77\x37\x2d\x74\x65\x73\x74\x00\x00\xff\x00\x01";

static int raw_packet_ethernet_ipv6_udp_llmnr_length = 95;


// ethernet,ipv6, tcp,and HTTP GET"
static char *raw_packet_ethernet_ipv6_tcp_http_get2=
// ethernet header
"\x00\x90\x1a\x41\x65\x41\x00\x16\xcf\x41\x9c\x20\x86\xdd"              //14
// ipv6 header size 40,payload length 4
// dstip = 2002:4637:d5d3::4637:d5d3
// srcip= 2001:4860:0:2001::68
"\x60\x00\x00\x00\x00\x18\x06\x80" // header
"\x20\x01\x48\x60\x00\x00\x20\x01\x00\x00\x00\x00\x00\x00\x00\x68"
"\x20\x02\x46\x37\xd5\xd3\x00\x00\x00\x00\x00\x00\x46\x37\xd5\xd3"      
// tcp header,source port 1287 and dest port 80
"\x05\x07\x00\x50\x22\xec\x55\x11\x3a\xc0\x0d\x61\x50\x18\x41\xcb"      //20
"\x66\x18\x00\x00"
// HTTP GET
"\x47\x45\x54\x20";

static int raw_packet_ethernet_ipv6_tcp_http_get2_length = 14+40+20+4;


// packet from the defcon21
// srcip dc20:c7f:2012:5::2
// dstip dc20:c7f:2012:13::2
// tcpsrc port 40667
// tcpdst port 6941
// payload: its peanut butter & semem time.
// payloadlength:31
static char *raw_packet_ethernet_ipv6_tcp_port_6941 = 
"\x00\x50\x56\xb5\x64\xe7\x00\x50\x56\xb5\x64\xc6\x86\xdd\x60\x0e"
"\x4f\x40\x00\x3f\x06\x40\xdc\x20\x0c\x7f\x20\x12\x00\x05\x00\x00"
"\x00\x00\x00\x00\x00\x02\xdc\x20\x0c\x7f\x20\x12\x00\x13\x00\x00"
"\x00\x00\x00\x00\x00\x02\x9e\xdb\x1b\x1d\xf4\x2f\xb6\xfc\x9f\x2b"
"\xc2\x4f\x80\x18\x04\x02\x8b\x75\x00\x00\x01\x01\x08\x0a\x00\x0e"
"\x3b\x62\xe4\x96\xee\xe3\x69\x74\x73\x20\x70\x65\x61\x6e\x75\x74"
"\x20\x62\x75\x74\x74\x65\x72\x20\x26\x20\x73\x65\x6d\x65\x6d\x20"
"\x74\x69\x6d\x65\x0a";

static int raw_packet_ethernet_ipv6_tcp_port_6941_length = 117;

// DNS Packet
// srcip 3ffe:507:0:1:200:86ff:fe05:80da 
// dstip 3ffe:501:4819::42 
// srcport 2415
// dstport 53
// query: standar query
// NEED TO FIX THE LENGTH OF THIS PACKET.
static char *raw_packet_ethernet_ipv6_udp_dns =
"\x00\x60\x97\x07\x69\xea\x00\x00\x86\x05\x80\xda\x86\xdd\x60\x00"
"\x00\x00\x00\x61\x11\x40\x3f\xfe\x05\x07\x00\x00\x00\x01\x02\x00"
"\x86\xff\xfe\x05\x80\xda\x3f\xfe\x05\x01\x48\x19\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x42\x09\x6f\x00\x35\x00\x61\xa3\x35\x5c\x78"
"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x61\x01\x65\x01\x39"
"\x01\x36\x01\x37\x01\x30\x01\x65\x01\x66\x01\x66\x01\x66\x01\x37"
"\x01\x39\x01\x30\x01\x36\x01\x32\x01\x30\x01\x31\x01\x30\x01\x30"
"\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x37\x01\x30\x01\x35"
"\x01\x30\x01\x65\x01\x66\x01\x66\x01\x33\x03\x69\x70\x36\x03\x69"
"\x6e\x74\x00\x00\x0c\x00\x01";

static int raw_packet_ethernet_ipv6_udp_dns_length = 151;

// Packet from the defcon20 pcapfiles
// srcip dc20:c7f:2012:5::2 
// dstip dc20:c7f:2012:11::2 
// srcport 19027
// dstport 35575
// tcp flags:push,ack,fin
// payloadlengt =103

static char *raw_packet_ethernet_ipv6_tcp_nopsled = 
"\x00\x50\x56\xb5\x64\xe7\x00\x50\x56\xb5\x64\xc6\x86\xdd\x60\x08"
"\xee\xf6\x00\x87\x06\x40\xdc\x20\x0c\x7f\x20\x12\x00\x05\x00\x00"
"\x00\x00\x00\x00\x00\x02\xdc\x20\x0c\x7f\x20\x12\x00\x11\x00\x00"
"\x00\x00\x00\x00\x00\x02\x4a\x53\x8a\xf7\x84\x1f\xbf\xc6\x54\x3b"
"\x81\xd2\x80\x19\x04\x02\x1e\xff\x00\x00\x01\x01\x08\x0a\x00\x0e"
"\x55\xbf\x05\x0e\x9a\xe7\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";

static int raw_packet_ethernet_ipv6_tcp_nopsled_length = 189;

#endif

