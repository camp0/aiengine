/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2016  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
 *
 */
#ifndef SRC_PYTHON_HELP_H_
#define SRC_PYTHON_HELP_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

const char *help_stack_name = 			"Gets the name of the Stack.";
const char *help_stack_stats_level = 		"Gets/Sets the number of statistics level for the stack (1-5).";
const char *help_stack_flows_timeout = 		"Gets/Sets the timeout for the TCP/UDP Flows of the stack";
const char *help_stack_tcp_flows = 		"Gets/Sets the maximum number of Flows to be on the cache for TCP traffic.";
const char *help_stack_udp_flows = 		"Gets/Sets the maximum number of Flows to be on the cache for UDP traffic.";
const char *help_stack_tcp_regex_manager = 	"Gets/Sets the TCP RegexManager for TCP traffic.";
const char *help_stack_udp_regex_manager = 	"Gets/Sets the UDP RegexManager for UDP traffic.";
const char *help_stack_tcp_ip_set_manager = 	"Gets/Sets the TCP IPSetManager for TCP traffic.";
const char *help_stack_udp_ip_set_manager = 	"Gets/Sets the UDP IPSetManager for UDP traffic.";
const char *help_stack_link_layer_tag = 	"Gets/Sets the Link layer tag for Vlans,Mpls encapsulations.";
const char *help_stack_tcp_flow_manager = 	"Gets the TCP FlowManager for iterate over the Flows.";
const char *help_stack_udp_flow_manager = 	"Gets the UDP FlowManager for iterate over the Flows.";
const char *help_enable_freq_engine = 		"Enables/Disables the Frequency Engine.";
const char *help_enable_nids_engine = 		"Enables/Disables the NIDS Engine.";
const char *help_increase_alloc_mem = 		"Increase the allocated memory for a protocol given as parameter.";
const char *help_decrease_alloc_mem = 		"Decrease the allocated memory for a protocol given as parameter.";
const char *help_set_domain_name_manager = 	"Sets a DomainNameManager on a specific protocol (HTTP,SSL or DNS).";
const char *help_set_tcp_database_adaptor = 	"Sets a databaseAdaptor for TCP traffic.";
const char *help_set_udp_database_adaptor = 	"Sets a databaseAdattor for UDP traffic.";
const char *help_release_cache = 		"Release the cache of a specific protocol.";
const char *help_releases_caches = 		"Release all the caches.";
const char *help_get_counters = 		"Gets the counters of a specific protocol on a python dict.";
const char *help_get_cache = 			"Gets the main cache of a protocol on a python dict.";
const char *help_anomaly_callback = 		"Sets a callback for specific anomalies on the given protocol.";
const char *help_get_statistics =		"Gets the statisitics of a protocol on a python dict.";
	
const char *help_regex_expression = 		"Gets the regular expression.";
const char *help_regex_name = 			"Gets the name of the regular expression.";
const char *help_regex_matchs = 		"Gets the number of matches of the regular expression.";
const char *help_regex_callback = 		"Gets/Sets the callback function for the regular expression.";
const char *help_regex_next_regex = 		"Gets/Sets the next regular expression that should match.";
const char *help_regex_next_regex_manager = 	"Gets/Sets the next RegexManager for assign to the Flow when a match occurs.";

const char *help_pdis_status =			"Gets the status of the PacketDispatcher.";
const char *help_pdis_packets =			"Gets the total number of packets process by the PacketDispatcher.";
const char *help_pdis_bytes =			"Gets the total number of bytes process by the PacketDispatcher.";
const char *help_pdis_enable_shell =		"Gets/Sets a python shell in order to interact with the system on real time.";
const char *help_pdis_stack =			"Gets/Sets the Network stack that is running on the PacketDispatcher.";	
const char *help_pdis_pcap_filter =		"Gets/Sets a pcap filter on the PacketDispatcher";
const char *help_pdis_evidences =		"Gets/Sets the evidences for make forensic analysis.";
const char *help_pdis_open =			"Opens a network device or a pcap file for analysis.";
const char *help_pdis_close =			"Closes a network device or a pcap file.";
const char *help_pdis_run =			"Start to process packets.";
const char *help_pdis_forward_packet =		"Forwards the received packet to a external packet engine(Netfilter).";
const char *help_set_scheduler =		"Sets the scheduler for make periodically tasks (DDoS checks).";

const char *help_regex_manager_iter =		"Iterate over the Regex stored on the RegexManager object.";
const char *help_regex_manager_name = 		"Gets/Sets the name of the RegexManager.";
const char *help_regex_manager_add_regex =	"Adds a Regex object to the RegexManager.";
const char *help_regex_manager_len =		"Gets the total number of Regex stored on the RegexManager object.";	
const char *help_regex_manager_show =		"Shows the Regexs stored on the RegexManager.";
const char *help_regex_manager_show_name =	"Shows the Regexs stored on the RegexManager by name.";

const char *help_flow_manager_iter =		"Iterate over the Flows stored on the FlowManager object.";
const char *help_flow_manager_len =		"Gets the number of Flows stored on the FlowManager.";
const char *help_flow_manager_flows =		"Gets the number of Flows stored on the FlowManager.";
const char *help_flow_manager_process_flows =	"Gets the total number of process Flows.";
const char *help_flow_manager_timeout_flows =	"Gets the total number of Flows that have been expired by the timeout.";

const char *help_flow_protocol =		"Gets the protocol of the Flow (tcp,udp).";
const char *help_flow_dst_port =		"Gets the destination port of the Flow.";
const char *help_flow_src_port =		"Gets the source port of the Flow.";
const char *help_flow_dst_ip =			"Gets the destination IP address.";
const char *help_flow_src_ip =			"Gets the source IP address.";
const char *help_flow_packets_layer7 = 		"Gets the total number of layer7 packets.";
const char *help_flow_packets =			"Gets the total number of packets on the Flow.";
const char *help_flow_bytes = 			"Gets the total number of bytes.";
const char *help_flow_have_tag =		"Gets if the Flow have tag from lower network layers."; 
const char *help_flow_reject =			"Gets/Sets the reject of the connection.";
const char *help_flow_tag =			"Gets the tag from lower network layers."; 
const char *help_flow_evidence =		"Gets/Sets the evidence of the Flow for make forensic analysis."; 
const char *help_flow_label =			"Gets/Sets the label of the Flow (external labeling)."; 
const char *help_flow_duration =		"Gets the duration on secs of the Flow."; 
const char *help_flow_ip_set = 			"Gets the IPSet Info of the Flow if is part of an IPSet."; 
const char *help_flow_http_info =		"Gets the HTTPInfo if the Flow is HTTP."; 
const char *help_flow_sip_info =		"Gets the SIPInfo if the Flow is SIP.";	
const char *help_flow_smtp_info = 		"Gets the SMTP Info if the Flow is SMTP.";	
const char *help_flow_pop_info = 		"Gets the POP Info if the Flow is POP.";	
const char *help_flow_imap_info = 		"Gets the IMAP Info if the Flow is IMAP.";	
const char *help_flow_frequencies =		"Gets a map of frequencies of the payload of the Flow."; 	
const char *help_flow_packet_frequencies =	"Gets the packet frequencies of the Flow."; 	
const char *help_flow_ssl_info = 		"Gets a SSLInfo object the Flow is SSL.";	
const char *help_flow_dns_info = 		"Gets a DNSInfo object if the Flow is a DNS.";	
const char *help_flow_ssdp_info =		"Gets a SSDPInfo object if the Flow is SSDP.";	
const char *help_flow_bitcoin_info =		"Gets a BitcoinInfo object if the Flow is Bitcoin.";	
const char *help_flow_coap_info =		"Gets a CoAPInfo object if the Flow is CoAP.";	
const char *help_flow_mqtt_info =		"Gets a MQTTInfo object if the Flow is MQTT.";	
const char *help_flow_regex =			"Gets the regex if the Flow have been matched with the associated regex.";	
const char *help_flow_payload = 		"Gets a list of the bytes of the payload of the Flow.";	
const char *help_flow_anomaly =			"Gets the attached anomaly of the Flow."; 		 	
const char *help_flow_l7_protocol_name =	"Gets the name of the Protocol of L7 of the Flow.";

const char *help_mqtt_info_topic =		"Gets the MQTT publish topic if the Flow is MQTT.";
 
const char *help_coap_info_uri =		"Gets the CoAP URI if the Flow is CoAP.";
const char *help_coap_info_host_name =		"Gets the CoAP Hostname if the Flow is CoAP."; 
const char *help_coap_info_matched_domain_name ="Gets the matched DomainName object."; 

const char *help_bitcoin_info_tx =		"Get the total number of Bitcoin transactions on the Flow.";
const char *help_bitcoin_info_blocks =		"Get the total number of Bitcoin blocks on the Flow.";
const char *help_bitcoin_info_rejects =		"Get the total number of Bitcoin rejects on the Flow.";
	
const char *help_dns_info_iter =		"Iterate over the IP addresses returned on the query response."; 
const char *help_dns_info_domain_name =		"Gets the DNS domain name."; 
const char *help_dns_info_matched_domain_name =	"Gets the matched DomainName object."; 

const char *help_ssl_info_server_name =		"Gets the SSL server name."; 
const char *help_ssl_info_matched_domain_name =	"Gets the matched DomainName object."; 

const char *help_http_info_uri =		"Gets the HTTP URI if the Flow is HTTP.";
const char *help_http_info_host_name =		"Gets the HTTP Host if the Flow is HTTP."; 
const char *help_http_info_user_agent =		"Gets the HTTP UserAgent if the Flow is HTTP."; 
const char *help_http_info_content_type =	"Gets the HTTP Content Type if the Flow is HTTP."; 
const char *help_http_info_banned =		"Gets/Sets the Flow banned for no more analysis on the python side and release resources."; 
const char *help_http_info_matched_domain_name ="Gets the matched DomainName object."; 

const char *help_http_uri_set_callback =	"Gets/Sets a callback function for the matching set."; 
const char *help_http_uri_set_uris =		"Gets the total number of URIs on the set.";  
const char *help_http_uri_set_lookups =		"Gets the total number of lookups of the set.";  
const char *help_http_uri_set_lookups_in =	"Gets the total number of matched lookups of the set.";  
const char *help_http_uri_set_lookups_out =	"Gets the total number of non matched lookups of the set.";  
const char *help_http_uri_set_add_uri =		"Adds a URI to the HTTPUriSet.";  

const char *help_sip_info_uri =			"Gets the SIP URI if the Flow is SIP."; 
const char *help_sip_info_from_name =		"Gets the SIP From if the Flow is SIP."; 
const char *help_sip_info_to_name =		"Gets the SIP To if the Flow is SIP."; 
const char *help_sip_info_via = 		"Gets the SIP Via if the Flow is SIP."; 

const char *help_smtp_info_mail_from =		"Gets the Mail From if the Flow is SMTP."; 
const char *help_smtp_info_mail_to = 		"Gets the Rcpt To if the Flow is SMTP."; 
const char *help_smtp_info_banned = 		"Gets or Sets the banned of the Flow."; 

const char *help_pop_info_user_name =		"Gets the user name of the POP session if the Flow is POP.";  

const char *help_imap_info_user_name =		"Gets the user name of the IMAP session if the Flow is IMAP.";  

const char *help_ssdp_info_uri = 		"Gets the SSDP URI if the Flow is SSDP."; 
const char *help_ssdp_info_host_name = 		"Gets the SSDP Host if the Flow is SSDP.";

const char *help_frequencies_dispersion =	"Returns the dispersion value of the Flow."; 
const char *help_frequencies_enthropy =		"Returns the enthopy value of the Flow.";  
const char *help_frequencies_get_freq_string =	""; 

const char *help_packet_frequencies_get_freq = 	"";

const char *help_domain_name_expresion = 	"Gets the domain expression."; 
const char *help_domain_name_name = 		"Gets the name of the domain."; 
const char *help_domain_name_matchs = 		"Gets the total number of matches of the domain."; 
const char *help_domain_name_callback = 	"Gets/Sets the callback of the domain."; 
const char *help_domain_name_http_uri_set = 	"Gets/Sets the HTTPUriSet used on this DomainName (only works on HTTP)."; 
const char *help_domain_name_regex_manager = 	"Gets/Sets the HTTP RegexManager used on this DomainName (only works on HTTP).";

const char *help_domain_name_mng_name = 	"Gets/Sets the name of the DomainNameManager object.";
const char *help_domain_name_mng_add_domain_n =	"Adds a DomainName by using the name and the domain name to the DomainNameManager."; 
const char *help_domain_name_mng_add_domain =	"Adds a DomainName object to the DomainNameManager."; 
const char *help_domain_name_mng_remove_dom = 	"Removes a DomainName object"; 
const char *help_domain_name_mng_remove_dom_n =	"Removes a DomainName by name."; 
const char *help_domain_name_mng_len = 		"Return the total number of DomainName objects on the DomainNameManager."; 
const char *help_domain_name_mng_show =		"Shows the DomainName objects"; 
const char *help_domain_name_mng_show_n =	"Shows the DomainName objects by name."; 

const char *help_adaptor_connect = 		"Method for connect to the database.";
const char *help_adaptor_insert =		"Method called when a new Flow is created."; 
const char *help_adaptor_update = 		"Method called when the Flow is updating.";
const char *help_adaptor_remove =		"Method called when the Flow is removed."; 

const char *help_ip_abstract_set_add_ip	=	"Adds a IP address to the set.";

const char *help_ip_set_name =			"Gets the name of the IPSet."; 
const char *help_ip_set_lookups =		"Gets the total number of lookups of the IPSet."; 
const char *help_ip_set_lookups_in =		"Gets the total number of matched lookups of the IPSet."; 
const char *help_ip_set_lookups_out =		"Gets the total number of non matched lookups of the IPSet."; 
const char *help_ip_set_callback = 		"Gets/Sets a function callback for the IPSet."; 
const char *help_ip_set_regex_manager = 	"Gets/Sets the RegexManager for this group of IP addresses.";
const char *help_ip_set_add_ip =		"Add a IP address to the IPSet.";
const char *help_ip_set_len = 			"Returns the total number of IP address on the IPSet.";
 
#ifdef HAVE_BLOOMFILTER

const char *help_ip_bloom_set_add_ip =		"Add a IP address to the IPBloomSet.";
const char *help_ip_bloom_set_callback = 	"Gets/Sets a function callback for the IPBloomSet."; 
const char *help_ip_bloom_set_len = 		"Returns the total number of IP address on the IPBloomSet.";

#endif // HAVE_BLOOMFILTER

const char *help_ip_set_manager_iter = 		"Iterate over the IPSets.";
const char *help_ip_set_manager_name =		"Gets/Sets the name of the IPSetManager object.";
const char *help_ip_set_manager_add_ip = 	"Adds a IPSet.";
const char *help_ip_set_manager_del_ip =	"Removes a IPSet.";
const char *help_ip_set_manager_del_ip_name = 	"Removes a IPSet by name.";
const char *help_ip_set_manager_show =		"Shows the IPSets.";
const char *help_ip_set_manager_show_name =	"Shows the IPSets by name.";
const char *help_ip_set_manager_len = 		"Return the total number of IPSets.";

const char *help_freq_group_tot_proc_flows =	"Returns the total number of computed Flows";
const char *help_freq_group_tot_comp_freq =	"Returns the total number of computed frequencies";
const char *help_freq_group_add_by_src_port =	"Adds a list of Flows and group them by source port.";
const char *help_freq_group_add_by_dst_port =	"Adds a list of Flows and group them by destination port.";
const char *help_freq_group_add_by_src_addr =	"Adds a list of Flows and group them by source IP address.";
const char *help_freq_group_add_by_dst_addr = 	"Adds a list of Flows and group them by destination IP address.";
const char *help_freq_group_add_by_dst_p_a =	"Adds a list of Flows and group them by destination IP address and port.";
const char *help_freq_group_add_by_src_p_a =	"Adds a list of Flows and group them by source IP address and port.";
const char *help_freq_group_compute =		"Computes the frequencies of the Flows.";
const char *help_freq_group_reset =		"Resets all the temporay memory used by the engine."; 
const char *help_freq_group_get_ref_flow_k =	""; 
const char *help_freq_group_get_ref_flow =	"Returns a list of the processed Flows by the FrequencyGroup."; 

const char *help_learn_flows_proc =		"Gets the total number of Flows processes by the LearnerEngine."; 
const char *help_learn_regex =			"Gets the generated regular expression."; 
const char *help_learn_agregate_flows = 	"Adds a list of Flows to be process."; 
const char *help_learn_compute = 		"Runs the engine."; 

#endif
