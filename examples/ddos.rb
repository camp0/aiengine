#!/usr/bin/ruby -w
# Created by Luis Campo Giralte
# GPL License
# 
# Example for detect denial of service attacks 
require "../src/ruaiengine"

def scheduler_handler_tcp

  print "TCP DoS Checker\n"
  c = @s.get_counters("TCPProtocol")

  print c  
  # Code the intelligence for detect DDoS based on 
  # combination flags, bytes, packets and so on. 
  syns = c["syns"]
  synacks = c["synacks"]
  if (syns > (synacks * 100))
      print "System under a SYN DoS attack\n"
  end
end

@s = StackLan.new
pd = PacketDispatcher.new
pd.stack = @s

@s.total_tcp_flows = 327680
@s.total_udp_flows = 163840 

pd.set_scheduler(method(:scheduler_handler_tcp),5)

pd.open("ens7")
begin
  pd.run()
rescue => e
  print "Stop capturing packets"
  print e.inspect
  print e.backtrace
end

pd.close()

