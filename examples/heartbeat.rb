#!/usr/bin/ruby -w
# Created by Luis Campo Giralte
# GPL License
# 
# Example for detecting SSL Heartbeats with leaks on the network 
require "../src/ruaiengine"
require "redis"

def heartbeat_callback(flow)

  # The payload is on a ruby Array
  p = flow.payload
  if (p.length > 9)
    # Heartbeat minimum header 
    if (p[7] > 1)
      printf "SSL Heartbeat leak on %s", flow.ip_src
    end
  end  
end

s = StackLan.new
pd = PacketDispatcher.new
pd.stack = s

# Heartbeat regex expression
# 18 -> Content Type: Heartbeat
#    0301, 0302 -> Version: TLS
#    xxxx -> Length
#    01 - Heartbeat
#    xx - heartbeat payload length
   
rbasic = Regex.new("SSL Basic regex","^\x16\x03")
rheart = Regex.new("SSL Heartbeat","^.*\x18\x03(\x01|\x02|\x03).*$")

rheart.callback = method(:heartbeat_callback)

rbasic.next_regex = rheart

rm = RegexManager.new

rm.add_regex(rbasic)

s.tcp_regex_manager = rm

s.enable_nids_engine = true

s.total_tcp_flows = 327680
s.total_udp_flows = 163840 

pd.open("ens7")
begin
  pd.run()
rescue => e
  print "Stop capturing packets"
  print e.inspect
  print e.backtrace
end

pd.close()

