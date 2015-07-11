#!/usr/bin/ruby -w
# Created by Luis Campo Giralte
# GPL License
# 
# Example for use DatabaseAdaptor for drop information 
require "../src/ruaiengine"

class OutputAdaptor < DatabaseAdaptor 
  attr_reader :total_inserts 
  attr_reader :total_updates 
  attr_reader :total_removes 

  def initialize
    @total_inserts = 0
    @total_updates = 0
    @total_removes = 0
  end

  def insert(flowid)
    printf "New Connection on %s\n", flowid
    @total_inserts += 1
  end
  def remove(flowid)
    printf "Remove Connection on %s\n", flowid
    @total_removes += 1
  end
  def update(flowid, data)
    printf "Update Connection on %s data:%s\n", flowid,data
    @total_updates += 1
  end
end

s = StackLan.new
pd = PacketDispatcher.new
pd.stack = s

s.total_tcp_flows = 32000
s.total_udp_flows = 32000

output = OutputAdaptor.new

s.set_tcp_database_adaptor(output)

pd.open("ens7")
begin
    pd.run()
rescue
    print "Stop capturing packets"
end

pd.close()

