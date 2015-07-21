#!/usr/bin/ruby -w
# Created by Luis Campo Giralte
# GPL License
# 
# Example for use DatabaseAdaptor with Redis database
require "../src/ruaiengine"
require "redis"

class RedisAdaptor < DatabaseAdaptor 
  attr_reader :total_inserts 
  attr_reader :total_updates 
  attr_reader :total_removes 
  attr_reader :ftype

  def initialize(ftype)
    @ftype = ftype
    @total_inserts = 0
    @total_updates = 0
    @total_removes = 0
    @conn = Redis.new
  end

  def insert(key)
    printf "(%s)New Connection on %s\n", @ftype, key
    @conn.hset(@ftype,key,"{}")
    @total_inserts += 1
  end
  def remove(key)
    printf "(%s)Remove Connection on %s\n", @ftype, key
    @conn.hdel(@ftype,key)
    @total_removes += 1
  end
  def update(key, data)
    printf "(%s)Update Connection on %s data:%s\n",@ftype, key,data
    @conn.hset(@ftype,key,data)
    @total_updates += 1
  end
  def show
    printf "Statistics of adaptor %s\n", @ftype
    printf "\tInserts %d\n", @total_inserts
    printf "\tUpdates %d\n", @total_updates
    printf "\tRemoves %d\n", @total_removes
  end
end

s = StackLan.new
pd = PacketDispatcher.new
pd.stack = s

s.total_tcp_flows = 327680
s.total_udp_flows = 163840 

r_udp = RedisAdaptor.new("udpflows")
r_tcp = RedisAdaptor.new("tcpflows")

s.set_tcp_database_adaptor(r_tcp,1024)
s.set_udp_database_adaptor(r_udp,512)

pd.open("ens7")
begin
  pd.run()
rescue => e
  print "Stop capturing packets"
  print e.inspect
  print e.backtrace
end

r_udp.show()
r_tcp.show()

pd.close()

