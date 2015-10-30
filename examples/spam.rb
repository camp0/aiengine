#!/usr/bin/ruby -w
# Created by Luis Campo Giralte
# GPL License
# Example for detect spam 

require "../src/ruaiengine"

def callback_spam_checker(flow)

    s = flow.smtp_info
    if (s)
        from = s.mail_from
        to = s.mail_to
        # Add the logic based on from, to and ip addresses
        # in order to reject the connection or whatever
    end

end

dallow = DomainNameManager.new
dreject = DomainNameManager.new

dt = DomainName.new("Trust domains","mytrustdomain.com")
dallow.add_domain_name(dt)

dr = DomainName.new("Unknown domains",".com")
dr.callback = method(:callback_spam_checker)
dreject.add_domain_name(dr)

s = StackLan.new
pd = PacketDispatcher.new
pd.stack = s

s.total_tcp_flows = 102400
s.total_udp_flows = 0

s.set_domain_name_manager(dallow,"SMTPProtocol")
s.set_domain_name_manager(dreject,"SMTPProtocol",false)

pd.open("ens7")
begin
    pd.run()
rescue
    print "Stop capturing packets"
end

pd.close()

