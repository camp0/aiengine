/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#include "NetworkStack.h"

void NetworkStack::enableLinkLayerTagging(std::string type)
{
        if(type.compare("vlan") == 0)
        {
                mux_eth_->addUpMultiplexer(mux_vlan_,ETH_P_8021Q);
                mux_vlan_->addUpMultiplexer(mux_ip_,ETHERTYPE_IP);
                mux_ip_->addDownMultiplexer(mux_vlan_);
        }
        else
        {
                if(type.compare("mpls") == 0)
                {
                        mux_eth_->addUpMultiplexer(mux_mpls_,ETH_P_MPLS_UC);
                        mux_mpls_->addUpMultiplexer(mux_ip_,ETHERTYPE_IP);
                        mux_ip_->addDownMultiplexer(mux_mpls_);
                }
                else
                {
                        LOG4CXX_WARN (logger, "Unknown tagging type " << type );
                }
        }
}

