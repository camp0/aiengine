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
#include "LearnerEngine.h"

void LearnerEngine::reset()
{
	items_ = 0;
	length_ = 0;
	raw_expression_="";
	for (int i = 0;i<5000;++i) q_array_[i].clear();
}


void LearnerEngine::statistics(std::basic_ostream<char>& out)
{
	out << "Learner statistics" << std::endl;
	for(int i = 0;i< 300;++i)
	{
		for (auto it = q_array_[i].begin(); it!=q_array_[i].end();++it)
		{
			out << "(" <<i <<")[" << hex << it->first << "," << dec << it->second << "]" <<std::endl;
		}	
	}
}

void LearnerEngine::agregatePacketFlow(PacketFrequenciesPtr pkt_freq)
{
	++items_;

	for(int i = 0;i< pkt_freq->getLength();++i)
	{
		int value = pkt_freq->index(i);

		auto it = q_array_[i].find(value);	
		if(it == q_array_[i].end()) 
		{
			q_array_[i].insert(std::make_pair(value,1));
		}
		else
		{
			int *j = &it->second;
			++(*j);
		}		
	}
	if(length_< pkt_freq->getLength()) length_ = pkt_freq->getLength();

}

int LearnerEngine::getQualityByte(int offset)
{
	int quality = 0;

	if(offset >=0 && offset < 5000)
	{
		int items = q_array_[offset].size();

		if(items_>0)
		{
			quality = 100- ( ((items-1)*100)/items_);
		}	
	}
	return quality;
}

void LearnerEngine::compute()
{
	std::ostringstream expr;
	std::ostringstream token;	

	expr << "^";
	
        for(int i = 0;i< length_;++i)
        {
		token.clear(); token.str("");

		int quality = getQualityByte(i);
	
		if((quality > 80)&&(q_array_[i].size()>0))
		{
			int token_candidate = q_array_[i].begin()->first;
			int quality_token = 0;
	
			for (auto it = q_array_[i].begin(); it!=q_array_[i].end();++it)
			{
				if(it->second > quality_token)
				{
					quality_token = it->second;
					token_candidate = it->first;
				}
			}
			token << boost::format("\\x%02x") % token_candidate;
		}
		else
		{
			token << ".?";
		}
		expr << token.str();
        }
	raw_expression_ = expr.str();
}
