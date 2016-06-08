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
#include "AnomalyManager.h"

namespace aiengine {

void AnomalyManager::statistics(std::basic_ostream<char>& out) {

	out << "Packet Anomalies " << std::endl;
	for (int i = 1; i < static_cast<std::int8_t>(PacketAnomalyType::MAX_PACKET_ANOMALIES) ; ++i ) { 
                const char *name = PacketAnomalyTypeString[i].name;
                int32_t hits = anomalies_[i].hits;

                out << "\t" << "Total " << name << ":" << std::right << std::setfill(' ') << std::setw(27 - strlen(name)) ;
		out << hits <<std::endl;
        }
}

void AnomalyManager::incAnomaly(Flow *flow, PacketAnomalyType t) { 

	AnomalyInfo &ai = anomalies_[static_cast<std::int8_t>(t)];
	ai.hits += 1; 
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)
	if (ai.call.haveCallback()) {
		ai.call.executeCallback(flow);
	}
#endif
}

void AnomalyManager::incAnomaly(PacketAnomalyType t) { 

	anomalies_[static_cast<std::int8_t>(t)].hits += 1; 
}

const char *AnomalyManager::getName(PacketAnomalyType t) {

	return PacketAnomalyTypeString[static_cast<std::int8_t>(t)].name;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)
#if defined(PYTHON_BINDING)
void AnomalyManager::setCallback(PyObject *callback,const std::string &protocol_name) {
#elif defined(RUBY_BINDING)
void AnomalyManager::setCallback(VALUE callback,const std::string &protocol_name) {
#elif defined(JAVA_BINDING)
void AnomalyManager::setCallback(JaiCallback *callback,const std::string &protocol_name) {
#elif defined(LUA_BINDING)
void AnomalyManager::setCallback(lua_State *lua, const std::string& callback,const std::string &protocol_name) {
#endif
	std::for_each(anomalies_.begin(),anomalies_.end(),[&](AnomalyInfo &ai){
		if (((protocol_name.compare(ai.protocol_name) == 0))and(strlen(ai.protocol_name) > 0)) {
#if defined(LUA_BINDING)
			ai.call.setCallback(lua,callback.c_str());
#else
			ai.call.setCallback(callback);		
#endif
		}			 
	});

}
#endif

} // namespace aiengine 

