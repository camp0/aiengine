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
#ifndef SRC_PROTOCOLS_BITCOIN_BITCOININFO_H_
#define SRC_PROTOCOLS_BITCOIN_BITCOININFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include "FlowInfo.h"

namespace aiengine {

class BitcoinInfo : public FlowInfo
{
public:
        explicit BitcoinInfo() { reset(); }
        virtual ~BitcoinInfo() {}

        void reset() {
		total_transactions_ = 0;
        }

	// TODO
	void serialize(std::ostream& stream) {}

	void incTransactions() { ++total_transactions_; }
	int32_t getTotalTransactions() const { return total_transactions_; }

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)

        friend std::ostream& operator<< (std::ostream& out, const BitcoinInfo& binfo) {

		out << " TX:" << binfo.total_transactions_;

                return out;
        }
#endif

private:
	int32_t total_transactions_;
};

} // namespace aiengine  

#endif  // SRC_PROTOCOLS_BITCOIN_BITCOININFO_H_
