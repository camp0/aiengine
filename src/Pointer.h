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
#ifndef SRC_POINTER_H_ 
#define SRC_POINTER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef PYTHON_BINDING
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>
#include <boost/make_shared.hpp>
#else
#include <memory>
#endif

namespace aiengine {

#ifdef PYTHON_BINDING
template <class T1>
using SharedPointer = boost::shared_ptr<T1>;
template <class T2>
using WeakPointer = boost::weak_ptr<T2>;
#else
template <class T1>
using SharedPointer = std::shared_ptr<T1>;
template <class T2>
using WeakPointer = std::weak_ptr<T2>;
#endif

} // namespace aiengine

#endif  // SRC_POINTER_H_
