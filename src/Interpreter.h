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
#ifndef SRC_INTERPRETER_H_
#define SRC_INTERPRETER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#if defined(PYTHON_BINDING)
#include <boost/python.hpp>
#elif defined(RUBY_BINDING)
#include <ruby.h>
#endif 

namespace aiengine {

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)

// TODO
#ifndef VERSION
#define VERSION "1.4"
#endif

class Interpreter 
{
public:
	explicit Interpreter(boost::asio::io_service &io_service_):Interpreter(io_service_,STDIN_FILENO) {}

	// Constructor for remote python shell
	Interpreter(boost::asio::io_service &io_service_, int fd):
		user_input_(io_service_,::dup(fd)),
		user_input_buffer_(64),
		shell_enable_(false),
		want_exit_(false) {
		std::ios_base::sync_with_stdio(false);
	}


    	virtual ~Interpreter() { user_input_.close(); }

	void start(); 
	void stop();
	void readUserInput();

	void setShell(bool enable);  
	bool getShell() const { return shell_enable_; }  
private:

	void handle_read_user_input(boost::system::error_code error);

	boost::asio::posix::stream_descriptor user_input_;
	boost::asio::streambuf user_input_buffer_;
	bool shell_enable_;
	bool want_exit_;
};

#endif // PYTHON_BINDING || RUBY_BINDING

} // namespace aiengine

#endif  // SRC_INTERPRETER_H_
