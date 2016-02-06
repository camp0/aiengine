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
#include "Interpreter.h"

namespace aiengine {

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)

void Interpreter::setShell(bool enable) {

	if (shell_enable_) {
		if (!enable) {
			stop();
		}
	} else {
		if (enable) {
			start();
		}
	}
}

void Interpreter::start() {

	shell_enable_ = true;
	std::cout << "AIEngine " << VERSION << " shell" << std::endl << std::flush;
	std::cout << "==> " << std::flush;
}

void Interpreter::stop() {
       
        shell_enable_ = false;
        user_input_buffer_.consume(64);
        std::cout << "exiting AIEngine " << VERSION << " shell" <<std::endl << std::flush;
	user_input_.close();
}

void Interpreter::readUserInput() {

	if (shell_enable_) {
        	boost::asio::async_read_until(user_input_, user_input_buffer_,'\n',
                	boost::bind(&Interpreter::handle_read_user_input, this,
                        boost::asio::placeholders::error));
        }
}

void Interpreter::handle_read_user_input(boost::system::error_code error) {

	if ((!error)and(shell_enable_)) {
		std::istream user_stream(&user_input_buffer_);
                std::string header;

		std::getline(user_stream, header);

		std::string cmd(header);

		if (want_exit_) {
			if (cmd.compare("yes") == 0) {
				stop();
				return;
			}	
			want_exit_ = false;
                        user_input_buffer_.consume(64);
			std::cout << "==> " << std::flush;
                        return;
		}		

		if (cmd.compare("quit()") == 0) {
			std::cout << "Are you sure? (yes/no)" << std::flush;
                	user_input_buffer_.consume(64);
			want_exit_ = true;
			return;
		}
#if defined(PYTHON_BINDING)

		// PyGILState_STATE gstate = PyGILState_Ensure();
		try {
			PyGilContext gil_lock();

			// Retrieve the main module.
			boost::python::object main = boost::python::import("__main__");
  			// Retrieve the main module's namespace
  			boost::python::object global(main.attr("__dict__"));

			boost::python::exec(cmd.c_str(),global);
		} catch (boost::python::error_already_set const &) {	
			PyErr_Print();
		}
		// PyGILState_Release(gstate);
#elif defined(RUBY_BINDING)
	
		int state = 0;
		rb_eval_string_protect(cmd.c_str(),&state);
		if (state) {
			rb_raise(rb_eRuntimeError, "Error");
		}
#endif
               	user_input_buffer_.consume(64);
	
		std::cout << "==> " << std::flush;
		std::cout.flush();
	} 
}

#endif

} // namespace aiengine 



