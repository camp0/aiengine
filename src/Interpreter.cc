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
#include "Interpreter.h"

namespace aiengine {

#ifdef PYTHON_BINDING

void Interpreter::enableShell(bool enable) {

	if (python_shell_enable_) {
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

	python_shell_enable_ = true;
	std::cout << "AIEngine " << VERSION << " shell" << std::endl << std::flush;
	std::cout << "==> " << std::flush;
}

void Interpreter::stop() {
       
        python_shell_enable_ = false;
        user_input_buffer_.consume(64);
        std::cout << "exiting AIEngine " << VERSION << " shell" <<std::endl << std::flush;
	user_input_.close();
}

void Interpreter::readUserInput() {

	if (python_shell_enable_) {
        	boost::asio::async_read_until(user_input_, user_input_buffer_,'\n',
                	boost::bind(&Interpreter::handle_read_user_input, this,
                        boost::asio::placeholders::error));
        }
}

void Interpreter::handle_read_user_input(boost::system::error_code error) {

	if ((!error)and(python_shell_enable_)) {
		std::istream user_stream(&user_input_buffer_);
                std::ostringstream buffer;
                std::string header;

                user_stream >> header;
                buffer << header;
                while (std::getline(user_stream, header) && header != "\r") {
                        buffer << header;
                }
                //std::cout << buffer.str() << std::endl;
                //std::cout << "FULL message:" << buffer.str() << "\n";
                //user_input_buffer_.consume(64);

		std::string cad(buffer.str());

		if (cad.compare("quit()") == 0) {
			stop();
			return;
		}

		try {
			// Retrieve the main module.
			boost::python::object main = boost::python::import("__main__");
  			// Retrieve the main module's namespace
  			boost::python::object global(main.attr("__dict__"));

			boost::python::exec(cad.c_str(),global);
		} catch (boost::python::error_already_set const &) {	
			//std::cout << "JODER" << std::endl;
			PyErr_Print();
		}
                user_input_buffer_.consume(64);
		
		std::cout << "==> " << std::flush;
	} 
/*
        else if (error== boost::asio::error::not_found) {
			std::string msg;
                        std::istream(&user_input_buffer_) >> msg;
                        std::cout << "handle_read_input NOT FOUND:" << error.message() << " msg:"<< msg << std::endl;
                }else{
                        std::cout << "handle_read_input ERROR:" << error.message() << std::endl;
                }
*/

}

#endif

} // namespace aiengine 



