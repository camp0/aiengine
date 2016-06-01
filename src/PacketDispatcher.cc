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
#include "PacketDispatcher.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr PacketDispatcher::logger(log4cxx::Logger::getLogger("aiengine.packetdispatcher"));
#endif


PacketDispatcher::~PacketDispatcher() { 

#if defined(LUA_BINDING)
        if ((ref_function_ != LUA_NOREF) and ( lua_ != nullptr)) {
                // delete the reference from registry
                luaL_unref(lua_, LUA_REGISTRYINDEX, ref_function_);
        }
#endif
	io_service_.stop(); 
}

void PacketDispatcher::info_message(const std::string &msg) {

#ifdef HAVE_LIBLOG4CXX
        LOG4CXX_INFO(logger, msg);
#else
        std::chrono::system_clock::time_point time_point = std::chrono::system_clock::now();
        std::time_t now = std::chrono::system_clock::to_time_t(time_point);
#ifdef __clang__
        std::cout << "[" << std::put_time(std::localtime(&now), "%D %X") << "] ";
#else
        char mbstr[100];
        std::strftime(mbstr, 100, "%D %X", std::localtime(&now));
        std::cout << "[" << mbstr << "] ";
#endif
        std::cout << msg << std::endl;
#endif
}

void PacketDispatcher::statistics() {

	std::cout << *this;
	if (have_evidences_) {
		em_->statistics(); 
	}
}


void PacketDispatcher::setStack(const SharedPointer<NetworkStack>& stack) {

	current_network_stack_ = stack;
	stack_name_ = stack->getName();
        setDefaultMultiplexer(stack->getLinkLayerMultiplexer().lock());
        stack->setAsioService(io_service_);
}

void PacketDispatcher::setDefaultMultiplexer(MultiplexerPtr mux) {

	defMux_ = mux;
	eth_ = std::dynamic_pointer_cast<EthernetProtocol>(defMux_->getProtocol());
}


void PacketDispatcher::open_device(const std::string& device) {

	char errorbuf[PCAP_ERRBUF_SIZE];
#ifdef __FREEBSD__
	int timeout = 1000; // miliseconds
#else
	int timeout = -1;
#endif

	pcap_ = pcap_open_live(device.c_str(), PACKET_RECVBUFSIZE, 0, timeout, errorbuf);
	if (pcap_ == nullptr) {
#ifdef HAVE_LIBLOG4CXX
		LOG4CXX_ERROR(logger,"Device:" <<device.c_str() << " error:" << errorbuf );
#else
		std::cerr << "Device:" << device.c_str() << " error:" << errorbuf << std::endl;
#endif
		device_is_ready_ = false;
		exit(-1);
		return;
	}
	int ifd = pcap_get_selectable_fd(pcap_);
	if (pcap_setnonblock(pcap_, 1, errorbuf) == 1) {
		device_is_ready_ = false;
		return;
	}
	stream_ = PcapStreamPtr(new PcapStream(io_service_));
			
	stream_->assign(::dup(ifd));
	device_is_ready_ = true;
	input_name_ = device;
}

void PacketDispatcher::close_device(void) {

	if (device_is_ready_) {
		stream_->close();
		pcap_close(pcap_);
		device_is_ready_ = false;
	}
}

void PacketDispatcher::open_pcap_file(const std::string& filename) {

	char errorbuf[PCAP_ERRBUF_SIZE];

        pcap_ = pcap_open_offline(filename.c_str(),errorbuf);
        if (pcap_ == nullptr) {
		pcap_file_ready_ = false;
#ifdef HAVE_LIBLOG4CXX
		LOG4CXX_ERROR(logger,"Unknown pcapfile:" << filename.c_str());
#else
		std::cerr << "Unkown pcapfile:" << filename.c_str() << std::endl;
#endif
		exit(-1);
	} else {
		pcap_file_ready_ = true;
		input_name_ = filename;
	}
}

void PacketDispatcher::close_pcap_file(void) {

	if (pcap_file_ready_) {
		pcap_close(pcap_);
		pcap_file_ready_ = false;
	}
}

void PacketDispatcher::do_read(boost::system::error_code ec) {

	int len = pcap_next_ex(pcap_,&header_,&pkt_data_);
	if (len >= 0) {
		forward_raw_packet((unsigned char*)pkt_data_,header_->len,header_->ts.tv_sec);
	}

// This prevents a problem on the boost asio signal
// remove this if when boost will be bigger than 1.50
#ifdef PYTHON_BINDING
#if BOOST_VERSION >= 104800 && BOOST_VERSION < 105000
	if (PyErr_CheckSignals() == -1) {
		std::cout << "Throwing exception from python" << std::endl;
		throw std::runtime_error("Python exception\n");
       	}
#endif
#endif

	if (!ec || ec == boost::asio::error::would_block)
      		start_operations();
	// else error but not handler
}

void PacketDispatcher::forward_raw_packet(unsigned char *packet,int length, time_t packet_time) {

	++total_packets_;
	total_bytes_ += length;

	if (defMux_) {
		current_packet_.setPayload(packet);
		current_packet_.setPayloadLength(length);
		current_packet_.setPrevHeaderSize(0);
		current_packet_.setPacketTime(packet_time);
		current_packet_.setEvidence(false);

		if (defMux_->acceptPacket(current_packet_)) {
			defMux_->setPacket(&current_packet_);
			defMux_->setNextProtocolIdentifier(eth_->getEthernetType());
			defMux_->forwardPacket(current_packet_);
			if ((have_evidences_)and(current_packet_.haveEvidence())) {
				em_->write(current_packet_);
			}
                }
	}
}

void PacketDispatcher::start_operations(void) {

	read_in_progress_ = false;
	if (!read_in_progress_) {
		read_in_progress_ = true;

		stream_->async_read_some(boost::asio::null_buffers(),
                	boost::bind(&PacketDispatcher::do_read, this,
                                boost::asio::placeholders::error));
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
		user_shell_->readUserInput();
#endif
	}
}

void PacketDispatcher::run_pcap(void) {

        std::ostringstream msg;
        msg << "Processing packets from file " << input_name_.c_str();
       	info_message(msg.str());

	if (current_network_stack_) {
		int memory = current_network_stack_->getAllocatedMemory();
		std::string unit = "Bytes";

		unitConverter(memory,unit);
	
		msg.clear();
		msg.str("");
        	msg << "Stack '" << stack_name_ << "' using " << memory << " " << unit << " of memory";
       		info_message(msg.str());
	}
	status_ = PacketDispatcherStatus::RUNNING;
	while (pcap_next_ex(pcap_,&header_,&pkt_data_) >= 0) {
		// Friendly remminder:
		//     header_->len contains length this packet (off wire)
		//     header_->caplen length of portion present	
		forward_raw_packet((unsigned char*)pkt_data_,header_->caplen,header_->ts.tv_sec);
	}
	status_ = PacketDispatcherStatus::STOP;
}


void PacketDispatcher::run_device(void) {

	if (device_is_ready_) {

        	std::ostringstream msg;
        	msg << "Processing packets from device " << input_name_.c_str();

        	info_message(msg.str());

        	if (current_network_stack_) {
                	int memory = current_network_stack_->getAllocatedMemory();
                	std::string unit = "Bytes";

                	unitConverter(memory,unit);

                	msg.clear();
                	msg.str("");
                	msg << "Stack '" << stack_name_ << "' using " << memory << " " << unit << " of memory";
                	info_message(msg.str());
        	}

		try {
			status_ = PacketDispatcherStatus::RUNNING;
			start_operations();
			io_service_.run();
		} catch (std::exception& e) {
        		std::cerr << e.what() << std::endl;
        	}
		status_ = PacketDispatcherStatus::STOP;
	} else {

                std::ostringstream msg;
                msg << "The device is not ready to run";

                info_message(msg.str());
	}
}

void PacketDispatcher::open(const std::string &source) {

	std::ifstream infile(source);

	device_is_ready_ = false;
	pcap_file_ready_ = false;

	if (infile.good()) { // The source is a file
		open_pcap_file(source);
	} else {
		open_device(source);
	}
}

void PacketDispatcher::run(void) {

	if (device_is_ready_) {
		run_device();
	} else {
		if(pcap_file_ready_) {
			run_pcap();
		}
	}
}

void PacketDispatcher::close(void) {

        if (device_is_ready_) {
                close_device();
        } else {
                if (pcap_file_ready_) {
                        close_pcap_file();
                }
        }
}

void PacketDispatcher::setPcapFilter(const char *filter) {

	if ((device_is_ready_)or(pcap_file_ready_)) {
		struct bpf_program fp;
		char *c_filter = const_cast<char*>(filter);

		if (pcap_compile(pcap_, &fp, c_filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {

			pcap_filter_ = filter;			
			if (pcap_setfilter(pcap_,&fp) == 0) {
				std::ostringstream msg;
                		msg << "Pcap filter set:" << filter;

                		info_message(msg.str());
			}
		}
	}
}


void PacketDispatcher::setEvidences(bool value) {

        if ((!have_evidences_)and(value)) {
                have_evidences_ = true;
                em_->enable();
        } else if ((have_evidences_)and(!value)) {
                have_evidences_ = false;
                em_->disable();
        }
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)

void PacketDispatcher::restart_timer(int seconds) {

	// reset the shared pointer and create a new timer.
        timer_.reset(new boost::asio::deadline_timer(io_service_,
        	boost::posix_time::seconds(seconds)));

        timer_->expires_at(timer_->expires_at() + boost::posix_time::seconds(seconds));
        timer_->async_wait(boost::bind(&PacketDispatcher::scheduler_handler, this,
        	boost::asio::placeholders::error));
}

#endif

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 

void PacketDispatcher::setShell(bool enable) {

        user_shell_->setShell(enable);
}

bool PacketDispatcher::getShell() const {

        return user_shell_->getShell();
}

#endif

#if defined(LUA_BINDING)

void PacketDispatcher::setShell(lua_State *lua, bool enable) {

        user_shell_->setShell(enable);
	user_shell_->setLuaInterpreter(lua);
}

bool PacketDispatcher::getShell() const {

        return user_shell_->getShell();
}

#endif

#if defined(PYTHON_BINDING)
void PacketDispatcher::setScheduler(PyObject *callback, int seconds) {

        if (timer_) // cancel the timer if exists
                timer_->cancel();

        if ((callback == Py_None)or(seconds <= 0)) {
                scheduler_set_ = false;
                scheduler_seconds_ = 0;
                
		if (scheduler_callback_)
                        Py_XDECREF(scheduler_callback_);
                timer_.reset();
        } else {
                if (!PyCallable_Check(callback)) {
                        std::cerr << "Object is not callable" << std::endl;
                } else {
                        if ( scheduler_callback_ ) Py_XDECREF(scheduler_callback_);
                        scheduler_callback_ = callback;
                        Py_XINCREF(scheduler_callback_);

                        scheduler_set_ = true;
                        scheduler_seconds_ = seconds;

			restart_timer(seconds);
		}
	}
}
#elif defined(RUBY_BINDING)
void PacketDispatcher::setScheduler(VALUE callback, int seconds) {

        if (timer_) // cancel the timer if exists
                timer_->cancel();

        // reset the values of the scheduler
        if ((callback == Qnil)or(seconds <= 0)) {
                scheduler_set_ = false;
                scheduler_seconds_ = 0;

		scheduler_callback_ = Qnil;
                timer_.reset();
        } else {
		// TODO: Verify if the callback is callable
		if (NIL_P(callback)) {
                        std::cerr << "Object is not callable" << std::endl;
                } else {

			scheduler_callback_ = callback;

                        scheduler_set_ = true;
                        scheduler_seconds_ = seconds;

			restart_timer(seconds);
                }
        }
}
#elif defined(LUA_BINDING)

void PacketDispatcher::setScheduler(lua_State* lua, const char *callback,int seconds) {

        if (timer_) // cancel the timer if exists
                timer_->cancel();

	if ((callback == nullptr)or(seconds <=0)) {
		scheduler_callback_ = nullptr;
                lua_ = nullptr;
		scheduler_set_ = false;
                scheduler_seconds_ = 0;
                ref_function_ = LUA_NOREF;
		timer_.reset();
	} else {
        	lua_getglobal(lua,callback);
        	if (lua_isfunction(lua,-1)) {
                	ref_function_ = luaL_ref(lua, LUA_REGISTRYINDEX);
                	// std::cout << __FILE__<< ":" << __func__ << ":name:" << callback << " ref:" << ref_function_ << std::endl;
                	lua_ = lua;
                	scheduler_callback_ = callback;
			scheduler_seconds_ = seconds;
                        scheduler_set_ = true;

			restart_timer(seconds);
		} else {
                	lua_pop(lua, 1);
                	ref_function_ = LUA_NOREF;
                	lua_ = nullptr;
                	throw std::runtime_error("not a valid LUA function");
		}
	}
}

#endif

#if defined(RUBY_BINDING)

static VALUE ruby_schedule_callback(VALUE ptr) {

        ruby_shared_data *data = (ruby_shared_data*)ptr;

        return rb_funcall2(data->obj,data->method_id,data->nargs,data->args);
}

#endif

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)

void PacketDispatcher::scheduler_handler(boost::system::error_code error) {

        // Check if the timer have been cancel
        if (error ==  boost::asio::error::operation_aborted) {
                return;
        }

        // Update the values of the timer and reschedule
        timer_->expires_at(timer_->expires_at() + boost::posix_time::seconds(scheduler_seconds_));
        timer_->async_wait(boost::bind(&PacketDispatcher::scheduler_handler, this,
                boost::asio::placeholders::error));

#if defined(PYTHON_BINDING)
        try {
		PyGilContext gil_lock();

                boost::python::call<void>(scheduler_callback_);
        } catch (std::exception &e) {
                std::cout << "ERROR:" << e.what() << std::endl;
        }
#elif defined(RUBY_BINDING)
        ruby_shared_data rbdata;

        rbdata.obj = scheduler_callback_;
        rbdata.method_id = rb_intern("call");
        rbdata.nargs = 0;

        int rberror = 0;
        VALUE result = rb_protect(ruby_schedule_callback,(VALUE)&rbdata,&rberror);

        if (rberror)
                throw "Ruby exception on schedule callback";
#elif defined(LUA_BINDING)

        lua_rawgeti(lua_, LUA_REGISTRYINDEX, ref_function_);

        int ret;
        if ((ret = lua_pcall(lua_,0,0,0)) != 0) {
		throw lua_tostring(lua_,1);
        	// std::cout << "ERROR:" << lua_tostring(lua_, -1) << std::endl;
        }

#endif
        return;
}

#endif

#if defined(PYTHON_BINDING)

void PacketDispatcher::setStack(boost::python::object& stack) {

	if (stack.is_none()) {
		// The user sends a Py_None 
		pystack_ = boost::python::object();
		stack_name_ = "None";
        	defMux_.reset();
	} else {
		boost::python::extract<SharedPointer<NetworkStack>> extractor(stack);

        	if (extractor.check()) {
        		SharedPointer<NetworkStack> pstack = extractor();
                	pystack_ = stack;
                
			// The NetworkStack have been extracted and now call the setStack method
                	setStack(pstack);
        	} else {
			std::cerr << "Can not extract NetworkStack from python object" << std::endl;
		}
	}
}

PacketDispatcher& PacketDispatcher::__enter__() {

	open(input_name_);
        return *this;
}

bool PacketDispatcher::__exit__(boost::python::object type, boost::python::object val, boost::python::object traceback) {

	close();
        return type.ptr() == Py_None;
}

void PacketDispatcher::forwardPacket(const std::string &packet, int length) {

	const unsigned char *pkt = reinterpret_cast<const unsigned char *>(packet.c_str());

	// TODO: pass the time to the method forward_raw_packet from the
	// python binding
	forward_raw_packet((unsigned char*)pkt,length,0);
	return;
}

const char *PacketDispatcher::getStatus() const {

        if (status_ == PacketDispatcherStatus::RUNNING)
                return "running";
        else
                return "stoped";
}

#endif

std::ostream& operator<< (std::ostream& out, const PacketDispatcher& pdis) {

	out << "PacketDispatcher(" << &pdis <<") statistics" << std::endl;
	out << "\t" << "Connected to " << pdis.stack_name_ <<std::endl;
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
	if (pdis.scheduler_set_) {
		out << "\t" << "Scheduler on (" << pdis.scheduler_callback_ << ") seconds:" << pdis.scheduler_seconds_ <<std::endl;
	} else {
		out << "\t" << "Scheduler off" << std::endl;
	}
#endif
	if (pdis.pcap_filter_.length() > 0) {
		out << "\t" << "Pcap filter:" << pdis.pcap_filter_ <<std::endl;
	}
	out << "\t" << "Total packets:          " << std::setw(10) << pdis.total_packets_ <<std::endl;
	out << "\t" << "Total bytes:        " << std::setw(14) << pdis.total_bytes_ <<std::endl;

        return out;
}

void PacketDispatcher::status(void) {

	std::ostringstream msg;
        msg << "PacketDispatcher ";
	if (status_ == PacketDispatcherStatus::RUNNING)
		msg << "running";
	else
		msg << "stoped";
	msg << ", plug to " << stack_name_;
	msg << ", packets " << total_packets_ << ", bytes " << total_bytes_;

        info_message(msg.str());
}



} // namespace aiengine
