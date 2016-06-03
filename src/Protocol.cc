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
#include "Protocol.h"
#if defined(LUA_BINDING)
#include "swigluarun.h"
#endif

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr Protocol::logger(log4cxx::Logger::getLogger("aiengine.protocol"));
#endif

#ifdef PYTHON_BINDING
void Protocol::setDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) { 

	// The user could unref the DatabaseAdaptor on execution time
	if (dbptr.is_none()) {
		is_set_db_ = false;
		Py_DECREF(dbptr_.ptr());
	} else {
		dbptr_ = dbptr; 
		is_set_db_ = true; 
		packet_sampling_ = packet_sampling; 
	}
}
#elif defined(RUBY_BINDING)
void Protocol::setDatabaseAdaptor(VALUE dbptr, int packet_sampling) { 

        if (!NIL_P(dbptr)) {
		// Ruby dont have the concept of abstract clases so in order
		// to verify that VALUE inheritance from DatabaseAdaptor we just
		// verify from the object dbptr that the methods insert,update and remove
		// exists on the instance
		
		if (rb_respond_to(dbptr, rb_intern("insert"))) {
			if (rb_respond_to(dbptr, rb_intern("update"))) {
				if (rb_respond_to(dbptr, rb_intern("remove"))) {
                			dbptr_ = dbptr;
                			is_set_db_ = true;
					packet_sampling_ = packet_sampling;
				}
			}
		}
        } else {
                dbptr_ = Qnil;
                is_set_db_ = false;
        }
}
#elif defined(JAVA_BINDING) 
void Protocol::setDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling) {

	if (dbptr == nullptr) {
		dbptr_ = nullptr;
		is_set_db_ = false;
		packet_sampling_ = 0;
	} else {
		dbptr_ = dbptr;
		is_set_db_ = true;
		packet_sampling_ = packet_sampling;
		// std::cout << __FILE__ << ":" << __func__ << " new adaptor set" << std::endl;
	}	
}

#elif defined(LUA_BINDING)

void lua_stacktrace(lua_State* L)
{
    lua_Debug entry;
    int depth = 0; 

    while (lua_getstack(L, depth, &entry))
    {
        int status = lua_getinfo(L, "Sln", &entry);
        assert(status);

	//std::cout << "(" << entry.currentline << "): " << (entry.name ? entry.name : "?")  << std::endl;
	std::cout << entry.short_src << "(" << entry.currentline << "): " << (entry.name ? entry.name : "?");
	std::cout << " what(" << (entry.what ? entry.what : "?") << std::endl; 

        // dprintf("%s(%d): %s\n", entry.short_src, entry.currentline, entry.name ? entry.name : "?");
        depth++;
    }
}

static void dumpstack (lua_State *L, const char *message) {
  int i;
  int top=lua_gettop(L);
  printf("dumpstack -- %s\n",message);
  for (i=1; i<=top; i++) {
    printf("%d\t%s\t",i,luaL_typename(L,i));
    switch (lua_type(L, i)) {
      case LUA_TNUMBER:
        printf("%g\n",lua_tonumber(L,i));
        break;
      case LUA_TSTRING:
        printf("%s\n",lua_tostring(L,i));
        break;
      case LUA_TBOOLEAN:
        printf("%s\n", (lua_toboolean(L, i) ? "true" : "false"));
        break;
      case LUA_TNIL:
        printf("%s\n", "nil");
        break;
      default:
        printf("%p\n",lua_topointer(L,i));
        break;
    }
  }
  printf("dumpstack -- END\n");
}


void PrintTable(lua_State *L)
{
    lua_pushnil(L);

    while(lua_next(L, -2) != 0)
    {
        if(lua_isstring(L, -1))
		std::cout << lua_tostring(L, -2) << "=" << lua_tostring(L, -1) << std::endl;
        else if(lua_isnumber(L, -1))
		std::cout << lua_tostring(L, -2) << "=" << lua_tonumber(L, -1) << std::endl;
        else if(lua_istable(L, -1))
          PrintTable(L);

        lua_pop(L, 1);
    }
}

void Protocol::setDatabaseAdaptor(lua_State *lua, int packet_sampling) {

	lua_ = lua;
	/// https://www.lua.org/source/5.1/lua.h.html
	const char *object_name = lua_tostring(lua, -1);
	std::cout << "Setting adaptor on protocol:" << lua_tostring(lua, -1) << std::endl;
	// PrintTable(lua);	
	dumpstack(lua, "protocol");
	// lua_stacktrace(lua);

        lua_getglobal(lua,object_name);
        if (lua_istable(lua,-1)) {
		std::cout << "im a table" << std::endl;
		// lua_gettable(lua,-1);
		PrintTable(lua);	
                // ref_function_ = luaL_ref(lua, LUA_REGISTRYINDEX);
                lua_getfield(lua,-1,"insert");
		if (lua_isfunction(lua,-1)) {
                	// lua_pushnumber(lua,67);
			ref_function_insert_ = luaL_ref(lua, LUA_REGISTRYINDEX);
			// int Error = lua_pcall(lua, 1, 0, 0);
			std::cout << "method inset locate" << std::endl;
			is_set_db_ = true;
			packet_sampling_ =1; 
		} else {	
			std::cout << "no insert method on class " << object_name << std::endl;
			return;
		}
                lua_getfield(lua,-1,"update");
		if (lua_isfunction(lua,-1)) {
                	// lua_pushnumber(lua,67);
			ref_function_update_ = luaL_ref(lua, LUA_REGISTRYINDEX);
		} else {	
			std::cout << "no update method on class " << object_name << std::endl;
			return;
		}
                lua_getfield(lua,-1,"remove");
		if (lua_isfunction(lua,-1)) {
                	// lua_pushnumber(lua,67);
			ref_function_remove_ = luaL_ref(lua, LUA_REGISTRYINDEX);
		} else {	
			std::cout << "no remove method on class " << object_name << std::endl;
			return;
		}

	} else {
		std::cout << "im not a table" << std::endl;
	} 
}


bool Protocol::push_pointer(lua_State *L, void* ptr, const char* type_name, int owned) {

        // task 1: get the object 'type' which is registered with SWIG
        // you need to call SWIG_TypeQuery() with the class name
        // (normally, just look in the wrapper file to get this)
      
        swig_type_info * pTypeInfo = SWIG_TypeQuery(L, type_name);
        if (pTypeInfo == 0)
        	return false;   // error
        // task 2: push the pointer to the Lua stack
        // this requires a pointer & the type
        // the last param specifies if Lua is responsible for deleting the object

        SWIG_NewPointerObj(L, ptr, pTypeInfo, owned);
        return true;
}

#endif

#if (defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)) && defined(HAVE_ADAPTOR)

#if defined(RUBY_BINDING)

// function for call ruby objects
static VALUE ruby_database_callback(VALUE ptr) {

	ruby_shared_data *data = (ruby_shared_data*)ptr;

	return rb_funcall2(data->obj,data->method_id,data->nargs,data->args);
}

#endif

void Protocol::databaseAdaptorInsertHandler(Flow *flow) {
	std::ostringstream key;

        key << *flow;
#if defined(PYTHON_BINDING)
       	try {
		PyGilContext gil_lock();

               	boost::python::call_method<void>(dbptr_.ptr(),"insert",key.str());
        } catch(std::exception &e) {
              	std::cout << "ERROR:" << e.what() << std::endl;
        } 
#elif defined(RUBY_BINDING)

	ruby_shared_data rbdata;

	rbdata.obj = dbptr_;
	rbdata.method_id = rb_intern("insert");
	rbdata.nargs = 1;
	rbdata.args[0] = rb_str_new2(key.str().c_str());
 
	int error = 0;
	VALUE result = rb_protect(ruby_database_callback,(VALUE)&rbdata,&error);

	if (error)
		throw "Ruby exception on insert";	

#elif defined(JAVA_BINDING)
	if (dbptr_ != nullptr) { 
		dbptr_->insert(key.str());
	}
#elif defined(LUA_BINDING)

	std::cout << "Calling from c++ to lua" << std::endl;
        lua_rawgeti(lua_, LUA_REGISTRYINDEX, ref_function_insert_);

        //if (push_pointer(lua_,flow,"aiengine::Flow*",0)) {
                int ret;
		lua_pushnumber(lua_,1000);
                if ((ret = lua_pcall(lua_,1,0,0)) != 0) {
                        std::cout << "ERROR:" << lua_tostring(lua_, -1) << std::endl;
                }
        //}

#endif
}

void Protocol::databaseAdaptorUpdateHandler(Flow *flow) {
       	std::ostringstream data;
        std::ostringstream key;

        key << *flow;
        flow->serialize(data);

#if defined(PYTHON_BINDING)
        try {
		PyGilContext gil_lock();

              	boost::python::call_method<void>(dbptr_.ptr(),"update",key.str(),data.str());
        } catch(std::exception &e) {
                std::cout << "ERROR:" << e.what() << std::endl;
        }
#elif defined(RUBY_BINDING)

        ruby_shared_data rbdata;

        rbdata.obj = dbptr_;
        rbdata.method_id = rb_intern("update");
        rbdata.nargs = 2;
        rbdata.args[0] = rb_str_new2(key.str().c_str());
        rbdata.args[1] = rb_str_new2(data.str().c_str());

        int error = 0;
        VALUE result = rb_protect(ruby_database_callback,(VALUE)&rbdata,&error);

        if (error)
                throw "Ruby exception on update";
#elif defined(JAVA_BINDING)
	if (dbptr_ != nullptr) { 
		dbptr_->update(key.str(),data.str());
	}
#endif
}

void Protocol::databaseAdaptorRemoveHandler(Flow *flow) {
      	std::ostringstream key;

        key << *flow;

#if defined(PYTHON_BINDING)
        try {
		PyGilContext gil_lock();

               	boost::python::call_method<void>(dbptr_.ptr(),"remove",key.str());
        } catch(std::exception &e) {
                std::cout << "ERROR:" << e.what() << std::endl;
        }
#elif defined(RUBY_BINDING)

        ruby_shared_data rbdata;

        rbdata.obj = dbptr_;
        rbdata.method_id = rb_intern("remove");
        rbdata.nargs = 1;
        rbdata.args[0] = rb_str_new2(key.str().c_str());

        int error = 0;
        VALUE result = rb_protect(ruby_database_callback,(VALUE)&rbdata,&error);

        if (error)
                throw "Ruby exception on remove";
#elif defined(JAVA_BINDING)
	if (dbptr_ != nullptr) { 
		dbptr_->remove(key.str());
	}
#endif
}

#if defined(LUA_BINDING)

//void Protocol::getCounters(lua_State *lua) {


//}

#endif

#endif

void Protocol::infoMessage(const std::string& msg) {

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

void Protocol::showCacheMap(std::basic_ostream<char>& out,GenericMapType &mt, const std::string &title, const std::string &item_name) {

        out << "\t" << title << " usage" << std::endl;

        std::vector<PairStringCacheHits> g_list(mt.begin(),mt.end());
        // Sort by using lambdas
        std::sort(
                g_list.begin(),
                g_list.end(),
                [](PairStringCacheHits const &a, PairStringCacheHits const &b )
                {
                        int v1 = std::get<1>(a.second);
                        int v2 = std::get<1>(b.second);

                        return v1 > v2;
        });

        for(auto it = g_list.begin(); it!=g_list.end(); ++it) {
                SharedPointer<StringCache> uri = std::get<0>((*it).second);
                int count = std::get<1>((*it).second);
                if(uri)
                         out << "\t\t" << item_name << ":" << uri->getName() <<":" << count << std::endl;
        }
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)

#if defined(PYTHON_BINDING)
boost::python::dict Protocol::addMapToHash(const GenericMapType &mt) const {
        boost::python::dict cc;
#elif defined(RUBY_BINDING)
VALUE Protocol::addMapToHash(const GenericMapType &mt) const {
        VALUE cc = rb_hash_new();
#endif
        for (auto &item: mt) {
                boost::string_ref label = item.first;
                int32_t hits = std::get<1>(item.second);
#if defined(PYTHON_BINDING)
                // The label must be converted to std::string
                std::string key(label);
#elif defined(RUBY_BINDING)
                const char *key = label.data();
#endif
                addValueToCounter(cc,key,hits);
        }

        return cc;
}

#endif

} // namespace aiengine  

