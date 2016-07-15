#include <string>
#include <fstream>

#include "falco_engine.h"

extern "C" {
#include "lpeg.h"
#include "lyaml.h"
}

#include "config_falco.h"
#include "formats.h"
#include "fields.h"
#include "logger.h"
#include "utils.h"
#include <yaml-cpp/yaml.h>


string lua_on_event = "on_event";
string lua_add_output = "add_output";
string lua_print_stats = "print_stats";

using namespace std;

// XXX/mstemm TODO:
//  - DONE Move output_config type to one exported by falco_engine, so it can be shared with the falco-level configuration.
//  - DONE don't use sinsp_exeception
//  - don't read a rules file, instead be handed rules content
//  - lua_close is being called multiple times--change lua_parser.cpp to not own lua state and try to close it. Currently falco_rules is leaking.
//  - create falco_engine library, link with it in falco.
//  - come up with a falco_engine logging mechanism separate from falco_logger
//  - Don't have a header file with all the built-in pathnames. Put in falco_engine class instead?
//  - Better document main methods.

falco_engine::falco_engine()
{

}

falco_engine::~falco_engine()
{
	if(m_ls)
	{
		lua_close(m_ls);
	}

	if (m_rules)
	{
//		delete m_rules;
	}
}

void falco_engine::set_inspector(sinsp *inspector)
{
	m_inspector = inspector;
}

bool falco_engine::init(string &rules_filename, bool json_output, string lua_dir, bool verbose)
{
	// The engine must have been given an inspector by now.
	if(! m_inspector)
	{
		return false;
	}

	string lua_main_filename;

	lua_main_filename = lua_dir + FALCO_LUA_MAIN;
	if (!std::ifstream(lua_main_filename))
	{
		lua_dir = FALCO_SOURCE_LUA_DIR;
		lua_main_filename = lua_dir + FALCO_LUA_MAIN;
		if (!std::ifstream(lua_main_filename))
		{
			falco_logger::log(LOG_ERR, "Could not find Falco Lua libraries (tried " +
					  string(FALCO_LUA_DIR FALCO_LUA_MAIN) + ", " +
					  lua_main_filename + "). Exiting.\n");
			return false;
		}
	}

	// Initialize Lua interpreter
	m_ls = lua_open();
	luaL_openlibs(m_ls);
	luaopen_lpeg(m_ls);
	luaopen_yaml(m_ls);
	add_lua_path(lua_dir);

	falco_formats::init(m_inspector, m_ls, json_output);
	falco_fields::init(m_inspector, m_ls);

	falco_logger::init(m_ls);

	m_rules = new falco_rules(m_inspector, m_ls, lua_main_filename);
	m_rules->load_rules(rules_filename, verbose);

	falco_logger::log(LOG_INFO, "Parsed rules from file " + rules_filename + "\n");

	return true;
}

void falco_engine::handle_event(sinsp_evt *ev)
{

	lua_getglobal(m_ls, lua_on_event.c_str());

	if(lua_isfunction(m_ls, -1))
	{
		lua_pushlightuserdata(m_ls, ev);
		lua_pushnumber(m_ls, ev->get_check_id());

		if(lua_pcall(m_ls, 2, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function output: " + string(lerr);
			throw falco_engine_exception(err);
		}
	}
	else
	{
		throw falco_engine_exception("No function " + lua_on_event + " found in lua compiler module");
	}
}

void falco_engine::add_lua_path(string &path)
{
	string cpath = string(path);
	path += "?.lua";
	cpath += "?.so";

	lua_getglobal(m_ls, "package");

	lua_getfield(m_ls, -1, "path");
	string cur_path = lua_tostring(m_ls, -1 );
	cur_path += ';';
	lua_pop(m_ls, 1);

	cur_path.append(path.c_str());

	lua_pushstring(m_ls, cur_path.c_str());
	lua_setfield(m_ls, -2, "path");

	lua_getfield(m_ls, -1, "cpath");
	string cur_cpath = lua_tostring(m_ls, -1 );
	cur_cpath += ';';
	lua_pop(m_ls, 1);

	cur_cpath.append(cpath.c_str());

	lua_pushstring(m_ls, cur_cpath.c_str());
	lua_setfield(m_ls, -2, "cpath");

	lua_pop(m_ls, 1);
}

void falco_engine::add_output(output_config oc)
{
	uint8_t nargs = 1;
	lua_getglobal(m_ls, lua_add_output.c_str());

	if(!lua_isfunction(m_ls, -1))
	{
		throw falco_engine_exception("No function " + lua_add_output + " found. ");
	}
	lua_pushstring(m_ls, oc.name.c_str());

	// If we have options, build up a lua table containing them
	if (oc.options.size())
	{
		nargs = 2;
		lua_createtable(m_ls, 0, oc.options.size());

		for (auto it = oc.options.cbegin(); it != oc.options.cend(); ++it)
		{
			lua_pushstring(m_ls, (*it).second.c_str());
			lua_setfield(m_ls, -2, (*it).first.c_str());
		}
	}

	if(lua_pcall(m_ls, nargs, 0, 0) != 0)
	{
		const char* lerr = lua_tostring(m_ls, -1);
		throw falco_engine_exception(string(lerr));
	}

}

// Print statistics on the the rules that triggered
void falco_engine::print_stats()
{
	lua_getglobal(m_ls, lua_print_stats.c_str());

	if(lua_isfunction(m_ls, -1))
	{
		if(lua_pcall(m_ls, 0, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function print_stats: " + string(lerr);
			throw falco_engine_exception(err);
		}
	}
	else
	{
		throw falco_engine_exception("No function " + lua_print_stats + " found in lua rule loader module");
	}

}

void falco_engine::describe_rule(string *rule)
{
	return m_rules->describe_rule(rule);
}
