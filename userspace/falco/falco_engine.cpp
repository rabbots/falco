#include <string>

#include "falco_engine.h"

extern "C" {
#include "lpeg.h"
#include "lyaml.h"
}

#include "logger.h"
#include "utils.h"
#include <yaml-cpp/yaml.h>


string lua_on_event = "on_event";
string lua_print_stats = "print_stats";

using namespace std;

// XXX/mstemm TODO:
//  - DONE Move output_config type to one exported by falco_engine, so it can be shared with the falco-level configuration.
//  - DONE don't use sinsp_exeception
//  - DONE Use a base class for falco_engine/falco_outputs to handle the details of starting lua?
//  - DONE Audit use of headers to make sure appropriate headers being included everywhere.
//  - don't read a rules file, instead be handed rules content
//  - lua_close is being called multiple times--change lua_parser.cpp to not own lua state and try to close it. Currently falco_rules is leaking.
//  - create falco_engine library, link with it in falco.
//  - come up with a falco_engine logging mechanism separate from falco_logger
//  - Better document main methods.

falco_engine::falco_engine()
{

}

falco_engine::~falco_engine()
{
	if (m_rules)
	{
//		delete m_rules;
	}
}


bool falco_engine::init(string &rules_filename, bool verbose)
{
	// The engine must have been given an inspector by now.
	if(! m_inspector)
	{
		return false;
	}

	luaopen_lpeg(m_ls);
	luaopen_yaml(m_ls);

	falco_common::init(m_lua_main_filename);

	m_rules = new falco_rules(m_inspector, m_ls);
	m_rules->load_rules(rules_filename, verbose);

	falco_logger::log(LOG_INFO, "Parsed rules from file " + rules_filename + "\n");

	return true;
}

falco_engine::rule_result falco_engine::handle_event(sinsp_evt *ev)
{
	struct rule_result res;

	lua_getglobal(m_ls, lua_on_event.c_str());

	if(lua_isfunction(m_ls, -1))
	{
		lua_pushlightuserdata(m_ls, ev);
		lua_pushnumber(m_ls, ev->get_check_id());

		if(lua_pcall(m_ls, 2, 3, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function output: " + string(lerr);
			throw falco_exception(err);
		}
		res.evt = ev;
		const char *p =  lua_tostring(m_ls, -3);
		res.rule = p;
		res.priority = lua_tostring(m_ls, -2);
		res.format = lua_tostring(m_ls, -1);
		return res;
	}
	else
	{
		throw falco_exception("No function " + lua_on_event + " found in lua compiler module");
	}

	return res;
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
			throw falco_exception(err);
		}
	}
	else
	{
		throw falco_exception("No function " + lua_print_stats + " found in lua rule loader module");
	}

}

void falco_engine::describe_rule(string *rule)
{
	return m_rules->describe_rule(rule);
}
