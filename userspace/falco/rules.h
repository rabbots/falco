#pragma once

#include <list>

#include "sinsp.h"
#include "lua_parser.h"

class falco_rules
{
 public:
	falco_rules(sinsp* inspector, lua_State *ls);
	~falco_rules();
	void load_rules(string rules_filename, bool verbose);
	void describe_rule(string *rule);
	sinsp_filter* get_filter();

	static void init(lua_State *ls);
	static int add_filter(lua_State *ls);

 private:
	void add_filter(list<uint32_t> &evttypes);

	lua_parser* m_lua_parser;
	sinsp* m_inspector;
	lua_State* m_ls;

	string m_lua_load_rules = "load_rules";
	string m_lua_ignored_syscalls = "ignored_syscalls";
	string m_lua_ignored_events = "ignored_events";
	string m_lua_events = "events";
	string m_lua_describe_rule = "describe_rule";
};
