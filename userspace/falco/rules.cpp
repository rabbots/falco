#include "rules.h"
#include "logger.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include "falco_engine.h"
const static struct luaL_reg ll_falco_rules [] =
{
	{"add_filter", &falco_rules::add_filter},
	{NULL,NULL}
};

falco_rules::falco_rules(sinsp* inspector, falco_engine *engine, lua_State *ls)
	: m_inspector(inspector), m_engine(engine), m_ls(ls)
{
	m_lua_parser = new lua_parser(inspector, m_ls);
}

void falco_rules::init(lua_State *ls)
{
	luaL_openlib(ls, "falco_rules", ll_falco_rules, 0);
}

int falco_rules::add_filter(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -2) ||
	    ! lua_istable(ls, -1))
	{
		throw falco_exception("Invalid arguments passed to add_filter()\n");
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -2);

	list<uint32_t> evttypes;

	lua_pushnil(ls);  /* first key */
	while (lua_next(ls, -2) != 0) {
                // key is at index -2, value is at index
                // -1. We want the keys.
		evttypes.push_back(luaL_checknumber(ls, -2));

		// Remove value, keep key for next iteration
		lua_pop(ls, 1);
	}

	rules->add_filter(evttypes);

	return 0;
}

void falco_rules::add_filter(list<uint32_t> &evttypes)
{
	// While the current rule was being parsed, a sinsp_filter
	// object was being populated by lua_parser. Grab that filter
	// and pass it to the engine.
	sinsp_filter *filter = m_lua_parser->get_filter(true);

	m_engine->add_evttype_filter(evttypes, filter);
}

void falco_rules::load_rules(string &rules_content, bool verbose)
{
	lua_getglobal(m_ls, m_lua_load_rules.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		// Create a table containing all events, so they can
		// be mapped to event ids.
		sinsp_evttables* einfo = m_inspector->get_event_info_tables();
		const struct ppm_event_info* etable = einfo->m_event_info;
		const struct ppm_syscall_desc* stable = einfo->m_syscall_info_table;

		map<string,string> events_by_name;
		for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
		{
			auto it = events_by_name.find(etable[j].name);

			if (it == events_by_name.end()) {
				events_by_name[etable[j].name] = to_string(j);
			} else {
				string cur = it->second;
				cur += " ";
				cur += to_string(j);
				events_by_name[etable[j].name] = cur;
			}
		}

		lua_newtable(m_ls);

		for( auto kv : events_by_name)
		{
			lua_pushstring(m_ls, kv.first.c_str());
			lua_pushstring(m_ls, kv.second.c_str());
			lua_settable(m_ls, -3);
		}

		lua_setglobal(m_ls, m_lua_events.c_str());

		// Create a table containing the syscalls/events that
		// are ignored by the kernel module. load_rules will
		// return an error if any rule references one of these
		// syscalls/events.

		lua_newtable(m_ls);

		for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
		{
			if(etable[j].flags & EF_DROP_FALCO)
			{
				lua_pushstring(m_ls, etable[j].name);
				lua_pushnumber(m_ls, 1);
				lua_settable(m_ls, -3);
			}
		}

		lua_setglobal(m_ls, m_lua_ignored_events.c_str());

		lua_newtable(m_ls);

		for(uint32_t j = 0; j < PPM_SC_MAX; j++)
		{
			if(stable[j].flags & EF_DROP_FALCO)
			{
				lua_pushstring(m_ls, stable[j].name);
				lua_pushnumber(m_ls, 1);
				lua_settable(m_ls, -3);
			}
		}

		lua_setglobal(m_ls, m_lua_ignored_syscalls.c_str());

		lua_pushstring(m_ls, rules_content.c_str());
		lua_pushlightuserdata(m_ls, this);
		lua_pushboolean(m_ls, (verbose ? 1 : 0));
		if(lua_pcall(m_ls, 3, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error loading rules:" + string(lerr);
			throw falco_exception(err);
		}
	} else {
		throw falco_exception("No function " + m_lua_load_rules + " found in lua rule module");
	}
}

void falco_rules::describe_rule(std::string *rule)
{
	lua_getglobal(m_ls, m_lua_describe_rule.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		if (rule == NULL)
		{
			lua_pushnil(m_ls);
		} else {
			lua_pushstring(m_ls, rule->c_str());
		}

		if(lua_pcall(m_ls, 1, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Could not describe " + (rule == NULL ? "all rules" : "rule " + *rule) + ": " + string(lerr);
			throw falco_exception(err);
		}
	} else {
		throw falco_exception("No function " + m_lua_describe_rule + " found in lua rule module");
	}
}


falco_rules::~falco_rules()
{
	delete m_lua_parser;
}

