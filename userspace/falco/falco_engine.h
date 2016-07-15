/* This class acts as the primary interface between a program and all
 * falco-related functionality. */

#include <string>
extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include <sinsp.h>

#include "config_falco.h"
#include "rules.h"

#include "configuration.h"

class falco_engine
{
public:
	falco_engine();
	virtual ~falco_engine();

	bool init(string &rules_filename, bool json_output, string lua_dir = FALCO_LUA_DIR);

	void set_inspector(sinsp *inspector);

	void handle_event(sinsp_evt *ev);

	void describe_rule(std::string *rule);
	sinsp_filter *get_filter()
	{
		return m_rules->get_filter();
	}

	void add_output(output_config oc);
	void print_stats();

private:
	void add_lua_path(std::string &path);

	lua_State *m_ls;
	falco_rules *m_rules;
	sinsp *m_inspector;
};

