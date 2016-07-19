#pragma once
/* This class acts as the primary interface between a program and the
 * falco rules engine. Falco outputs (writing to files/syslog/etc) are
 * handled in the main program. */

#include <string>

#include "sinsp.h"

#include "rules.h"

#include "config_falco.h"
#include "falco_common.h"

class falco_engine : public falco_common
{
public:
	falco_engine();
	virtual ~falco_engine();

	void load_rules_file(std::string &rules_filename, bool verbose);
	void load_rules(std::string &rules_content, bool verbose);

	// XXX/mstemm is there a way to avoid this data copy? Maybe
	// it's not so bad as it's only the events that match.
	struct rule_result {
		sinsp_evt *evt;
		std::string rule;
		std::string priority;
		std::string format;
	};

	rule_result handle_event(sinsp_evt *ev);

	void describe_rule(std::string *rule);
	sinsp_filter *get_filter()
	{
		return m_rules->get_filter();
	}

	void print_stats();

private:
	falco_rules *m_rules;
	std::string m_lua_main_filename = "rule_loader.lua";
};

