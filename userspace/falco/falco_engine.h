#pragma once

#include <string>

#include "sinsp.h"

#include "rules.h"

#include "config_falco.h"
#include "falco_common.h"

//
// This class acts as the primary interface between a program and the
// falco rules engine. Falco outputs (writing to files/syslog/etc) are
// handled in a separate class falco_outputs.
//

class falco_engine : public falco_common
{
public:
	falco_engine();
	virtual ~falco_engine();

	//
	// Load rules either directly or from a filename.
	//
	void load_rules_file(std::string &rules_filename, bool verbose);
	void load_rules(std::string &rules_content, bool verbose);

	struct rule_result {
		sinsp_evt *evt;
		std::string rule;
		std::string priority;
		std::string format;
	};

	//
	// After loading rules and after matching events against the
	// rules, ev is an event that matched some rule. Call
	// handle_event to get details on the exact tule that matched
	// the event.
	//
	// the reutrned rule_result is allocated and must be delete()d.
	rule_result *handle_event(sinsp_evt *ev);

	//
	// Print details on the given rule. If rule is NULL, print
	// details on all rules.
	//
	void describe_rule(std::string *rule);

	//
	// Get the filter associated with the current ruleset.
	//
	sinsp_filter *get_filter()
	{
		return m_rules->get_filter();
	}

	//
	// Print statistics on how many events matched each rule.
	//
	void print_stats();

private:
	falco_rules *m_rules;
	std::string m_lua_main_filename = "rule_loader.lua";
};

