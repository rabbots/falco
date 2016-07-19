#pragma once

#include <string>
#include <exception>

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include <sinsp.h>

#include "config_falco.h"

struct falco_exception : std::exception
{
	falco_exception()
	{
	}

	~falco_exception() throw()
	{
	}

	falco_exception(std::string error_str)
	{
		m_error_str = error_str;
	}

	char const* what() const throw()
	{
		return m_error_str.c_str();
	}

	std::string m_error_str;
};

class falco_common
{
public:
	falco_common();
	virtual ~falco_common();

	void init(std::string &lua_main_filename);

	void set_inspector(sinsp *inspector);

protected:
	lua_State *m_ls;

	sinsp *m_inspector;

private:
	void add_lua_path(std::string &path);
};



