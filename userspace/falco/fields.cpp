#include "fields.h"
#include "chisel_api.h"
#include "filterchecks.h"

#include "falco_engine.h"

extern sinsp_filter_check_list g_filterlist;

const static struct luaL_reg ll_falco [] =
{
	{"field", &falco_fields::field},
	{NULL,NULL}
};

sinsp* falco_fields::s_inspector = NULL;

std::map<string, sinsp_filter_check*> falco_fields::s_fieldname_map;


void falco_fields::init(sinsp* inspector, lua_State *ls)
{
	s_inspector = inspector;

	luaL_openlib(ls, "falco", ll_falco, 0);
}

int falco_fields::field(lua_State *ls)
{

	sinsp_filter_check* chk=NULL;

	if (!lua_islightuserdata(ls, 1))
	{
		string err = "invalid argument passed to falco.field()";
		fprintf(stderr, "%s\n", err.c_str());
		throw falco_engine_exception("falco.field() error");
	}
	sinsp_evt* evt = (sinsp_evt*)lua_topointer(ls, 1);

	string fieldname = luaL_checkstring(ls, 2);

	if (s_fieldname_map.count(fieldname) == 0)
	{

		chk = g_filterlist.new_filter_check_from_fldname(fieldname,
								 s_inspector,
								 false);

		if(chk == NULL)
		{
			string err = "nonexistent fieldname passed to falco.field(): " + string(fieldname);
			fprintf(stderr, "%s\n", err.c_str());
			throw falco_engine_exception("falco.field() error");
		}

		chk->parse_field_name(fieldname.c_str(), true);
		s_fieldname_map[fieldname] = chk;
	}
	else
	{
		chk = s_fieldname_map[fieldname];
	}

	uint32_t vlen;
	uint8_t* rawval = chk->extract(evt, &vlen);

	if(rawval != NULL)
	{
		return lua_cbacks::rawval_to_lua_stack(ls, rawval, chk->get_field_info(), vlen);
	}
	else
	{
		lua_pushnil(ls);
		return 1;
	}
}

