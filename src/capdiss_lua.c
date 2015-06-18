/*
 * Copyright (c) 2015, CodeWard.org
 */
#include <lua.h>
#include <lauxlib.h>

#include "capdiss_lua.h"

#if 0
static void
capdiss_dump_stack (lua_State *lua_state, const char *label)
{
	int top, i, type;

	top = lua_gettop (lua_state);

	fprintf (stderr, ">>%s\n", label);

	for ( i = top; i >= 1; i-- ){
		type = lua_type (lua_state, i);

		fprintf (stderr, "[%d] => %s\n", i, lua_typename (lua_state, type));
	}

	fprintf (stderr, ">>END %s\n", label);
}
#endif

static int
capdiss_get_table (lua_State *lua_state, const char *name)
{
	lua_getglobal (lua_state, name);

	if ( ! lua_istable (lua_state, -1) ){
		lua_pop (lua_state, 1);
		return 1;
	}

	return 0;
}

int
capdiss_get_table_item (lua_State *lua_state, const char *name, int type)
{
	int rval;

	rval = capdiss_get_table (lua_state, "Capdiss");

	if ( rval == 1 )
		return 1;

	// FIXME: add stack size check (lua_checkstack)
	lua_pushstring (lua_state, name);
	lua_gettable (lua_state, -2);

	if ( lua_type (lua_state, -1) != type ){
		lua_pop (lua_state, 2);
		return 1;
	}

	lua_remove (lua_state, -2);

	return 0;
}

