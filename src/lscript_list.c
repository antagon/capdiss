/*
 * Copyright (c) 2015, CodeWard.org
 */
#include <stdlib.h>
#include <string.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "lscript_list.h"

static int
lua_get_table (lua_State *lua_state, const char *name)
{
	lua_getglobal (lua_state, name);

	if ( ! lua_istable (lua_state, -1) ){
		lua_pop (lua_state, 1);
		return 1;
	}

	return 0;
}

static void
lscript_free (struct lscript *script)
{
	if ( script->state != NULL )
		lua_close (script->state);

	if ( script->payload != NULL )
		free (script->payload);
}

struct lscript*
lscript_new (const char *payload, int type)
{
	struct lscript *script;

	script = (struct lscript*) malloc (sizeof (struct lscript));

	if ( script == NULL )
		return NULL;

	memset (script, 0, sizeof (struct lscript));

	script->payload = strdup (payload);

	if ( script->payload == NULL ){
		free (script);
		return NULL;
	}

	script->type = type;
	script->ok = 1;

	script->state = luaL_newstate ();
	luaL_openlibs (script->state);

	return script;
}

int
lscript_do_payload (struct lscript *script)
{
	if ( script->type == LSCRIPT_SRC ){
		if ( luaL_dostring (script->state, script->payload) != 0 )
			return 1;
	} else if ( script->type == LSCRIPT_PATH ){
		if ( luaL_dofile (script->state, script->payload) != 0 )
			return 1;
	}

	return 0;
}

void
lscript_reset (struct lscript *script)
{
	if ( script->state != NULL )
		lua_close (script->state);

	script->state = luaL_newstate ();
	luaL_openlibs (script->state);
}

int
lscript_get_table_item (struct lscript *script, const char *name, int type)
{
	if ( lua_get_table (script->state, CAPDISS_TABLE) == 1 )
		return 1;

	if ( ! lua_checkstack (script->state, 1) )
		return 1;

	lua_pushstring (script->state, name);
	lua_gettable (script->state, -2);

	if ( lua_type (script->state, -1) != type ){
		lua_pop (script->state, 2);
		return 1;
	}

	lua_remove (script->state, -2);

	return 0;
}

int
lscript_set_table_item (struct lscript *script, const char *name, int type, void *val)
{
	if ( lua_get_table (script->state, CAPDISS_TABLE) == 1 )
		return 1;

	switch ( type ){
		case LUA_TNIL:
			lua_pushnil (script->state);
			break;

		case LUA_TBOOLEAN:
			lua_pushboolean (script->state, (int) *((int*) val));
			break;

		case LUA_TNUMBER:
			lua_pushnumber (script->state, (lua_Number) *((lua_Number*) val));
			break;

		case LUA_TSTRING:
			lua_pushstring (script->state, (const char*) val);
			break;

		default:
			return 1;
	}

	lua_setfield (script->state, -2, name);

	return 0;
}

void
lscript_list_init (struct lscript_list *script_env)
{
	script_env->head = NULL;
	script_env->tail = NULL;
}

void
lscript_list_add (struct lscript_list *script_env, struct lscript *script)
{
	if ( script_env->head == NULL ){
		script->prev = NULL;
		script->next = NULL;
		script_env->head = script;
		script_env->tail = script_env->head;
	} else {
		script->prev = script_env->tail;
		script->next = NULL;
		script_env->tail->next = script;
		script_env->tail = script;
	}
}

void
lscript_list_free (struct lscript_list *script_env)
{
	struct lscript *script, *script_next;

	script = script_env->head;

	while ( script != NULL ){
		script_next = script->next;	
		lscript_free (script);
		free (script);
		script = script_next;
	}
}

