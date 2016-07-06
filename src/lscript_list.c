/*
* capdiss - capture file dissector with embedded Lua interpreter.
*
* Copyright (c) 2016, CodeWard.org
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of
* this software and associated documentation files (the "Software"), to deal in
* the Software without restriction, including without limitation the rights to
* use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
* of the Software, and to permit persons to whom the Software is furnished to do
* so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.

* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/
#include <stdlib.h>
#include <string.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "lscript_list.h"

#if 0
#include <stdio.h>

static void
lua_dump_stack (lua_State *lua_state, const char *label)
{
	int top, i, type;
	top = lua_gettop (lua_state);
	fprintf (stderr, ">>%s\n", label);
	for ( i = top; i >= 1; i-- ){
		type = lua_type (lua_state, i);
		fprintf (stderr, "[%d] => %s\n", i, lua_typename (lua_state, type));
	}
	fprintf (stderr, "<<END %s\n", label);
}
#endif

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

static int
lua_load_file (lua_State *lua_state, const char *name)
{
	if ( luaL_loadfile (lua_state, name) != LUA_OK )
		return 1;

	if ( lua_pcall (lua_state, 0, 1, 0) != LUA_OK )
		return 1;

	if ( lua_istable (lua_state, -1) )
		lua_setglobal (lua_state, "capdiss");

	return 0;
}

static int
lua_load_module (lua_State *lua_state, const char *name)
{
	lua_getglobal (lua_state, "require");

	if ( ! lua_isfunction (lua_state, -1) ){
		lua_pop (lua_state, 1);
		return 1;
	}

	if ( ! lua_checkstack (lua_state, 1) ){
		lua_pop (lua_state, 1);
		return 1;
	}

	lua_pushstring (lua_state, name);

	if ( lua_pcall (lua_state, 1, 1, 0) != LUA_OK )
		return 1;

	if ( lua_istable (lua_state, -1) )
		lua_setglobal (lua_state, "capdiss");

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

	// FIXME: load only neccessary libraries!
	luaL_openlibs (script->state);

	return script;
}

int
lscript_do_payload (struct lscript *script)
{
	int rval;

	switch ( script->type ){
		case LSCRIPT_SRC:
			rval = luaL_dostring (script->state, script->payload);
			break;

		case LSCRIPT_FILE:
			rval = lua_load_file (script->state, script->payload);
			break;

		case LSCRIPT_MOD:
			rval = lua_load_module (script->state, script->payload);
			break;

		default:
			return 1;
	}

	return rval;
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

