/*
 * Copyright (c) 2015, CodeWard.org
 */
#include <stdlib.h>
#include <string.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "lscript_list.h"

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

	if ( script->payload == NULL )
		return NULL;

	script->type = type;

	script->state = luaL_newstate ();
	// TODO: customize which libraries to load.
	luaL_openlibs (script->state);

	script->ok = 1;

	return script;
}

void
lscript_reset (struct lscript *script)
{
	if ( script->state != NULL )
		lua_close (script->state);

	script->state = luaL_newstate ();
	luaL_openlibs (script->state);
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

