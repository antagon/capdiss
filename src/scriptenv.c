/*
 * Copyright (c) 2015, CodeWard.org
 */
#include <stdlib.h>
#include <string.h>
#include <lua.h>

#include "scriptenv.h"

static void
script_free (struct script *script)
{
	if ( script->state != NULL )
		lua_close (script->state);

	if ( script->source != NULL )
		free (script->source);

	if ( script->file != NULL )
		free (script->file);
}

void
scriptenv_init (struct scriptenv *script_env)
{
	script_env->head = NULL;
	script_env->tail = NULL;
}

void
scriptenv_add (struct scriptenv *script_env, struct script *script)
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
scriptenv_free (struct scriptenv *script_env)
{
	struct script *script, *script_next;

	script = script_env->head;

	while ( script != NULL ){
		script_next = script->next;	
		script_free (script);
		free (script);
		script = script_next;
	}
}

struct script*
script_new (void)
{
	struct script *script;

	script = (struct script*) malloc (sizeof (struct script));

	if ( script == NULL )
		return NULL;

	memset (script, 0, sizeof (struct script));
	script->ok = 1;

	return script;
}

