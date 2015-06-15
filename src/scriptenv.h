/*
 * Copyright (c) 2015 CodeWard.org
 */
#ifndef _SCRIPTENV_H
#define _SCRIPTENV_H

#include <lua.h>

struct scriptenv
{
	struct script *head;
	struct script *tail;
};

struct script
{
	lua_State *state;
	char *source;
	char *file;
	struct script *prev;
	struct script *next;
};

extern void scriptenv_init (struct scriptenv *script_env);

extern void scriptenv_add (struct scriptenv *script_env, struct script *script);

extern void scriptenv_delete (struct scriptenv *script_env, struct script *script);

extern void scriptenv_free (struct scriptenv *script_env);

extern struct script* script_new (void);

#endif

