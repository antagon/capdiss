/*
 * Copyright (c) 2015, CodeWard.org
 */
#ifndef _LSCRIPT_LIST_H
#define _LSCRIPT_LIST_H

#include <lua.h>

#define CAPDISS_TABLE "capdiss"

enum
{
	LSCRIPT_SRC = 1,
	LSCRIPT_PATH = 2
};

struct lscript_list
{
	struct lscript *head;
	struct lscript *tail;
};

struct lscript
{
	lua_State *state;
	char *payload;
	int type;
	int ok;
	struct lscript *prev;
	struct lscript *next;
};

extern void lscript_list_init (struct lscript_list *script_list);

extern void lscript_list_add (struct lscript_list *script_list, struct lscript *script);

extern void lscript_list_free (struct lscript_list *script_list);

extern struct lscript* lscript_new (const char *payload, int type);

extern void lscript_reset (struct lscript *script);

extern int lscript_get_table_item (struct lscript *script, const char *name, int type);

extern int lscript_set_table_item (struct lscript *script, const char *name, int type, void *val);

#endif

