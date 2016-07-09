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
#ifndef _LSCRIPT_LIST_H
#define _LSCRIPT_LIST_H

#include <lua.h>

#define CAPDISS_TABLE "capdiss"

enum
{
	LSCRIPT_SRC = 1,
	LSCRIPT_FILE = 2,
	LSCRIPT_MOD = 3
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

#define lscript_strerror(script) lua_tostring ((script)->state, -1)

extern void lscript_list_init (struct lscript_list *script_list);

extern void lscript_list_add (struct lscript_list *script_list, struct lscript *script);

extern void lscript_list_free (struct lscript_list *script_list);

extern struct lscript* lscript_new (const char *payload, int type);

extern int lscript_prepare (struct lscript *script);

extern int lscript_do_payload (struct lscript *script);

#if 0
extern void lscript_reset (struct lscript *script);
#endif

extern int lscript_get_table_item (struct lscript *script, const char *name, int type);

#if 0
extern int lscript_set_table_item (struct lscript *script, const char *name, int type, void *val);
#endif

#endif

