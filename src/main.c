/*
 * Copyright (c) 2015, CodeWard.org
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <getopt.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <signal.h>
#include <unistd.h>

#include "pathname.h"
#include "scriptenv.h"
#include "capdiss_lua.h"
#include "capdiss.h"

static int loop;
static int exitno;

static void
usage (const char *p)
{
	fprintf (stderr, "Usage: %s <OPTIONS> <FILE>\n\n\
Options:\n\
 -e, --source='PROGTEXT'    load Lua script source code\n\
 -f, --file=PROGFILE        load Lua script file\n\
 -t, --filter='FILTERTEXT'  apply packet filter\n\
 -v, --version              show version information\n\
 -h, --help                 show usage information (this text)\n", p);
}

static void
version (const char *p)
{
	fprintf (stderr, "%s %u.%u.%u, %s\n", p, CAPDISS_VERSION_MAJOR, CAPDISS_VERSION_MINOR, CAPDISS_VERSION_PATCH, LUA_VERSION);
}

static void
terminate (int signo)
{
	loop = 0;
	exitno = signo;
}

int
main (int argc, char *argv[])
{
	pcap_t *pcap_res;
	struct pcap_pkthdr *pkt_hdr;
	const u_char *pkt_data;
	char errbuff[PCAP_ERRBUF_SIZE];
	char cwd[PATH_MAX];
	char *bpf;
	struct scriptenv script_env;
	struct script *script;
	struct option opt_long[] = {
		{ "file", required_argument, 0, 'f' },
		{ "source", required_argument, 0, 'e' },
		{ "filter", required_argument, 0, 't' },
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'v' },
		{ NULL, 0, 0, 0 }
	};
	int rval, c, opt_index;

	pcap_res = NULL;
	bpf = NULL;
	exitno = EXIT_SUCCESS;

	scriptenv_init (&script_env);

	while ( (c = getopt_long (argc, argv, "f:e:t:hv", opt_long, &opt_index)) != -1 ){
		switch ( c ){
			case 'f':
			case 'e':
				script = script_new ();

				if ( script == NULL ){
					fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
					exitno = EXIT_FAILURE;
					goto cleanup;
				}

				if ( c == 'f' ){
					script->file = strdup (optarg);

					if ( script->file == NULL ){
						fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
						exitno = EXIT_FAILURE;
						goto cleanup;
					}
				} else if ( c == 'e' ){
					script->source = strdup (optarg);

					if ( script->source == NULL ){
						fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
						exitno = EXIT_FAILURE;
						goto cleanup;
					}
				}

				scriptenv_add (&script_env, script);
				break;

			case 't':
				bpf = strdup (optarg);

				if ( bpf == NULL ){
					fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
				break;

			case 'h':
				usage (argv[0]);
				exitno = EXIT_SUCCESS;
				goto cleanup;

			case 'v':
				version (argv[0]);
				exitno = EXIT_SUCCESS;
				goto cleanup;

			default:
				usage (argv[0]);
				exitno = EXIT_FAILURE;
				goto cleanup;
		}
	}

	if ( (argc - optind) == 0 ){
		fprintf (stderr, "%s: no capture file specified.\n", argv[0]);
		usage (argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	if ( script_env.head == NULL ){
		fprintf (stderr, "%s: no Lua scripts specified.\n", argv[0]);
		usage (argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}	

	pcap_res = pcap_open_offline (argv[optind], errbuff);

	if ( pcap_res == NULL ){
		fprintf (stderr, "%s: cannot open file '%s': %s\n", argv[0], argv[optind], errbuff);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	if ( bpf != NULL ){
		struct bpf_program bpf_prog;

		rval = pcap_compile (pcap_res, &bpf_prog, bpf, 0, 0);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot compile packet filter program: %s\n", argv[0], pcap_geterr (pcap_res));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_setfilter (pcap_res, &bpf_prog);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot apply packet filter: %s\n", argv[0], pcap_geterr (pcap_res));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		pcap_freecode (&bpf_prog);
		free (bpf);
	}

	if ( getcwd (cwd, sizeof (cwd)) == NULL ){
		fprintf (stderr, "%s: cannot obtain current working directory: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	script = script_env.head;

	while ( script != NULL ){
		script->state = luaL_newstate ();

		luaL_openlibs (script->state);
		/*luaopen_base (script->state);
		luaopen_coroutine (script->state);
		luaopen_table (script->state);
		luaopen_io (script->state);
		luaopen_os (script->state);
		luaopen_string (script->state);
		luaopen_bit32 (script->state);
		luaopen_math (script->state);
		luaopen_debug (script->state);
		luaopen_package (script->state);*/

		if ( script->source != NULL ){
			rval = luaL_dostring (script->state, script->source);

			if ( rval != 0 ){
				fprintf (stderr, "%s: %s\n", argv[0], lua_tostring (script->state, -1));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

		} else if ( script->file != NULL ){
			struct pathname path;

			path_split (script->file, &path);

			rval = chdir (path.dir);

			if ( rval == -1 ){
				fprintf (stderr, "%s: cannot change working directory to '%s': %s\n", argv[0], path.dir, strerror (errno));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			rval = luaL_dofile (script->state, path.base);

			if ( rval != 0 ){
				fprintf (stderr, "%s: %s\n", argv[0], lua_tostring (script->state, -1));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			path_free (&path);

			rval = chdir (cwd);

			if ( rval == -1 ){
				fprintf (stderr, "%s: cannot change working directory to '%s': %s\n", argv[0], cwd, strerror (errno));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

		} else {
			// This case should not happen
			script = script->next;
			continue;
		}

		if ( capdiss_get_table_item (script->state, "begin", LUA_TFUNCTION) == 0 ){
			rval = lua_pcall (script->state, 0, 0, 0);

			if ( rval != LUA_OK ){
				fprintf (stderr, "%s: cannot execute 'begin' method: %s\n", argv[0], lua_tostring (script->state, -1));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}
		}

		script = script->next;
	}

	// Setup signal handlers
	signal (SIGINT, terminate);
	signal (SIGTERM, terminate);
	signal (SIGQUIT, terminate);

	loop = 1;

	while ( loop ){
		rval = pcap_next_ex (pcap_res, &pkt_hdr, &pkt_data);

		if ( rval == -1 ){
			fprintf (stderr, "%s: reading a packet from file '%s' failed: %s\n", argv[0], argv[1], pcap_geterr (pcap_res));
			exitno = EXIT_FAILURE;
			goto cleanup;
		} else if ( rval == -2 ){
			// EOF
			break;
		}

		script = script_env.head;

		while ( script != NULL ){

			if ( capdiss_get_table_item (script->state, "each", LUA_TFUNCTION) == 0 ){

				if ( ! lua_checkstack (script->state, 2) ){
					fprintf (stderr, "%s: oops, something went wrong, Lua stack is full!\n", argv[0]);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}

				lua_pushnumber (script->state, pkt_hdr->ts.tv_sec);
				lua_pushlstring (script->state, (const char*) pkt_data, pkt_hdr->len);

				rval = lua_pcall (script->state, 2, 0, 0);

				if ( rval != LUA_OK ){
					fprintf (stderr, "%s: cannot execute 'each' method: %s\n", argv[0], lua_tostring (script->state, -1));
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
			}

			script = script->next;
		}
	}

	script = script_env.head;

	while ( script != NULL ){
		if ( capdiss_get_table_item (script->state, "finish", LUA_TFUNCTION) == 0 ){
			rval = lua_pcall (script->state, 0, 0, 0);

			if ( rval != LUA_OK ){
				fprintf (stderr, "%s: cannot execute 'finish' method: %s\n", argv[0], lua_tostring (script->state, -1));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}
		}

		script = script->next;
	}

cleanup:
	if ( pcap_res != NULL )
		pcap_close (pcap_res);

	scriptenv_free (&script_env);

	return exitno;
}

