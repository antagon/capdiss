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
#include "lscript_list.h"
#include "capdiss_lua.h"
#include "capdiss.h"

static int loop;
static int exitno;

static void
capdiss_usage (const char *p)
{
	fprintf (stderr, "Usage: %s <OPTIONS> <pcap-file> ...\n\n\
Options:\n\
 -e, --source='PROGTEXT'    load Lua script source code\n\
 -f, --file=PROGFILE        load Lua script file\n\
 -t, --filter='FILTERTEXT'  apply packet filter\n\
 -v, --version              show version information\n\
 -h, --help                 show usage information (this text)\n", p);
}

static void
capdiss_version (const char *p)
{
	fprintf (stderr, "%s %u.%u.%u, %s\n", p, CAPDISS_VERSION_MAJOR, CAPDISS_VERSION_MINOR, CAPDISS_VERSION_PATCH, LUA_VERSION);
}

static void
capdiss_terminate (int signo)
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
	struct lscript_list script_list;
	struct lscript *script;
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
	lscript_list_init (&script_list);

	// Setup signal handlers
	signal (SIGINT, capdiss_terminate);
	signal (SIGTERM, capdiss_terminate);
	signal (SIGQUIT, capdiss_terminate);

	while ( (c = getopt_long (argc, argv, "f:e:t:hv", opt_long, &opt_index)) != -1 ){
		switch ( c ){
			case 'f':
			case 'e':
				if ( c == 'f' )
					script = lscript_new (optarg, LSCRIPT_PATH);
				else
					script = lscript_new (optarg, LSCRIPT_SRC);

				if ( script == NULL ){
					fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
					exitno = EXIT_FAILURE;
					goto cleanup;
				}

				lscript_list_add (&script_list, script);
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
				capdiss_usage (argv[0]);
				exitno = EXIT_SUCCESS;
				goto cleanup;

			case 'v':
				capdiss_version (argv[0]);
				exitno = EXIT_SUCCESS;
				goto cleanup;

			default:
				exitno = EXIT_FAILURE;
				goto cleanup;
		}
	}

	if ( (argc - optind) == 0 ){
		fprintf (stderr, "%s: no pcap file specified. Use '--help' to see usage information.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	if ( script_list.head == NULL ){
		fprintf (stderr, "%s: no Lua script specified. Use '--help' to see usage information.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	if ( getcwd (cwd, sizeof (cwd)) == NULL ){
		fprintf (stderr, "%s: cannot obtain current working directory: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	//
	// Loop through available pcap files
	//
	for ( ; optind < argc; optind++ ){
		pcap_res = pcap_open_offline (argv[optind], errbuff);

		if ( pcap_res == NULL ){

			// Are we reading from a standard input?
			if ( argv[optind][0] == '-' )
				fprintf (stderr, "%s: cannot interpret input data: %s\n", argv[0], errbuff);
			else
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
				pcap_freecode (&bpf_prog);
				fprintf (stderr, "%s: cannot apply packet filter program: %s\n", argv[0], pcap_geterr (pcap_res));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			pcap_freecode (&bpf_prog);
			free (bpf);
		}

		//
		// Load Lua scripts
		//
		for ( script = script_list.head; script != NULL; script = script->next ){

			if ( script->type == LSCRIPT_SRC ){
				rval = luaL_dostring (script->state, script->payload);

				if ( rval != 0 ){
					fprintf (stderr, "%s: %s\n", argv[0], lua_tostring (script->state, -1));
					exitno = EXIT_FAILURE;
					goto cleanup;
				}

			} else if ( script->type == LSCRIPT_PATH ){
				struct pathname path;

				path_split (script->payload, &path);

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
				fprintf (stderr, "%s: undefined script type (0x%08x)!!!\n", argv[0], script->type);
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			if ( (exitno == EXIT_SUCCESS) && (capdiss_get_table_item (script->state, "begin", LUA_TFUNCTION) == 0) ){

				if ( ! lua_checkstack (script->state, 1) ){
					fprintf (stderr, "%s: oops, something went wrong, Lua stack is full!\n", argv[0]);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}

				lua_pushlstring (script->state, (const char*) argv[optind], strlen (argv[optind]));

				rval = lua_pcall (script->state, 1, 0, 0);

				if ( rval != LUA_OK ){
					fprintf (stderr, "%s: %s\n", argv[0], lua_tostring (script->state, -1));
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
			}
		}

		loop = 1;

		while ( loop ){
			rval = pcap_next_ex (pcap_res, &pkt_hdr, &pkt_data);

			if ( rval == -1 ){
				// Are we reading from a standard input?
				if ( argv[optind][0] == '-' )
					fprintf (stderr, "%s: reading a frame from input data failed: %s\n", argv[0], pcap_geterr (pcap_res));
				else
					fprintf (stderr, "%s: reading a frame from file '%s' failed: %s\n", argv[0], argv[optind], pcap_geterr (pcap_res));

				exitno = EXIT_FAILURE;
				goto cleanup;
			} else if ( rval == -2 ){
				// EOF
				break;
			}

			for ( script = script_list.head; script != NULL; script = script->next ){

				if ( ! script->ok )
					continue;

				if ( (exitno == EXIT_SUCCESS) && (capdiss_get_table_item (script->state, "each", LUA_TFUNCTION) == 0) ){

					if ( ! lua_checkstack (script->state, 2) ){
						fprintf (stderr, "%s: oops, something went wrong, Lua stack is full!\n", argv[0]);
						exitno = EXIT_FAILURE;
						goto cleanup;
					}

					lua_pushnumber (script->state, pkt_hdr->ts.tv_sec);
					lua_pushlstring (script->state, (const char*) pkt_data, pkt_hdr->len);

					rval = lua_pcall (script->state, 2, 0, 0);

					if ( rval != LUA_OK ){
						fprintf (stderr, "%s: %s\n", argv[0], lua_tostring (script->state, -1));
						exitno = EXIT_FAILURE;
						goto cleanup;
					}
				} else {
					// If the method 'each' was not found first time, there is no
					// reason to look for it again. The name of the field is
					// somewhat ambiguous, please change it in future...
					script->ok = 0;
				}
			}
		}

		for ( script = script_list.head; script != NULL; script = script->next ){
			if ( (exitno == EXIT_SUCCESS) && (capdiss_get_table_item (script->state, "finish", LUA_TFUNCTION) == 0) ){
				rval = lua_pcall (script->state, 0, 0, 0);

				if ( rval != LUA_OK ){
					fprintf (stderr, "%s: %s\n", argv[0], lua_tostring (script->state, -1));
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
			}
		}

		pcap_close (pcap_res);
		pcap_res = NULL;
	}

cleanup:
	if ( pcap_res != NULL )
		pcap_close (pcap_res);

	lscript_list_free (&script_list);

	return exitno;
}

