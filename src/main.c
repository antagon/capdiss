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
#include <sys/stat.h>
#include <unistd.h>

#include "capdiss.h"
#include "pathname.h"
#include "lscript_list.h"

static int loop;
static int exitno;

static void
capdiss_usage (const char *p)
{
	fprintf (stderr, "Usage: %s <options> <pcap-file> ...\n\n\
Options:\n\
 -r, --run <file>           run Lua script from file\n\
 -s, --run-source <code>    run Lua source code\n\
 -F, --filter <filter>      apply packet filter\n\
 -v, --version              show version information\n\
 -h, --help                 show usage information\n", p);
}

static void
capdiss_version (const char *p)
{
	fprintf (stderr, "%s %u.%u.%u\n%s\n%s\n", p, CAPDISS_VERSION_MAJOR, CAPDISS_VERSION_MINOR, CAPDISS_VERSION_PATCH, pcap_lib_version (), LUA_VERSION);
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
	struct stat ifstatus;
	struct pcap_pkthdr *pkt_hdr;
	const u_char *pkt_data;
	char errbuff[PCAP_ERRBUF_SIZE];
	unsigned long int pkt_cnt;
	char *bpf;
	const char *linktype;
	struct lscript_list script_list;
	struct lscript *script;
	struct option opt_long[] = {
		{ "run", required_argument, 0, 'r' },
		{ "run-source", required_argument, 0, 's' },
		{ "filter", required_argument, 0, 'F' },
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'v' },
		{ NULL, 0, 0, 0 }
	};
	int rval, c, opt_index;

	loop = 1;
	bpf = NULL;
	pcap_res = NULL;
	linktype = NULL;
	exitno = EXIT_SUCCESS;

	memset (&ifstatus, 0, sizeof (struct stat));

	lscript_list_init (&script_list);

	while ( (c = getopt_long (argc, argv, "r:s:F:hv", opt_long, &opt_index)) != -1 ){
		switch ( c ){
			case 'r':
			case 's':
				if ( c == 'r' ){
					errno = 0;
					rval = stat (optarg, &ifstatus);

					if ( rval == -1 && errno != ENOENT ){
						fprintf (stderr, "%s: cannot stat input file '%s': %s\n", argv[0], optarg, strerror (errno));
						exitno = EXIT_FAILURE;
						goto cleanup;
					}

					// If stat on a file failed, try to load it as a module using 'require'.
					if ( errno != 0 ){
						script = lscript_new (optarg, LSCRIPT_MOD);
					} else {
						script = lscript_new (optarg, LSCRIPT_FILE);
					}
				} else {
					script = lscript_new (optarg, LSCRIPT_SRC);
				}

				if ( script == NULL ){
					fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
					exitno = EXIT_FAILURE;
					goto cleanup;
				}

				lscript_list_add (&script_list, script);
				break;

			case 'F':
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

	// Setup signal handlers
	signal (SIGINT, capdiss_terminate);
	signal (SIGTERM, capdiss_terminate);
	signal (SIGQUIT, capdiss_terminate);

	//
	// Loop through available pcap files
	//
	for ( ; optind < argc; optind++ ){
		pkt_cnt = 0;
		pcap_res = pcap_open_offline_with_tstamp_precision (argv[optind], PCAP_TSTAMP_PRECISION_MICRO, errbuff);

		if ( pcap_res == NULL ){

			// Are we reading from a standard input?
			if ( argv[optind][0] == '-' && argv[optind][1] == '\0' )
				fprintf (stderr, "%s: cannot interpret input data: %s\n", argv[0], errbuff);
			else
				fprintf (stderr, "%s: cannot open file %s\n", argv[0], errbuff);

			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		// Get pcap file data link value and convert it to string.
		// This string is passed to Lua function 'begin'.
		linktype = pcap_datalink_val_to_name (pcap_datalink (pcap_res));

		if ( bpf != NULL ){
			struct bpf_program bpf_prog;

			rval = pcap_compile (pcap_res, &bpf_prog, bpf, 1, PCAP_NETMASK_UNKNOWN);

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
			bpf = NULL;
		}

		//
		// Load Lua scripts
		//
		for ( script = script_list.head; script != NULL; script = script->next ){

			if ( lscript_do_payload (script) != 0 ){
				fprintf (stderr, "%s: %s\n", argv[0], lscript_strerror (script));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			if ( (exitno == EXIT_SUCCESS) && (lscript_get_table_item (script, "begin", LUA_TFUNCTION) == 0) ){

				if ( ! lua_checkstack (script->state, 2) ){
					fprintf (stderr, "%s: oops, something went wrong, Lua stack is full!\n", argv[0]);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}

				lua_pushstring (script->state, (const char*) argv[optind]);
				lua_pushstring (script->state, linktype);

				rval = lua_pcall (script->state, 2, 0, 0);

				if ( rval != LUA_OK ){
					fprintf (stderr, "%s: %s\n", argv[0], lua_tostring (script->state, -1));
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
			}
		}

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

			pkt_cnt++;

			for ( script = script_list.head; script != NULL; script = script->next ){

				if ( ! script->ok )
					continue;

				if ( (exitno == EXIT_SUCCESS) && (lscript_get_table_item (script, "each", LUA_TFUNCTION) == 0) ){

					if ( ! lua_checkstack (script->state, 3) ){
						fprintf (stderr, "%s: oops, something went wrong, Lua stack is full!\n", argv[0]);
						exitno = EXIT_FAILURE;
						goto cleanup;
					}

					lua_pushlstring (script->state, (const char*) pkt_data, pkt_hdr->len);
					lua_pushnumber (script->state, pkt_hdr->ts.tv_sec + pkt_hdr->ts.tv_usec);
					lua_pushnumber (script->state, pkt_cnt);

					rval = lua_pcall (script->state, 3, 0, 0);

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
			if ( (exitno == EXIT_SUCCESS) && (lscript_get_table_item (script, "finish", LUA_TFUNCTION) == 0) ){
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
	if ( bpf != NULL )
		free (bpf);

	if ( pcap_res != NULL )
		pcap_close (pcap_res);

	lscript_list_free (&script_list);

	return exitno;
}

