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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <getopt.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <sys/stat.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>

#include "capdiss.h"
#include "pathname.h"
#include "lscript_list.h"
#include "flist.h"

static int loop;
static int exitno;
static jmp_buf signal_script;

static void
capdiss_usage (const char *p)
{
	fprintf (stderr, "Usage: %s <options> <script-name> [args ...]\n\n\
Options:\n\
 -f, --file=<pcap-file>    read network frames from a file\n\
 -F, --filter=<filter>     apply packet filter before reading from a file\n\
 -v, --version             show version information\n\
 -h, --help                show usage information\n", p);
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
	// Reset a signal handler to default and jump back to main function.  This
	// code breaks out from infinite loop (if there is one), yet still allows
	// to execute scripts' sigaction hook.
	signal (signo, SIG_DFL);
	longjmp (signal_script, 1);
}

int
main (int argc, char *argv[])
{
	pcap_t *pcap_res;
	const u_char *pkt_data;
	struct pcap_pkthdr *pkt_hdr;
	struct flist files;
	struct flist_path *file;
	struct stat ifstatus;
	char errbuff[PCAP_ERRBUF_SIZE];
	unsigned long int pkt_cnt;
	char **script_args;
	char *bpf, *stdout_type;
	const char *linktype;
	struct lscript *script;
	struct option opt_long[] = {
		{ "file", required_argument, 0, 'f' },
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
	script = NULL;
	exitno = EXIT_SUCCESS;

	flist_init (&files);

	// Setup signal handlers
	signal (SIGINT, capdiss_terminate);
	signal (SIGTERM, capdiss_terminate);

	while ( (c = getopt_long (argc, argv, "+f:F:hv", opt_long, &opt_index)) != -1 ){

		switch ( c ){
			case 'f':
				if ( flist_add (&files, optarg) == 1 ){
					fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
				break;

			case 'F':
				// Prevent a memory leak, if the option is specified multiple
				// times.
				if ( bpf != NULL )
					free (bpf);

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
		fprintf (stderr, "%s: no Lua script specified. Use '--help' to see usage information.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// Determine what type the stdout is. This may be helpful for scripts that
	// use ASCII color sequences to not use them if stdout is redirected to
	// another program via anonymous pipe, or to regular file.
	memset (&ifstatus, 0, sizeof (struct stat));

	errno = 0;
	if ( fstat (STDOUT_FILENO, &ifstatus) == -1 ){
		fprintf (stderr, "%s: stat failed 'stdout': %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	switch ( ifstatus.st_mode & S_IFMT ){
		case S_IFREG:
			stdout_type = "file";
			break;

		case S_IFCHR:
			stdout_type = "chrdev";
			break;

		case S_IFBLK:
			stdout_type = "blkdev";
			break;

#ifndef _WIN32
		case S_IFSOCK:
			stdout_type = "socket";
			break;
#endif

		case S_IFIFO:
			stdout_type = "fifo";
			break;

		default:
			stdout_type = "unknown";
			break;
	}

	//
	// Load Lua script
	//
	memset (&ifstatus, 0, sizeof (struct stat));

	errno = 0;
	if ( stat (argv[optind], &ifstatus) == -1 && errno != ENOENT ){
		fprintf (stderr, "%s: stat failed '%s': %s\n", argv[0], optarg, strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// If stat on a file failed, try to load it as a module using 'require'.
	if ( errno == ENOENT || !S_ISREG (ifstatus.st_mode) )
		script = lscript_new (argv[optind], LSCRIPT_MOD);
	else
		script = lscript_new (argv[optind], LSCRIPT_FILE);

	if ( script == NULL ){
		fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// Copy arguments that will be passed to Lua script.
	script_args = (char**) malloc (sizeof (char*) * (argc - optind + 1));

	if ( script_args == NULL ){
		fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	script_args[0] = argv[optind];

	for ( c = 1; c < (argc - optind); c++ )
		script_args[c] = argv[optind + c];

	// Prepare Lua environment.
	if ( lscript_prepare (script, argc - optind, script_args) != 0 ){
		free (script_args);
		fprintf (stderr, "%s: cannot prepare Lua environment: %s\n", argv[0], lscript_strerror (script));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	free (script_args);

	if ( lscript_set_glbstring (script, "_STDOUT_TYPE", stdout_type) == 1 ){
		fprintf (stderr, "%s: cannot prepare Lua environment: %s\n", argv[0], lscript_strerror (script));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// Do the long jump back here from a signal handler.
	if ( setjmp (signal_script) ){
		lscript_clear_stack (script);
		goto pass_signal;
	}

	if ( lscript_do_payload (script) != 0 ){
		fprintf (stderr, "%s: %s\n", argv[0], lscript_strerror (script));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	for ( file = files.head; file != NULL; file = file->next ){
#ifdef _WIN32
		pcap_res = pcap_open_offline (file->path, errbuff);
#else
		pcap_res = pcap_open_offline_with_tstamp_precision (file->path, PCAP_TSTAMP_PRECISION_MICRO, errbuff);
#endif

		if ( pcap_res == NULL ){

			// Are we reading from a standard input?
			if ( file->path[0] == '-' && file->path[1] == '\0' )
				fprintf (stderr, "%s: cannot interpret input data: %s\n", argv[0], errbuff);
			else
				fprintf (stderr, "%s: cannot open file: %s\n", argv[0], errbuff);

			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		// Reinitialize value of the packet counter for each file.
		pkt_cnt = 0;

		// Get pcap file data link value and convert it to string.
		// This string is passed to Lua function 'begin'.
		linktype = pcap_datalink_val_to_name (pcap_datalink (pcap_res));

		if ( bpf != NULL ){
			struct bpf_program bpf_prog;

			rval = pcap_compile (pcap_res, &bpf_prog, bpf, 1, 0);

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
		}

		if ( exitno == EXIT_SUCCESS && lscript_get_table_item (script, "begin", LUA_TFUNCTION) == 0 ){

			if ( ! lua_checkstack (script->state, 2) ){
				fprintf (stderr, "%s: internal error: Lua stack is full\n", argv[0]);
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			lua_pushstring (script->state, (const char*) file->path);
			lua_pushstring (script->state, linktype);

			rval = lua_pcall (script->state, 2, 0, 0);

			if ( rval != LUA_OK ){
				fprintf (stderr, "%s: %s\n", argv[0], lua_tostring (script->state, -1));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}
		}

		while ( loop ){
			rval = pcap_next_ex (pcap_res, &pkt_hdr, &pkt_data);

			if ( rval == -1 ){
				// Are we reading from a standard input?
				if ( file->path[0] == '-' && file->path[1] == '\0' )
					fprintf (stderr, "%s: reading a frame from input data failed: %s\n", argv[0], pcap_geterr (pcap_res));
				else
					fprintf (stderr, "%s: reading a frame from file '%s' failed: %s\n", argv[0], file->path, pcap_geterr (pcap_res));

				exitno = EXIT_FAILURE;
				goto cleanup;
			} else if ( rval == -2 ){
				// EOF
				break;
			}

			pkt_cnt++;

			if ( exitno == EXIT_SUCCESS && lscript_get_table_item (script, "each", LUA_TFUNCTION) == 0 ){

				if ( ! lua_checkstack (script->state, 3) ){
					fprintf (stderr, "%s: internal error: Lua stack is full\n", argv[0]);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}

				lua_pushlstring (script->state, (const char*) pkt_data, pkt_hdr->len);
				lua_pushnumber (script->state, pkt_hdr->ts.tv_sec + (pkt_hdr->ts.tv_usec / 1000000.0));
				lua_pushnumber (script->state, pkt_cnt);

				rval = lua_pcall (script->state, 3, 0, 0);

				if ( rval != LUA_OK ){
					fprintf (stderr, "%s: %s\n", argv[0], lua_tostring (script->state, -1));
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
			} else {
				// Function not found... no reason to continue reading other packets.
				loop = 0;
				break;
			}
		}

		if ( exitno == EXIT_SUCCESS && lscript_get_table_item (script, "finish", LUA_TFUNCTION) == 0 ){
			rval = lua_pcall (script->state, 0, 0, 0);

			if ( rval != LUA_OK ){
				fprintf (stderr, "%s: %s\n", argv[0], lua_tostring (script->state, -1));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}
		}

		// Close pcap resource, in case we have another file to process...
		pcap_close (pcap_res);
		pcap_res = NULL;
	}

pass_signal:
	if ( (exitno != EXIT_SUCCESS) && (exitno != EXIT_FAILURE) ){

		if ( lscript_get_table_item (script, "sigaction", LUA_TFUNCTION) == 0 ){

			if ( ! lua_checkstack (script->state, 1) ){
				fprintf (stderr, "%s: internal error: Lua stack is full\n", argv[0]);
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			lua_pushinteger (script->state, exitno);

			rval = lua_pcall (script->state, 1, 0, 0);

			if ( rval != LUA_OK ){
				fprintf (stderr, "%s: %s\n", argv[0], lua_tostring (script->state, -1));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}
		}
	}

cleanup:
	if ( bpf != NULL )
		free (bpf);

	if ( pcap_res != NULL )
		pcap_close (pcap_res);

	if ( script != NULL ){
		lscript_free (script);
		free (script);
	}

	flist_free (&files);

	return exitno;
}

