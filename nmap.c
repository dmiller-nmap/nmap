/***********************************************************************/
/* nmap.c -- Currently handles the bulk of Nmap's port scanning        */
/* features as well as the command line user interface.  At some point */
/* I hope to move the port scanning & related support functions to     */
/* another file.                                                       */
/*                                                                     */
/***********************************************************************/
/*  The Nmap Security Scanner is (C) 1995-2001 Insecure.Com LLC. This  */
/*  program is free software; you can redistribute it and/or modify    */
/*  it under the terms of the GNU General Public License as published  */
/*  by the Free Software Foundation; Version 2.  This guarantees your  */
/*  right to use, modify, and redistribute this software under certain */
/*  conditions.  If this license is unacceptable to you, we may be     */
/*  willing to sell alternative licenses (contact sales@insecure.com). */
/*                                                                     */
/*  If you received these files with a written license agreement       */
/*  stating terms other than the (GPL) terms above, then that          */
/*  alternative license agreement takes precendence over this comment. */
/*                                                                     */
/*  Source is provided to this software because we believe users have  */
/*  a right to know exactly what a program is going to do before they  */
/*  run it.  This also allows you to audit the software for security   */
/*  holes (none have been found so far).                               */
/*                                                                     */
/*  Source code also allows you to port Nmap to new platforms, fix     */
/*  bugs, and add new features.  You are highly encouraged to send     */
/*  your changes to fyodor@insecure.org for possible incorporation     */
/*  into the main distribution.  By sending these changes to Fyodor or */
/*  one the insecure.org development mailing lists, it is assumed that */
/*  you are offering Fyodor the unlimited, non-exclusive right to      */
/*  reuse, modify, and relicense the code.  This is important because  */
/*  the inability to relicense code has caused devastating problems    */
/*  for other Free Software projects (such as KDE and NASM).  Nmap     */
/*  will always be available Open Source.  If you wish to specify      */
/*  special license conditions of your contributions, just say so      */
/*  when you send them.                                                */
/*                                                                     */
/*  This program is distributed in the hope that it will be useful,    */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of     */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  */
/*  General Public License for more details (                          */
/*  http://www.gnu.org/copyleft/gpl.html ).                            */
/*                                                                     */
/***********************************************************************/

/* $Id$ */

#include "nmap.h"
#include "osscan.h"
#include "scan_engine.h"
#include "idle_scan.h"
#include "timing.h"

/* global options */
extern char *optarg;
extern int optind;
struct ops o;  /* option structure */
extern char **environ;

int main(int argc, char *argv[], char *envp[]) {
  /* The "real" main is nmap_main().  This function hijacks control at the
     beginning to do the following:
     1) Check if Nmap called under name listed in INTERACTIVE_NAMES or with
     interactive.
     2) Start interactive mode or just call nmap_main
  */
  char *interactive_names[] = INTERACTIVE_NAMES;
  int numinames = sizeof(interactive_names) / sizeof(char *);
  int nameidx;
  char *nmapcalledas;
  char command[2048];
  int myargc, fakeargc;
  char **myargv = NULL, **fakeargv = NULL;
  char *cptr;
  int ret;
  int i;
  char nmapargs[1024];
  char fakeargs[1024];
  char nmappath[MAXPATHLEN];
  char *pptr;
  char path[4096];
  struct stat st;
  char *endptr;
  int interactivemode = 0;
  int fd;
  struct timeval tv;

  /* You never know when "random" numbers will come in handy ... */
  gettimeofday(&tv, NULL);
  srand((tv.tv_sec ^ tv.tv_usec) ^ getpid());

  /* initialize our options */
  options_init();

  /* Trap these sigs for cleanup */
#if HAVE_SIGNAL
  signal(SIGINT, sigdie);
  signal(SIGTERM, sigdie);
  signal(SIGHUP, sigdie); 

  signal(SIGCHLD, reaper);
#endif

  /* First we figure out whether the name nmap is called as qualifies it 
     for interactive mode treatment */
  nmapcalledas = strrchr(argv[0], '/');
  if (!nmapcalledas) {
    nmapcalledas = argv[0];
  } else nmapcalledas++;

  if ((cptr = getenv("NMAP_ARGS"))) {
    snprintf(command, sizeof(command), "nmap %s", cptr);
    myargc = arg_parse(command, &myargv);
    if (myargc < 1) {
      fatal("NMAP_ARG variable could not be parsed");
    }
    options_init();
    ret = nmap_main(myargc, myargv);
    arg_parse_free(myargv);
    return ret;
  }

  for(nameidx = 0; nameidx < numinames; nameidx++) {
    if (strcasecmp(nmapcalledas, interactive_names[nameidx]) == 0) {
      printf("Entering Interactive Mode because argv[0] == %s\n", nmapcalledas);
      interactivemode = 1;
      break;
    }
  }

  if (interactivemode == 0 &&
      argc == 2 && strcmp("--interactive", argv[1]) == 0) {
    interactivemode = 1;
  }

  if (!interactivemode) {
    options_init();
    if (argc == 3 && strcmp("--resume", argv[1]) == 0) {
      /* OK, they want to resume an aborted scan given the log file specified.
	 Lets gather our state from the log file */
      if (gather_logfile_resumption_state(argv[2], &myargc, &myargv) == -1) {
	fatal("Cannot resume from (supposed) log file %s", argv[2]);
      }
      return nmap_main(myargc, myargv);
    }
    return nmap_main(argc, argv);
  }
  /*  printf("\nStarting nmap V. %s by fyodor@insecure.org ( www.insecure.org/nmap/ )\n", VERSION);*/
  printf("\nStarting %s V. %s ( %s )\n", NMAP_NAME, NMAP_VERSION, NMAP_URL);

  printf("Welcome to Interactive Mode -- press h <enter> for help\n");

  while(1) {
    printf("nmap> ");
    fflush(stdout);
    fgets(command, sizeof(command), stdin);
    myargc = arg_parse(command, &myargv);
    if (myargc < 1) {
      printf("Bogus command -- press h <enter> for help\n");
      continue;
    }
    if (strcasecmp(myargv[0], "h") == 0 ||
	strcasecmp(myargv[0], "help") == 0) {
      printinteractiveusage();
      continue;
    } else if (strcasecmp(myargv[0], "x") == 0 ||
	       strcasecmp(myargv[0], "q") == 0 ||
	       strcasecmp(myargv[0], "e") == 0 ||
	       strcasecmp(myargv[0], ".") == 0 ||
	       strcasecmp(myargv[0], "exit") == 0 ||
	       strcasecmp(myargv[0], "quit") == 0) {
      printf("Quitting by request.\n");
      exit(0);
    } else if (strcasecmp(myargv[0], "n") == 0 ||
	       strcasecmp(myargv[0], "nmap") == 0) {
      options_init();
      o.interactivemode = 1;
      nmap_main(myargc, myargv);
    } else if (*myargv[0] == '!') {
      cptr = strchr(command, '!');
      system(cptr + 1);
    } else if (*myargv[0] == 'd') {
      o.debugging++;
    } else if (strcasecmp(myargv[0], "f") == 0) {
      switch((ret = fork())) {
      case 0: /* Child */
	/* My job is as follows:
	   1) Go through arguments for the following 3 purposes:
	   A.  Build env variable nmap execution will read args from
	   B.  Find spoof and realpath variables
	   C.  If realpath var was not set, find an Nmap to use
	   2) Exec the sucka!@#$! 
	*/
	fakeargs[0] = nmappath[0] = '\0';
	strcpy(nmapargs, "NMAP_ARGS=");
	for(i=1; i < myargc; i++) {
	  if (strcasecmp(myargv[i], "--spoof") == 0) {
	    if (++i > myargc -1) {
	      fatal("Bad arguments to f!");
	    }	    
	    strncpy(fakeargs, myargv[i], sizeof(fakeargs));
	  } else if (strcasecmp(myargv[i], "--nmap_path") == 0) {
	    if (++i > myargc -1) {
	      fatal("Bad arguments to f!");
	    }	    
	    strncpy(nmappath, myargv[i], sizeof(nmappath));
	  } else {
	    if (strlen(nmapargs) + strlen(myargv[i]) + 1 < sizeof(nmapargs)) {
	      strcat(nmapargs, " ");
	      strcat(nmapargs, myargv[i]);
	    } else fatal("Arguments too long.");
	  }	 
	}
	/* First we stick our arguments into envp */
	if (o.debugging) {
	  error("Adding to environment: %s", nmapargs);
	}
	if (putenv(nmapargs) == -1) {
	  pfatal("Failed to add NMAP_ARGS to environment");
	}
	/* Now we figure out where the #@$#@ Nmap is located */
	if (!*nmappath) {
	  if (stat(argv[0], &st) != -1 && !S_ISDIR(st.st_mode)) {
	    strncpy(nmappath, argv[0], sizeof(nmappath));
	  } else {
	    nmappath[0] = '\0';
	    /* Doh!  We must find it in path */
	    if ((pptr = getenv("PATH"))) {
	      strncpy(path, pptr, sizeof(path));
	      pptr = path;
	      while(pptr && *pptr) {
		endptr = strchr(pptr, ':');
		if (endptr) { 
		  *endptr = '\0';
		}
		snprintf(nmappath, sizeof(nmappath), "%s/%s", pptr, nmapcalledas);
		if (stat(nmappath, &st) != -1)
		  break;
		nmappath[0] = '\0';
		if (endptr) pptr = endptr + 1;
		else pptr = NULL;
	      }
	    }
	  }
	}
	if (!*nmappath) {
	  fatal("Could not find Nmap -- you must add --nmap_path argument");
	}       

	/* We should be courteous and give Nmap reasonable signal defaults */
#if HAVE_SIGNAL
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGSEGV, SIG_DFL);
#endif

	/* Now I must handle spoofery */
	if (*fakeargs) {
	  fakeargc = arg_parse(fakeargs, &fakeargv);
	  if (fakeargc < 1) {
	    fatal("Bogus --spoof parameter");
	  }
	} else {
	  fakeargc = 1;
	  fakeargv = (char **) malloc(sizeof(char *) * 2);
	  fakeargv[0] = nmappath;
	  fakeargv[1] = NULL;
	}

	if (o.debugging) error("About to exec %s", nmappath);
	/* Kill stdout & stderr */
	if (!o.debugging) {
	  fd = open(DEVNULL, O_WRONLY);
	  if (fd != -1) {
	    dup2(fd, STDOUT_FILENO);
	    dup2(fd, STDERR_FILENO);
	  }
	}

	/* OK, I think we are finally ready for the big exec() */
	ret = execve(nmappath, fakeargv, environ);
	if (ret == -1) {
	  pfatal("Could not exec %s", nmappath);
	}
	break;
      case -1:
	gh_perror("fork() failed");
	break;
      default: /* Parent */
	printf("[PID: %d]\n", ret);
	break;
      }
    } else {
      printf("Unknown command (%s) -- press h <enter> for help\n", myargv[0]);
      continue;
    }
    arg_parse_free(myargv);
  }
  return 0;

}


/* parse a URL stype ftp string of the form user:pass@server:portno */
static int parse_bounce_argument(struct ftpinfo *ftp, char *url) {
  char *p = url,*q, *s;

  if ((q = strrchr(url, '@'))) /*we have username and/or pass */ {
    *(q++) = '\0';
    if ((s = strchr(q, ':')))
      { /* has portno */
	*(s++) = '\0';
	strncpy(ftp->server_name, q, MAXHOSTNAMELEN);
	ftp->port = atoi(s);
      }
    else  strncpy(ftp->server_name, q, MAXHOSTNAMELEN);

    if ((s = strchr(p, ':'))) { /* User AND pass given */
      *(s++) = '\0';
      strncpy(ftp->user, p, 63);
      strncpy(ftp->pass, s, 255);
    }
    else { /* Username ONLY given */
      log_write(LOG_STDOUT, "Assuming %s is a username, and using the default password: %s\n",
	      p, ftp->pass);
      strncpy(ftp->user, p, 63);
    }
  }
  else /* no username or password given */ 
    if ((s = strchr(url, ':'))) { /* portno is given */
      *(s++) = '\0';
      strncpy(ftp->server_name, url, MAXHOSTNAMELEN);
      ftp->port = atoi(s);
    }
    else  /* default case, no username, password, or portnumber */
      strncpy(ftp->server_name, url, MAXHOSTNAMELEN);

  ftp->user[63] = ftp->pass[255] = ftp->server_name[MAXHOSTNAMELEN] = 0;

  return 1;
}

int nmap_main(int argc, char *argv[]) {
  char *p, *q;
  int i, arg;
  size_t j, argvlen;
  FILE *inputfd = NULL;
  char *host_spec;
  short fastscan=0, randomize=1, resolve_all=0;
  short quashargv = 0;
  int numhosts_scanned = 0;
  char **host_exp_group;
  char *idleProxy = NULL; /* The idle host used to "Proxy" an Idlescan */
  int num_host_exp_groups = 0;
  char *machinefilename = NULL, *kiddiefilename = NULL, 
       *normalfilename = NULL, *xmlfilename = NULL;
  struct hostgroup_state hstate;
  int numhosts_up = 0;
  int starttime;
  struct scan_lists *ports = NULL;
  char myname[MAXHOSTNAMELEN + 1];
#if (defined(IN_ADDR_DEEPSTRUCT) || defined( SOLARIS))
  /* Note that struct in_addr in solaris is 3 levels deep just to store an
   * unsigned int! */
  struct ftpinfo ftp = { FTPUSER, FTPPASS, "",  { { { 0 } } } , 21, 0};
#else
  struct ftpinfo ftp = { FTPUSER, FTPPASS, "", { 0 }, 21, 0};
#endif
  struct hostent *target = NULL;
  char **fakeargv;
  struct hoststruct *currenths;
  char emptystring[1];
  int sourceaddrwarning = 0; /* Have we warned them yet about unguessable
				source addresses? */
  time_t timep;
  char mytime[128];
  int option_index;
  struct option long_options[] =
  {
    {"version", no_argument, 0, 'V'},
    {"verbose", no_argument, 0, 'v'},
    {"debug", optional_argument, 0, 'd'},
    {"help", no_argument, 0, 'h'},
    {"max_parallelism", required_argument, 0, 'M'},
    {"timing", required_argument, 0, 'T'},
    {"max_rtt_timeout", required_argument, 0, 0},
    {"min_rtt_timeout", required_argument, 0, 0},
    {"host_timeout", required_argument, 0, 0},
    {"scan_delay", required_argument, 0, 0},
    {"initial_rtt_timeout", required_argument, 0, 0},
    {"oA", required_argument, 0, 0},  
    {"oN", required_argument, 0, 0},
    {"oM", required_argument, 0, 0},  
    {"oG", required_argument, 0, 0},  
    {"oS", required_argument, 0, 0},
    {"oH", required_argument, 0, 0},  
    {"oX", required_argument, 0, 0},  
    {"iL", required_argument, 0, 0},  
    {"iR", no_argument, 0, 0},
    {"sI", required_argument, 0, 0},  
    {"initial_rtt_timeout", required_argument, 0, 0},
    {"randomize_hosts", no_argument, 0, 0},
    {"osscan_limit", no_argument, 0, 0}, /* skip OSScan if no open ports */
    {"osscan_guess", no_argument, 0, 0}, /* More guessing flexability */
    {"data_length", required_argument, 0, 0},
    {"rH", no_argument, 0, 0},
    {"vv", no_argument, 0, 0},
    {"append_output", no_argument, 0, 0},
    {"noninteractive", no_argument, 0, 0},
#ifdef WIN32
    {"win_list_interfaces", no_argument, 0, 0},
    {"win_norawsock", no_argument, 0, 0}, 
    {"win_forcerawsock", no_argument, 0, 0}, 
    {"win_nopcap", no_argument, 0, 0}, 
    {"win_nt4route", no_argument, 0, 0}, 
    {"win_noiphlpapi", no_argument, 0, 0}, 
    {"win_help", no_argument, 0, 0},
    {"win_trace", no_argument, 0, 0},
#endif
    {0, 0, 0, 0}
  };

#ifdef ROUTETHROUGHTEST
  /* Routethrough stuff -- kill later */
  {
    char *dev;
    struct in_addr dest;
    struct in_addr source;
    if (!resolve(argv[1], &dest))
      fatal("Failed to resolve %s\n", argv[1]);
    dev = routethrough(&dest, &source);
    if (dev)
      log_write(LOG_STDOUT, "%s routes through device %s using IP address %s\n", argv[1], dev, inet_ntoa(source));
    else log_write(LOG_STDOUT, "Could not determine which device to route through for %s!!!\n", argv[1]);

    exit(0);
  }
#endif

  /* argv faking silliness */
  fakeargv = (char **) safe_malloc(sizeof(char *) * (argc + 1));
  for(i=0; i < argc; i++) {
    fakeargv[i] = strdup(argv[i]);
  }
  fakeargv[argc] = NULL;

  emptystring[0] = '\0'; /* It wouldn't be an emptystring w/o this ;) */

  if (argc < 2 ) printusage(argv[0], -1);

  /* OK, lets parse these args! */
  optind = 1; /* so it can be called multiple times */
  while((arg = getopt_long_only(argc,fakeargv,"b:D:d::e:Ffg:hIi:M:m:NnOo:P:p:qRrS:s:T:Vv", long_options, &option_index)) != EOF) {
    switch(arg) {
    case 0:
      if (strcmp(long_options[option_index].name, "max_rtt_timeout") == 0) {
	o.max_rtt_timeout = atoi(optarg);
	if (o.max_rtt_timeout <= 5) {
	  fatal("max_rtt_timeout is given in milliseconds and must be at least 5");
	}       
        if (o.max_rtt_timeout < 20) {
	  error("WARNING: You specified a round-trip time timeout (%d ms) that is EXTRAORDINARILY SMALL.  Accuracy may suffer.", o.max_rtt_timeout);
	}
	if ( o.initial_rtt_timeout > o.max_rtt_timeout)
	  o.initial_rtt_timeout = o.max_rtt_timeout;
      } else if (strcmp(long_options[option_index].name, "min_rtt_timeout") == 0) {
	o.min_rtt_timeout = atoi(optarg);
	if (o.min_rtt_timeout > 50000) {
	  fatal("Warning:  o.min_rtt_timeout is given in milliseconds, your value seems pretty large.");
	}
      } else if (strcmp(long_options[option_index].name, "host_timeout") == 0) {
	o.host_timeout = strtoul(optarg, NULL, 10);
	if (o.host_timeout <= 200) {
	  fatal("host_timeout is given in milliseconds and must be greater than 200");
	}
#ifdef WIN32
      } else if (strcmp(long_options[option_index].name, "win_list_interfaces") == 0 ) { 
	wo.listinterfaces = 1; 
      } else if (strcmp(long_options[option_index].name, "win_norawsock") == 0 ) { 
	wo.norawsock = 1; 
      } else if (strcmp(long_options[option_index].name, "win_forcerawsock") == 0 ) { 
	wo.forcerawsock = 1; 
      } else if (strcmp(long_options[option_index].name, "win_nopcap") == 0 ) { 
	wo.nopcap = 1; 
      } else if (strcmp(long_options[option_index].name, "win_nt4route") == 0 ) { 
	wo.nt4route = 1; 
      } else if (strcmp(long_options[option_index].name, "win_noiphlpapi") == 0 ) { 
	wo.noiphlpapi = 1; 
      } else if (strcmp(long_options[option_index].name, "win_trace") == 0 ) { 
	wo.trace++; 
      } else if (strcmp(long_options[option_index].name, "win_help") == 0 ) { 
	printf("Windows-specific options:\n\n"); 
	printf(" --win_list_interfaces : list all network interfaces\n"); 
	printf(" --win_norawsock       : disable raw socket support\n"); 
	printf(" --win_forcerawsock    : try raw sockets even on non-W2K systems\n"); 
	printf(" --win_nopcap          : disable winpcap support\n"); 
	printf(" --win_nt4route        : test nt4 route code\n"); 
	printf(" --win_noiphlpapi      : test response to lack of iphlpapi.dll\n"); 
	printf(" --win_trace           : trace through raw IP initialization\n");
	exit(0);
#endif
      } else if (strcmp(long_options[option_index].name, "append_output") == 0) {
	o.append_output = 1;
      } else if (strcmp(long_options[option_index].name, "noninteractive") == 0) {
	/* Do nothing */
      } else if (strcmp(long_options[option_index].name, "scan_delay") == 0) {
	o.scan_delay = atoi(optarg);
	if (o.scan_delay <= 0) {
	  fatal("scan_delay must be greater than 0");
	}   
	o.max_parallelism = 1;
      } else if (strcmp(long_options[option_index].name, "randomize_hosts") == 0
		 || strcmp(long_options[option_index].name, "rH") == 0) {
	o.randomize_hosts = 1;
	o.host_group_sz = 2048;
      } else if (strcmp(long_options[option_index].name, "osscan_limit")  == 0) {
	o.osscan_limit = 1;
      } else if (strcmp(long_options[option_index].name, "osscan_guess")  == 0) {
	o.osscan_guess = 1;
      } else if (strcmp(long_options[option_index].name, "initial_rtt_timeout") == 0) {
	o.initial_rtt_timeout = atoi(optarg);
	if (o.initial_rtt_timeout <= 0) {
	  fatal("initial_rtt_timeout must be greater than 0");
	}
      } else if (strcmp(long_options[option_index].name, "data_length") == 0) {
	o.extra_payload_length = atoi(optarg);
	if (o.extra_payload_length < 0) {
	  fatal("data_length must be greater than 0");
	} else if (o.extra_payload_length > 0) {
	  o.extra_payload = (char *) safe_malloc(o.extra_payload_length);
	  get_random_bytes(o.extra_payload, o.extra_payload_length);
	}
      } else if (strcmp(long_options[option_index].name, "oN") == 0) {
	normalfilename = optarg;
      } else if (strcmp(long_options[option_index].name, "oG") == 0 ||
		 strcmp(long_options[option_index].name, "oM") == 0) {
	machinefilename = optarg;
      } else if (strcmp(long_options[option_index].name, "oS") == 0) {
	kiddiefilename = optarg;
      } else if (strcmp(long_options[option_index].name, "oH") == 0) {
	fatal("HTML output is not yet supported");
      } else if (strcmp(long_options[option_index].name, "oX") == 0) {
	xmlfilename = optarg;
      } else if (strcmp(long_options[option_index].name, "oA") == 0) {
	char buf[MAXPATHLEN];
	snprintf(buf, sizeof(buf), "%s.nmap", optarg);
	normalfilename = strdup(buf);
	snprintf(buf, sizeof(buf), "%s.gnmap", optarg);
	machinefilename = strdup(buf);
	snprintf(buf, sizeof(buf), "%s.xml", optarg);
	xmlfilename = strdup(buf);
      }
      else if (strcmp(long_options[option_index].name, "iL") == 0) {
	if (inputfd) {
	  fatal("Only one input filename allowed");
	}
	if (!strcmp(optarg, "-")) {
	  inputfd = stdin;
	  log_write(LOG_STDOUT, "Reading target specifications from stdin\n");
	} else {    
	  inputfd = fopen(optarg, "r");
	  if (!inputfd) {
	    fatal("Failed to open input file %s for reading", optarg);
	  }  
	  log_write(LOG_STDOUT, "Reading target specifications from FILE: %s\n", optarg);
	}
      } else if (strcmp(long_options[option_index].name, "iR") == 0) {
	o.generate_random_ips = 1;
      } else if (strcmp(long_options[option_index].name, "sI") == 0) {
	o.idlescan = 1;
	idleProxy = optarg;
      } else if (strcmp(long_options[option_index].name, "vv") == 0) {
	/* Compatability hack ... ugly */
	o.verbose += 2;
      } else {
	fatal("Unknown long option (%s) given@#!$#$", long_options[option_index].name);
      }
      break;
    case 'b': 
      o.bouncescan++;
      if (parse_bounce_argument(&ftp, optarg) < 0 ) {
	fprintf(stderr, "Your argument to -b is fucked up. Use the normal url style:  user:pass@server:port or just use server and use default anon login\n  Use -h for help\n");
      }
      break;
    case 'D':
      p = optarg;
      do {    
	q = strchr(p, ',');
	if (q) *q = '\0';
	if (!strcasecmp(p, "me")) {
	  if (o.decoyturn != -1) 
	    fatal("Can only use 'ME' as a decoy once.\n");
	  o.decoyturn = o.numdecoys++;
	} else {      
	  if (o.numdecoys >= MAX_DECOYS -1)
	    fatal("You are only allowed %d decoys (if you need more redefine MAX_DECOYS in nmap.h)");
	  if (resolve(p, &o.decoys[o.numdecoys])) {
	    o.numdecoys++;
	  } else {
	    fatal("Failed to resolve decoy host: %s (must be hostname or IP address", optarg);
	  }
	}
	if (q) {
	  *q = ',';
	  p = q+1;
	}
      } while(q);
      break;
    case 'd': 
      if (optarg)
	o.debugging = o.verbose = atoi(optarg);
      else {
	o.debugging++; o.verbose++;
      }
      break;
    case 'e': 
      strncpy(o.device, optarg,63); o.device[63] = '\0'; break;
    case 'F': fastscan++; break;
    case 'f': o.fragscan++; break;
    case 'g': 
      o.magic_port = atoi(optarg);
      o.magic_port_set = 1;
      if (!o.magic_port) fatal("-g needs nonzero argument");
      break;    
    case 'h': printusage(argv[0], 0); break;
    case '?': printusage(argv[0], -1); break;
    case 'I': o.identscan++; break;
    case 'i': 
      if (inputfd) {
	fatal("Only one input filename allowed");
      }
      if (!strcmp(optarg, "-")) {
	inputfd = stdin;
	log_write(LOG_STDOUT, "Reading target specifications from stdin\n");
      } else {    
	inputfd = fopen(optarg, "r");
	if (!inputfd) {
	  fatal("Failed to open input file %s for reading", optarg);
	}  
	log_write(LOG_STDOUT, "Reading target specifications from FILE: %s\n", optarg);
      }
      break;  
    case 'M': 
      o.max_parallelism = atoi(optarg); 
      if (o.max_parallelism < 1) fatal("Argument to -M must be at least 1!");
      if (o.max_parallelism > MAX_SOCKETS_ALLOWED) {
	fprintf(stderr, "Warning: You are limited to MAX_SOCKETS_ALLOWED (%d) parallel sockets.  If you really need more, change the #define and recompile.\n", MAX_SOCKETS_ALLOWED);
	o.max_parallelism = MAX_SOCKETS_ALLOWED;
      }
      break;
    case 'm': 
      machinefilename = optarg;
      break;
    case 'N': o.force++; break;
    case 'n': o.noresolve++; break;
    case 'O': 
      o.osscan++; 
      o.reference_FPs = parse_fingerprint_reference_file();
      break;
    case 'o':
      normalfilename = optarg;
      break;
    case 'P': 
      if (*optarg == '\0' || *optarg == 'I')
	o.pingtype |= PINGTYPE_ICMP;
      else if (*optarg == '0' || *optarg == 'N' || *optarg == 'D')      
	o.pingtype = PINGTYPE_NONE;
      else if (*optarg == 'S') {
	o.pingtype |= (PINGTYPE_TCP|PINGTYPE_TCP_USE_SYN);
	if (isdigit((int) *(optarg+1))) {      
	  o.tcp_probe_port = atoi(optarg+1);
	  log_write(LOG_STDOUT, "TCP probe port is %hu\n", o.tcp_probe_port);
	} else if (o.verbose)
	  log_write(LOG_STDOUT, "TCP probe port is %hu\n", o.tcp_probe_port);
      }
      else if (*optarg == 'T' || *optarg == 'A') {
	o.pingtype |= (PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK);
	if (isdigit((int) *(optarg+1))) {      
	  o.tcp_probe_port = atoi(optarg+1);
	  log_write(LOG_STDOUT, "TCP probe port is %hu\n", o.tcp_probe_port);
	} else if (o.verbose)
	  log_write(LOG_STDOUT, "TCP probe port is %hu\n", o.tcp_probe_port);
      }
      else if (*optarg == 'B') {
	o.pingtype = (PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK|PINGTYPE_ICMP);
	if (isdigit((int) *(optarg+1)))
	  o.tcp_probe_port = atoi(optarg+1);
	log_write(LOG_STDOUT, "TCP probe port is %hu\n", o.tcp_probe_port);
      }
      else {fatal("Illegal Argument to -P, use -P0, -PI, -PT, or -PT80 (or whatever number you want for the TCP probe destination port)"); }
      break;
    case 'p': 
      if (ports)
	fatal("Only 1 -p option allowed, separate multiple ranges with commas.");
      ports = getpts(optarg);
      if (!ports)
	fatal("Your port specification string is not parseable");
      break;
    case 'q': quashargv++; break;
    case 'R': resolve_all++; break;
    case 'r': 
      randomize = 0;
      break;
    case 'S': 
      if (o.spoofsource)
	fatal("You can only use the source option once!  Use -D <decoy1> -D <decoy2> etc. for decoys\n");
      o.source = (struct in_addr *) safe_malloc(sizeof(struct in_addr));
      o.spoofsource = 1;
      if (!resolve(optarg, o.source))
	fatal("Failed to resolve source address, try dotted decimal IP address\n");
      break;
    case 's': 
      if (!*optarg) {
	fprintf(stderr, "An option is required for -s, most common are -sT (tcp scan), -sS (SYN scan), -sF (FIN scan), -sU (UDP scan) and -sP (Ping scan)");
	printusage(argv[0], -1);
      }
      p = optarg;
      while(*p) {
	switch(*p) {
	case 'A': o.ackscan = 1; break;
	case 'B':  fatal("No scan type 'B', did you mean bounce scan (-b)?");
	  break;
	case 'F':  o.finscan = 1; break;
	case 'L':  o.listscan = 1; o.pingtype = PINGTYPE_NONE; break;
	case 'M':  o.maimonscan = 1; break;
	case 'N':  o.nullscan = 1; break;
	case 'O':  o.ipprotscan = 1; break;
	case 'P':  o.pingscan = 1; break;
	case 'R':  o.rpcscan = 1; break;
	case 'S':  o.synscan = 1; break;	  
	case 'W':  o.windowscan = 1; break;
	case 'T':  o.connectscan = 1; break;
	case 'U':  
	  o.udpscan++;
	  break;
	case 'X':  o.xmasscan++;break;
	default:  error("Scantype %c not supported\n",*p); printusage(argv[0], -1); break;
	}
	p++;
      }
      break;
    case 'T':
      if (*optarg == '0' || (strcasecmp(optarg, "Paranoid") == 0)) {
	o.max_parallelism = 1;
	o.scan_delay = 300000;
	o.initial_rtt_timeout = 300000;
      } else if (*optarg == '1' || (strcasecmp(optarg, "Sneaky") == 0)) {
	o.max_parallelism = 1;
	o.scan_delay = 15000;
	o.initial_rtt_timeout = 15000;
      } else if (*optarg == '2' || (strcasecmp(optarg, "Polite") == 0)) {
	o.max_parallelism = 1;
	o.scan_delay = 400;
      } else if (*optarg == '3' || (strcasecmp(optarg, "Normal") == 0)) {
      } else if (*optarg == '4' || (strcasecmp(optarg, "Aggressive") == 0)) {
	o.max_rtt_timeout = 1250;
	o.host_timeout = 300000;
	o.initial_rtt_timeout = 1000;
      } else if (*optarg == '5' || (strcasecmp(optarg, "Insane") == 0)) {
	o.max_rtt_timeout = 300;
	o.initial_rtt_timeout = 300;
	o.host_timeout = 75000;
      } else {
	fatal("Unknown timing mode (-T argment).  Use either \"Paranoid\", \"Sneaky\", \"Polite\", \"Normal\", \"Aggressive\", \"Insane\" or a number from 0 (Paranoid) to 5 (Insane)");
      }
      break;
    case 'V': 
      printf("\nnmap V. %s\n", NMAP_VERSION); 
      exit(0);
      break;
    case 'v': o.verbose++; break;
    }
  }

#ifdef WIN32
  winip_postopt_init();
#endif

#if HAVE_SIGNAL
  if (!o.debugging)
    signal(SIGSEGV, sigdie); 
#endif

  if (o.pingtype == PINGTYPE_UNKNOWN) {
    if (o.isr00t) o.pingtype = PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK|PINGTYPE_ICMP;
    else o.pingtype = PINGTYPE_TCP;
  }

  /* Open the log files, now that we know whether the user wants them appended
     or overwritten */
  if (normalfilename)
    log_open(LOG_NORMAL, o.append_output, normalfilename);
  if (machinefilename)
    log_open(LOG_MACHINE, o.append_output, machinefilename);
  if (kiddiefilename)
    log_open(LOG_SKID, o.append_output, kiddiefilename);
  if (xmlfilename)
    log_open(LOG_XML, o.append_output, xmlfilename);

  if (!o.interactivemode)
    log_write(LOG_STDOUT|LOG_SKID, "\nStarting %s V. %s ( %s )\n", NMAP_NAME, NMAP_VERSION, NMAP_URL);

  /* Now we check the option sanity */
  /* Insure that at least one scantype is selected */
  if (!o.connectscan && !o.udpscan && !o.synscan && !o.windowscan && !o.idlescan && !o.finscan && !o.maimonscan &&  !o.nullscan && !o.xmasscan && !o.ackscan && !o.bouncescan && !o.pingscan && !o.ipprotscan && !o.listscan) {
    o.connectscan++;
    if (o.verbose) error("No tcp,udp, or ICMP scantype specified, assuming vanilla tcp connect() scan. Use -sP if you really don't want to portscan (and just want to see what hosts are up).");
  }

  if (o.pingtype != PINGTYPE_NONE && o.spoofsource) {
    error("WARNING:  If -S is being used to fake your source address, you may also have to use -e <iface> and -P0 .  If you are using it to specify your real source address, you can ignore this warning.");
  }

  if (o.pingtype != PINGTYPE_NONE && o.idlescan) {
    error("WARNING: Many people use -P0 w/Idlescan to prevent pings from your true IP");
    sleep(1); /* Give ppl a chance for ^C :) */
  }

  if (o.numdecoys > 1 && o.idlescan) {
    error("WARNING: Your decoys won't be used in the Idlescan portion of your scanning (although all packets sent to the target are spoofed anyway");
  }

  if (o.connectscan && o.spoofsource) {
    error("WARNING:  -S will not affect the source address used in a connect() scan.  Use -sS or another raw scan if you want to use the specified source address for the port scanning stage of nmap");
  }


  if (o.ipprotscan && (o.connectscan | o.windowscan | o.synscan | o.finscan | o.maimonscan | o.xmasscan | o.nullscan | o.ackscan | o.udpscan | o.idlescan )) {
  /* It's no longer the case that the reason this doesn't work is due to port
   * list conflicts. Port ranges and protocol ranges could be specified on
   * the command line. Right now though, the main issue is with conflicting
   * port vs protocol scan output (in particular, -oG output format would have
   * to be updated). 
   *
   * if (!ports)
   *   fatal("Sorry, IP protocol scan can only be used with other scan types if port ranges and protocol ranges are specified on command line with -p\n");
   */
     fatal("Sorry, IP protocol scan can not be used with other scan types for now");
   }

  if (fastscan && ports) {
    fatal("You can specify fast scan (-F) or explicitly select individual ports (-p), but not both");
  } else if (fastscan && o.ipprotscan) {
    ports = getfastprots();
  } else if (fastscan) {
    ports = getfastports(o.windowscan|o.synscan|o.connectscan|o.fragscan|o.idlescan|o.finscan|o.maimonscan|o.bouncescan|o.nullscan|o.xmasscan|o.ackscan,o.udpscan);
  }


  if ((o.pingscan || o.listscan) && ports) {
    fatal("You cannot use -F (fast scan) or -p (explicit port selection) with PING scan or LIST scan");
  }

  if ((o.pingscan || o.listscan) && fastscan) {
    fatal("The fast scan (-F) is incompatible with ping scan");
  }

  if ((o.pingscan && o.pingtype == PINGTYPE_NONE)) {
    fatal("-P0 (skip ping) is incompatable with -sP (ping scan).  If you only want to enumerate hosts, try list scan (-sL)");
  }

  if (!ports) {
    if (o.ipprotscan) {
      ports = getdefaultprots();
    } else {
      ports = getdefaultports(o.windowscan|o.synscan|o.connectscan|o.fragscan|o.idlescan|o.finscan|
			      o.maimonscan|o.bouncescan|o.nullscan|o.xmasscan|o.ackscan,
			      o.udpscan);
    }
  }

  /* By now, we've got our port lists.  Give the user a warning if no 
   * ports are specified for the type of scan being requested.  Other things
   * (such as OS ident scan) might break cause no ports were specified,  but
   * we've given our warning...
   */
  if ((o.windowscan|o.synscan|o.connectscan|o.fragscan|o.finscan|o.maimonscan|o.bouncescan|o.nullscan|o.xmasscan|o.ackscan|o.idlescan) && ! ports->tcp_count)
    error("WARNING: a TCP scan type was requested, but no tcp ports were specified.  Skipping this scan type.");
  if (o.udpscan && ! ports->udp_count)
    error("WARNING: UDP scan was requested, but no udp ports were specified.  Skipping this scan type.");
  if (o.ipprotscan && ! ports->prot_count)
    error("WARNING: protocol scan was requested, but no protocols were specified to be scanned.  Skipping this scan type.");

  /* Default dest port for tcp probe */
  if (!o.tcp_probe_port) o.tcp_probe_port = DEFAULT_TCP_PROBE_PORT;


  if (o.pingscan && (o.connectscan || o.udpscan || o.windowscan || o.synscan || o.idlescan || o.finscan || o.maimonscan ||  o.nullscan || o.xmasscan || o.ackscan || o.bouncescan || o.ipprotscan || o.listscan)) {
    fatal("Ping scan is not valid with any other scan types (the other ones all include a ping scan");
  }

  if (o.listscan && (o.connectscan || o.udpscan || o.windowscan || o.synscan || o.idlescan || o.finscan || o.maimonscan ||  o.nullscan || o.xmasscan || o.ackscan || o.bouncescan || o.pingscan)) {
    fatal("List scan is not valid with any other scan types (it just lists the hosts that WOULD be scanned)");
  }


  /* We start with stuff users should not do if they are not root */
  if (!o.isr00t) {

#ifndef WIN32	/*	Win32 has perfectly fine ICMP socket support */
    if (o.pingtype & PINGTYPE_ICMP) {
      error("Warning:  You are not root -- using TCP pingscan rather than ICMP");
      o.pingtype = PINGTYPE_TCP;
    }
#endif

    if (o.idlescan || o.finscan || o.windowscan || o.synscan || o.maimonscan || o.nullscan || o.xmasscan || o.ackscan
	|| o.udpscan || o.ipprotscan) {
#ifndef WIN32
      fatal("You requested a scan type which requires r00t privileges, and you do not have them.\n");
#else
      winip_barf(0);
#endif
    }
  
    if (o.numdecoys > 0) {
#ifndef WIN32
      fatal("Sorry, but you've got to be r00t to use decoys, boy!");
#else
      winip_barf(0);
#endif
    }
  
    if (o.fragscan) {
#ifndef WIN32
      fatal("Sorry, but fragscan requires r00t privileges\n");
#else
      winip_barf(0);
#endif
    }

    if (o.osscan) {
#ifndef WIN32
      fatal("TCP/IP fingerprinting (for OS scan) requires root privileges which you do not appear to possess.  Sorry, dude.\n");
#else
      winip_barf(0);
#endif
    }
  }

  if (o.numdecoys > 0 && o.rpcscan) {
    error("WARNING:  RPC scan currently does not make use of decoys so don't count on that protection");
  }

  if (o.bouncescan && o.pingtype != PINGTYPE_NONE) 
    log_write(LOG_STDOUT, "Hint: if your bounce scan target hosts aren't reachable from here, remember to use -P0 so we don't try and ping them prior to the scan\n");

  if (o.connectscan + o.windowscan + o.synscan + o.finscan + o.idlescan + o.maimonscan + o.xmasscan + o.nullscan + o.ackscan  > 1) {
    fatal("You specified more than one type of TCP scan.  Please choose only one of -sT, -sS, -sF, -sM, -sX, -sA, -sW, and -sN");
  }

  if (o.numdecoys > 0 && (o.bouncescan || o.connectscan)) {
    fatal("Decoys are irrelevant to the bounce or connect scans");
  }

  if (o.fragscan && (o.connectscan || 
		     ((o.udpscan || o.ipprotscan) &&
		      (o.windowscan + o.synscan + o.finscan + o.maimonscan + 
		       o.xmasscan + o.ackscan + o.nullscan == 0))))
    fatal("Fragmentation scan can only be used with SYN, FIN, Maimon, XMAS, ACK, or NULL scan types");
 
  if (o.identscan && !o.connectscan) {
    error("Identscan only works with connect scan (-sT) ... ignoring option");
    o.identscan = 0;
  }

  if (o.osscan && o.bouncescan)
    error("Combining bounce scan with OS scan seems silly, but I will let you do whatever you want!");

#if !defined(LINUX) && !defined(OPENBSD) && !defined(FREEBSD) && !defined(NETBSD)
  if (o.fragscan) {
    fprintf(stderr, "Warning: Packet fragmentation selected on a host other than Linux, OpenBSD, FreeBSD, or NetBSD.  This may or may not work.\n");
  }
#endif

  if (o.max_parallelism > MAX_SOCKETS_ALLOWED) {
    error("Warning: You are limited to MAX_SOCKETS_ALLOWED (%d) parallel sockets.  If you really need more, change the #define and recompile.\n", MAX_SOCKETS_ALLOWED);
    o.max_parallelism = MAX_SOCKETS_ALLOWED;
  }

  if (o.osscan && o.pingscan) {
    fatal("WARNING:  OS Scan is unreliable with a ping scan.  You need to use a scan type along with it, such as -sS, -sT, -sF, etc instead of -sP");
  }

  if (o.magic_port_set && o.connectscan) {
    error("WARNING:  -g is incompatible with the default connect() scan (-sT).  Use a raw scan such as -sS if you want to set the source port.");
  }

  /* Set up our array of decoys! */
  if (o.decoyturn == -1) {
    o.decoyturn = (o.numdecoys == 0)?  0 : get_random_uint() % o.numdecoys; 
    o.numdecoys++;
    for(i=o.numdecoys-1; i > o.decoyturn; i--)
      o.decoys[i] = o.decoys[i-1];
  }

  /* We need to find what interface to route through if:
   * --None have been specified AND
   * --We are root and doing tcp ping OR
   * --We are doing a raw sock scan and NOT pinging anyone */
  if (o.source && !*o.device) {
    if (ipaddr2devname(o.device, o.source) != 0) {
      fatal("Could not figure out what device to send the packet out on with the source address you gave me!  If you are trying to sp00f your scan, this is normal, just give the -e eth0 or -e ppp0 or whatever.  Otherwise you can still use -e, but I find it kindof fishy.");
    }
  }

  if (*o.device && !o.source) {
    o.source = (struct in_addr *) safe_malloc(sizeof(struct in_addr)); 
    if (devname2ipaddr(o.device, o.source) == -1) {
      fatal("I cannot figure out what source address to use for device %s, does it even exist?", o.device);
    }
  }


  /* If he wants to bounce off of an ftp site, that site better damn well be reachable! */
  if (o.bouncescan) {
    if (!inet_aton(ftp.server_name, &ftp.server)) {
      if ((target = gethostbyname(ftp.server_name)))
	memcpy(&ftp.server, target->h_addr_list[0], 4);
      else {
	fprintf(stderr, "Failed to resolve ftp bounce proxy hostname/IP: %s\n",
		ftp.server_name);
	exit(1);
      } 
    }  else if (o.verbose)
      log_write(LOG_STDOUT, "Resolved ftp bounce attack proxy to %s (%s).\n", 
		ftp.server_name, inet_ntoa(ftp.server)); 
  }
  fflush(stdout);

  timep = time(NULL);
  
  /* Brief info incase they forget what was scanned */
  Strncpy(mytime, ctime(&timep), sizeof(mytime));
  chomp(mytime);
  log_write(LOG_XML, "<?xml version=\"1.0\" ?>\n<!-- ");
  log_write(LOG_NORMAL|LOG_MACHINE, "# ");
  log_write(LOG_NORMAL|LOG_MACHINE|LOG_XML, "%s (V. %s) scan initiated %s as: ", NMAP_NAME, NMAP_VERSION, mytime);
  

  for(i=0; i < argc; i++) {
    char *p = xml_convert(fakeargv[i]);
    log_write(LOG_XML,"%s ", p);
    free(p);
    log_write(LOG_NORMAL|LOG_MACHINE,"%s ", fakeargv[i]);
  }
  log_write(LOG_XML, "-->");
  log_write(LOG_NORMAL|LOG_MACHINE|LOG_XML,"\n");  

  log_write(LOG_XML, "<nmaprun scanner=\"nmap\" args=\"");
  for(i=0; i < argc; i++) 
    log_write(LOG_XML, (i == argc-1)? "%s\" " : "%s ", fakeargv[i]);

  log_write(LOG_XML, "start=\"%d\" version=\"%s\" xmloutputversion=\"1.0\">\n",
	    timep, NMAP_VERSION);

  output_xml_scaninfo_records(ports);

  log_write(LOG_XML, "<verbose level=\"%d\" />\n<debugging level=\"%d\" />\n",
	    o.verbose, o.debugging);

  /* Before we randomize the ports scanned, lets output them to machine 
     parseable output */
  if (o.verbose)
     output_ports_to_machine_parseable_output(ports, o.windowscan|o.synscan|o.connectscan|o.fragscan|o.finscan|o.maimonscan|o.bouncescan|o.nullscan|o.xmasscan|o.ackscan|o.idlescan,o.udpscan,o.ipprotscan);

  /* more fakeargv junk, BTW malloc'ing extra space in argv[0] doesn't work */
  if (quashargv) {
    argvlen = strlen(argv[0]);
    if (argvlen < strlen(FAKE_ARGV))
      fatal("If you want me to fake your argv, you need to call the program with a longer name.  Try the full pathname, or rename it fyodorssuperdedouperportscanner");
    strncpy(argv[0], FAKE_ARGV, strlen(FAKE_ARGV));
    for(j = strlen(FAKE_ARGV); j < argvlen; j++) argv[0][j] = '\0';
    for(i=1; i < argc; i++) {
      argvlen = strlen(argv[i]);
      for(j=0; j <= argvlen; j++)
	argv[i][j] = '\0';
    }
  }

#if HAVE_SIGNAL
  signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE so our program doesn't crash because
			       of it, but we really shouldn't get an unsuspected
			       SIGPIPE */
#endif

  if (o.max_parallelism && (i = max_sd()) && i < o.max_parallelism) {
    fprintf(stderr, "WARNING:  Your specified max_parallel_sockets of %d, but your system says it might only give us %d.  Trying anyway\n", o.max_parallelism, i);
  }

  if (o.debugging > 1) log_write(LOG_STDOUT, "The max # of sockets we are using is: %d\n", o.max_parallelism);


  if  (randomize) {
    if (ports->tcp_count) 
	    shortfry(ports->tcp_ports, ports->tcp_count); 
    if (ports->udp_count) 
	    shortfry(ports->udp_ports, ports->udp_count); 
    if (ports->prot_count) 
	    shortfry(ports->prots, ports->prot_count); 
  }

  starttime = time(NULL);

  /* Time to create a hostgroup state object filled with all the requested
     machines */
  host_exp_group = (char **) safe_malloc(o.host_group_sz * sizeof(char *));

  while(1) {
    while(num_host_exp_groups < o.host_group_sz &&
	  (host_spec = grab_next_host_spec(inputfd, argc, fakeargv))) {
      host_exp_group[num_host_exp_groups++] = strdup(host_spec);
    }
    if (num_host_exp_groups == 0)
      break;

    hostgroup_state_init(&hstate, o.host_group_sz, o.randomize_hosts, 
			 host_exp_group, num_host_exp_groups);
  
    while((currenths = nexthost(&hstate, ports))) {
      numhosts_scanned++;
      if (currenths->flags & HOST_UP && !o.listscan) 
	numhosts_up++;
      
      /* Set timeout info */
      currenths->timedout = 0;
      if (o.host_timeout) {
	gettimeofday(&currenths->host_timeout, NULL);
	
	/* Must go through all this to avoid int overflow */
	currenths->host_timeout.tv_sec += o.host_timeout / 1000;
	currenths->host_timeout.tv_usec += (o.host_timeout % 1000) * 1000;
	currenths->host_timeout.tv_sec += currenths->host_timeout.tv_usec / 1000000;
	currenths->host_timeout.tv_usec %= 1000000;
      }
      
      /*    printf("Nexthost() returned: %s\n", inet_ntoa(currenths->host));*/
      target = NULL;
      if (((currenths->flags & HOST_UP) || resolve_all) && !o.noresolve)
	target = gethostbyaddr((char *) &currenths->host, 4, AF_INET);
      if (target && *target->h_name) {
	currenths->name = strdup(target->h_name);
      }
      else {
	currenths->name = emptystring;
      }
      
      if (o.source) memcpy(&currenths->source_ip, o.source, sizeof(struct in_addr));
      log_write(LOG_XML, "<host>");
      write_host_status(currenths, resolve_all);
      
      /* The !currenths->wierd_responses was commented out after I found
	 a smurf address which DID allow port scanninng and you could even
	 telnetthere.  wierd :0 
	 IGNORE THAT COMMENT!  The check is back again ... for now 
	 NOPE -- gone again */
      
      if (currenths->flags & HOST_UP /*&& !currenths->wierd_responses*/ &&
	  !o.pingscan && !o.listscan) {
	
	if (currenths->flags & HOST_UP && !currenths->source_ip.s_addr && ( o.windowscan || o.synscan || o.idlescan || o.finscan || o.maimonscan || o.udpscan || o.nullscan || o.xmasscan || o.ackscan || o.ipprotscan )) {
	  if (gethostname(myname, MAXHOSTNAMELEN) || 
	      !(target = gethostbyname(myname)))
	    fatal("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n"); 
	  memcpy(&currenths->source_ip, target->h_addr_list[0], sizeof(struct in_addr));
	  if (! sourceaddrwarning) {
	    fprintf(stderr, "WARNING:  We could not determine for sure which interface to use, so we are guessing %s .  If this is wrong, use -S <my_IP_address>.\n", inet_ntoa(currenths->source_ip));
	    sourceaddrwarning = 1;
	  }
	}
	
	/* Figure out what link-layer device (interface) to use (ie eth0, ppp0, etc) */
	if (!*currenths->device && currenths->flags & HOST_UP && (o.nullscan || o.xmasscan || o.ackscan || o.udpscan || o.idlescan || o.finscan || o.maimonscan ||  o.synscan || o.osscan || o.windowscan || o.ipprotscan) && (ipaddr2devname( currenths->device, &currenths->source_ip) != 0))
	  fatal("Could not figure out what device to send the packet out on!  You might possibly want to try -S (but this is probably a bigger problem).  If you are trying to sp00f the source of a SYN/FIN scan with -S <fakeip>, then you must use -e eth0 (or other devicename) to tell us what interface to use.\n");
	/* Set up the decoy */
	o.decoys[o.decoyturn] = currenths->source_ip;
	
	/* Time for some actual scanning! */    
	        /* Time for some actual scanning! */    
	if (o.synscan) pos_scan(currenths, ports->tcp_ports, ports->tcp_count, SYN_SCAN);
	if (o.windowscan) pos_scan(currenths, ports->tcp_ports, ports->tcp_count, WINDOW_SCAN);
	if (o.connectscan) pos_scan(currenths, ports->tcp_ports, ports->tcp_count, CONNECT_SCAN);
	if (o.ackscan) pos_scan(currenths, ports->tcp_ports, ports->tcp_count, ACK_SCAN); 
	if (o.finscan) super_scan(currenths, ports->tcp_ports, ports->tcp_count, FIN_SCAN);
	if (o.xmasscan) super_scan(currenths, ports->tcp_ports, ports->tcp_count, XMAS_SCAN);
	if (o.nullscan) super_scan(currenths, ports->tcp_ports, ports->tcp_count, NULL_SCAN);
	if (o.maimonscan) super_scan(currenths, ports->tcp_ports, 
				     ports->tcp_count, MAIMON_SCAN);
	if (o.udpscan) super_scan(currenths, ports->udp_ports, 
				  ports->udp_count, UDP_SCAN);
	if (o.ipprotscan) super_scan(currenths, ports->prots, 
				     ports->prot_count, IPPROT_SCAN);

	if (o.idlescan) idle_scan(currenths, ports->tcp_ports, 
				  ports->tcp_count, idleProxy);

	if (o.bouncescan) {
	  if (ftp.sd <= 0) ftp_anon_connect(&ftp);
	  if (ftp.sd > 0) bounce_scan(currenths, ports->tcp_ports, 
				      ports->tcp_count, &ftp);
	}
	
	/* This scantype must be after any TCP or UDP scans since it
	 * get's it's port scan list from the open port list of the current
	 * host rather than port list the user specified.
	 */
	if (o.rpcscan)  pos_scan(currenths, NULL, 0, RPC_SCAN);
	
	
	if (o.osscan) {
	  os_scan(currenths);
	}
	
	if (currenths->timedout) {
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Skipping host  %s (%s) due to host timeout\n", currenths->name,
		    inet_ntoa(currenths->host));
	  log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Timeout", 
		    inet_ntoa(currenths->host), currenths->name);
	} else {
	  assignignoredportstate(&currenths->ports);
	  printportoutput(currenths, &currenths->ports);
	  printosscanoutput(currenths);
 	}      

	if (o.debugging) log_write(LOG_STDOUT, "Final times for host: srtt: %d rttvar: %d  to: %d\n", currenths->to.srtt, currenths->to.rttvar, currenths->to.timeout);
	log_write(LOG_MACHINE,"\n");
      }
      log_write(LOG_XML, "</host>\n");
  
      log_flush_all();
      hoststruct_free(currenths);
    }

    hostgroup_state_destroy(&hstate);

    /* Free my host expressions */
    for(i=0; i < num_host_exp_groups; i++)
      free(host_exp_group[i]);
    num_host_exp_groups = 0;
  }

  free(host_exp_group);

  printfinaloutput(numhosts_scanned, numhosts_up, starttime);

  /* Free fake argv */
  for(i=0; i < argc; i++)
    free(fakeargv[i]);
  free(fakeargv);

  return 0;
}


/* Reads in a (normal or machine format) Nmap log file and gathers enough
   state to allow Nmap to continue where it left off.  The important things
   it must gather are:
   1) The last host completed
   2) The command arguments
*/
   
int gather_logfile_resumption_state(char *fname, int *myargc, char ***myargv) {
  char *filestr;
  int filelen;
  char nmap_arg_buffer[1024];
  struct in_addr lastip;
  char *p, *q, *found; /* I love C! */
  /* We mmap it read/write since we will change the last char to a newline if it is not already */
  filestr = mmapfile(fname, &filelen, O_RDWR);
  if (!filestr) {
    fatal("Could not mmap() %s read/write", fname);
  }

  if (filelen < 20) {
    fatal("Output file %s is too short -- no use resuming", fname);
  }

  /* For now we terminate it with a NUL, but we will terminate the file with
     a '\n' later */
  filestr[filelen - 1] = '\0';

  /* First goal is to find the nmap args */
  p = strstr(filestr, " as: ");
  p += 5;
  while(*p && !isspace((int) *p))
    p++;
  if (!*p) fatal("Unable to parse supposed log file %s.  Sorry", fname);
  p++; /* Skip the space between program name and first arg */
  if (*p == '\n' || !*p) fatal("Unable to parse supposed log file %s.  Sorry", fname);

  q = strchr(p, '\n');
  if (!q || ((unsigned int) (q - p) >= sizeof(nmap_arg_buffer) - 32))
    fatal("Unable to parse supposed log file %s.  Sorry", fname);

  strcpy(nmap_arg_buffer, "nmap --append_output ");
  memcpy(nmap_arg_buffer + 21, p, q-p);
  nmap_arg_buffer[21 + q-p] = '\0';

  *myargc = arg_parse(nmap_arg_buffer, myargv);
  if (*myargc == -1) {  
    fatal("Unable to parse supposed log file %s.  Sorry", fname);
  }
     
  /* Now it is time to figure out the last IP that was scanned */
  q = p;
  found = NULL;
  /* Lets see if its a machine log first */
  while((q = strstr(q, "\nHost: ")))
    found = q = q + 7;

  if (found) {
    q = strchr(found, ' ');
    if (!q) fatal("Unable to parse supposed log file %s.  Sorry", fname);
    *q = '\0';
    if (inet_aton(found, &lastip) == 0)
      fatal("Unable to parse supposed log file %s.  Sorry", fname);
    *q = ' ';
  } else {
    /* OK, I guess (hope) it is a normal log then */
    q = p;
    found = NULL;
    while((q = strstr(q, "\nInteresting ports on ")))
      found = q++;

    if (found) {    
      found = strchr(found, '(');
      if (!found) fatal("Unable to parse supposed log file %s.  Sorry", fname);
      found++;
      q = strchr(found, ')');
      if (!q) fatal("Unable to parse supposed log file %s.  Sorry", fname);
      *q = '\0';
      if (inet_aton(found, &lastip) == 0)
	fatal("Unable to parse ip (%s) supposed log file %s.  Sorry", found, fname);
      *q = ')';
    } else {
      error("Warning: You asked for --resume but it doesn't look like any hosts in the log file were successfully scanned.  Starting from the beginning.");
      lastip.s_addr = 0;
    }
  }
  o.resume_ip = lastip;

  /* Ensure the log file ends with a newline */
  filestr[filelen - 1] = '\n';
  munmap(filestr, filelen);
  return 0;
}

void options_init() {

  bzero( (char *) &o, sizeof(struct ops));
#ifndef WIN32
  o.isr00t = !(geteuid());
#else
  winip_init();	//	wrapper for all win32 initialization
#endif
  o.debugging = DEBUGGING;
  o.verbose = DEBUGGING;
  /*o.max_parallelism = MAX_SOCKETS;*/
  o.magic_port = 33000 + (get_random_uint() % 31000);
  o.pingtype = PINGTYPE_UNKNOWN;
  o.decoyturn = -1;
  o.nmap_stdout = stdout;
  o.host_group_sz = HOST_GROUP_SZ;
  o.min_rtt_timeout = MIN_RTT_TIMEOUT;
  o.max_rtt_timeout = MAX_RTT_TIMEOUT;
  o.initial_rtt_timeout = INITIAL_RTT_TIMEOUT;
  o.host_timeout = HOST_TIMEOUT;
  o.scan_delay = 0;
  o.extra_payload_length = 0;
  o.extra_payload = NULL;
}

/* We set the socket lingering so we will RST connection instead of wasting
   bandwidth with the four step close  */
void init_socket(int sd) {
  struct linger l;
  int res;
  static int bind_failed=0;
  struct sockaddr_in sin;

  l.l_onoff = 1;
  l.l_linger = 0;

  if (setsockopt(sd, SOL_SOCKET, SO_LINGER,  (const char *) &l, sizeof(struct linger)))
    {
      fprintf(stderr, "Problem setting socket SO_LINGER, errno: %d\n", errno);
      perror("setsockopt");
    }
  if (o.spoofsource && !bind_failed)
    {
      bzero(&sin,sizeof(sin));
      sin.sin_family=AF_INET;
      memcpy(&sin.sin_addr,o.source,sizeof(sin.sin_addr));
      res=bind(sd,(struct sockaddr*)&sin,sizeof(sin));
      if (res<0)
	{
	  fprintf(stderr, "init_socket: Problem binding source address (%s), errno :%d\n", inet_ntoa(sin.sin_addr), errno);
	  perror("bind");
	  bind_failed=1;
	}
    }
}

/* Convert a string like "-100,200-1024,3000-4000,60000-" into an array 
   of port numbers. Note that one trailing comma is OK -- this is actually
   useful for machine generated lists */
struct scan_lists *getpts(char *origexpr) {
  u8 porttbl[65536];
  int portwarning = 0; /* have we warned idiot about dup ports yet? */
  long rangestart = -2343242, rangeend = -9324423;
  char *current_range;
  char *endptr;
  int i;
  int tcpportcount = 0, udpportcount = 0, protcount = 0;
  struct scan_lists *ports;
  int range_type = SCAN_TCP_PORT|SCAN_UDP_PORT|SCAN_PROTOCOLS;

  bzero(porttbl, sizeof(porttbl));

  current_range = origexpr;
  do {
    while(isspace((int) *current_range))
      current_range++; /* I don't know why I should allow spaces here, but I will */
    if (*current_range == 'T' && *++current_range == ':') {
	current_range++;
	range_type = SCAN_TCP_PORT;
	continue;
    }
    if (*current_range == 'U' && *++current_range == ':') {
	current_range++;
	range_type = SCAN_UDP_PORT;
	continue;
    }
    if (*current_range == 'P' && *++current_range == ':') {
	current_range++;
	range_type = SCAN_PROTOCOLS;
	continue;
    }
    if (*current_range == '-') {
      rangestart = 1;
    }
    else if (isdigit((int) *current_range)) {
      rangestart = strtol(current_range, &endptr, 10);
      if (rangestart <= 0 || rangestart > 65535) {
	fatal("Ports to be scanned must be between 1 and 65535 inclusive");
      }
      current_range = endptr;
      while(isspace((int) *current_range)) current_range++;
    } else {
      fatal("Error #485: Your port specifications are illegal.  Example of proper form: \"-100,200-1024,T:3000-4000,U:60000-\"");
    }
    /* Now I have a rangestart, time to go after rangeend */
    if (!*current_range || *current_range == ',') {
      /* Single port specification */
      rangeend = rangestart;
    } else if (*current_range == '-') {
      current_range++;
      if (!*current_range || *current_range == ',') {
	/* Ended with a -, meaning up until the last possible port */
	rangeend = 65535;
      } else if (isdigit((int) *current_range)) {
	rangeend = strtol(current_range, &endptr, 10);
	if (rangeend <= 0 || rangeend > 65535) {
	  fatal("Ports to be scanned must be between 1 and 65535 inclusive");
	}
	current_range = endptr;
      } else {
	fatal("Error #486: Your port specifications are illegal.  Example of proper form: \"-100,200-1024,3000-4000,60000-\"");
      }
    } else {
	fatal("Error #487: Your port specifications are illegal.  Example of proper form: \"-100,200-1024,3000-4000,60000-\"");
    }

    /* Now I have a rangestart and a rangeend, so I can add these ports */
    while(rangestart <= rangeend) {
      if (porttbl[rangestart] & range_type) {
	if (!portwarning) {
	  error("WARNING:  Duplicate port number(s) specified.  Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm).");
	  portwarning++;
	} 
      }
      if (range_type & SCAN_TCP_PORT)
	tcpportcount++;
      if (range_type & SCAN_UDP_PORT)
	udpportcount++;
      if (range_type & SCAN_PROTOCOLS)
	protcount++;
      porttbl[rangestart] |= range_type;
      rangestart++;
    }
    
    /* Find the next range */
    while(isspace((int) *current_range)) current_range++;
    if (*current_range && *current_range != ',') {
      fatal("Error #488: Your port specifications are illegal.  Example of proper form: \"-100,200-1024,3000-4000,60000-\"");
    }
    if (*current_range == ',')
      current_range++;
  } while(current_range && *current_range);

  if ( 0 == (tcpportcount + udpportcount + protcount))
    fatal("No ports specified -- If you really don't want to scan any ports use ping scan...");

  ports = (struct scan_lists *) safe_malloc(sizeof(struct scan_lists));
  bzero(ports, sizeof(ports));
  if (tcpportcount) {
    ports->tcp_ports = (unsigned short *)safe_malloc((tcpportcount + 1) * sizeof(unsigned short));
    bzero(ports->tcp_ports, (tcpportcount + 1) * sizeof(unsigned short));
  }
  if (udpportcount) {
    ports->udp_ports = (unsigned short *)safe_malloc((udpportcount + 1) * sizeof(unsigned short));
    bzero(ports->udp_ports, (udpportcount + 1) * sizeof(unsigned short));
  }
  if (protcount) {
    ports->prots = (unsigned short *)safe_malloc((protcount + 1) * sizeof(unsigned short));
    bzero(ports->prots, (protcount + 1) * sizeof(unsigned short));
  }
  ports->tcp_count = tcpportcount;
  ports->udp_count = udpportcount;
  ports->prot_count = protcount;

  tcpportcount=0;
  udpportcount=0;
  protcount=0;
  for(i=0; i <= 65535; i++) {
    if (porttbl[i] & SCAN_TCP_PORT)
      ports->tcp_ports[tcpportcount++] = i;
    if (porttbl[i] & SCAN_UDP_PORT)
      ports->udp_ports[udpportcount++] = i;
    if (porttbl[i] & SCAN_PROTOCOLS)
      ports->prots[protcount++] = i;
  }

  /* Someday I am going to make sure this isn't neccessary and then I
     will start allowing (invalid) port 0 scans */
  if (tcpportcount)
    ports->tcp_ports[ports->tcp_count] = 0; 
  if (udpportcount)
    ports->udp_ports[ports->udp_count] = 0; 
  if (protcount)
    ports->prots[ports->prot_count] = 0; 
  return ports;
}

void printusage(char *name, int rc) {
#ifdef WIN32
#define WIN32_PRINTF "  --win_help Windows-specific features\n"
#else
#define WIN32_PRINTF
#endif
  printf(
	 "Nmap V. %s Usage: nmap [Scan Type(s)] [Options] <host or net list>\n"
	 "Some Common Scan Types ('*' options require root privileges)\n"
	 "  -sT TCP connect() port scan (default)\n"
	 "* -sS TCP SYN stealth port scan (best all-around TCP scan)\n"
	 "* -sU UDP port scan\n"
	 "  -sP ping scan (Find any reachable machines)\n"
	 "* -sF,-sX,-sN Stealth FIN, Xmas, or Null scan (experts only)\n"
	 "  -sR/-I RPC/Identd scan (use with other scan types)\n"
	 "Some Common Options (none are required, most can be combined):\n"
	 "* -O Use TCP/IP fingerprinting to guess remote operating system\n"
	 "  -p <range> ports to scan.  Example range: '1-1024,1080,6666,31337'\n"
	 "  -F Only scans ports listed in nmap-services\n"
	 "  -v Verbose. Its use is recommended.  Use twice for greater effect.\n"
	 "  -P0 Don't ping hosts (needed to scan www.microsoft.com and others)\n"
	 "* -Ddecoy_host1,decoy2[,...] Hide scan using many decoys\n"
	 "  -T <Paranoid|Sneaky|Polite|Normal|Aggressive|Insane> General timing policy\n"
	 "  -n/-R Never do DNS resolution/Always resolve [default: sometimes resolve]\n"
	 "  -oN/-oX/-oG <logfile> Output normal/XML/grepable scan logs to <logfile>\n"
	 "  -iL <inputfile> Get targets from file; Use '-' for stdin\n"
	 "* -S <your_IP>/-e <devicename> Specify source address or network interface\n"
	 "  --interactive Go into interactive mode (then press h for help)\n"
         WIN32_PRINTF
	 "Example: nmap -v -sS -O www.my.com 192.168.0.0/16 '192.88-90.*.*'\n"
	 "SEE THE MAN PAGE FOR MANY MORE OPTIONS, DESCRIPTIONS, AND EXAMPLES \n", NMAP_VERSION);
  exit(rc);
}

void printinteractiveusage() {
  printf(
	 "Nmap Interactive Commands:\n\
n <nmap args> -- executes an nmap scan using the arguments given and\n\
waits for nmap to finish.  Results are printed to the\n\
screen (of course you can still use file output commands).\n\
! <command>   -- runs shell command given in the foreground\n\
x             -- Exit Nmap\n\
f [--spoof <fakeargs>] [--nmap_path <path>] <nmap args>\n\
-- Executes nmap in the background (results are NOT\n\
printed to the screen).  You should generally specify a\n\
file for results (with -oX, -oG, or -oN).  If you specify\n\
fakeargs with --spoof, Nmap will try to make those\n\
appear in ps listings.  If you wish to execute a special\n\
version of Nmap, specify --nmap_path.\n\
n -h          -- Obtain help with Nmap syntax\n\
h             -- Prints this help screen.\n\
Examples:\n\
n -sS -O -v example.com/24\n\
f --spoof \"/usr/local/bin/pico -z hello.c\" -sS -oN /tmp/e.log example.com/24\n\n");
}

char *seqreport(struct seq_info *seq) {
  static char report[512];
  char tmp[256];
  char *p;
  int i;

  snprintf(report, sizeof(report), "TCP Sequence Prediction: Class=%s\n                         Difficulty=%d (%s)\n", seqclass2ascii(seq->seqclass), seq->index, seqidx2difficultystr(seq->index));
  if (o.verbose > 1 || o.debugging ) {
    p = tmp;
    strcpy(p, "TCP ISN Seq. Numbers: ");
    p += 22;
    for(i=0; i < seq->responses; i++) {
      if (p - tmp + 20 > (sizeof(tmp)))
	fatal("0verfl0w Error #234112");
      p += snprintf(p, 16, "%X ", seq->seqs[i]);
    }
    *--p = '\n';
    strcat(report, tmp);
  }
  return report;
}

/* Convert a TCP sequence prediction difficulty index like 1264386
   into a difficulty string like "Worthy Challenge */
const char *seqidx2difficultystr(unsigned long idx) {
  return  (idx < 10)? "Trivial joke" : (idx < 80)? "Easy" : (idx < 3000)? "Medium" : (idx < 5000)? "Formidable" : (idx < 100000)? "Worthy challenge" : "Good luck!";
}

char *seqclass2ascii(int seqclass) {
  switch(seqclass) {
  case SEQ_CONSTANT:
    return "constant sequence number (!)";
  case SEQ_64K:
    return "64K rule";
  case SEQ_TD:
    return "trivial time dependency";
  case SEQ_i800:
    return "increments by 800";
  case SEQ_RI:
    return "random positive increments";
  case SEQ_TR:
    return "truly random";
  case SEQ_UNKNOWN:
    return "unknown class";
  default:
    return "ERROR, WTF?";
  }
}

char *ipidclass2ascii(int seqclass) {
  switch(seqclass) {
  case IPID_SEQ_CONSTANT:
    return "Duplicated ipid (!)";
  case IPID_SEQ_INCR:
    return "Incremental";
  case IPID_SEQ_BROKEN_INCR:
    return "Broken little-endian incremental";
  case IPID_SEQ_RD:
    return "Randomized";
  case IPID_SEQ_RPI:
    return "Random positive increments";
  case IPID_SEQ_ZERO:
    return "All zeros";
  case IPID_SEQ_UNKNOWN:
    return "Busy server or unknown class";
  default:
    return "ERROR, WTF?";
  }
}

char *tsseqclass2ascii(int seqclass) {
  switch(seqclass) {
  case TS_SEQ_ZERO:
    return "zero timestamp";
  case TS_SEQ_2HZ:
    return "2HZ";
  case TS_SEQ_100HZ:
    return "100HZ";
  case TS_SEQ_1000HZ:
    return "1000HZ";
  case TS_SEQ_UNSUPPORTED:
    return "none returned (unsupported)";
  case TS_SEQ_UNKNOWN:
    return "unknown class";
  default:
    return "ERROR, WTF?";
  }
}


/**
 * Returns 1 if this is a reserved IP address, where "reserved" means
 * either a private address, non-routable address, or even a non-reserved
 * but unassigned address which has an extremely high probability of being
 * black-holed.
 *
 * We try to optimize speed when ordering the tests. This optimization
 * assumes that all byte values are equally likely in the input.
 *
 * Warning: This function could easily become outdated if the IANA
 * starts to assign some more IPv4 ranges to RIPE, etc. as they have
 * started doing this year (2001), for example 80.0.0.0/4 used to be
 * completely unassigned until they gave 80.0.0.0/7 to RIPE in April
 * 2001 (www.junk.org is an example of a new address in this range).
 *
 * Check <http://www.iana.org/assignments/ipv4-address-space> for
 * the most recent assigments.
 */

int ip_is_reserved(struct in_addr *ip)
{
  char *ipc = (char *) &(ip->s_addr);
  unsigned char i1 = ipc[0], i2 = ipc[1], i3 = ipc[2], i4 = ipc[3];

  /* 219-223/8 is IANA reserved */
  /* 224-239/8 is all multicast stuff */
  /* 240-255/8 is IANA reserved */
  if (i1 >= 219)
    return 1;

  /* 096-126/8 is IANA reserved */
  /* 127/8 is reserved for loopback */
  if (i1 >= 96 && i1 <= 127)
    return 1;

  /* 069-079/8 is IANA reserved */
  if (i1 >= 69 && i1 <= 79)
    return 1;

  /* 082-095/8 is IANA reserved */
  if (i1 >= 82 && i1 <= 95)
    return 1;

  /* do all the /7's and /8's with a big switch statement, hopefully the
   * compiler will be able to optimize this a little better using a jump table
   * or what have you
   */
  switch (i1)
    {
    case 0:         /* 000/8 is IANA reserved       */
    case 1:         /* 001/8 is IANA reserved       */
    case 2:         /* 002/8 is IANA reserved       */
    case 5:         /* 005/8 is IANA reserved       */
    case 6:         /* USA Army ISC                 */
    case 7:         /* used for BGP protocol        */
    case 10:        /* the infamous 10.0.0.0/8      */
    case 23:        /* 023/8 is IANA reserved       */
    case 27:        /* 027/8 is IANA reserved       */
    case 31:        /* 031/8 is IANA reserved       */
    case 36:        /* 036/8 is IANA reserved       */
    case 37:        /* 037/8 is IANA reserved       */
    case 39:        /* 039/8 is IANA reserved       */
    case 41:        /* 041/8 is IANA reserved       */
    case 42:        /* 042/8 is IANA reserved       */
    case 55:        /* misc. U.S.A. Armed forces    */
    case 58:        /* 058/8 is IANA reserved       */
    case 59:        /* 059/8 is IANA reserved       */
    case 60:        /* 060/8 is IANA reserved       */
    case 197:
      return 1;
    default:
      break;
    }

  /* 172.16.0.0/12 is reserved for private nets by RFC1819 */
  if (i1 == 172 && i2 >= 16 && i2 <= 31)
    return 1;

  /* 192.168.0.0/16 is reserved for private nets by RFC1819 */
  /* 192.0.2.0/24 is reserved for documentation and examples */
  if (i1 == 192) {
    if (i2 == 168)
      return 1;
    else if (i2 == 0 && i3 == 2)
      return 1;
  }

  /* reserved for DHCP clients seeking addresses, not routable outside LAN */
  if (i1 == 169 && i2 == 254)
    return 1;

  /* believe it or not, 204.152.64.0/23 is some bizarre Sun proprietary
   * clustering thing */
  if (i1 == 204 && i2 == 152 && (i3 == 64 || i3 == 65))
    return 1;

  /* 255.255.255.255, note we already tested for i1 in this range */
  if (i2 == 255 && i3 == 255 && i4 == 255)
    return 1;

  return 0;

}

char *grab_next_host_spec(FILE *inputfd, int argc, char **fakeargv) {
  static char host_spec[512];
  int host_spec_index;
  int ch;
  struct in_addr ip;

  if (o.generate_random_ips) {
    do {
      ip.s_addr = get_random_u32();
    } while (ip_is_reserved(&ip));
    strcpy(host_spec, inet_ntoa(ip));
  } else if (!inputfd) {
    return( (optind < argc)?  fakeargv[optind++] : NULL);
  } else { 
    host_spec_index = 0;
    while((ch = getc(inputfd)) != EOF) {
      if (ch == ' ' || ch == '\n' || ch == '\t' || ch == '\0') {
	if (host_spec_index == 0) continue;
	host_spec[host_spec_index] = '\0';
	return host_spec;
      } else if (host_spec_index < 511) {
	host_spec[host_spec_index++] = (char) ch;
      } else fatal("One of the host_specifications from your input file is too long (> %d chars)", sizeof(host_spec));
    }
    host_spec[host_spec_index] = '\0';
  }
  if (!*host_spec) return NULL;
  return host_spec;
}

/* Just a routine for obtaining a string for printing based on the scantype */
char *scantype2str(stype scantype) {

  switch(scantype) {
  case ACK_SCAN: return "ACK Scan"; break;
  case SYN_SCAN: return "SYN Stealth Scan"; break;
  case FIN_SCAN: return "FIN Scan"; break;
  case XMAS_SCAN: return "XMAS Scan"; break;
  case UDP_SCAN: return "UDP Scan"; break;
  case CONNECT_SCAN: return "Connect() Scan"; break;
  case NULL_SCAN: return "NULL Scan"; break;
  case WINDOW_SCAN: return "Window Scan"; break;
  case RPC_SCAN: return "RPCGrind Scan"; break;
  case MAIMON_SCAN: return "Maimon Scan"; break;
  case IPPROT_SCAN: return "IPProto Scan"; break;
  default: assert(0); break;
  }

  return NULL; /* Unreached */

}

char *statenum2str(int state) {
  switch(state) {
  case PORT_OPEN: return "open"; break;
  case PORT_FIREWALLED: return "filtered"; break;
  case PORT_UNFIREWALLED: return "UNfiltered"; break;
  case PORT_CLOSED: return "closed"; break;
  default: return "unknown"; break;
  }
  return "unknown";
}


/* Checks whether the identd port (113) is open on the target machine.  No
   sense wasting time trying it for each good port if it is down! */

int check_ident_port(struct in_addr target) {
  int sd;
  char buf[4096];
  struct sockaddr_in sock;
  int res;
  struct sockaddr_in stranger;
  NET_SIZE_T sockaddr_in_len = sizeof(struct sockaddr_in);
  fd_set fds_read, fds_write;
  struct timeval tv;
  tv.tv_sec = o.initial_rtt_timeout / 1000;
  tv.tv_usec = (o.initial_rtt_timeout % 1000) * 1000;
  if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {perror("Socket troubles"); exit(1);}
  unblock_socket(sd);
  sock.sin_family = AF_INET;
  sock.sin_addr.s_addr = target.s_addr;
  sock.sin_port = htons(113); /*should use getservbyname(3), yeah, yeah */
  FD_ZERO(&fds_read);
  FD_ZERO(&fds_write);
  FD_SET(sd, &fds_read);
  FD_SET(sd, &fds_write);
  res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));
  if (res != -1) /* must be scanning localhost, this socket is non-blocking */ 
    goto success;
  if (errno == ECONNREFUSED) /* Unlikely in non-blocking, but could happen  */ 
    goto failure;
  if ((res = select(sd+1, &fds_read, &fds_write, NULL, &tv)) > 0) {
    /* Yay, it may be up ... */
    if (FD_ISSET(sd, &fds_read) && FD_ISSET(sd, &fds_write)) {
      res = recvfrom(sd, buf,4096, 0, (struct sockaddr *) & stranger, &sockaddr_in_len);
      if (res >= 0) goto success;
      goto failure;
    }
    else if (FD_ISSET(sd, &fds_write)) {
      res = send(sd, buf, 0, 0);
      if (res < 0) goto failure;
      goto success;
    } else if (FD_ISSET(sd, &fds_read)) {
      fprintf(stderr, "I have never seen this type of socket selectable for read only.  Please let me know how you did it and what OS you are running (fyodor@insecure.org).\n");
      goto success;
    }
    else {
      fprintf(stderr, "Wow, select blatantly lied to us!  Please let fyodor know what OS you are running (fyodor@insecure.org).\n");
      goto failure;
    } 
  }

 failure:
  close(sd);
  if (o.debugging || o.verbose) log_write(LOG_STDOUT, "identd port not active\n");
  return 0;

 success:
  close(sd);
  if (o.debugging || o.verbose) log_write(LOG_STDOUT, "identd port is active\n");
  return 1;
}

/* returns 0 for possibly temporary error, -1 means we shouldn't attempt
   inetd again on this host */
int getidentinfoz(struct in_addr target, u16 localport, u16 remoteport,
		  char *owner, int ownersz) {
  int sd;
  struct sockaddr_in sock;
  int res;
  char request[16];
  char response[1024];
  char *p,*q;
  char  *os;

  if (ownersz == 0) return 0;
  owner[0] = '\0';
  if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {perror("Socket troubles"); exit(1);}

  sock.sin_family = AF_INET;
  sock.sin_addr.s_addr = target.s_addr;
  sock.sin_port = htons(113);
  usleep(50000);   /* If we aren't careful, we really MIGHT take out inetd, 
		      some are very fragile */
  res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));

  if (res < 0 ) {
    if (o.debugging)
      fprintf(stderr, "Identd port not open, cannot obtain port owner info.\n"); 
    close(sd);
    return -1;
  }
  snprintf(request, sizeof(request), "%hu,%hu\r\n", remoteport, localport);
  if (o.debugging > 1) log_write(LOG_STDOUT, "Connected to identd, sending request: %s", request);
  if (write(sd, request, strlen(request) + 1) == -1) {
    perror("identd write");
    close(sd);
    return 0;
  }
  else if ((res = read(sd, response, sizeof(response))) == -1) {
    perror("reading from identd");
    close(sd);
    return 0;
  }
  else {
    close(sd);
    if (o.debugging > 1) log_write(LOG_STDOUT, "Read %d bytes from identd: %s\n", res, response);
    if ((p = strchr(response, ':'))) {
      p++;
      if ((q = strtok(p, " :"))) {
	if (!strcasecmp( q, "error")) {
	  if (strstr(response, "HIDDEN-USER") || strstr(response, "hidden-user")) {
	    log_write(LOG_STDOUT, "identd returning HIDDEN-USER, giving up on it\n");
	    return -1;
	  }
	  if (o.debugging) log_write(LOG_STDOUT, "ERROR returned from identd for port %d\n", remoteport);
	  return 0;
	}
	if ((os = strtok(NULL, " :"))) {
	  if ((p = strtok(NULL, " :"))) {
	    if ((q = strchr(p, '\r'))) *q = '\0';
	    if ((q = strchr(p, '\n'))) *q = '\0';
	    Strncpy(owner, p, ownersz);
	  }
	}
      } 
    }  
  }
  return 1;
}



/* Determine whether firewall mode should be on for a scan */
/* If firewall mode is active, we increase the scan group size every
   30 seconds */
int check_firewallmode(struct hoststruct *target, struct scanstats *ss) {
  struct firewallmodeinfo *fm = &(target->firewallmode);
  struct timeval current_time;
  static struct timeval last_adjust;
  static int init = 0;

  if (!init) {
    gettimeofday(&last_adjust, NULL);
    init = 1;
  }

  if (fm->nonresponsive_ports > 50 && ((double)fm->responsive_ports / (fm->responsive_ports + fm->nonresponsive_ports)) < 0.05) {  
    if (fm->active == 0 && o.debugging)
      error("Activating firewall speed-optimization mode for host %s (%s)", target->name, inet_ntoa(target->host)); 
    fm->active = 1;
  }

  if (fm->active) {
    gettimeofday(&current_time, NULL);
    if (TIMEVAL_SEC_SUBTRACT(current_time, last_adjust) > 5) {
      ss->numqueries_ideal = MIN(ss->numqueries_ideal + (ss->packet_incr/ss->numqueries_ideal), ss->max_width); 
      if (o.debugging) {
	error("Raising ideal number of queries to %10.7g to account for firewalling", ss->numqueries_ideal);
      }
      last_adjust = current_time;
    }
  }
  return fm->active;
}

int ftp_anon_connect(struct ftpinfo *ftp) {
  int sd;
  struct sockaddr_in sock;
  int res;
  char recvbuf[2048];
  char command[512];

  if (o.verbose || o.debugging) 
    log_write(LOG_STDOUT, "Attempting connection to ftp://%s:%s@%s:%i\n", ftp->user, ftp->pass,
	      ftp->server_name, ftp->port);

  if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    perror("Couldn't create ftp_anon_connect socket");
    return 0;
  }

  sock.sin_family = AF_INET;
  sock.sin_addr.s_addr = ftp->server.s_addr;
  sock.sin_port = htons(ftp->port); 
  res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));
  if (res < 0 ) {
    fprintf(stderr, "Your ftp bounce proxy server won't talk to us!\n");
    exit(1);
  }
  if (o.verbose || o.debugging) log_write(LOG_STDOUT, "Connected:");
  while ((res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,7)) > 0) 
    if (o.debugging || o.verbose) {
      recvbuf[res] = '\0';
      log_write(LOG_STDOUT, "%s", recvbuf);
    }
  if (res < 0) {
    perror("recv problem from ftp bounce server");
    exit(1);
  }

  snprintf(command, 511, "USER %s\r\n", ftp->user);

  send(sd, command, strlen(command), 0);
  res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,12);
  if (res <= 0) {
    perror("recv problem from ftp bounce server");
    exit(1);
  }
  recvbuf[res] = '\0';
  if (o.debugging) log_write(LOG_STDOUT, "sent username, received: %s", recvbuf);
  if (recvbuf[0] == '5') {
    fprintf(stderr, "Your ftp bounce server doesn't like the username \"%s\"\n", 
	    ftp->user);
    exit(1);
  }

  snprintf(command, 511, "PASS %s\r\n", ftp->pass);

  send(sd, command, strlen(command), 0);
  res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,12);
  if (res < 0) {
    perror("recv problem from ftp bounce server\n");
    exit(1);
  }
  if (!res) fprintf(stderr, "Timeout from bounce server ...");
  else {
    recvbuf[res] = '\0';
    if (o.debugging) log_write(LOG_STDOUT, "sent password, received: %s", recvbuf);
    if (recvbuf[0] == '5') {
      fprintf(stderr, "Your ftp bounce server refused login combo (%s/%s)\n",
	      ftp->user, ftp->pass);
      exit(1);
    }
  }
  while ((res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,2)) > 0) 
    if (o.debugging) {
      recvbuf[res] = '\0';
      log_write(LOG_STDOUT, "%s", recvbuf);
    }
  if (res < 0) {
    perror("recv problem from ftp bounce server");
    exit(1);
  }
  if (o.verbose) log_write(LOG_STDOUT, "Login credentials accepted by ftp server!\n");

  ftp->sd = sd;
  return sd;
}

#ifndef WIN32

void reaper(int signo) {
  int status;
  pid_t pid;

  if ((pid = wait(&status)) == -1) {
    gh_perror("waiting to reap child");
  } else {
    fprintf(stderr, "\n[%d finished status=%d (%s)]\nnmap> ", (int) pid, status, (status == 0)? "success"  : "failure");
  }
}

void sigdie(int signo) {
  switch(signo) {
  case SIGINT:
    fprintf(stderr, "caught SIGINT signal, cleaning up\n");
    break;
  case SIGTERM:
    fprintf(stderr, "caught SIGTERM signal, cleaning up\n");
    break;
  case SIGHUP:
    fprintf(stderr, "caught SIGHUP signal, cleaning up\n");
    break;
  case SIGSEGV:
    fprintf(stderr, "caught SIGSEGV signal, cleaning up\n");
    if (o.debugging) abort();
    break;
  case SIGBUS:
    fprintf(stderr, "caught SIGBUS signal, cleaning up\n");
    break;
  default:
    fprintf(stderr, "caught signal %d, cleaning up\n", signo);
    break;
  }
  fflush(stdout);
  log_close(LOG_MACHINE|LOG_NORMAL|LOG_SKID);
  exit(1);
}

#endif

int nmap_fetchfile(char *filename_returned, int bufferlen, char *file) {
  char *dirptr;
  int res;
  int foundsomething = 0;
  struct passwd *pw;
  char dot_buffer[512];
  static int warningcount = 0;

  /* First we try $NMAPDIR/file
     next we try ~user/nmap/file
     then we try NMAPDATADIR/file <--NMAPDATADIR 
     finally we try ./file

	 -- or on Windows --

	 $NMAPDIR -> nmap.exe directory -> NMAPDATADIR -> .
  */
  if ((dirptr = getenv("NMAPDIR"))) {
    res = snprintf(filename_returned, bufferlen, "%s/%s", dirptr, file);
    if (res > 0 && res < bufferlen) {
      if (fileexistsandisreadable(filename_returned))
	foundsomething = 1;
    }
  }
#ifndef WIN32
  if (!foundsomething) {
    pw = getpwuid(getuid());
    if (pw) {
      res = snprintf(filename_returned, bufferlen, "%s/.nmap/%s", pw->pw_dir, file);
      if (res > 0 && res < bufferlen) {
	if (fileexistsandisreadable(filename_returned))
	  foundsomething = 1;
      }
    }
    if (!foundsomething && getuid() != geteuid()) {
      pw = getpwuid(geteuid());
      if (pw) {
	res = snprintf(filename_returned, bufferlen, "%s/nmap/%s", pw->pw_dir, file);
	if (res > 0 && res < bufferlen) {
	  if (fileexistsandisreadable(filename_returned))
	    foundsomething = 1;
	}
      }
    }
  }
#else
  if (!foundsomething) { /* Try the nMap directory */
	  char fnbuf[MAX_PATH];
	  int i;
	  res = GetModuleFileName(GetModuleHandle(0), fnbuf, 1024);
      if(!res) fatal("GetModuleFileName failed (!)\n");
	  //	Strip it
	  for(i = res - 1; i >= 0 && fnbuf[i] != '/' && fnbuf[i] != '\\'; i--);
	  if(i >= 0) // we found it
		  fnbuf[i] = 0;
	  res = snprintf(filename_returned, bufferlen, "%s/%s", fnbuf, file);
	  if(res > 0 && res < bufferlen) {
		  if (fileexistsandisreadable(filename_returned))
            foundsomething = 1;
      }
  }
#endif
  if (!foundsomething) {
    res = snprintf(filename_returned, bufferlen, "%s/%s", NMAPDATADIR, file);
    if (res > 0 && res < bufferlen) {
      if (fileexistsandisreadable(filename_returned))
	foundsomething = 1;
    }
  }
  if (foundsomething && (*filename_returned != '.')) {    
    res = snprintf(dot_buffer, sizeof(dot_buffer), "./%s", file);
    if (res > 0 && res < bufferlen) {
      if (fileexistsandisreadable(dot_buffer)) {
	if (warningcount++ < 5)
	  error("WARNING!  The following files exist and are readable: %s and %s.  I am choosing %s for security reasons.  set NMAPDIR=. to give priority to files in your local directory", filename_returned, dot_buffer, filename_returned);
      }
    }
  }

  if (!foundsomething) {
    res = snprintf(filename_returned, bufferlen, "./%s", file);
    if (res > 0 && res < bufferlen) {
      if (fileexistsandisreadable(filename_returned))
	foundsomething = 1;
    }
  }

  if (!foundsomething) {
    filename_returned[0] = '\0';
    return -1;
  }

  if (o.debugging > 1)
    error("Fetchfile found %s\n", filename_returned);

  return 0;

}

int fileexistsandisreadable(char *pathname) {
  FILE *fp;
  /* We check this the easy way! */
  fp = fopen(pathname, "r");
  if (fp) fclose(fp);
  return (fp == NULL)? 0 : 1;
}

