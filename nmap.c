#include "nmap.h"
#include "osscan.h"

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
  signal(SIGINT, sigdie);
  signal(SIGTERM, sigdie);
  signal(SIGHUP, sigdie); 
  
  signal(SIGCHLD, reaper);


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
  printf("\nStarting nmap V. %s by fyodor@insecure.org ( www.insecure.org/nmap/ )\n", VERSION);
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
      
	/* We should be courtious and give Nmap reasonable signal defaults */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGSEGV, SIG_DFL);

	/* Now I must handle spoofery */
	if (*fakeargs) {
	  fakeargc = arg_parse(fakeargs, &fakeargv);
	  if (fakeargc < 1) {
	    fatal("Bogus --spoof parameter");
	  }
	} else {
	  fakeargc = 1;
	  fakeargv = malloc(sizeof(char *) * 2);
	  fakeargv[0] = nmappath;
	  fakeargv[1] = NULL;
	}

	if (o.debugging) error("About to exec %s", nmappath);
	/* Kill stdout & stderr */
	if (!o.debugging) {	
	  fd = open("/dev/null", O_WRONLY);
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

int nmap_main(int argc, char *argv[]) {
  char *p, *q;
  int i, j, arg, argvlen;
  FILE *inputfd = NULL;
  char *host_spec;
  short fastscan=0, randomize=1, resolve_all=0;
  short quashargv = 0;
  int numhosts_scanned = 0;
  char **host_exp_group;
  int num_host_exp_groups = 0;
  char *machinefilename = NULL, *kiddiefilename = NULL, *normalfilename = NULL;
  struct hostgroup_state hstate;
  int numhosts_up = 0;
  int starttime;
  unsigned short *ports = NULL;
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
    {"oN", required_argument, 0, 0},
    {"oM", required_argument, 0, 0},  
    {"oS", required_argument, 0, 0},
    {"oH", required_argument, 0, 0},  
    {"iL", required_argument, 0, 0},  
    {"iR", no_argument, 0, 0},  
    {"initial_rtt_timeout", required_argument, 0, 0},
    {"randomize_hosts", no_argument, 0, 0},
    {"rH", no_argument, 0, 0},
    {"vv", no_argument, 0, 0},
    {"append_output", no_argument, 0, 0},
    {"noninteractive", no_argument, 0, 0},
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
	  fatal("max_rtt_timeout is given in milliseconds and must be greater than 5");
	}
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
      } else if (strcmp(long_options[option_index].name, "initial_rtt_timeout") == 0) {
	o.initial_rtt_timeout = atoi(optarg);
	if (o.initial_rtt_timeout <= 0) {
	  fatal("scan_delay must be greater than 0");
	}   
      } else if (strcmp(long_options[option_index].name, "oN") == 0) {
	normalfilename = optarg;
      } else if (strcmp(long_options[option_index].name, "oM") == 0) {
	machinefilename = optarg;
      } else if (strcmp(long_options[option_index].name, "oS") == 0) {
	kiddiefilename = optarg;
      } else if (strcmp(long_options[option_index].name, "oH") == 0) {
	fatal("HTML output is not yet supported");
      } else if (strcmp(long_options[option_index].name, "iL") == 0) {
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
      } else if (strcmp(long_options[option_index].name, "vv") == 0) {
	/* Compatability hack ... ugly */
	o.verbose += 2;
      } else {
	fatal("Unknown long option (%s) given@#!$#$", long_options[option_index].name);
      }
      break;
    case 'b': 
      o.bouncescan++;
      if (parse_bounce(&ftp, optarg) < 0 ) {
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
      ports = getpts(optarg); break;
      if (!ports)
	fatal("Your port specification string is not parseable");
    case 'q': quashargv++; break;
    case 'R': resolve_all++; break;
    case 'r': 
      randomize = 0;
      break;
    case 'S': 
      if (o.spoofsource)
	fatal("You can only use the source option once!  Use -D <decoy1> -D <decoy2> etc. for decoys\n");
      o.source = safe_malloc(sizeof(struct in_addr));
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
	case 'M':  o.maimonscan = 1; break;
	case 'N':  o.nullscan = 1; break;
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
      printf("\nnmap V. %s\n", VERSION); 
      exit(0);
      break;
    case 'v': o.verbose++; break;
    }
  }

  if (!o.debugging)
    signal(SIGSEGV, sigdie); 

  if (!o.interactivemode)
    log_write(LOG_STDOUT|LOG_SKID, "\nStarting nmap V. %s by fyodor@insecure.org ( www.insecure.org/nmap/ )\n", VERSION);

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

  /* Now we check the option sanity */
  /* Insure that at least one scantype is selected */
  if (!o.connectscan && !o.udpscan && !o.synscan && !o.windowscan && !o.finscan && !o.maimonscan &&  !o.nullscan && !o.xmasscan && !o.ackscan && !o.bouncescan && !o.pingscan) {
    o.connectscan++;
    if (o.verbose) error("No tcp,udp, or ICMP scantype specified, assuming vanilla tcp connect() scan. Use -sP if you really don't want to portscan (and just want to see what hosts are up).");
  }

  if (o.pingtype != PINGTYPE_NONE && o.spoofsource) {
    error("WARNING:  If -S is being used to fake your source address, you may also have to use -e <iface> and -P0 .  If you are using it to specify your real source address, you can ignore this warning.");
  }

  if (o.connectscan && o.spoofsource) {
    error("WARNING:  -S will not affect the source address used in a connect() scan.  Use -sS or another raw scan if you want to use the specified source address for the port scanning stage of nmap");
  }

  if (fastscan && ports) {
    fatal("You can specify fast scan (-F) or explicitly select individual ports (-p), but not both");
  } else if (fastscan) {
    ports = getfastports(o.windowscan|o.synscan|o.connectscan|o.fragscan|o.finscan|o.maimonscan|o.bouncescan|o.nullscan|o.xmasscan|o.ackscan,o.udpscan);
  }

  if (o.pingscan && ports) {
    fatal("You cannot use -F (fast scan) or -p (explicit port selection) with PING scan");
  }

  if (o.pingscan && fastscan) {
    fatal("The fast scan (-F) is incompatible with ping scan");
  }

  if (!ports) {
    ports = getdefaultports(o.windowscan|o.synscan|o.connectscan|o.fragscan|o.finscan|
			    o.maimonscan|o.bouncescan|o.nullscan|o.xmasscan|o.ackscan,
			    o.udpscan);
  }

  /* Default dest port for tcp probe */
  if (!o.tcp_probe_port) o.tcp_probe_port = 80;


  if (o.pingscan && (o.connectscan || o.udpscan || o.windowscan || o.synscan || o.finscan || o.maimonscan ||  o.nullscan || o.xmasscan || o.ackscan || o.bouncescan)) {
    fatal("Ping scan is not valid with any other scan types (the other ones all include a ping scan");
  }

  /* We start with stuff users should not do if they are not root */
  if (!o.isr00t) {

    if (o.pingtype & PINGTYPE_ICMP) {
      error("Warning:  You are not root -- using TCP pingscan rather than ICMP");
      o.pingtype = PINGTYPE_TCP;
    }

    if (o.finscan || o.windowscan || o.synscan || o.maimonscan || o.nullscan || o.xmasscan || o.ackscan
	|| o.udpscan ) {
      fatal("You requested a scan type which requires r00t privileges, and you do not have them.\n");
    }
  
    if (o.numdecoys > 0) {
      fatal("Sorry, but you've got to be r00t to use decoys, boy!");
    }
  
    if (o.fragscan) {
      fatal("Sorry, but fragscan requires r00t privileges\n");
    }

    if (o.osscan) {
      fatal("TCP/IP fingerprinting (for OS scan) requires root privileges which you do not appear to possess.  Sorry, dude.\n");
    }
  }

  if (o.numdecoys > 0 && o.rpcscan) {
    error("WARNING:  RPC scan currently does not make use of decoys so don't count on that protection");
  }

  if (o.bouncescan && o.pingtype != PINGTYPE_NONE) 
    log_write(LOG_STDOUT, "Hint: if your bounce scan target hosts aren't reachable from here, remember to use -P0 so we don't try and ping them prior to the scan\n");

  if (o.connectscan + o.windowscan + o.synscan + o.finscan + o.maimonscan + o.xmasscan + o.nullscan + o.ackscan  > 1) {
    fatal("You specified more than one type of TCP scan.  Please choose only one of -sT, -sS, -sF, -sM, -sX, -sA, -sW, and -sN");
  }

  if (o.numdecoys > 0 && (o.bouncescan || o.connectscan)) {
    fatal("Decoys are irrelevant to the bounce or connect scans");
  }

  if (o.fragscan && (o.connectscan || 
		     (o.udpscan && (o.windowscan + o.synscan + o.finscan + o.maimonscan + 
				    o.xmasscan + o.ackscan + o.nullscan == 0))))
    fatal("Fragmentation scan can only be used with SYN, FIN, Maimon, XMAS, ACK, or NULL scan types");
 
  if (o.identscan && !o.connectscan) {
    error("Identscan only works with connect scan (-sT) ... ignoring option");
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
    o.source = safe_malloc(sizeof(struct in_addr)); 
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
  log_write(LOG_NORMAL|LOG_MACHINE, "# Nmap (V. %s) scan initiated %s as: ", VERSION, mytime);

  for(i=0; i < argc; i++) log_write(LOG_NORMAL|LOG_MACHINE,"%s ", fakeargv[i]);
  log_write(LOG_NORMAL|LOG_MACHINE,"\n");  


  /* more fakeargv junk, BTW malloc'ing extra space in argv[0] doesn't work */
  if (quashargv) {
    argvlen = strlen(argv[0]);
    if (argvlen < strlen(FAKE_ARGV))
      fatal("If you want me to fake your argv, you need to call the program with a longer name.  Try the full pathname, or rename it fyodorssuperdedouperportscanner");
    strncpy(argv[0], FAKE_ARGV, strlen(FAKE_ARGV));
    for(i = strlen(FAKE_ARGV); i < argvlen; i++) argv[0][i] = '\0';
    for(i=1; i < argc; i++) {
      argvlen = strlen(argv[i]);
      for(j=0; j <= argvlen; j++)
	argv[i][j] = '\0';
    }
  }

  signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE so our program doesn't crash because
			       of it, but we really shouldn't get an unsuspected
			       SIGPIPE */
  if (o.max_parallelism && (i = max_sd()) && i < o.max_parallelism) {
    fprintf(stderr, "WARNING:  Your specified max_parallel_sockets of %d, but your system says it might only give us %d.  Trying anyway\n", o.max_parallelism, i);
  }

  if (o.debugging > 1) log_write(LOG_STDOUT, "The max # of sockets we are using is: %d\n", o.max_parallelism);

  if (randomize)
    shortfry(ports, o.numports); 

  starttime = time(NULL);

  /* Time to create a hostgroup state object filled with all the requested
     machines */
  host_exp_group = safe_malloc(o.host_group_sz * sizeof(char *));

  while(1) {
    while(num_host_exp_groups < o.host_group_sz &&
	  (host_spec = grab_next_host_spec(inputfd, argc, fakeargv))) {
      host_exp_group[num_host_exp_groups++] = strdup(host_spec);
    }
    if (num_host_exp_groups == 0)
      break;
    hostgroup_state_init(&hstate, o.host_group_sz, o.randomize_hosts, 
			 host_exp_group, num_host_exp_groups);
  
    while((currenths = nexthost(&hstate)) && currenths->host.s_addr) {
      numhosts_scanned++;
      if (currenths->flags & HOST_UP) 
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
      if (!o.pingscan) {
	if (o.pingtype != PINGTYPE_NONE && (currenths->flags & HOST_UP) && (o.verbose || o.debugging)) 
	  log_write(LOG_STDOUT, "Host %s (%s) appears to be up ... good.\n", currenths->name, inet_ntoa(currenths->host));
	else if (o.verbose && o.pingtype != PINGTYPE_NONE && !(currenths->flags & HOST_UP)) {  
	  if (resolve_all)
	    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host %s (%s) appears to be down, skipping it.\n", currenths->name, inet_ntoa(currenths->host));
	  else log_write(LOG_STDOUT,"Host %s (%s) appears to be down, skipping it.\n", currenths->name, inet_ntoa(currenths->host));
	}

      }
      else {
	if (currenths->flags & HOST_UP) {  
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host %s (%s) appears to be up.\n", currenths->name, inet_ntoa(currenths->host));
	  log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Up\n", inet_ntoa(currenths->host), currenths->name);
	}
	else 
	  if (o.verbose || o.debugging || resolve_all) {    
	    if (resolve_all)
	      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host %s (%s) appears to be down.\n", currenths->name, inet_ntoa(currenths->host));
	    else log_write(LOG_STDOUT,"Host %s (%s) appears to be down.\n", currenths->name, inet_ntoa(currenths->host));
	  }
      }

      if (currenths->wierd_responses) {  
	if (!(currenths->flags & HOST_UP))
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host  %s (%s) seems to be a subnet broadcast address (returned %d extra pings).  Skipping host.\n",  currenths->name, inet_ntoa(currenths->host), currenths->wierd_responses);
	else
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host  %s (%s) seems to be a subnet broadcast address (returned %d extra pings).  Still scanning it.\n",  currenths->name, inet_ntoa(currenths->host), currenths->wierd_responses);
	log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Smurf (%d responses)\n",  inet_ntoa(currenths->host), currenths->name, currenths->wierd_responses);
      }
 
      /* The !currenths->wierd_responses was commented out after I found
	 a smurf address which DID allow port scanninng and you could even
	 telnetthere.  wierd :0 
	 IGNORE THAT COMMENT!  The check is back again ... for now 
	 NOPE -- gone again */
    
      if (currenths->flags & HOST_UP /*&& !currenths->wierd_responses*/ &&
	  !o.pingscan) {
   
	if (currenths->flags & HOST_UP && !currenths->source_ip.s_addr && ( o.windowscan || o.synscan || o.finscan || o.maimonscan || o.udpscan || o.nullscan || o.xmasscan || o.ackscan )) {
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
	if (!*currenths->device && currenths->flags & HOST_UP && (o.nullscan || o.xmasscan || o.ackscan || o.udpscan || o.finscan || o.maimonscan ||  o.synscan || o.osscan || o.windowscan) && (ipaddr2devname( currenths->device, &currenths->source_ip) != 0))
	  fatal("Could not figure out what device to send the packet out on!  You might possibly want to try -S (but this is probably a bigger problem).  If you are trying to sp00f the source of a SYN/FIN scan with -S <fakeip>, then you must use -e eth0 (or other devicename) to tell us what interface to use.\n");
	/* Set up the decoy */
	o.decoys[o.decoyturn] = currenths->source_ip;
   
	/* Time for some actual scanning! */    
	if (o.synscan) pos_scan(currenths, ports, SYN_SCAN);
	if (o.windowscan) pos_scan(currenths, ports, WINDOW_SCAN);
	if (o.connectscan) pos_scan(currenths, ports, CONNECT_SCAN);      
	if (o.ackscan) pos_scan(currenths, ports, ACK_SCAN);

	if (o.finscan) super_scan(currenths, ports, FIN_SCAN);
	if (o.xmasscan) super_scan(currenths, ports, XMAS_SCAN);
	if (o.nullscan) super_scan(currenths, ports, NULL_SCAN);
	if (o.maimonscan) super_scan(currenths, ports, MAIMON_SCAN);
	if (o.udpscan) super_scan(currenths, ports, UDP_SCAN);
   
	if (o.bouncescan) {
	  if (ftp.sd <= 0) ftp_anon_connect(&ftp);
	  if (ftp.sd > 0) bounce_scan(currenths, ports, &ftp);
	}

	/* This scantype must be after any TCP or UDP scans ... */
	if (o.rpcscan)  pos_scan(currenths, ports, RPC_SCAN);


	if (o.osscan) {
	  os_scan(currenths, ports);
	}

	if (currenths->timedout) {
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Skipping host  %s (%s) due to host timeout\n", currenths->name,
		   inet_ntoa(currenths->host));
	  log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Timeout", 
			   inet_ntoa(currenths->host), currenths->name);
	}
	else if (!o.pingscan) {
	  assignignoredportstate(&currenths->ports);
	  printportoutput(currenths, &currenths->ports);
	  resetportlist(&currenths->ports);
	  
	  if (o.osscan) {
	    if (currenths->seq.responses > 3) {
	      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"%s", seqreport(&(currenths->seq)));
	      log_write(LOG_MACHINE,"\tSeq Index: %d", currenths->seq.index);
	    }
	    if (currenths->FP_matches[0]) {
	      log_write(LOG_MACHINE,"\tOS: %s",  currenths->FP_matches[0]->OS_name);
	      i = 1;
	      while(currenths->FP_matches[i]) {
		log_write(LOG_MACHINE,"|%s", currenths->FP_matches[i]->OS_name);
		i++;
	      }
	      if (!currenths->FP_matches[1])
		log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Remote operating system guess: %s", 
			 currenths->FP_matches[0]->OS_name);
	      else  {
		log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Remote OS guesses: %s", 
			 currenths->FP_matches[0]->OS_name);
		i = 1;
		while(currenths->FP_matches[i]) {
		  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,", %s", currenths->FP_matches[i]->OS_name);
		  i++;
		}
	      }
	      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"\n");	  
	      if (currenths->goodFP >= 0 && (o.debugging || o.verbose > 1)) {
		log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"OS Fingerprint:\n%s\n", fp2ascii(currenths->FPs[currenths->goodFP]));
	      }
	      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"\n");
	    } else {
	      if (currenths->goodFP == ENOMATCHESATALL && o.scan_delay < 500) {
		log_write(LOG_NORMAL|LOG_SKID_NOXLT|LOG_STDOUT,"No OS matches for host (If you know what OS is running on it, see http://www.insecure.org/cgi-bin/nmap-submit.cgi).\nTCP/IP fingerprint:\n%s\n\n", mergeFPs(currenths->FPs, currenths->numFPs));
	      } else if (currenths->goodFP == ETOOMANYMATCHES) {
		log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Too many fingerprints match this host for me to give an accurate OS guess\n");
		if (o.debugging || o.verbose) {
		  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"TCP/IP fingerprint:\n%s\n\n",  mergeFPs(currenths->FPs, currenths->numFPs));
		}
	      }
	    }
	    for(i=0; i < currenths->numFPs; i++)
	      freeFingerPrint(currenths->FPs[i]);
	  }
	}

	if (o.debugging) log_write(LOG_STDOUT, "Final times for host: srtt: %d rttvar: %d  to: %d\n", currenths->to.srtt, currenths->to.rttvar, currenths->to.timeout);
	log_write(LOG_MACHINE,"\n");
      }
      log_flush_all();
      if (*currenths->name) free(currenths->name);
    }
    /* Free my host expressions */
    for(i=0; i < num_host_exp_groups; i++)
      free(host_exp_group[i]);
    num_host_exp_groups = 0;
  }
  free(host_exp_group);
  timep = time(NULL);
  i = timep - starttime;
  if (numhosts_scanned == 1 && numhosts_up == 0)
    log_write(LOG_STDOUT, "Note: Host seems down. If it is really up, but blocking our ping probes, try -P0\n");
  log_write(LOG_STDOUT|LOG_SKID, "Nmap run completed -- %d %s (%d %s up) scanned in %d %s\n", numhosts_scanned, (numhosts_scanned == 1)? "IP address" : "IP addresses", numhosts_up, (numhosts_up == 1)? "host" : "hosts",  i, (i == 1)? "second": "seconds");


  Strncpy(mytime, ctime(&timep), sizeof(mytime));
  chomp(mytime);
  
  log_write(LOG_NORMAL|LOG_MACHINE, "# Nmap run completed at %s -- %d %s (%d %s up) scanned in %d %s\n", mytime, numhosts_scanned, (numhosts_scanned == 1)? "IP address" : "IP addresses", numhosts_up, (numhosts_up == 1)? "host" : "hosts",  i, (i == 1)? "second": "seconds");


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
  unsigned char *p, *q, *found; /* I love C! */
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
  while(*p && !isspace(*p))
    p++;
  if (!*p) fatal("Unable to parse supposed log file %s.  Sorry", fname);
  p++; /* Skip the space between program name and first arg */
  if (*p == '\n' || !*p) fatal("Unable to parse supposed log file %s.  Sorry", fname);

  q = strchr(p, '\n');
  if (!q || (q - p >= sizeof(nmap_arg_buffer) - 32))
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
  o.isr00t = !(geteuid());
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

}

inline void max_rcvbuf(int sd) {
  int optval = 524288 /*2^19*/, optlen = sizeof(int);

  if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (void *) &optval, optlen))
    if (o.debugging) perror("Problem setting large socket recieve buffer");
  if (o.debugging) {
    getsockopt(sd, SOL_SOCKET, SO_RCVBUF,(void *) &optval, &optlen);
    log_write(LOG_STDOUT, "Our buffer size is now %d\n", optval);
  }
}
/* Maximize the open file descriptor limit for this process go up to the
   max allowed  */
int max_sd() {
  struct rlimit r;
  static int maxfds = -1;

  if (maxfds > 0)
    return maxfds;

#if(defined(RLIMIT_NOFILE))
  if (!getrlimit(RLIMIT_NOFILE, &r)) {
    r.rlim_cur = r.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &r))
      if (o.debugging) perror("setrlimit RLIMIT_NOFILE failed");
    if (!getrlimit(RLIMIT_NOFILE, &r)) {
      maxfds =  MIN(r.rlim_cur, MAX_SOCKETS_ALLOWED);
      /* I do not feel comfortable going over 255 for now .. */
      maxfds = MIN(maxfds, 250);
      return maxfds;
    } else return 0;
  }
#endif
#if(defined(RLIMIT_OFILE) && !defined(RLIMIT_NOFILE))
  if (!getrlimit(RLIMIT_OFILE, &r)) {
    r.rlim_cur = r.rlim_max;
    if (setrlimit(RLIMIT_OFILE, &r))
      if (o.debugging) perror("setrlimit RLIMIT_OFILE failed");
    if (!getrlimit(RLIMIT_OFILE, &r)) {
      maxfds =  MIN(r.rlim_cur, MAX_SOCKETS_ALLOWED);
      /* I do not feel comfortable going over 255 for now .. */
      maxfds = MIN(maxfds, 250);
      return maxfds;
    }
    else return 0;
  }
#endif
  return 0;
}

inline int block_socket(int sd) {
  int options;
  options = (~O_NONBLOCK) & fcntl(sd, F_GETFL);
  fcntl(sd, F_SETFL, options);
  return 1;
}

inline void broadcast_socket(int sd) {
  int one = 1;
  if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, (void *)&one, sizeof(int)) != 0) {
    fprintf(stderr, "Failed to secure socket broadcasting permission\n");
    perror("setsockopt");
  }
}

/* We set the socket lingering so we will RST connection instead of wasting
   bandwidth with the four step close  */
inline void init_socket(int sd) {
  struct linger l;
  int res;
  static int bind_failed=0;
  struct sockaddr_in sin;

  l.l_onoff = 1;
  l.l_linger = 0;

  if (setsockopt(sd, SOL_SOCKET, SO_LINGER,  (void *) &l, sizeof(struct linger)))
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
unsigned short *getpts(char *origexpr) {
  unsigned char porttbl[65536];
  int portwarning = 0; /* have we warned idiot about dup ports yet? */
  long rangestart = -2343242, rangeend = -9324423;
  unsigned char *current_range;
  char *endptr;
  int i;
  unsigned short *ports;

  bzero(porttbl, sizeof(porttbl));
  o.numports = 0;

  current_range = origexpr;
  do {
    while(isspace(*current_range))
      current_range++; /* I don't know why I should allow spaces here, but I will */
    if (*current_range == '-') {
      rangestart = 1;
    }
    else if (isdigit(*current_range)) {
      rangestart = strtol(current_range, &endptr, 10);
      if (rangestart <= 0 || rangestart > 65535) {
	fatal("Ports to be scanned must be between 1 and 65535 inclusive");
      }
      current_range = endptr;
      while(isspace(*current_range)) current_range++;
    } else {
      fatal("Your port specifications are illegal.  Example of proper form: \"-100,200-1024,3000-4000,60000-\"");
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
      } else if (isdigit(*current_range)) {
	rangeend = strtol(current_range, &endptr, 10);
	if (rangeend <= 0 || rangeend > 65535) {
	  fatal("Ports to be scanned must be between 1 and 65535 inclusive");
	}
	current_range = endptr;
      } else {
	fatal("Your port specifications are illegal.  Example of proper form: \"-100,200-1024,3000-4000,60000-\"");
      }
    }

    /* Now I have a rangestart and a rangeend, so I can add these ports */
    while(rangestart <= rangeend) {
      if (porttbl[rangestart]) {      
	if (!portwarning) {
	  error("WARNING:  Duplicate port number(s) specified.  Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm).");
	  portwarning++;
	} 
      } else o.numports++;
      porttbl[rangestart] = 1;
      rangestart++;
    }
    
    /* Find the next range */
    while(isspace(*current_range)) current_range++;
    if (*current_range && *current_range != ',') {
      fatal("Your port specifications are illegal.  Example of proper form: \"-100,200-1024,3000-4000,60000-\"");
    }
    if (*current_range == ',')
      current_range++;
  } while(current_range && *current_range);

  if (o.numports == 0)
    fatal("No ports specified -- If you really don't want to scan any ports use ping scan...");

  ports = safe_malloc(sizeof(unsigned short ) * (o.numports + 1));
  bzero(ports, sizeof(unsigned short ) * (o.numports + 1));

  /* I is the next index into which we should add good ports */
  for(i=0, rangestart = 1; i < o.numports ; rangestart++) {
    assert(rangestart <= 65535);
    if (porttbl[rangestart]) {
      ports[i++] = rangestart;
    }
  }

  ports[o.numports] = 0; /* Someday I am going to make sure this isn't neccessary
			    and then I will start allowing (invalid) port 0 scans */
  return ports;
}

void printusage(char *name, int rc) {
  printf(
	 "nmap V. %s Usage: nmap [Scan Type(s)] [Options] <host or net list>\n"
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
	 "  -oN/-oM <logfile> Output normal/machine parsable scan logs to <logfile>\n"
	 "  -iL <inputfile> Get targets from file; Use '-' for stdin\n"
	 "* -S <your_IP>/-e <devicename> Specify source address or network interface\n"
	 "  --interactive Go into interactive mode (then press h for help)\n"
	 "Example: nmap -v -sS -O www.my.com 192.168.0.0/16 '192.88-90.*.*'\n"
	 "SEE THE MAN PAGE FOR MANY MORE OPTIONS, DESCRIPTIONS, AND EXAMPLES \n", VERSION);
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
file for results (with -oM or -oN).  If you specify\n\
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

  snprintf(report, sizeof(report), "TCP Sequence Prediction: Class=%s\n                         Difficulty=%d (%s)\n", seqclass2ascii(seq->class), seq->index, (seq->index < 10)? "Trivial joke" : (seq->index < 80)? "Easy" : (seq->index < 3000)? "Medium" : (seq->index < 5000)? "Formidable" : (seq->index < 100000)? "Worthy challenge" : "Good luck!");
  if (o.verbose) {
    tmp[0] = '\n';
    tmp[1] = '\0'; 
    p = tmp + 1;
    strcpy(p, "Sequence numbers: ");
    p += 18;
    for(i=0; i < seq->responses; i++) {
      p += snprintf(p, 16, "%X ", seq->seqs[i]);
    }
    *--p = '\n';
    strcat(report, tmp);
  }
  return report;
}

char *seqclass2ascii(int class) {
  switch(class) {
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
    return "Error, WTF?";
  }
}

char *grab_next_host_spec(FILE *inputfd, int argc, char **fakeargv) {
  static char host_spec[512];
  int host_spec_index;
  int ch;
  unsigned char *ipc;
  struct in_addr ip;

  if (o.generate_random_ips) {
    do {    
      ipc = (unsigned char *) &ip.s_addr;
      get_random_bytes(ipc, 4);
    } while(ipc[0] == 10 || ipc[0] > 224 || ipc[0] == 127 || !ipc[0]); /* Skip these private, multicast, reserved, and localhost addresses */
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


void printportoutput(struct hoststruct *currenths, portlist *plist) {
  char protocol[4];
  char rpcinfo[64];
  char rpcmachineinfo[64];
  char portinfo[64];
  char *state;
  char serviceinfo[64];
  char *name;
  int first = 1;
  struct servent *service;
  struct port *current;
  int numignoredports;
  int portno, protocount;
  struct port **protoarrays[2];

  numignoredports = plist->state_counts[plist->ignored_port_state];

  assert(numignoredports <= plist->numports);

  if (numignoredports == plist->numports) {
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,
              "%s %d scanned ports on %s (%s) %s: %s\n",
	      (numignoredports == 1)? "The" : "All", numignoredports,
	      currenths->name, 
	      inet_ntoa(currenths->host), 
	      (numignoredports == 1)? "is" : "are", 
	      statenum2str(currenths->ports.ignored_port_state));
    log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Up", 
	      inet_ntoa(currenths->host), currenths->name);
    return;
  }

  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Interesting ports on %s (%s):\n", currenths->name, 
	    inet_ntoa(currenths->host));
  log_write(LOG_MACHINE,"Host: %s (%s)", inet_ntoa(currenths->host), 
	    currenths->name);
  
  if (numignoredports > 0) {
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"(The %d %s scanned but not shown below %s in state: %s)\n", numignoredports, (numignoredports == 1)? "port" : "ports", (numignoredports == 1)? "is" : "are", statenum2str(plist->ignored_port_state));
  }

  if (!o.rpcscan) {  
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Port       State       Service");
  } else {
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Port       State       Service (RPC)");
  }
  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"%s", (o.identscan)?"         Owner\n":"\n");
  log_write(LOG_MACHINE,"\tPorts: ");
  
  protoarrays[0] = plist->tcp_ports;
  protoarrays[1] = plist->udp_ports;
  current = NULL;
  for(portno = 1; portno < 65536; portno++) {
    for(protocount = 0; protocount < 2; protocount++) {
      if (protoarrays[protocount] && protoarrays[protocount][portno]) 
	current = protoarrays[protocount][portno];
      else continue;
      
      if (current->state != plist->ignored_port_state) {    
	if (!first) log_write(LOG_MACHINE,", ");
	else first = 0;
	strcpy(protocol,(current->proto == IPPROTO_TCP)? "tcp": "udp");
	snprintf(portinfo, sizeof(portinfo), "%d/%s", current->portno, protocol);
	state = statenum2str(current->state);
	service = nmap_getservbyport(htons(current->portno), protocol);
	
	if (o.rpcscan) {
	  switch(current->rpc_status) {
	  case RPC_STATUS_UNTESTED:
	    rpcinfo[0] = '\0';
	    strcpy(rpcmachineinfo, "");
	    break;
	  case RPC_STATUS_UNKNOWN:
	    strcpy(rpcinfo, "(RPC (Unknown Prog #))");
	    strcpy(rpcmachineinfo, "R");
	    break;
	  case RPC_STATUS_NOT_RPC:
	    rpcinfo[0] = '\0';
	    strcpy(rpcmachineinfo, "N");
	    break;
	  case RPC_STATUS_GOOD_PROG:
	    name = nmap_getrpcnamebynum(current->rpc_program);
	    snprintf(rpcmachineinfo, sizeof(rpcmachineinfo), "(%s:%li*%i-%i)", (name)? name : "", current->rpc_program, current->rpc_lowver, current->rpc_highver);
	    if (!name) {
	      snprintf(rpcinfo, sizeof(rpcinfo), "(#%li (unknown) V%i-%i)", current->rpc_program, current->rpc_lowver, current->rpc_highver);
	    } else {
	      if (current->rpc_lowver == current->rpc_highver) {
		snprintf(rpcinfo, sizeof(rpcinfo), "(%s V%i)", name, current->rpc_lowver);
	      } else 
		snprintf(rpcinfo, sizeof(rpcinfo), "(%s V%i-%i)", name, current->rpc_lowver, current->rpc_highver);
	    }
	    break;
	  default:
	    fatal("Unknown rpc_status %d", current->rpc_status);
	    break;
	  }
	  snprintf(serviceinfo, sizeof(serviceinfo), "%s%s%s", (service)? service->s_name : ((*rpcinfo)? "" : "unknown"), (service)? " " : "",  rpcinfo);
	} else {
	  Strncpy(serviceinfo, (service)? service->s_name : "unknown" , sizeof(serviceinfo));
	  strcpy(rpcmachineinfo, "");
	}
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"%-11s%-12s%-24s", portinfo, state, serviceinfo);
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"%s\n", (current->owner)? current->owner : "");
	
	log_write(LOG_MACHINE,"%d/%s/%s/%s/%s/%s//", current->portno, state, 
		  protocol, (current->owner)? current->owner : "",
		  (service)? service->s_name: "", rpcmachineinfo);    
	
      }
    }
  }
  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"\n");
  log_write(LOG_MACHINE, "\tIgnored State: %s", statenum2str(plist->ignored_port_state));
}

/* This attempts to calculate the round trip time (rtt) to a host by timing a
   connect() to a port which isn't listening.  A better approach is to time a
   ping (since it is more likely to get through firewalls (note, this isn't
   always true nowadays --fyodor).  This is now 
   implemented in isup() for users who are root.  */
unsigned long calculate_sleep(struct in_addr target) {
  struct timeval begin, end;
  int sd;
  struct sockaddr_in sock;
  int res;

  if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {perror("Socket troubles"); exit(1);}

  sock.sin_family = AF_INET;
  sock.sin_addr.s_addr = target.s_addr;
  sock.sin_port = htons(o.magic_port);

  gettimeofday(&begin, NULL);
  if ((res = connect(sd, (struct sockaddr *) &sock, 
		     sizeof(struct sockaddr_in))) != -1)
    fprintf(stderr, "WARNING: You might want to use a different value of -g (or change o.magic_port in the include file), as it seems to be listening on the target host!\n");
  close(sd);
  gettimeofday(&end, NULL);
  if (end.tv_sec - begin.tv_sec > 5 ) /*uh-oh!*/
    return 0;
  return (end.tv_sec - begin.tv_sec) * 1000000 + (end.tv_usec - begin.tv_usec);
}

/* Checks whether the identd port (113) is open on the target machine.  No
   sense wasting time trying it for each good port if it is down! */

int check_ident_port(struct in_addr target) {
  int sd;
  char buf[4096];
  struct sockaddr_in sock;
  int res;
  struct sockaddr_in stranger;
  int sockaddr_in_len = sizeof(struct sockaddr_in);
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
      fprintf(stderr, "I have never seen this type of socket selectable for read only.  Please let me know how you did it and what OS you are running (fyodor@dhp.com).\n");
      goto success;
    }
    else {
      fprintf(stderr, "Wow, select blatantly lied to us!  Please let fyodor know what OS you are running (fyodor@dhp.com).\n");
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
int getidentinfoz(struct in_addr target, int localport, int remoteport,
		  char *owner) {
  int sd;
  struct sockaddr_in sock;
  int res;
  char request[16];
  char response[1024];
  char *p,*q;
  char  *os;

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
  else if ((res = read(sd, response, 1024)) == -1) {
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
	    strncpy(owner, p, 512);
	    owner[512] = '\0';
	  }
	}
      } 
    }  
  }
  return 1;
}


void super_scan(struct hoststruct *target, unsigned short *portarray, stype scantype) {
  int initial_packet_width;  /* How many scan packets in parallel (to start with) */
  int packet_incr = 4; /* How much we increase the parallel packets by each round */
  double fallback_percent = 0.7;
  int rawsd;
  char myname[513];
  int scanflags = 0;

  int dropped = 0;  /* These three are for UDP squelching */
  int freshportstried = 0;
  int senddelay = 0;
  pcap_t *pd;
  int bytes;
  struct ip *ip, *ip2;
  struct tcphdr *tcp;
  struct bpf_program fcode;
  char err0r[PCAP_ERRBUF_SIZE];
  char filter[512];
  char *p;
  int changed = 0;  /* Have we found new ports (or rejected earlier "found" ones) this round? */
  int numqueries_outstanding = 0; /* How many unexpired queries are on the 'net right now? */
  double numqueries_ideal; /* How many do we WANT to be on the 'net right now? */
  int max_width; /* No more packets than this at once, pleeze */
  int tries = 0;
  int tmp = 0;
  unsigned int localnet, netmask;
  int starttime;
  unsigned short newport;
  int newstate = 999; /* This ought to break something if used illegally */
  struct hostent *myhostent = NULL;
  struct portinfo *scan, *openlist, *current, *testinglist, *next;
  int portlookup[65536]; /* Indexes port number -> scan[] index */
  struct timeval now, end;
  int packcount, timedout;
  int UDPPacketWarning = 0;
  int i;
  unsigned short *data;
  int packet_trynum = 0;
  int windowdecrease = 0; /* Has the window been decreased this round yet? */
  struct icmp *icmp;
  int portno;
  struct port *current_port_tmp;

  if (target->timedout)
    return;

  if (o.debugging) 
    log_write(LOG_STDOUT, "Starting super_scan\n");

  max_width = (o.max_parallelism)? o.max_parallelism : 125;
  numqueries_ideal = initial_packet_width = MIN(max_width, 10);

  memset(portlookup, 255, 65536 * sizeof(int)); /* 0xffffffff better always be (int) -1 */
  scan = safe_malloc(o.numports * sizeof(struct portinfo));

  /* Initialize timeout info */
  /*
    target->to.srtt = (target->rtt > 0)? 4 * target->rtt : 1000000;
    target->to.rttvar = (target->rtt > 0)? target->rtt / 2 : 1000000;
    target->to.timeout = target->to.srtt + 4 * target->to.rttvar;
  */

  /* Initialize our portlist (scan) */
  for(i = 0; i < o.numports; i++) {
    scan[i].state = PORT_FRESH;
    scan[i].portno = portarray[i];
    scan[i].trynum = 0;
    scan[i].prev = i-1;
    if (i < o.numports -1 ) scan[i].next = i+1;
    else scan[i].next = -1;
    portlookup[portarray[i]] = i;
  }

  current = testinglist = &scan[0]; /* fresh == unscanned ports, testinglist is a list of all ports that haven't been determined to be closed yet */
  openlist = NULL; /* we haven't shown any ports to be open yet... */


    
  /* Init our raw socket */
  if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
    pfatal("socket troubles in super_scan");
  broadcast_socket(rawsd); /* This isn't pretty, but I don't have much of a
			      choice */
  /* No reason to do this since we don't receive on this socket,
     and it can cause ENOBUF errors if socket transmit buffers
     overflow 
     unblock_socket(rawsd);
  */

  /* Do we have a correct source address? */
  if (!target->source_ip.s_addr) {
    if (gethostname(myname, MAXHOSTNAMELEN) != 0 && 
	!((myhostent = gethostbyname(myname))))
      fatal("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n"); 
    memcpy(&target->source_ip, myhostent->h_addr_list[0], sizeof(struct in_addr));
    if (o.debugging || o.verbose) 
      log_write(LOG_STDOUT, "We skillfully deduced that your address is %s\n",
	      inet_ntoa(target->source_ip));
  }

  /* Now for the pcap opening nonsense ... */
  /* Note that the snaplen is 92 = 64 byte max IPhdr + 24 byte max link_layer
   * header + 4 bytes of TCP port info.
   */

  pd = my_pcap_open_live(target->device, 92,  (o.spoofsource)? 1 : 0, 10);

  if (pcap_lookupnet(target->device, &localnet, &netmask, err0r) < 0)
    fatal("Failed to lookup device subnet/netmask: %s", err0r);
  p = strdup(inet_ntoa(target->host));
  snprintf(filter, sizeof(filter), "(icmp and dst host %s) or (tcp and src host %s and dst host %s and ( dst port %d or dst port %d))", inet_ntoa(target->source_ip), p, inet_ntoa(target->source_ip), o.magic_port , o.magic_port + 1);
  free(p);
  /* Due to apparent bug in libpcap */
  if (islocalhost(&(target->host)))
    filter[0] = '\0';

  if (o.debugging)
    log_write(LOG_STDOUT, "Packet capture filter: %s\n", filter);
  if (pcap_compile(pd, &fcode, filter, 0, netmask) < 0)
    fatal("Error compiling our pcap filter: %s\n", pcap_geterr(pd));
  if (pcap_setfilter(pd, &fcode) < 0 )
    fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));
 
  if (scantype == XMAS_SCAN) scanflags = TH_FIN|TH_URG|TH_PUSH;
  else if (scantype == NULL_SCAN) scanflags = 0;
  else if (scantype == FIN_SCAN) scanflags = TH_FIN;
  else if (scantype == MAIMON_SCAN) scanflags = TH_FIN|TH_ACK;
  else if (scantype != UDP_SCAN) { fatal("Unknown scan type for super_scan"); }

  starttime = time(NULL);

  if (o.debugging || o.verbose)
    log_write(LOG_STDOUT, "Initiating FIN,NULL, UDP, or Xmas stealth scan against %s (%s)\n", target->name, inet_ntoa(target->host));
  

  do {
    changed = 0;
    if (tries > 3 && senddelay == 0) senddelay = 10000; 
							   
    while(testinglist != NULL)  /* While we have live queries or more ports to scan */
      {
	/* Check the possible retransmissions first */
	gettimeofday(&now, NULL);

	/* Insure we haven't overrun our allotted time ... */
	if (o.host_timeout && numqueries_outstanding > 0 && (TIMEVAL_MSEC_SUBTRACT(now, target->host_timeout) >= 0))
	  {
	    target->timedout = 1;
	    goto superscan_timedout;
	  }

	for( current = testinglist; current ; current = next) {
	  next = (current->next > -1)? &scan[current->next] : NULL;
	  if (current->state == PORT_TESTING) {
	    if ( TIMEVAL_SUBTRACT(now, current->sent[current->trynum]) > target->to.timeout) {
	      if (current->trynum > 0) {
		/* We consider this port valid, move it to open list */
		if (o.debugging > 1) { log_write(LOG_STDOUT, "Moving port %lu to the open list\n", current->portno); }
		freshportstried--;
		current->state = PORT_OPEN;
		/* First delete from old list */
		if (current->next > -1) scan[current->next].prev = current->prev;
		if (current->prev > -1) scan[current->prev].next = current->next;
		if (current == testinglist)
		  testinglist = (current->next >= 0)?  &scan[current->next] : NULL;
		current->next = current->prev = -1;

		/* Now move into new list */
		if (!openlist) openlist = current;
		else {
		  current->next = openlist - scan;
		  openlist = current;
		  scan[current->next].prev = current - scan;	      
		}
		numqueries_outstanding--;
	      } else {
		/* Initial timeout ... we've got to resend */
		if (o.scan_delay) enforce_scan_delay(NULL);
		if (o.debugging > 1) { log_write(LOG_STDOUT, "Initial timeout, resending to portno %lu\n", current->portno); }
		current->trynum++;
		/* If they didn't specify the magic port, we use magic_port +1
		   so we can tell that it was a retransmit later */
		i = (o.magic_port_set)? o.magic_port : o.magic_port + 1;
		gettimeofday(&current->sent[1], NULL);
		now = current->sent[1];
		if (o.fragscan)
		  send_small_fragz_decoys(rawsd, &target->host, 0,i, current->portno, scanflags);
		else if (scantype != UDP_SCAN) 
		  send_tcp_raw_decoys(rawsd, &target->host, i, 
				      current->portno, 0, 0, scanflags, 0, NULL, 0,
				      0, 0);
		else send_udp_raw_decoys(rawsd, &target->host, i,
					 current->portno, NULL ,0);	      
		if (senddelay && scantype == UDP_SCAN) usleep(senddelay);
	      }
	    }
	  } else { 
	    /* current->state == PORT_FRESH */
	    /* OK, now we have gone through our list of in-transit queries, 
	       so now we try to send off new queries if we can ... */
	    if (numqueries_outstanding >= (int) numqueries_ideal) break;
	    if (o.scan_delay) enforce_scan_delay(NULL);
	    if (o.debugging > 1) log_write(LOG_STDOUT, "Sending initial query to port %lu\n", current->portno);
	    freshportstried++;
	    /* lets send a packet! */
	    current->state = PORT_TESTING;
	    /*	if (!testinglist) testinglist = current; */
	    numqueries_outstanding++;
	    gettimeofday(&current->sent[0], NULL);
	    if (o.fragscan)
	      send_small_fragz_decoys(rawsd, &target->host, 0, o.magic_port, current->portno, scanflags);
	    else if (scantype != UDP_SCAN) 
	      send_tcp_raw_decoys(rawsd, &target->host, o.magic_port, 
				  current->portno, 0, 0, scanflags, 0, NULL, 0, 0, 0);
	    else send_udp_raw_decoys(rawsd, &target->host, o.magic_port,
				     current->portno, NULL, 0);
	    if (scantype == UDP_SCAN && senddelay) usleep(senddelay);
	  }
	}

	if (o.debugging > 1) log_write(LOG_STDOUT, "Ideal number of queries: %d\n", (int) numqueries_ideal);
	tmp++;
	/* Now that we have sent the packets we wait for responses */
	windowdecrease = 0;
	timedout = packcount = 0;
	gettimeofday(&now, NULL);
	if (o.host_timeout && (TIMEVAL_MSEC_SUBTRACT(now, target->host_timeout) >= 0))
	  {
	    target->timedout = 1;
	    goto superscan_timedout;
	  }
	while (!timedout && numqueries_outstanding > 0 && ( ip = (struct ip*) readip_pcap(pd, &bytes, target->to.timeout)))
	  {
	    if (++packcount >= 30) {
	      /* We don't want to allow for the possibility if this going
		 forever */
	      gettimeofday(&end, NULL);
	      if (TIMEVAL_SUBTRACT(end, now) > 8000000)
		timedout = 1;
	    }
	    if (bytes < (4 * ip->ip_hl) + 4)
	      continue;	
	    current = NULL;
	    if (ip->ip_p == IPPROTO_ICMP ||
		ip->ip_src.s_addr == target->host.s_addr) {
	      if (ip->ip_p == IPPROTO_TCP) {
		tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
		if (tcp->th_flags & TH_RST) {	    
		  newstate = PORT_CLOSED;
		  newport = ntohs(tcp->th_sport);
		  if (portlookup[newport] < 0) {
		    if (o.debugging) {
		      log_write(LOG_STDOUT, "Strange packet from port %d:\n", ntohs(tcp->th_sport));
		      readtcppacket((char *)ip, bytes);
		    }
		    current = NULL;
		    continue;
		  }	  
		  current = &scan[portlookup[newport]];
		
		  if (ntohs(tcp->th_dport) != o.magic_port && 
		      ntohs(tcp->th_dport) != o.magic_port + 1) {
		    if (o.debugging)  {		
		      error("BAD TCP packet detected to port %d from port %d", ntohs(tcp->th_dport), newport);
		    }
		    continue;		
		  }
		
		  if (current->state != PORT_TESTING && o.debugging) {
		    error("TCP packet detected from port %d which is in state %d (should usually be PORT_TESTING (but not always)", 
			  newport, current->state); 
		  }
		
		  if (!o.magic_port_set) {
		    packet_trynum = ntohs(tcp->th_dport) - o.magic_port;
		    if ((packet_trynum|1) != 1) packet_trynum = -1;
		  }  else packet_trynum = -1;
		  if (current->trynum == 0) packet_trynum = 0;
		} else { continue; } /* Wrong TCP flags */
	      
	      } else if (ip->ip_p == IPPROTO_ICMP) {
		icmp = (struct icmp *) ((char *)ip + 4 * ip->ip_hl);
		ip2 = (struct ip *) (((char *) icmp) + 8);
		if (ip2->ip_dst.s_addr != target->host.s_addr)
		  continue;
		data = (unsigned short *) ((char *)ip2 + 4 * ip2->ip_hl);
		/*	    log_write(LOG_STDOUT, "Caught ICMP packet:\n");
			    hdump(icmp, ntohs(ip->ip_len) - sizeof(struct ip)); */
		if (icmp->icmp_type == 3) {
		  newport = ntohs(data[1]);
		  if (portlookup[newport] < 0) {
		    if (o.debugging) {
		      log_write(LOG_STDOUT, "Strange ICMP packet type 3 code %d related to port %d:\n", icmp->icmp_code, newport);
		      readtcppacket((char *)ip, bytes);		
		    }
		    continue;		
		  }
		  current = &scan[portlookup[newport]];
		  if (!o.magic_port_set) {
		    packet_trynum = ntohs(data[0]) - o.magic_port;
		    if ((packet_trynum|1) != 1) packet_trynum = -1;
		  } else {
		    if (current->trynum == 0)  {
		      packet_trynum = 0;
		    }
		    else packet_trynum = -1;
		  }
		
		  switch(icmp->icmp_code) {
		  
		  case 2: /* pr0t0c0l unreachable */
		    newstate = PORT_FIREWALLED;
		    break;
		  
		  case 3: /* p0rt unreachable */		
		    if (scantype == UDP_SCAN) {
		      newstate = PORT_CLOSED;
		    } else newstate = PORT_FIREWALLED;
		    break;
		  
		  case 9:
		  case 10:
		  case 13: /* Administratively prohibited packet */
		    newstate = PORT_FIREWALLED;
		    break;		
		  
		  default:
		    if (o.debugging) {
		      error("Received strange ICMP destunreach response -- code: %d", icmp->icmp_code);
		      hdump((unsigned char *)icmp, ntohs(ip->ip_len) - 
			    sizeof(struct ip));
		    }
		    continue;
		  }
		}
	      } else if (ip->ip_p == IPPROTO_UDP) {
		if (UDPPacketWarning == 0) {
		  UDPPacketWarning = 1;
		  if (o.debugging)
		    error("UDP packet received\n");
		}
		continue;
	      }
	    
	      if (current) {	  
		if (current->state == PORT_CLOSED && (packet_trynum < 0)) {
		  target->to.rttvar *= 1.2;
		  if (o.debugging) { log_write(LOG_STDOUT, "Late packet, couldn't figure out sendno so we do varianceincrease to %d\n", target->to.rttvar); 
		  }
		} 
		if (packet_trynum > -1) {		
		  /* Update our records */
		  adjust_timeouts(current->sent[packet_trynum], &(target->to));
		  numqueries_ideal = MIN(numqueries_ideal + (packet_incr/numqueries_ideal), max_width);
		  if (packet_trynum > 0 && current->trynum > 0) {
		    /* The first packet was apparently lost, slow down */
		    dropped++;
		    if (freshportstried > 50 && ((double) dropped/freshportstried) > 0.3) {
		      if (!senddelay) senddelay = 50000;
		      else senddelay = MIN(senddelay * 2, 1000000);
		      if (senddelay >= 200000 && scantype == UDP_SCAN)
			max_width = MIN(max_width,2);
		      freshportstried = 0;
		      dropped = 0;
		      if (o.verbose || o.debugging )  
			log_write(LOG_STDOUT, "Too many drops ... increasing senddelay to %d\n", senddelay);
		    }
		    if (windowdecrease == 0) {
		      numqueries_ideal *= fallback_percent;
		      if (numqueries_ideal < 1) numqueries_ideal = 1;
		      if (o.debugging) { log_write(LOG_STDOUT, "Lost a packet, decreasing window to %d\n", (int) numqueries_ideal);
		      windowdecrease++;
		      if (scantype == UDP_SCAN) usleep(250000);
		      }
		    } else if (o.debugging > 1) { 
		      log_write(LOG_STDOUT, "Lost a packet, but not decreasing\n");
		    }
		  }
		}    
		if (current->state != newstate) {
		  changed++;
		}
		if (current->state != PORT_OPEN && 
		    current->state != PORT_CLOSED) {	    
		  numqueries_outstanding--;
		}
		if (current->state == PORT_TESTING && current == testinglist)
		  testinglist = (current->next >= 0)?  &scan[current->next] : NULL;
		else if (current->state == PORT_OPEN && current == openlist)
		  openlist = (current->next >= 0)? &scan[current->next] : NULL;
		if (current->next >= 0) scan[current->next].prev = current->prev;
		if (current->prev >= 0) scan[current->prev].next = current->next;
		current->next = current->prev = -1;
		current->state = newstate;
		addport(&target->ports, current->portno, 
			(scantype == UDP_SCAN)? IPPROTO_UDP : IPPROTO_TCP, 
			NULL, current->state);	      
	      }
	    }
	  }
      } 
  
    
    /* Prepare for retry */
    testinglist = openlist;
    for(current = openlist; current; current = (current->next >= 0)? &scan[current->next] : NULL) {
      current->state = PORT_FRESH;
      current->trynum = 0;
      if (o.debugging) { 
	log_write(LOG_STDOUT, "Preparing for retry, open port %lu noted\n", current->portno); 
      }
    }
    
    openlist = NULL;
    numqueries_ideal = initial_packet_width;
    if (o.debugging)
      log_write(LOG_STDOUT, "Done with round %d\n", tries);
    if (scantype == UDP_SCAN && changed && (tries + 1) < 100) {
      if (o.debugging) {
	log_write(LOG_STDOUT, "Sleeping for 1/2 second to overcome ICMP error rate limiting\n");
      }
      usleep(500000);
    }
  } while(changed && ++tries < 100);   

  openlist = testinglist;

  if (o.debugging || o.verbose)
    log_write(LOG_STDOUT, "The UDP or stealth FIN/NULL/XMAS scan took %ld %s to scan %d ports.\n", 
	    (long) time(NULL) - starttime, (((long) time(NULL) - starttime) == 1)? "second" : "seconds",  o.numports);
  
  for (current = openlist; current;  current = (current->next >= 0)? &scan[current->next] : NULL) {
    if (scantype != UDP_SCAN)
      addport(&target->ports, current->portno, IPPROTO_TCP, NULL, PORT_OPEN);
    else
      addport(&target->ports, current->portno, IPPROTO_UDP, NULL, PORT_OPEN);
  }

 superscan_timedout:

  free(scan);
  close(rawsd);
  pcap_close(pd);

  /* Super scan relies on us receiving a response if the port is
     CLOSED and no response if the port is OPEN.  A problem with
     this is that when a machine is doing heavy filtering, all ports
     will seem to be open.  Thus we add a little metric: if > 25
     ports were scanned and they are ALL considered open by this
     function, then it is reasonably to assume that the REAL reason
     they are all open is that they have been filtered. */
  if (o.numports > 25) {    
    if (scantype == UDP_SCAN) {
      if (target->ports.state_counts_udp[PORT_OPEN] == o.numports) {
	if (o.verbose) { 
	  error("(no udp responses received -- assuming all ports filtered)");
	}
	for(portno = 0; portno < 65536; portno++)
	  {
	    current_port_tmp = lookupport(&target->ports, portno, IPPROTO_UDP);
	    if (current_port_tmp) {
	      assert(current_port_tmp->state == PORT_OPEN);
	      current_port_tmp->state = PORT_FIREWALLED;
	      target->ports.state_counts[PORT_OPEN]--;
	      target->ports.state_counts[PORT_FIREWALLED]++;
	      target->ports.state_counts_udp[PORT_OPEN]--;
	      target->ports.state_counts_udp[PORT_FIREWALLED]++;
	    }
	  }
      }
    } else { 
      if (target->ports.state_counts_tcp[PORT_OPEN] == o.numports) {
	if (o.verbose) { 
	  error("(no tcp responses received -- assuming all ports filtered)");
	}
	for(portno = 0; portno < 65536; portno++)
	  {
	    current_port_tmp = lookupport(&target->ports, portno, IPPROTO_TCP);
	    if (current_port_tmp) {
	      assert(current_port_tmp->state == PORT_OPEN);
	      current_port_tmp->state = PORT_FIREWALLED;
	      target->ports.state_counts[PORT_OPEN]--;
	      target->ports.state_counts[PORT_FIREWALLED]++;
	      target->ports.state_counts_tcp[PORT_OPEN]--;
	      target->ports.state_counts_tcp[PORT_FIREWALLED]++;
	    }
	  }
      }
    }
  }
  return;
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

void pos_scan(struct hoststruct *target, unsigned short *portarray, stype scantype) {
  int initial_packet_width;  /* How many scan packets in parallel (to start with) */
  struct scanstats ss;
  int rawsd;
  char myname[513];
  int scanflags = 0;
  int victim;
  int senddelay = 0;
  pcap_t *pd = NULL;
  struct bpf_program fcode;
  char err0r[PCAP_ERRBUF_SIZE];
  char filter[512];
  char *p;
  unsigned int ack_number = 0;
  int tries = 0;
  int  res;
  int connecterror = 0;
  unsigned int localnet, netmask;
  int starttime;
  struct hostent *myhostent = NULL;
  struct sockaddr_in sock;
  struct portinfo *scan = NULL,  *current, *next;
  struct portinfolist pil;
  int portlookup[65536]; /* Indexes port number -> scan[] index */
  struct timeval now;
  struct connectsockinfo csi;
  struct rpcscaninfo rsi;
  unsigned long sequences[3]; /* for various reasons we use 3 separate
				 ones rather than simply incrementing from
				 a base */
  int i;

  if (target->timedout)
    return;

  if (o.debugging)
    log_write(LOG_STDOUT, "Starting pos_scan\n");

  if (scantype == RPC_SCAN) initial_packet_width = 2;
  else initial_packet_width = 10;

  ss.packet_incr = 4;
  ss.fallback_percent = 0.7;
  ss.numqueries_outstanding = 0;
  ss.ports_left = o.numports;
  ss.alreadydecreasedqueries = 0;

  bzero(&pil, sizeof(pil));

  FD_ZERO(&csi.fds_read);
  FD_ZERO(&csi.fds_write);
  FD_ZERO(&csi.fds_except);
  csi.maxsd = 0;

  /* Start the firewall mode with a clean slate ... */
  target->firewallmode.active = 0;
  target->firewallmode.nonresponsive_ports = 0;
  target->firewallmode.responsive_ports = 0;

  if (o.max_parallelism) {
    ss.max_width = o.max_parallelism;
  } else {
    if (scantype == CONNECT_SCAN) {
      ss.max_width = MAX(5, max_sd() - 4);
    } else {
      ss.max_width = 150;
    }
  }

  if (initial_packet_width > ss.max_width)
    initial_packet_width = ss.max_width;
  ss.numqueries_ideal = initial_packet_width;

  memset(portlookup, 255, 65536 * sizeof(int)); /* 0xffffffff better always be (int) -1 */
  bzero(csi.socklookup, sizeof(csi.socklookup));

  if (scantype != RPC_SCAN) {
    /* Initialize our portlist (scan) */
    scan = safe_malloc(o.numports * sizeof(struct portinfo));
    for(i = 0; i < o.numports; i++) {
      scan[i].state = PORT_FRESH;
      scan[i].portno = portarray[i];
      scan[i].trynum = 0;
      scan[i].prev = i-1;
      scan[i].sd[0] = scan[i].sd[1] = scan[i].sd[2] = -1;
      if (i < o.numports -1 ) scan[i].next = i+1;
      else scan[i].next = -1;
      portlookup[portarray[i]] = i;
    }
    current = pil.testinglist = &scan[0]; /* testinglist is a list of all 
					     ports that haven't been determined 					    to be closed yet */
  }
   
  /* Init our raw socket */
  if ((scantype == SYN_SCAN) || (scantype == WINDOW_SCAN) || 
      (scantype == ACK_SCAN)) {  
    if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
      pfatal("socket troubles in pos_scan");
    /* We do not wan't to unblock the socket since we want to wait 
       if kernel send buffers fill up rather than get ENOBUF, and
       we won't be receiving on the socket anyway 
       unblock_socket(rawsd);*/

    broadcast_socket(rawsd);
    

    /* Init ISNs */
    get_random_bytes(sequences, sizeof(sequences));

    /* Do we have a correct source address? */
    if (!target->source_ip.s_addr) {
      if (gethostname(myname, MAXHOSTNAMELEN) != 0 && 
	  !((myhostent = gethostbyname(myname))))
	fatal("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n"); 
      memcpy(&target->source_ip, myhostent->h_addr_list[0], sizeof(struct in_addr));
      if (o.debugging || o.verbose) 
	log_write(LOG_STDOUT, "We skillfully deduced that your address is %s\n",
		inet_ntoa(target->source_ip));
    }
    
    /* Now for the pcap opening nonsense ...
       Note that the snaplen is 100 = 64 byte max IPhdr + 24 byte max 
       link_layer header + first 12 bytes of TCP header.
    */
    
    pd = my_pcap_open_live(target->device, 100,  (o.spoofsource)? 1 : 0, 20);
    
    if (pcap_lookupnet(target->device, &localnet, &netmask, err0r) < 0)
      fatal("Failed to lookup device subnet/netmask: %s", err0r);
    p = strdup(inet_ntoa(target->host));
    snprintf(filter, sizeof(filter), "(icmp and dst host %s) or (tcp and src host %s and dst host %s)", inet_ntoa(target->source_ip), p, inet_ntoa(target->source_ip));
    free(p);

    /* Due to apparent bug in libpcap */
    if (islocalhost(&(target->host)))
      filter[0] = '\0';
     
    if (o.debugging)
      log_write(LOG_STDOUT, "Packet capture filter: %s\n", filter);
    if (pcap_compile(pd, &fcode, filter, 0, netmask) < 0)
      fatal("Error compiling our pcap filter: %s\n", pcap_geterr(pd));
    if (pcap_setfilter(pd, &fcode) < 0 )
      fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));
    if (scantype == SYN_SCAN)
      scanflags = TH_SYN;
    else
      scanflags = TH_ACK;
  } else if (scantype == CONNECT_SCAN) {
    rawsd = -1;
    /* Init our sock */
    bzero((char *)&sock,sizeof(struct sockaddr_in));
    sock.sin_addr.s_addr = target->host.s_addr;
    sock.sin_family=AF_INET;
  } else {
    /* RPC Scan */
    get_rpc_procs(&(rsi.rpc_progs), &(rsi.rpc_number));
    scan = safe_malloc(rsi.rpc_number * sizeof(struct portinfo));
    for(i = 0; i < rsi.rpc_number; i++) {
      scan[i].state = PORT_FRESH;
      scan[i].portno = rsi.rpc_progs[i];
      scan[i].trynum = 0;
      scan[i].prev = i-1;
      scan[i].sd[0] = scan[i].sd[1] = scan[i].sd[2] = -1;
      if (i < rsi.rpc_number -1 ) scan[i].next = i+1;
      else scan[i].next = -1;
    }
    current = pil.testinglist = &scan[0]; 
    rawsd = -1;
    rsi.rpc_current_port = nextport(&target->ports, NULL, 0, PORT_OPEN);
  }

  starttime = time(NULL);

  if (o.debugging || o.verbose) {  
    if (scantype == SYN_SCAN)
      log_write(LOG_STDOUT, "Initiating SYN half-open stealth scan against %s (%s)\n", target->name, inet_ntoa(target->host));
    else if (scantype == CONNECT_SCAN)
      log_write(LOG_STDOUT, "Initiating TCP connect() scan against %s (%s)\n",target->name, inet_ntoa(target->host)); 
    else if (scantype == WINDOW_SCAN) {    
      log_write(LOG_STDOUT, "Initiating Window scan against %s (%s)\n",target->name, inet_ntoa(target->host));
      ack_number = get_random_uint();
    }
    else if (scantype == ACK_SCAN) {    
      log_write(LOG_STDOUT, "Initiating ACK scan against %s (%s)\n",target->name, inet_ntoa(target->host));
      /* WE WANT TO ACK SCAN ACKNOWLEDGEMENT NUMBER TO LOOK AT LEAST A LITTLE
	 BIT RANDOM (even though it will be constant throughout a session) */
      ack_number = get_random_uint();
    }
    else {
      log_write(LOG_STDOUT, "Initiating RPC scan against %s (%s)\n",target->name, inet_ntoa(target->host)); 
    }
  }

  do {
    ss.changed = 0;
    if (tries > 3 && tries < 10) {
      senddelay += 10000 * (tries - 3); 
      if (o.verbose) log_write(LOG_STDOUT, "Bumping up senddelay by %d (to %d), due to excessive drops\n", 10000 * (tries - 3), senddelay);
    } else if (tries >= 10) {
      senddelay += 75000; 
      if (o.verbose) log_write(LOG_STDOUT, "Bumping up senddelay by 75000 (to %d), due to excessive drops\n", senddelay);
    }
    
    if (senddelay > 200000) {
      ss.max_width = MIN(ss.max_width, 5);
    }

    if (target->timedout)
      goto posscan_timedout;

    /* Find a good port to scan if we are rpc scanning */
    if (scantype == RPC_SCAN) {    
      /* Make sure we have ports left to scan */
      rsi.rpc_current_port = nextport(&target->ports, rsi.rpc_current_port,
				      0, PORT_OPEN);
      if (!rsi.rpc_current_port) /* Woop!  Done! */ break;

      /* Reinit our testinglist so we try each RPC prog */
      pil.testinglist = &scan[0];
      rsi.valid_responses_this_port = 0;
      rsi.rpc_status = RPC_STATUS_UNKNOWN;
    }

    while(pil.testinglist != NULL)  /* While we have live queries or more ports to scan */
      {
	/* Check the possible retransmissions first */
	gettimeofday(&now, NULL);
      
	/* Insure we haven't overrun our allotted time ... */
	if (o.host_timeout && (TIMEVAL_MSEC_SUBTRACT(now, target->host_timeout) >= 0))
	  {
	    target->timedout = 1;
	    goto posscan_timedout;
	  }

	/* Check if we should be in firewall mode and occasionally make 
	   related adjustments*/
	check_firewallmode(target, &ss);

	for( current = pil.testinglist; current ; current = next) {
	  /* For each port or RPC program */
	  next = (current->next > -1)? &scan[current->next] : NULL;
	  if (current->state == PORT_TESTING) {
	    if ( TIMEVAL_SUBTRACT(now, current->sent[current->trynum]) > target->to.timeout) {
	      if (current->trynum > 1 ||
		  (current->trynum > 0 && target->firewallmode.active)) {
		/* No responses !#$!#@$ firewalled? */
		if (scantype == RPC_SCAN) {
		  if (rsi.valid_responses_this_port == 0) {	       
		    if (o.debugging) {
		      log_write(LOG_STDOUT, "RPC Scan giving up on port %hi proto %d due to repeated lack of response\n", rsi.rpc_current_port->portno,  rsi.rpc_current_port->proto);
		    }
		    rsi.rpc_status = RPC_STATUS_NOT_RPC;
		    break;
		  }
		  else {
		    /* I think I am going to slow down a little */
		    target->to.rttvar = MIN(2000000, target->to.rttvar * 1.2);
		  }	      
		}
		if (o.debugging) { log_write(LOG_STDOUT, "Moving port or prog %lu to the potentially firewalled list\n", current->portno); }
		target->firewallmode.nonresponsive_ports++;
		current->state = PORT_FIREWALLED; /* For various reasons */
		/* First delete from old list */
		if (current->next > -1) scan[current->next].prev = current->prev;
		if (current->prev > -1) scan[current->prev].next = current->next;
		if (current == pil.testinglist)
		  pil.testinglist = (current->next >= 0)?  &scan[current->next] : NULL;
		current->next = -1;
		current->prev = -1;
		/* Now move into new list */
		if (scantype != RPC_SCAN) {	      
		  if (!pil.firewalled) pil.firewalled = current;
		  else {
		    current->next = pil.firewalled - scan;
		    pil.firewalled = current;
		    scan[current->next].prev = current - scan;	      
		  }
		}
		if (scantype == CONNECT_SCAN) {
		  /* close the appropriate sd for each try */
		  for(i=0; i <= current->trynum; i++) {
		    if (current->sd[i] >= 0) {
		      csi.socklookup[current->sd[i]] = NULL;
		      FD_CLR(current->sd[i], &csi.fds_read);
		      FD_CLR(current->sd[i], &csi.fds_write);
		      FD_CLR(current->sd[i], &csi.fds_except);
		      close(current->sd[i]);
		      current->sd[i] = -1;
		      ss.numqueries_outstanding--;
		    }
		  }
		} else { ss.numqueries_outstanding--; }
	      } else {  /* timeout ... we've got to resend */
		if (o.scan_delay) enforce_scan_delay(NULL);
		if (o.debugging > 1) { log_write(LOG_STDOUT, "Timeout, resending to portno/progno %lu\n", current->portno); }
		current->trynum++;
		gettimeofday(&current->sent[current->trynum], NULL);
		now = current->sent[current->trynum];
		if ((scantype == SYN_SCAN) || (scantype == WINDOW_SCAN) || (scantype == ACK_SCAN)) {	      
		  if (o.fragscan)
		    send_small_fragz_decoys(rawsd, &target->host, sequences[current->trynum], o.magic_port + tries * 3 + current->trynum, current->portno, scanflags);
		  else 
		    send_tcp_raw_decoys(rawsd, &target->host, o.magic_port + 
					tries * 3 + current->trynum, 
					current->portno, 
					sequences[current->trynum], 
					ack_number, scanflags, 0, NULL, 0, 0, 
					0);

		} else if (scantype == RPC_SCAN) {
		  if (send_rpc_query(&target->host, rsi.rpc_current_port->portno,
				     rsi.rpc_current_port->proto, 
				     current->portno, current - scan, 
				     current->trynum) == -1) {
		    /* Futz, I'll give up on this guy ... */
		    rsi.rpc_status = RPC_STATUS_NOT_RPC;
		    break;
		  }
		} else { /* Connect scan */
		  /* Unfortunately, retries cost us a socket!  If we are
		     out of sockets, we must drop one of our earlier tries
		     :( */
		  if (ss.numqueries_outstanding >= ss.max_width) {		
		    victim = -1;
		    for(i=0; i < current->trynum; i++)
		      if (current->sd[i] >= 0) {
			victim = i;
			break;
		      }
		    if (victim == -1) 
		      fatal("Illegal situation in pos_scan -- please report to fyodor@dhp.com");
		    csi.socklookup[current->sd[victim]] = NULL;
		    FD_CLR(current->sd[victim], &csi.fds_read);
		    FD_CLR(current->sd[victim], &csi.fds_write);
		    FD_CLR(current->sd[victim], &csi.fds_except);
		    close(current->sd[victim]);
		    current->sd[victim] = -1;
		  } else {
		    ss.numqueries_outstanding++;
		  }
		  res = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		  if (res == -1) pfatal("Socket troubles in pos_scan 143");
		  csi.socklookup[res] = current;
		  unblock_socket(res);
		  init_socket(res);
		  sock.sin_port = htons(current->portno);
		  current->sd[current->trynum] = res;		
		  res =  connect(res,(struct sockaddr *)&sock,sizeof(struct sockaddr));
		  if (res != -1) {
		    posportupdate(target, current, current->trynum, scan, &ss, scantype, PORT_OPEN, &pil, &csi);
		  } else {
		    switch(errno) {
		    case EINPROGRESS: /* The one I always see */
		    case EAGAIN:
		      /* GOOD REASON FOR THIS????block_socket(sockets[current_socket]); */
		      if (csi.maxsd < current->sd[current->trynum])
			csi.maxsd = current->sd[current->trynum];
		      FD_SET( current->sd[current->trynum], &csi.fds_write);
		      FD_SET( current->sd[current->trynum], &csi.fds_read);
		      FD_SET( current->sd[current->trynum], &csi.fds_except);
		      break;
		    default:
		      if (!connecterror) {	
			connecterror++;
			fprintf(stderr, "Strange error from connect (%d):", errno);
			fflush(stdout);
			perror(""); /*falling through intentionally*/
		      }
		    case ECONNREFUSED:
		      posportupdate(target, current, current->trynum, scan, &ss, scantype, PORT_CLOSED, &pil, &csi);
		      break;
		    }  		  
		  }
		}
		if (senddelay) usleep(senddelay);
	      }
	    }
	  } else { 
	    if (current->state != PORT_FRESH) 
	      fatal("State mismatch!!@ %d", current->state);
	    /* current->state == PORT_FRESH */
	    /* OK, now we have gone through our list of in-transit queries, so now
	       we try to send off new queries if we can ... */
	    if (ss.numqueries_outstanding >= (int) ss.numqueries_ideal) break;
	    if (o.scan_delay) enforce_scan_delay(NULL);
	    if (o.debugging > 1) log_write(LOG_STDOUT, "Sending initial query to port/prog %lu\n", current->portno);
	    /* Otherwise lets send a packet! */
	    current->state = PORT_TESTING;
	    current->trynum = 0;
	    /*	if (!testinglist) testinglist = current; */
	    ss.numqueries_outstanding++;
	    gettimeofday(&current->sent[0], NULL);
	    if ((scantype == SYN_SCAN) || (scantype == WINDOW_SCAN) || 
		(scantype == ACK_SCAN)) {	  
	      if (o.fragscan)
		send_small_fragz_decoys(rawsd, &target->host, sequences[current->trynum], o.magic_port + tries * 3, current->portno, scanflags);
	      else
		send_tcp_raw_decoys(rawsd, &target->host, 
				    o.magic_port + tries * 3, current->portno,
				    sequences[current->trynum], ack_number, 
				    scanflags, 0, NULL, 0, 0, 0);
	    } else if (scantype == RPC_SCAN) {
	      if (send_rpc_query(&target->host, rsi.rpc_current_port->portno,
				 rsi.rpc_current_port->proto, current->portno, 
				 current - scan, current->trynum) == -1) {
		/* Futz, I'll give up on this guy ... */
		rsi.rpc_status = RPC_STATUS_NOT_RPC;
		break;
	      }
	    } else { /* CONNECT SCAN */
	      res = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	      if (res == -1) pfatal("Socket troubles in pos_scan 11234");
	      csi.socklookup[res] = current;
	      unblock_socket(res);
	      init_socket(res);
	      sock.sin_port = htons(current->portno);
	      current->sd[current->trynum] = res;		
	      res =  connect(res,(struct sockaddr *)&sock,sizeof(struct sockaddr));
	      if (res != -1) {
		posportupdate(target, current, current->trynum, scan, &ss, scantype, PORT_OPEN, &pil, &csi);
	      } else {
		switch(errno) {
		case EINPROGRESS: /* The one I always see */
		case EAGAIN:
		  /* GOOD REASON FOR THIS????block_socket(sockets[current_socket]); */
		  if (csi.maxsd < current->sd[current->trynum])
		    csi.maxsd = current->sd[current->trynum];
		  FD_SET( current->sd[current->trynum], &csi.fds_write);
		  FD_SET( current->sd[current->trynum], &csi.fds_read);
		  FD_SET( current->sd[current->trynum], &csi.fds_except);
		  break;
		default:
		  if (!connecterror) {	
		    connecterror++;
		    fprintf(stderr, "Strange error from connect (%d):", errno);
		    fflush(stdout);
		    perror(""); /*falling through intentionally*/
		  }
		case ECONNREFUSED:
		  posportupdate(target, current, current->trynum, scan, &ss, scantype, PORT_CLOSED, &pil, &csi);
		  break;
		}  		  
	      }	    
	    }
	    if (senddelay) usleep(senddelay);
	  }
	}
	/*      if (o.debugging > 1) log_write(LOG_STDOUT, "Ideal number of queries: %d outstanding: %d max %d ports_left %d timeout %d\n", (int) ss.numqueries_ideal, ss.numqueries_outstanding, ss.max_width, ss.ports_left, target->to.timeout);*/

	/* Now that we have sent the packets we wait for responses */
	ss.alreadydecreasedqueries = 0;
	if ((scantype == SYN_SCAN) || (scantype == WINDOW_SCAN) || (scantype == ACK_SCAN))
	  get_syn_results(target, scan, &ss, &pil, portlookup, pd, sequences, scantype);
	else if (scantype == RPC_SCAN) {
	  /* We only bother worrying about responses if we haven't reached
	     a conclusion yet */
	  if (rsi.rpc_status == RPC_STATUS_UNKNOWN) {	  
	    get_rpc_results(target, scan, &ss, &pil, &rsi);
	  }
	  if (rsi.rpc_status != RPC_STATUS_UNKNOWN)
	    break;
	}
	else {
	  get_connect_results(target, scan, &ss, &pil, portlookup, sequences, &csi);	
	}

	/* If we timed out while trying to get results -- we're outta here! */
	if (target->timedout)
	  goto posscan_timedout;
      }

    if (scantype == RPC_SCAN) {
      /* Now we figure out the results of the port we just RPC scanned */
      rsi.rpc_current_port->rpc_status = rsi.rpc_status;
      if (rsi.rpc_status == RPC_STATUS_GOOD_PROG) {      
	rsi.rpc_current_port->rpc_program = rsi.rpc_program;
	rsi.rpc_current_port->rpc_lowver = rsi.rpc_lowver;
	rsi.rpc_current_port->rpc_highver = rsi.rpc_highver;
      }
      
      /* Next let us increment the port we are working on, since
	 this one is done ... */
      rsi.rpc_current_port = rsi.rpc_current_port->next;

      /* Time to put our RPC program scan list back together for the
	 next port ... */
      for(i = 0; i < rsi.rpc_number; i++) {
	scan[i].state = PORT_FRESH;
	scan[i].trynum = 0;
	scan[i].prev = i-1;
	if (i < rsi.rpc_number -1 ) scan[i].next = i+1;
	else scan[i].next = -1;
      }
      current = pil.testinglist = &scan[0]; 
      pil.firewalled = NULL;
      ss.numqueries_outstanding = 0;
      /* Now we out o' here! */
      continue;
    }

    if (ss.numqueries_outstanding != 0) {
      fatal("Bean counting error no. 4321897: ports_left: %d numqueries_outstanding: %d\n", ss.ports_left, ss.numqueries_outstanding);
    }

    /* We only want to try if the 'firewalled' list contains elements,
       meaning that some ports timed out.  We retry until nothing
       changes for a round (not counting the very first round).
    */
    if (pil.firewalled) {
      if (tries == 0 || ss.changed) {	
	pil.testinglist = pil.firewalled;
	for( current = pil.testinglist; current ; 
	     current = (current->next > -1)? &scan[current->next] : NULL) {
	  current->state = PORT_FRESH;
	  current->trynum = 0;
	  current->sd[0] = current->sd[1] = current->sd[2] = -1;
	  if (o.debugging) { 
	    log_write(LOG_STDOUT, "Preparing for retry, nonresponsive port %lu noted\n", current->portno); 
	  }
	}
	pil.firewalled = NULL;
      } else {
	/* Consider the ports firewalled */	
	for( current = pil.firewalled; current ; 
	     current = (current->next > -1)? &scan[current->next] : NULL) {
	  addport(&target->ports, current->portno, IPPROTO_TCP, NULL, PORT_FIREWALLED);
	}
	pil.testinglist = NULL;
      }
      tries++;
    }
    ss.numqueries_ideal = initial_packet_width;
    if (o.debugging)
      log_write(LOG_STDOUT, "Done with round %d\n", tries);
  } while(pil.testinglist && tries < 20);

  if (tries == 20) {
    error("WARNING: GAVE UP ON SCAN AFTER 20 RETRIES");
  }
  
  if (o.verbose)
    log_write(LOG_STDOUT, "The %s scan took %ld %s to scan %d ports.\n", (scantype == WINDOW_SCAN) ? "Window" : (scantype == SYN_SCAN)? "SYN" : (scantype == CONNECT_SCAN)? "TCP connect" : (scantype == RPC_SCAN)? "RPC" : "ACK",  (long) time(NULL) - starttime, (((long) time(NULL) - starttime) == 1)? "second" : "seconds", o.numports);
  
 posscan_timedout:
  
  free(scan);
  if (rawsd >= 0) 
    close(rawsd);
  if (pd)
    pcap_close(pd);
  if (scantype == RPC_SCAN)
    close_rpc_query_sockets();
  return;
}

/* Does the appropriate stuff when the port we are looking at is found
   to be open trynum is the try number that was successful 
   I USE CURRENT->STATE TO DETERMINE WHETHER THE PORT IS OPEN
   OR FIREWALLED */
void posportupdate(struct hoststruct *target, struct portinfo *current, 
		   int trynum, struct portinfo *scan,
		   struct scanstats *ss ,stype scantype, int newstate,
		   struct portinfolist *pil, struct connectsockinfo *csi) {
  static int tryident = -1;
  static unsigned int lasttarget = 0;
  struct sockaddr_in mysock;
  int sockaddr_in_len = sizeof(SA);
  int i;
  char owner[1024];

  if (tryident == -1 || target->host.s_addr != lasttarget) 
    tryident = o.identscan;
  lasttarget = target->host.s_addr;
  owner[0] = '\0';
  if (current->state != PORT_OPEN && current->state != PORT_CLOSED &&
      current->state != PORT_FIREWALLED && current->state != PORT_TESTING) {
    if (o.debugging) error("Whacked packet to port %lu passed to posportupdate with state %d\n", current->portno, current->state);
    return;
  }

  /* Lets do the timing stuff */
  if (trynum > -1) {
    adjust_timeouts(current->sent[trynum], &(target->to));
    target->firewallmode.responsive_ports++; 
  }
  /* If a non-zero trynum finds a port that hasn't been discovered, the
   earlier packets(s) were probably dropped.  So we decrease our 
   numqueries_ideal, otherwise we increase it slightly */
  if (trynum == 0) {
    ss->numqueries_ideal = MIN(ss->numqueries_ideal + (ss->packet_incr/ss->numqueries_ideal), ss->max_width);
  } else if (trynum != -1) {
    if (!ss->alreadydecreasedqueries) {
      ss->alreadydecreasedqueries = 1;
      ss->numqueries_ideal *= ss->fallback_percent;
      if (target->firewallmode.active)
	ss->numqueries_ideal *= ss->fallback_percent; /* We need to act 
							 forcefully on what 
							 little info we have */
      if (ss->numqueries_ideal < 1.0) ss->numqueries_ideal = 1.0;
    }
  }

  /* Collect IDENT info if requested */
  if (newstate == PORT_OPEN && scantype == CONNECT_SCAN && tryident) {
    if (getsockname(current->sd[trynum], (SA *) &mysock,
		    &sockaddr_in_len )) {
      pfatal("getsockname");
    }
    if (getidentinfoz(target->host, ntohs(mysock.sin_port), current->portno, owner) == -1)
      tryident = 0;
  }

  /* Now we convert current->state to state by making whatever adjustments
   are neccessary */
  switch(current->state) {
  case PORT_OPEN:
    return; /* Whew!  That was easy! */
    break;
  case PORT_FRESH:
    fprintf(stderr, "Fresh port %lu passed to posportupdate!\n", current->portno);
    return;
    break;
  case PORT_CLOSED:
    if (newstate == PORT_CLOSED)
      return; /* Closed -> Closed is not important and can cause some 
		 dup port problems */
    ss->changed++;
    current->state = newstate;
    break;
  case PORT_TESTING:
    /* If the newstate is FIREWALLED, nothing really "changed" since the
       default if there is no responses is to put the port into the firewalled
       state.  OK, OK, I don't know if this justification completely holds 
       water, but the shortcut of not updating change can save us a LOT of 
       time in cases of infrequent host unreachable packets (for example).  
       In that case, a few unreachables during each scan run causes the changed
       flag to be set and we need to try again.  Eventually the systems notices
       all the tries and starts increasing senddelay() and we are in even 
       worse shape */
    if (newstate != PORT_FIREWALLED)
      ss->changed++;
    if (scantype == SYN_SCAN)
      ss->numqueries_outstanding--;
    else {
      for(i=0; i <= current->trynum; i++)
	if (current->sd[i] > -1) {
	  csi->socklookup[current->sd[i]] = NULL;
	  FD_CLR(current->sd[i], &(csi->fds_read));
	  FD_CLR(current->sd[i], &(csi->fds_write));
	  FD_CLR(current->sd[i], &(csi->fds_except));
	  if (current->sd[i] == csi->maxsd)
	    csi->maxsd--;
	  close(current->sd[i]);
	  current->sd[i] = -1;
	  ss->numqueries_outstanding--;
	}
    }
    /* Now we delete the port from the testinglist */
    if (current == pil->testinglist)
      pil->testinglist = (current->next >= 0)? &scan[current->next] : NULL;
    if (current->next >= 0)  scan[current->next].prev = current->prev;
    if (current->prev >= 0)  scan[current->prev].next = current->next;
    break;
  case PORT_FIREWALLED:
    if (newstate != PORT_FIREWALLED)
      ss->changed++;
    if (current == pil->firewalled)
      pil->firewalled = (current->next >= 0)? &scan[current->next] : NULL;
    if (current->next >= 0)  scan[current->next].prev = current->prev;
    if (current->prev >= 0)  scan[current->prev].next = current->next;
    break;
  default:
    fatal("Unexpected port state: %d\n", current->state);
    break;
  } 
  current->state = newstate;
  current->next = -1;
  current->prev = -1;
  if (newstate == PORT_OPEN && o.verbose) {
    log_write(LOG_STDOUT, "Adding TCP port %lu (state %s).\n", current->portno, statenum2str(current->state));
    log_flush(LOG_STDOUT);
  }
  addport(&target->ports, current->portno, IPPROTO_TCP, owner, newstate);
  return;
}

inline void adjust_timeouts(struct timeval sent, struct timeout_info *to) {
  int delta = 0;
  struct timeval end;
  gettimeofday(&end, NULL);

  if (o.debugging > 1) {
    log_write(LOG_STDOUT, "Timeout vals: srtt: %d rttvar: %d to: %d ", to->srtt, to->rttvar, to->timeout);
  }
  if (to->srtt == -1 && to->rttvar == -1) {
    /* We need to initialize the sucker ... */
    to->srtt = TIMEVAL_SUBTRACT(end, sent);
    to->rttvar = MAX(5000, MIN(to->srtt, 2000000));
    to->timeout = to->srtt + (to->rttvar << 2);
  }
  else {
    delta = TIMEVAL_SUBTRACT(end, sent);
    if (delta >= 8000000 || delta < 0) {
      if (o.verbose)
	error("adjust_timeout: packet supposedly had rtt of %lu microseconds.  Ignoring time.", delta);
      return;
    }
    delta -= to->srtt;
    /* sanity check 2*/
    if (delta > 1500000 && delta > 3 * to->srtt + 2 * to->rttvar) {
      /* WANKER ALERT! */
      if (o.debugging) {
	log_write(LOG_STDOUT, "Bogus delta: %d (srtt %d) ... ignoring\n", delta, to->srtt);
      }
      return;
    }
    to->srtt += delta >> 3;
    to->rttvar += (ABS(delta) - to->rttvar) >> 2;
    to->timeout = to->srtt + (to->rttvar << 2);  
  }
  if (to->rttvar > 2300000) {
    fprintf(stderr, "RTTVAR has grown to over 2.3 seconds, decreasing to 2.0\n");
    to->rttvar = 2000000;
  }
  
  /* It hurts to do this ... it really does ... but otherwise we are being
     too risky */
  to->timeout = MAX(to->timeout, o.min_rtt_timeout * 1000);
  to->timeout = MIN(to->timeout, o.max_rtt_timeout * 1000);

  if (o.scan_delay)
    to->timeout = MAX(to->timeout, o.scan_delay * 1000);

  if (o.debugging > 1) {
    log_write(LOG_STDOUT, "delta %d ==> srtt: %d rttvar: %d to: %d\n", delta, to->srtt, to->rttvar, to->timeout);
  }

  if (to->srtt < 0 || to->rttvar < 0 || to->timeout < 0 || delta < -50000000) {
    fatal("Serious time computation problem in adjust_timeout ... end = (%d, %d) sent=(%d,%d) delta = %d srtt = %d rttvar = %d to = %d", end.tv_sec, end.tv_usec, sent.tv_sec, sent.tv_usec, delta, to->srtt, to->rttvar, to->timeout);
  }
}

/* Sleeps if necessary to ensure that it isn't called twice withen less
   time than o.send_delay.  If it is passed a non-null tv, the POST-SLEEP
   time is recorded in it */
void enforce_scan_delay(struct timeval *tv) {
  static int init = -1;
  static struct timeval lastcall;
  struct timeval now;
  int time_diff;

  if (!o.scan_delay) {
    if (tv) gettimeofday(tv, NULL);
    return;
  }

  if (init == -1) {
    gettimeofday(&lastcall, NULL);
    init = 0;
    if (tv)
      memcpy(tv, &lastcall, sizeof(struct timeval));
    return;
  }

  gettimeofday(&now, NULL);
  time_diff = TIMEVAL_MSEC_SUBTRACT(now, lastcall);
  if (time_diff < o.scan_delay) {  
    if (o.debugging > 1) {
      printf("Sleeping for %d milliseconds in enforce_scan_delay()\n", o.scan_delay - time_diff);
    }
    usleep((o.scan_delay - time_diff) * 1000);
    gettimeofday(&lastcall, NULL);
  } else
    memcpy(&lastcall, &now, sizeof(struct timeval));
  if (tv) {
    memcpy(tv, &lastcall, sizeof(struct timeval));
  }

  return;    
}

int get_connect_results(struct hoststruct *target, struct portinfo *scan, 
			struct scanstats *ss, struct portinfolist *pil, 
			int *portlookup, unsigned long *sequences, 
			struct connectsockinfo *csi) {
  fd_set fds_rtmp, fds_wtmp, fds_xtmp;
  int selectres;
  int selectedfound;
  int optval, optlen = sizeof(int);
  struct timeval timeout;
  int i, sd;
  int trynum;
  char buf[2048];
  struct portinfo *current = NULL;
  struct timeval tv;
  int res;
#ifdef LINUX
  struct sockaddr_in sin,sout;
  int sinlen = sizeof(sin);
  int soutlen = sizeof(sout);
#endif

  res = 0;  /* to prevent compiler warning */
  do {
    fds_rtmp = csi->fds_read;
    fds_wtmp = csi->fds_write;
    fds_xtmp = csi->fds_except;
    timeout.tv_sec = 0;
    timeout.tv_usec = 20000;
    selectedfound = 0;

    /* Insure there is no timeout ... */
    if (o.host_timeout) {	
      gettimeofday(&tv, NULL);
      if (TIMEVAL_MSEC_SUBTRACT(tv, target->host_timeout) >= 0) {
	target->timedout = 1;
	return 0;
      }
    }

    selectres = select(csi->maxsd+1, &fds_rtmp, &fds_wtmp, &fds_xtmp, &timeout);
    for(sd=0; selectedfound < selectres && sd <= csi->maxsd; sd++) {
      current = csi->socklookup[sd];
      if (!current) continue;
      trynum = -1;
      if  (FD_ISSET(sd, &fds_rtmp)  || FD_ISSET(sd, &fds_wtmp) || 
	   FD_ISSET(sd, &fds_xtmp)) {
	/*      current = csi->socklookup[i];*/
	for(i=0; i < 3; i++)
	  if (current->sd[i] == sd) {	
	    trynum = i;
	    break;
	  }

	if (o.debugging > 1 && current != NULL)
	  log_write(LOG_STDOUT, "portnumber %lu (try %d) selected for", current->portno, trynum);
	if (FD_ISSET(sd, &fds_rtmp)) {
	  if (o.debugging > 1) log_write(LOG_STDOUT, " READ");
	  selectedfound++;
	}
	if (FD_ISSET(sd, &fds_wtmp)) {
	  if (o.debugging > 1) log_write(LOG_STDOUT, " WRITE");
	  selectedfound++;
	}
	if (FD_ISSET(sd, &fds_xtmp)) {
	  if (o.debugging > 1) log_write(LOG_STDOUT, " EXCEPT");
	  selectedfound++;
	}
	if (o.debugging > 1 && current != NULL)
	  log_write(LOG_STDOUT, "\n");

	assert(trynum != -1);

	if (getsockopt(sd, SOL_SOCKET, SO_ERROR, (char *) &optval, &optlen) != 0)
	  optval = errno; /* Stupid Solaris ... */

	switch(optval) {
	case 0:
#ifdef LINUX
	  if (!FD_ISSET(sd, &fds_rtmp)) {
	    /* Linux goofiness -- We need to actually test that it is writeable */
	    res = send(current->sd[trynum], "", 0, 0);

	    if (res < 0 ) {
	      if (o.debugging > 1) {
		log_write(LOG_STDOUT, "Bad port %lu caught by 0-byte write: ", current->portno);
		perror("");
	      }
	      posportupdate(target, current, trynum, scan, ss, CONNECT_SCAN, PORT_CLOSED, pil, csi);
	    } else {
	      if (getpeername(sd, (struct sockaddr *) &sin, &sinlen) < 0) {
		pfatal("error in getpeername of connect_results for port %hi", current->portno);
	      } else {
		if (current->portno != ntohs(sin.sin_port)) {
		  error("Mismatch!!!! we think we have port %hi but we really have %hi", current->portno, ntohs(sin.sin_port));
		}
	      }

	      if (getsockname(sd, (struct sockaddr *) &sout, &soutlen) < 0) {
		pfatal("error in getsockname for port %hi", current->portno);
	      }
	      if (htons(sout.sin_port) == current->portno) {
		/* Linux 2.2 bug can lead to bogus successful connect()ions
		   in this case -- we treat the port as bogus even though it
		   is POSSIBLE that this is a real connection */
		posportupdate(target, current, trynum, scan, ss, CONNECT_SCAN, PORT_CLOSED, pil, csi);
	      } else {
		posportupdate(target, current, trynum, scan, ss, CONNECT_SCAN, PORT_OPEN, pil, csi);
	      }
	    }
	  } else {
	    posportupdate(target, current, trynum, scan, ss, CONNECT_SCAN, PORT_OPEN, pil, csi);
	  }
#else
	  posportupdate(target, current, trynum, scan, ss, CONNECT_SCAN, PORT_OPEN, pil, csi);
#endif
	  break;
	case ECONNREFUSED:
	  posportupdate(target, current, trynum, scan, ss, CONNECT_SCAN, PORT_CLOSED, pil, csi);
	  break;
	case EHOSTUNREACH:
	  /* It could be the host is down, or it could be firewalled.  We
	     will go on the safe side & assume port is closed ... on second
	     thought, lets go firewalled! and see if it causes any trouble */
	  posportupdate(target, current, trynum, scan, ss, CONNECT_SCAN, PORT_FIREWALLED, pil, csi);
	  break;
	case ENETDOWN:
	case ENETUNREACH:
	case ENETRESET:
	case ECONNABORTED:
	case ETIMEDOUT:
	case EHOSTDOWN:
	  snprintf(buf, sizeof(buf), "Strange SO_ERROR from connection to %s (%d) -- bailing scan", inet_ntoa(target->host), optval);
	  perror(buf);
	  return -1;
	  break;
	default:
	  snprintf(buf, sizeof(buf), "Strange read error from %s (%d)", inet_ntoa(target->host), optval);
	  perror(buf);
	  break;
	}
      } else continue;
    }
  } while(ss->numqueries_outstanding > 0 && selectres > 0);

  return 0;
}


void get_syn_results(struct hoststruct *target, struct portinfo *scan,
		     struct scanstats *ss, struct portinfolist *pil, 
		     int *portlookup, pcap_t *pd, unsigned long *sequences, 
		     stype scantype) {

  struct ip *ip;
  int bytes;
  struct tcphdr *tcp;
  int trynum;
  int newstate = -1;
  int i;
  int newport;
  struct portinfo *current = NULL;
  struct icmp *icmp;
  struct ip *ip2;
  unsigned short *data;
  struct timeval tv;

  while (ss->numqueries_outstanding > 0 && 
	 ( ip = (struct ip*) readip_pcap(pd, &bytes, target->to.timeout))) {
    if (bytes < (4 * ip->ip_hl) + 4)
      continue;
    current = NULL;
    trynum = newport = -1;
    newstate = PORT_UNKNOWN;
    
    /* Insure there is no timeout ... */
    if (o.host_timeout) {	
      gettimeofday(&tv, NULL);
      if (TIMEVAL_MSEC_SUBTRACT(tv, target->host_timeout) >= 0) {
	target->timedout = 1;
	return;
      }
    }

    if (ip->ip_src.s_addr == target->host.s_addr && ip->ip_p == IPPROTO_TCP) {
      tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
      i = ntohs(tcp->th_dport);
      if (i < o.magic_port || i > o.magic_port + 15) {
	if (o.debugging > 1)
	  error("SYN scan got TCP packet to port %d (magic port is %d) ... ignoring", i, o.magic_port);
	continue;
      }
      newport = ntohs(tcp->th_sport);
      /* In case we are scanning localhost and see outgoing packets */
      /* If only one of SYN, ACK flags are set, we skip it */
      if (ip->ip_src.s_addr == target->source_ip.s_addr && ((tcp->th_flags == TH_ACK) || (tcp->th_flags == TH_SYN))) {
	continue;
      }
      if (portlookup[newport] < 0) {
	if (o.debugging) {
	  log_write(LOG_STDOUT, "Strange packet from port %d:\n", ntohs(tcp->th_sport));
	  readtcppacket((char *)ip, bytes);
	}
	current = NULL;
	continue;
      }	      

      current = &scan[portlookup[newport]];
      for(i=0; i < 3; i++) {
	if (MOD_DIFF(sequences[i],ntohl(tcp->th_ack)) < 5)
	  break;
      }
      if (i < 3) trynum = i;
      else {
	if (o.debugging) 
	  log_write(LOG_STDOUT, "Strange ACK number from target: %lX\n", (unsigned long) ntohl(tcp->th_ack));
	trynum = (current->trynum == 0)? 0 : -1;	    
      }
      if (current->trynum < trynum) {
	if (o.debugging) 	    
	  error("Received SYN packet implying trynum %d from port %hi even though that port is only on trynum %d (could be from an earlier round)", trynum, newport, current->trynum);
	trynum = -1;
      }
      if (scantype == SYN_SCAN) {
	if ((tcp->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {	  
	  newstate = PORT_OPEN;
	}
	else if (tcp->th_flags & TH_RST) {	  
	  newstate = PORT_CLOSED;
	}	
      }
      else if (scantype == WINDOW_SCAN) {
	if (tcp->th_win) {
	  newstate = PORT_OPEN;
	} else {
	  newstate = PORT_CLOSED;
	}
      }
      else if (scantype == ACK_SCAN) {
	if (tcp->th_flags & TH_RST) {	  
	  newstate = PORT_UNFIREWALLED;
	}
      } 
    } else if (ip->ip_p == IPPROTO_ICMP) {
      icmp = (struct icmp *) ((char *)ip + 4 * ip->ip_hl);
      ip2 = (struct ip *) (((char *) ip) + 4 * ip->ip_hl + 8);
      if (bytes <= 4 * ip->ip_hl + 28 ||
	  bytes <= /* IP1len */ 4 * ip->ip_hl + /*ICMPlen */ 8 + 
	  /* IP2len */ 4 * ip2->ip_hl + 4 /* TCP ports */)
	{
	  if (o.debugging) {
	    error("Icmp message too short (%d bytes)", bytes);
	  }
	  continue;
	}
      data = (unsigned short *) ((char *)ip2 + 4 * ip2->ip_hl);
      /*	    log_write(LOG_STDOUT, "Caught ICMP packet:\n");
		    hdump(icmp, ntohs(ip->ip_len) - sizeof(struct ip)); */
      if (icmp->icmp_type == 3) {
	if (icmp->icmp_code != 1 && icmp->icmp_code != 2 && 
	    icmp->icmp_code != 3 && icmp->icmp_code != 13 &&
	    icmp->icmp_code != 9 && icmp->icmp_code != 10) {
	  error("Unexpected ICMP type/code 3/%d unreachable packet:", icmp->icmp_code);
	  hdump((unsigned char *)icmp, ntohs(ip->ip_len) - sizeof(struct ip));
	  continue;
	}
	newport = ntohs(data[1]);
	if (portlookup[newport] >= 0) {
	  current = &scan[portlookup[newport]];
	  trynum = (current->trynum == 0)? 0 : -1;
	  newstate = PORT_FIREWALLED;
	} else { 
	  if (o.debugging) {
	    error("Illegal ICMP type/code 3/%d unreachable packet:", 
		  icmp->icmp_code);
	    hdump((unsigned char *)icmp, ntohs(ip->ip_len) - sizeof(struct ip));
	  }
	  continue;
	}	      
      }
    }      
    /* OK, now we manipulate the port lists and adjust the time */
    if (current) {
      posportupdate(target, current, trynum, scan, ss, SYN_SCAN, newstate,
		    pil, NULL);
      current = NULL;
      trynum = -1;
      newstate = PORT_UNKNOWN;
    }
  }
  return;
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
  while ((res = recvtime(sd, recvbuf, 2048,7)) > 0) 
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
  res = recvtime(sd, recvbuf, 2048,12);
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
  res = recvtime(sd, recvbuf, 2048,12);
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
  while ((res = recvtime(sd, recvbuf, 2048,2)) > 0) 
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

int recvtime(int sd, char *buf, int len, int seconds) {

  int res;
  struct timeval timeout;
  fd_set readfd;

  timeout.tv_sec = seconds;
  timeout.tv_usec = 0;
  FD_ZERO(&readfd);
  FD_SET(sd, &readfd);
  res = select(sd + 1, &readfd, NULL, NULL, &timeout);
  if (res > 0 ) {
    res = recv(sd, buf, len, 0);
    if (res >= 0) return res;
    perror("recv in recvtime");
    return 0; 
  }
  else if (!res) return 0;
  perror("select() in recvtime");
  return -1;
}

void bounce_scan(struct hoststruct *target, unsigned short *portarray,
		 struct ftpinfo *ftp) {
  int starttime,  res , sd = ftp->sd,  i=0;
  char *t = (char *)&target->host; 
  int retriesleft = FTP_RETRIES;
  char recvbuf[2048]; 
  char targetstr[20];
  char command[512];
  unsigned short portno,p1,p2;
  struct timeval now;

  snprintf(targetstr, 20, "%d,%d,%d,%d,", UC(t[0]), UC(t[1]), UC(t[2]), UC(t[3]));

  starttime = time(NULL);
  if (o.verbose || o.debugging)
    log_write(LOG_STDOUT, "Initiating TCP ftp bounce scan against %s (%s)\n",
	    target->name,  inet_ntoa(target->host));
  for(i=0; portarray[i]; i++) {

    /* Check for timeout */
    if (o.host_timeout) {
      gettimeofday(&now, NULL);
      if ((TIMEVAL_MSEC_SUBTRACT(now, target->host_timeout) >= 0))
	{
	  target->timedout = 1;
	  return;
	}
    }

    portno = htons(portarray[i]);
    p1 = ((unsigned char *) &portno)[0];
    p2 = ((unsigned char *) &portno)[1];
    snprintf(command, 512, "PORT %s%i,%i\r\n", targetstr, p1,p2);
    if (o.debugging) log_write(LOG_STDOUT, "Attempting command: %s", command);
    if (send(sd, command, strlen(command), 0) < 0 ) {
      perror("send in bounce_scan");
      if (retriesleft) {
	if (o.verbose || o.debugging) 
	  log_write(LOG_STDOUT, "Our ftp proxy server hung up on us!  retrying\n");
	retriesleft--;
	close(sd);
	ftp->sd = ftp_anon_connect(ftp);
	if (ftp->sd < 0) return;
	sd = ftp->sd;
	i--;
      }
      else {
	fprintf(stderr, "Our socket descriptor is dead and we are out of retries. Giving up.\n");
	close(sd);
	ftp->sd = -1;
	return;
      }
    } else { /* Our send is good */
      res = recvtime(sd, recvbuf, 2048,15);
      if (res <= 0) perror("recv problem from ftp bounce server\n");
  
      else { /* our recv is good */
	recvbuf[res] = '\0';
	if (o.debugging) log_write(LOG_STDOUT, "result of port query on port %i: %s", 
				 portarray[i],  recvbuf);
	if (recvbuf[0] == '5') {
	  if (portarray[i] > 1023) {
	    fprintf(stderr, "Your ftp bounce server sucks, it won't let us feed bogus ports!\n");
	    exit(1);
	  }
	  else {
	    fprintf(stderr, "Your ftp bounce server doesn't allow priviliged ports, skipping them.\n");
	    while(portarray[i] && portarray[i] < 1024) i++;
	    if (!portarray[i]) {
	      fprintf(stderr, "And you didn't want to scan any unpriviliged ports.  Giving up.\n");
	      /*	  close(sd);
			  ftp->sd = -1;
			  return *ports;*/
	      /* screw this gentle return crap!  This is an emergency! */
	      exit(1);
	    }
	  }  
	}
	else  /* Not an error message */
	  if (send(sd, "LIST\r\n", 6, 0) > 0 ) {
	    res = recvtime(sd, recvbuf, 2048,12);
	    if (res <= 0) {
	      perror("recv problem from ftp bounce server\n");
	    }
	    else {
	      recvbuf[res] = '\0';
	      if (o.debugging) log_write(LOG_STDOUT, "result of LIST: %s", recvbuf);
	      if (!strncmp(recvbuf, "500", 3)) {
		/* fuck, we are not aligned properly */
		if (o.verbose || o.debugging)
		  fprintf(stderr, "FTP command misalignment detected ... correcting.\n");
		res = recvtime(sd, recvbuf, 2048,10);
	      }
	      if (recvbuf[0] == '1' || recvbuf[0] == '2') {
		if (o.verbose || o.debugging) log_write(LOG_STDOUT, "Port number %i appears good.\n",
						      portarray[i]);
		addport(&target->ports, portarray[i], IPPROTO_TCP, NULL, PORT_OPEN);
		if (recvbuf[0] == '1') {
		  res = recvtime(sd, recvbuf, 2048,5);
		  recvbuf[res] = '\0';
		  if (res > 0) {
		    if (o.debugging) log_write(LOG_STDOUT, "nxt line: %s", recvbuf);
		    if (recvbuf[0] == '4' && recvbuf[1] == '2' && 
			recvbuf[2] == '6') {	      	
		      deleteport(&target->ports, portarray[i], IPPROTO_TCP);
		      if (o.debugging || o.verbose)
			log_write(LOG_STDOUT, "Changed my mind about port %i\n", portarray[i]);
		    }
		  }
		}
	      } else {
		/* This means the port is closed ... */
		addport(&target->ports, portarray[i], IPPROTO_TCP, NULL, PORT_CLOSED);
	      }
	    }
	  }
      }
    }
  }

  if (o.debugging || o.verbose) 
    log_write(LOG_STDOUT, "Scanned %d ports in %ld seconds via the Bounce scan.\n",
	    o.numports, (long) time(NULL) - starttime);
  return;
}

/* parse a URL stype ftp string of the form user:pass@server:portno */
int parse_bounce(struct ftpinfo *ftp, char *url) {
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

char *logtypes[LOG_TYPES]={"normal","machine","HTML","$cR1pT |<1dd13"};

int log_open(int logt, int append, char *filename)
{
  int i=0;
  if (logt<=0 || logt>LOG_MASK) return -1;
  while ((logt&1)==0) { i++; logt>>=1; }
  if (o.logfd[i]) fatal("Only one %s output filename allowed",logtypes[i]);
  if (*filename == '-' && *(filename + 1) == '\0')
    {
      o.logfd[i]=stdout;
      o.nmap_stdout = fopen("/dev/null", "w");
      if (!o.nmap_stdout)
	fatal("Could not assign /dev/null to stdout for writing");
  }
  else
    {
      if (o.append_output)
	o.logfd[i] = fopen(filename, "a");
      else
	o.logfd[i] = fopen(filename, "w");
      if (!o.logfd[i])
	fatal("Failed to open %s output file %s for writing", logtypes[i], filename);
    }
  return 1;
}

void skid_output(unsigned char *s)
{
  int i;
  for (i=0;s[i];i++)
    if (rand()%2==0)
      /* Substitutions commented out are not known to me, but maybe look nice */
      switch(s[i])
	{
	case 'A': s[i]='4'; break;
	  /*	case 'B': s[i]='8'; break;
	 	case 'b': s[i]='6'; break;
	        case 'c': s[i]='k'; break;
	        case 'C': s[i]='K'; break; */
	case 'e':
	case 'E': s[i]='3'; break;
	case 'i':
	case 'I': s[i]="!|1"[rand()%3]; break;
	  /*      case 'k': s[i]='c'; break;
	        case 'K': s[i]='C'; break;*/
	case 'o':
	case 'O': s[i]='0'; break;
	case 's':
	case 'S': 
	  if (s[i+1] && !isalnum(s[i+1])) 
	    s[i] = 'z';
	  else s[i] = '$';
	  break;
	case 'z': s[i]='s'; break;
	case 'Z': s[i]='S'; break;
	}  
    else
      {
	if (s[i]>='A' && s[i]<='Z' && (rand()%3==0)) s[i]+='a'-'A';
	else if (s[i]>='a' && s[i]<='z' && (rand()%3==0)) s[i]-='a'-'A';
      }
}

void log_write(int logt, char *fmt, ...)
{
  va_list  ap;
  int i,l=logt,skid=1;
  char buffer[1000];

  va_start(ap, fmt);
  if (l & LOG_STDOUT) {
    vfprintf(o.nmap_stdout, fmt, ap);
    l-=LOG_STDOUT;
  }
  if (l & LOG_SKID_NOXLT) { skid=0; l -= LOG_SKID_NOXLT; l |= LOG_SKID; }
  if (l<0 || l>LOG_MASK) return;
  for (i=0;l;l>>=1,i++)
    {
      if (!o.logfd[i] || !(l&1)) continue;
      vsnprintf(buffer,sizeof(buffer)-1,fmt,ap);
      if (skid && ((1<<i)&LOG_SKID)) skid_output(buffer);
      fwrite(buffer,1,strlen(buffer),o.logfd[i]);
    }
  va_end(ap);
}

void log_close(int logt)
{
  int i;
  if (logt<0 || logt>LOG_MASK) return;
  for (i=0;logt;logt>>=1,i++) if (o.logfd[i] && (logt&1)) fclose(o.logfd[i]);
}

void log_flush(int logt) {
  int i;

  if (logt & LOG_STDOUT) {
    fflush(o.nmap_stdout);
    logt -= LOG_STDOUT;
  }
  if (logt & LOG_SKID_NOXLT)
    fatal("You are not allowed to log_flush() with LOG_SKID_NOXLT");

  if (logt<0 || logt>LOG_MASK) return;

  for (i=0;logt;logt>>=1,i++)
    {
      if (!o.logfd[i] || !(logt&1)) continue;
      fflush(o.logfd[i]);
    }

}

void log_flush_all() {
  int fileno;

  for(fileno = 0; fileno < LOG_TYPES; fileno++) {
    if (o.logfd[fileno]) fflush(o.logfd[fileno]);
  }
  fflush(stdout);
  fflush(stderr);
}

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

int nmap_fetchfile(char *filename_returned, int bufferlen, char *file) {
  char *dirptr;
  int res;
  int foundsomething = 0;
  struct passwd *pw;
  char dot_buffer[512];
  static int warningcount = 0;

  /* First we try $NMAPDIR/file
     next we try ~user/nmap/file
     then we try LIBDIR/nmap/file <--LIBDIR 
     finally we try ./file
  */
  if ((dirptr = getenv("NMAPDIR"))) {
    res = snprintf(filename_returned, bufferlen, "%s/%s", dirptr, file);
    if (res > 0 && res < bufferlen) {
      if (fileexistsandisreadable(filename_returned))
	foundsomething = 1;
    }
  }
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
  if (!foundsomething) {
    res = snprintf(filename_returned, bufferlen, "%s/%s", LIBDIR, file);
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
