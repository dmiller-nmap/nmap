
/***********************************************************************
 * main.c -- Contains the main() function of Nmap.  Note that main()   *
 * does very little except for calling nmap_main() (which is in        *
 * nmap.c)                                                             *
 *                                                                     *
 ***********************************************************************
 *  The Nmap Security Scanner is (C) 1995-2001 Insecure.Com LLC. This  *
 *  program is free software; you can redistribute it and/or modify    *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; Version 2.  This guarantees your  *
 *  right to use, modify, and redistribute this software under certain *
 *  conditions.  If this license is unacceptable to you, we may be     *
 *  willing to sell alternative licenses (contact sales@insecure.com). *
 *                                                                     *
 *  If you received these files with a written license agreement       *
 *  stating terms other than the (GPL) terms above, then that          *
 *  alternative license agreement takes precendence over this comment. *
 *                                                                     *
 *  Source is provided to this software because we believe users have  *
 *  a right to know exactly what a program is going to do before they  *
 *  run it.  This also allows you to audit the software for security   *
 *  holes (none have been found so far).                               *
 *                                                                     *
 *  Source code also allows you to port Nmap to new platforms, fix     *
 *  bugs, and add new features.  You are highly encouraged to send     *
 *  your changes to fyodor@insecure.org for possible incorporation     *
 *  into the main distribution.  By sending these changes to Fyodor or *
 *  one the insecure.org development mailing lists, it is assumed that *
 *  you are offering Fyodor the unlimited, non-exclusive right to      *
 *  reuse, modify, and relicense the code.  This is important because  *
 *  the inability to relicense code has caused devastating problems    *
 *  for other Free Software projects (such as KDE and NASM).  Nmap     *
 *  will always be available Open Source.  If you wish to specify      *
 *  special license conditions of your contributions, just say so      *
 *  when you send them.                                                *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  *
 *  General Public License for more details (                          *
 *  http://www.gnu.org/copyleft/gpl.html ).                            *
 *                                                                     *
 ***********************************************************************/

/* $Id$ */

#include "nmap.h"
#include "osscan.h"
#include "scan_engine.h"
#include "idle_scan.h"
#include "timing.h"

/* global options */
extern NmapOps o;  /* option structure */
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
    if (fgets(command, sizeof(command), stdin) == NULL && feof(stdin)) {
      fatal("EOF reached -- quitting");
    }
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
      o.ReInit();
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
