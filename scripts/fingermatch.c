/***********************************************************************
 * fingermatch.c -- A relatively simple utility for determining        *
 * whether a given Nmap fingerprint matches (or comes close to         *
 * matching) any of the fingerprints in a collection such as the       *
 * nmap-os-fingerprints file that ships with Nmap.                     *
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


#include "nbase.h"
#include "nmap.h"
#include "osscan.h"

#define FINGERMATCH_GUESS_THRESHOLD 0.75 /* How low we will still show guesses for */

void usage() {
  printf("Usage: fingermatch <fingerprintfilename>\n"
         "(You will be prompted for the fingerprint data)\n"
	 "\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  char *fingerfile = NULL;
  FingerPrint **reference_FPs = NULL;
  FingerPrint *testFP;
  struct FingerPrintResults FPR;
  char fprint[2048];
  int printlen = 0;
  char line[512];
  int linelen;
  int i;
  char lasttestname[32];
  int lastlinelen = 0;
  char *p;
  int adjusted = 0; /* Flags if we have adjusted the entered fingerprint */

  if (argc != 2)
    usage();

  /* First we read in the fingerprint file provided on the command line */
  fingerfile = argv[1];
  reference_FPs = parse_fingerprint_file(fingerfile);
  if (reference_FPs == NULL) 
    fatal("Could not open or parse Fingerprint file given on the command line: %s", fingerfile);

  /* Now we read in the user-provided fingerprint */
  printf("Enter the fingerprint you would like to match, followed by a blank single-dot line:\n");

  lasttestname[0] = '\0';
  while(fgets(line, sizeof(line), stdin)) {
    if (*line == '\n' || *line == '.')
      break;
    linelen = strlen(line);
    /* Check if it is a duplicate testname */
    if (*line == '#')
      continue;
    p = strchr(line, '(');
    if (p) {
      *p = '\0';
      if (strcmp(line, lasttestname) == 0) {
	adjusted = 1;
	if (lastlinelen >= linelen)
	  continue;
	/* The new one is longer (and thus probably better) -- clobber the last
	   line */
	printlen -= lastlinelen;
	fprint[printlen] = '\0';
      }
      Strncpy(lasttestname, line, sizeof(lasttestname));
      lastlinelen = linelen;
      *p = '(';
    } else {
      /* The only legitimate non-comment line that doesn't have a ( is the 
	 initial Fingerprint line */
      if (strncmp(line, "Fingerprint ", 12) != 0) {
	printf("Warning: Bogus line skipped\n");
	continue;
      }
    }
    if (printlen + linelen >= sizeof(fprint) - 5)
      fatal("Overflow!");
    strcpy(fprint + printlen, line);
    printlen += linelen;
  }

  if (adjusted) {
    printf("\n**WARNING**: Adjusted fingerprint due to duplicated tests (we only look at the first).  Results are based on this adjusted fingerprint:\n%s\n", fprint);
  }

  /* Now we validate that all elements are present */
  if (!strstr(fprint, "TSeq(") || !strstr(fprint, "T1(") || 
      !strstr(fprint, "T2(") || !strstr(fprint, "T3(") || 
      !strstr(fprint, "T4(") || !strstr(fprint, "T5(") || 
      !strstr(fprint, "T6(") || !strstr(fprint, "T7(") ||
      !strstr(fprint, "PU(")) {
    /* This ought to get my attention :) */
    printf("\n"
           "********************************************************\n"
           "***WARNING: Fingerprint is missing at least 1 element***\n"
           "********************************************************\n");
  }

  testFP = parse_single_fingerprint(fprint);
  if (!testFP) fatal("Sorry -- failed to parse the so-called fingerprint you entered");

  /* Now we find the matches! */
  match_fingerprint(testFP, &FPR, reference_FPs, FINGERMATCH_GUESS_THRESHOLD);

  switch(FPR.overall_results) {
  case OSSCAN_NOMATCHES:
    printf("**NO MATCHES** found for the entered fingerprint in %s\n", fingerfile);
    break;
  case OSSCAN_TOOMANYMATCHES:
    printf("Found **TOO MANY EXACT MATCHES** to print for entered fingerprint in %s\n", fingerfile);
    break;
  case OSSCAN_SUCCESS:
    if (FPR.num_perfect_matches > 0) {
      printf("Found **%d PERFECT MATCHES** for entered fingerprint in %s:\n", FPR.num_perfect_matches, fingerfile);
      printf("Accu Line# OS\n");      
      for(i=0; i < FPR.num_matches && FPR.accuracy[i] == 1; i++) {
	printf("100%% %5d %s\n", FPR.prints[i]->line, FPR.prints[i]->OS_name);
      }
    } else {
      printf("No perfect matches found, **GUESSES AVAILABLE** for entered fingerprint in %s:\n", fingerfile);
      printf("Accu Line# OS\n");
      for(i=0; i < 10 && i < FPR.num_matches; i++) {
	printf("%3d%% %5d %s\n", (int) (FPR.accuracy[i] * 100), FPR.prints[i]->line, FPR.prints[i]->OS_name);
      }
    }
    printf("\n");
    break;
  default:
    fatal("Bogus error.");
    break;
  }

  return 0;
}
