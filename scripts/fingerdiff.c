/***********************************************************************
 * fingerdiff.c -- A relatively simple utility for determining the     *
 * differences between a "reference" fingerprint (which can have       *
 * expressions as attributes) and an observed fingerprint (no          *
 * expressions).                                                       *
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

void usage() {
  printf("\nUsage: fingerdiff does not accept any arguments.\n"
	 "\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  FingerPrint *referenceFP;
  FingerPrint *observedFP;
  double accuracy;
  char referenceFPString[2048];
  char observedFPString[2048];
  int printlen = 0;
  char line[512];
  int linelen;
  char lasttestname[32];
  int lastlinelen = 0;
  char *p;
  int adjusted = 0; /* Flags if we have adjusted the entered fingerprint */

  if (argc != 1)
    usage();

  referenceFPString[0] = observedFPString[0] = '\0';

  printf("STEP ONE: Enter the **REFERENCE FINGERPRINT**, followed by a blank or single-dot line:\n");

  lasttestname[0] = '\0';
  printlen = lastlinelen = 0;
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
	referenceFPString[printlen] = '\0';
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
    if (printlen + linelen >= sizeof(referenceFPString) - 5)
      fatal("Overflow!");
    strcpy(referenceFPString + printlen, line);
    printlen += linelen;
  }

  if (adjusted) {
    printf("\n**WARNING**: Adjusted fingerprint due to duplicated tests (we only look at the first).  Results are based on this adjusted fingerprint:\n%s\n",
	   referenceFPString);
  }

  /* Now we validate that all elements are present */
  p = referenceFPString;
  if (!strstr(p, "TSeq(") || !strstr(p, "T1(") || !strstr(p, "T2(") || 
      !strstr(p, "T3(") || !strstr(p, "T4(") || !strstr(p, "T5(") || 
      !strstr(p, "T6(") || !strstr(p, "T7(") || !strstr(p, "PU(")) {
    /* This ought to get my attention :) */
    printf("\n"
         "******************************************************************\n"
         "***WARNING: Reference Fingerprint is missing at least 1 element***\n"
         "******************************************************************\n"
	  );

  }

  referenceFP = parse_single_fingerprint(referenceFPString);
  if (!referenceFP) fatal("Sorry -- failed to parse the so-called reference fingerprint you entered");


  printf("STEP TWO: Enter the **OBSERVED FINGERPRINT**, followed by a blank or single-dot line:\n");

  lasttestname[0] = '\0';
  printlen = 0;
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
	referenceFPString[printlen] = '\0';
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
    if (printlen + linelen >= sizeof(observedFPString) - 5)
      fatal("Overflow!");
    strcpy(observedFPString + printlen, line);
    printlen += linelen;
  }

  if (adjusted) {
    printf("\n**WARNING**: Adjusted fingerprint due to duplicated tests (we only look at the first).  Results are based on this adjusted fingerprint:\n%s\n",
	   observedFPString);
  }

  /* Now we validate that all elements are present */
  p = observedFPString;
  if (!strstr(p, "TSeq(") || !strstr(p, "T1(") || !strstr(p, "T2(") || 
      !strstr(p, "T3(") || !strstr(p, "T4(") || !strstr(p, "T5(") || 
      !strstr(p, "T6(") || !strstr(p, "T7(") || !strstr(p, "PU(")) {
    /* This ought to get my attention :) */
    printf("\n"
         "*****************************************************************\n"
         "***WARNING: Observed Fingerprint is missing at least 1 element***\n"
         "*****************************************************************\n"
	  );

  }
  observedFP = parse_single_fingerprint(observedFPString);
  if (!observedFP) fatal("Sorry -- failed to parse the so-called reference fingerprint you entered");

  /* OK, now I've got the fingerprints -- I just need to compare them ... */


  accuracy = compare_fingerprints(referenceFP, observedFP, 1);
  if (accuracy == 1)
    printf("PERFECT MATCH!\n");
  else printf("Accuracy of the two prints is %d%% -- see differences above.\n",
	      (int) (accuracy * 100));


  return 0;
}
