/***********************************************************************
 * servicematch.cc -- A relatively simple utility for determining      *
 * whether a given Nmap service fingerprint matches (or comes close to *
 * any of the fingerprints in a collection such as the                 *
 * nmap-service-probes file that ships with Nmap.                      *
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
#include "service_scan.h"

#include <ctype.h>

void usage() {
  printf("Usage: servicematch <fingerprintfilename>\n"
         "(You will be prompted for the fingerprint data)\n"
	 "\n");
  exit(1);
}

// This function parses the read-in fprint, compares the responses to the
// given tests as if they had been read from a remote system, and prints out
// the first match if any, followed by the fingerprint in single-line format.
// The 'ipaddystr' is either a string of the form " on www.xx.y.zzz" containing the IP
// address of the target from which fprint was obtained, or it is empty (meaning we don't know).
int doMatch(AllProbes *AP, char *fprint, int fplen, char *ipaddystr) {
  u16 portno;
  int proto;
  char *p;
  char *currentprobe = NULL;
  char probename[128];
  char resptext[2048];
  unsigned int resptextlen;
  char *dst;
  ServiceProbe *SP = NULL;
  const char *matchedsvc;
  char matchedversion[256];

  // First lets find the port number and protocol
  assert(fplen > 10);
  assert(strncmp(fprint, "SF-Port", 7) == 0);
  portno = atoi(fprint + 7);
  p = strchr(fprint, ':');
  assert(p);
  p -= 3;
  if (strncmp(p, "TCP", 3) == 0)
    proto = IPPROTO_TCP;
  else proto = IPPROTO_UDP;

  currentprobe = strstr(p, "%r(");
  while(currentprobe) {
    // move to the probe name
    p = currentprobe + 3;
    dst = probename;
    while(*p && *p != ',') {
      assert((unsigned int) (dst - probename) < sizeof(probename) - 1);
      *dst++ = *p++;
    }
    *dst++ = '\0';

    // Skip the response length
    assert(*p == ',');
    p++;
    while(*p && *p != ',') 
      p++;
    assert(*p == ',');
    p++;
    assert(*p == '"');
    p++;

    dst = resptext;
    while(*p && (*p != '"' || (*(p-1) == '\\' && *(p-2) != '\\'))) {
      assert((unsigned int) (dst - resptext) < sizeof(resptext) - 1);
      *dst++ = *p++;
    }
    *dst++ = '\0';

    // Now we unescape the response into plain binary
    cstring_unescape(resptext, &resptextlen);

    // Finally we try to match this with the appropriate probe from the
    // nmap-service-probes file.
    SP = AP->getProbeByName(probename, proto);

    if (!SP) {
      error("WARNING: Unable to find probe named %s in given probe file.", probename);
    } else {
      matchedsvc = SP->testMatch((u8 *) resptext, resptextlen, matchedversion, sizeof(matchedversion));
      if (matchedsvc) {
	// YEAH!  Found a match!
	if (*matchedversion)
	  printf("MATCHED svc %s (%s)%s: %s\n", matchedsvc, matchedversion, ipaddystr, fprint);
	else
	  printf("MATCHED svc %s (NO VERSION)%s: %s\n", matchedsvc, ipaddystr, fprint);
	return 0;
      }
    }
    // Lets find the next probe, if any
    currentprobe = strstr(p, "%r(");
  }

  printf("FAILED to match%s: %s\n", ipaddystr, fprint);

  return 1;
}

int cleanfp(char *fprint, int *fplen) {
  char *src = fprint, *dst = fprint;

  while(*src) {
    if (strncmp(src, "\\x20", 4) == 0) {
      *dst++ = ' ';
      src += 4;
      /* } else if (*src == '\\' && (*(src+1) == '"' || *(src+1) == '\\')) {
      *dst++ = *++src;
      src++; */ // We shouldn't do this yet
    } else if (src != dst) {
      *dst++ = *src++;
    } else { dst++; src++; }
  }
  *dst++ = '\0';
  *fplen = dst - fprint - 1;
  return 0;
}


int main(int argc, char *argv[]) {
  AllProbes *AP = new AllProbes();
  char *probefile = NULL;
  char fprint[4096];
  int fplen = 0; // Amount of chars in the current fprint
  char line[512];
  unsigned int linelen;
  char *dst = NULL;
  int lineno;
  char *p, *q;
  bool isInFP = false; // whether we are currently reading in a fingerprint
  struct in_addr ip;
  char lastipbuf[64];

  if (argc != 2)
    usage();

  lastipbuf[0] = '\0';

  /* First we read in the fingerprint file provided on the command line */
  probefile = argv[1];
  parse_nmap_service_probe_file(AP, probefile);

  /* Now we read in the user-provided service fingerprint(s) */

  printf("Enter the service fingerprint(s) you would like to match.  Will read until EOF.  Other Nmap output text (besides fingerprints) is OK too and will be ignored\n");

  while(fgets(line, sizeof(line), stdin)) {
    lineno++;
    linelen = strlen(line);
    p = line;
    while(*p && isspace(*p)) p++;
    if (isInFP) {
      if (strncmp(p, "SF:", 3) == 0) {
	p += 3;
	assert(sizeof(fprint) > fplen + linelen + 1);
	dst = fprint + fplen;
	while(*p != '\r' && *p != '\n')
	*dst++ = *p++;
	fplen = dst - fprint;
	*dst++ = '\0';
      } else {
	fatal("Fingerprint incomplete ending on line #%d", lineno);
      }
    }

    if (strncmp(p, "SF-Port", 7) == 0) {
      if (isInFP) 
	fatal("New service fingerprint started before the previous one was complete -- line %d", lineno);
      assert(sizeof(fprint) > linelen + 1);
      dst = fprint;
      while(*p != '\r' && *p != '\n')
	*dst++ = *p++;
      fplen = dst - fprint;
      *dst++ = '\0';
      isInFP = true;
    } else if (strncmp(p, "Interesting port", 16) == 0) {
      q = line + linelen - 1;
      while(*q && (*q == ')' || *q == ':' || *q == '\n'|| *q == '.' || isdigit((int) (unsigned char) *q))) {
	if (*q == ')' || *q == ':' || *q == '\n') *q = '\0';
	q--;
      }
      q++;
      assert(isdigit((int)(unsigned char) *q));
      if (inet_aton(q, &ip) != 0) {
	snprintf(lastipbuf, sizeof(lastipbuf), " on %s", inet_ntoa(ip));
      }
    }

    // Now we test if the fingerprint is complete
    if (isInFP && fplen > 5 && strncmp(fprint + fplen - 3, "\");", 3) == 0) {
      // Yeah!  We have read in the whole fingerprint
      isInFP = false;
      // Cleans the fingerprint up a little, such as replacing \x20 with space and unescaping characters like \\ and \"
      cleanfp(fprint, &fplen);
      doMatch(AP, fprint, fplen, lastipbuf);
    }
  }

  return 0;
}
