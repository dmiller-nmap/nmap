
/***********************************************************************
 * service_scan.h -- Routines used for service fingerprinting to       *
 * determine what application-level protocol is listening on a given   *
 * port (e.g. snmp, http, ftp, smtp, etc.)                             *
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

#ifndef SERVICE_SCAN_H
#define SERVICE_SCAN_H

#include "nmap.h"
#include "global_structures.h"

#include <vector>
/* TODO: sometimes this is <pcre/pcre.h> or just <pcre.h> -- need to check 
   in configure */
#include <pcre.h>

using namespace std;

/**********************  DEFINES/ENUMS ***********************************/
#define DEFAULT_SERVICEWAITMS 7500
#define DEFAULT_CONNECT_TIMEOUT 5000
#define SERVICEMATCH_REGEX 1
#define SERVICEMATCH_STATIC 2

/**********************  STRUCTURES  ***********************************/

/**********************  CLASSES     ***********************************/

class ServiceProbeMatch {
 public:
  ServiceProbeMatch();
  ~ServiceProbeMatch();
// match text from the nmap-service-probes file.  This must be called before 
// you try and do anything with this match.  This
// function should be passed the text remaining in the line right AFTER 
// "match " in nmap-service-probes.  The line number that the text is
// provided so that it can be reported in error messages.  This function will
// abort the program if there is a syntax problem.
  void InitMatch(const char *matchtext, int lineno); 
  // Returns this service name if the givven buffer and length match it.  Otherwise
  // returns NULL.
  const char *testMatch(const u8 *buf, int buflen);
// Returns the service name this matches
  const char *getName() { return servicename; }
 private:
  bool isInitialized; // Has InitMatch yet been called?
  char *servicename;
  int matchtype; // SERVICEMATCH_REGEX or SERVICESCAN_STATIC
  char *matchstr; // Regular expression text, or static string
  int matchstrlen; // Because static strings may have embedded NULs
  pcre *regex_compiled;
  pcre_extra *regex_extra;
  bool matchops_ignorecase;
  // The anchor is for SERVICESCAN_STATIC matches.  If the anchor is not -1, the match must
  // start at that zero-indexed position in the response str.
  int matchops_anchor;
};


class ServiceProbe {
 public:
  ServiceProbe();
  ~ServiceProbe();
  const char *getName() { return probename; }
  void setName(const char *name); // a copy of name will be made and stored
  // Returns true if this is the "null" probe, meaning it sends no probe and
  // only listens for a banner.  Only TCP services have this.
  bool isNullProbe() { return (probestringlen == 0); }
  bool isProbablePort(u16 portno); // Returns true if the portnumber given was listed
                                   // as a port that is commonly identified by this
                                   // probe (e.g. an SMTP probe would commonly identify port 25)
// Amount of time to wait after a connection succeeds (or packet sent) for a responses.
  int totalwaitms;

  // Parses the "probe " line in the nmap-service-probes file.  Pass the rest of the line
  // after "probe ".  The format better be:
  // [TCP|UDP] [probename] "probetext"
  // the lineno is requested because this function will bail with an error
  // (giving the line number) if it fails to parse the string.
  void setProbeDetails(char *pd, int lineno);

  // obtains the probe string (in raw binary form) and the length.  The string will be 
  // NUL-terminated, but there may be other \0 in the string, so the termination is only
  // done for easo of printing ASCII probes in debugging cases.
  const u8 *getProbeString(int *stringlen) { *stringlen = probestringlen; return probestring; }
  void setProbeString(const u8 *ps, int stringlen);

  /* Protocols are IPPROTO_TCP and IPPROTO_UDP */
  u8 getProbeProtocol() { 
    assert(probeprotocol == IPPROTO_TCP || probeprotocol == IPPROTO_UDP); 
    return probeprotocol;  
  }
  void setProbeProtocol(u8 protocol) { probeprotocol = protocol; }

  // Takes a string as given in the 'ports ' line of
  // nmap-services-probes.  Pass in any text after "ports ".  The line
  // number is requested because this function will bail with an error
  // (giving the line number) if it fails to parse the string.  Ports are
  // a comma seperated list of prots and ranges (e.g. 53,80,6000-6010)
  void setProbablePorts(const char *portstr, int lineno);

  // Returns true if the passed in port is on the list of probable ports for this probe.
  bool portIsProbable(u16 portno);
  

  // Takes a "match" line in a probe description and adds it to the list of 
  // matches for this probe.  Pass in any text after "match ".  The line
  // number is requested because this function will bail with an error
  // (giving the line number) if it fails to parse the string.
  void addMatch(const char *match, int lineno);

  // Returns a service name if the givven buffer and length match one.  Otherwise
  // returns NULL.
  const char *testMatch(const u8 *buf, int buflen);

 private:
  char *probename;

  u8 *probestring;
  int probestringlen;
  vector<u16> probableports;
  int probeprotocol;
  vector<ServiceProbeMatch *> matches; // first-ever use of STL in Nmap!
};

/**********************  PROTOTYPES  ***********************************/

/* Execute a service fingerprinting scan against all open ports of the
   targets[] specified. */
int service_scan(Target *targets[], int num_targets);

#endif /* SERVICE_SCAN_H */





