
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


#include "service_scan.h"
#include "timing.h"
#include "NmapOps.h"
#include "nsock.h"

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <algorithm>
#include <list>

extern NmapOps o;

class AllProbes {
public:
  AllProbes();
  ~AllProbes();
  vector<ServiceProbe *> probes; // All the probes except nullProbe
  ServiceProbe *nullProbe; // No probe text - just waiting for banner
};

// Details on a particular service (open port) we are trying to match
class ServiceNFO {
public:
  ServiceNFO(AllProbes *AP);
  ~ServiceNFO();
  // Note that the next 2 members are for convenience and are not destroyed w/the ServiceNFO
  Target *target; // the port belongs to this target host
  Port *port; // The Port that this service represents (this copy is taken from inside Target)
  // if a match is found, it is placed here.  Otherwise NULL
  const char *probe_matched; 
  // most recent probe executed (or in progress).  If there has been a match 
  // (probe_matched != NULL), this will be the corresponding ServiceProbe.
  ServiceProbe *currentProbe();
  // computes the next probe to test, and ALSO CHANGES currentProbe() to
  // that!
  ServiceProbe *nextProbe(); 
  // Number of milliseconds left to complete the present probe, or 0 if
  // the probe is already expired.  Timeval can omitted, it is just there 
  // as an optimization in case you have it handy.
  int currentprobe_timemsleft(const struct timeval *now = NULL);
  enum serviceprobestate probe_state; // defined in portlist.h
  nsock_iod niod; // The IO Descriptor being used in this probe (or NULL)
  u16 portno; // in host byte order
  u8 proto; // IPPROTO_TCP or IPPROTO_UDP
  // The time that the current probe was executed (meaning TCP connection
  // made or first UDP packet sent
  struct timeval currentprobe_exec_time;
  // Append newly-received data to the current response string (if any)
  void appendtocurrentproberesponse(const u8 *respstr, int respstrlen);
  // Get the full current response string.  Note that this pointer is 
  // INVALIDATED if you call appendtocurrentproberesponse() or nextProbe()
  u8 *getcurrentproberesponse(int *respstrlen);
private:
  vector<ServiceProbe *>::iterator current_probe;
  u8 *currentresp;
  int currentresplen;
  AllProbes *AP;
};

// This holds the service information for a group of Targets being service scanned.
class ServiceGroup {
public:
  ServiceGroup(Target *targets[], int num_targets, AllProbes *AP);
  ~ServiceGroup();
  list<ServiceNFO *> services_finished; // Services finished (discovered or not)
  list<ServiceNFO *> services_in_progress; // Services currently being probed
  list<ServiceNFO *> services_remaining; // Probes not started yet
  unsigned int ideal_parallelism; // Max (and desired) number of probes out at once.
  private:
};

/********************   PROTOTYPES *******************/
void servicescan_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void servicescan_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void servicescan_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void end_svcprobe(enum serviceprobestate probe_state, ServiceGroup *SG, ServiceNFO *svc, nsock_iod nsi);
static void startNextProbe(nsock_pool nsp, nsock_iod nsi, ServiceGroup *SG, 
			   struct ServiceNFO *svc);
int launchSomeServiceProbes(nsock_pool nsp, ServiceGroup *SG);

ServiceProbeMatch::ServiceProbeMatch() {
  servicename = NULL;
  matchstr = NULL;
  regex_compiled = NULL;
  regex_extra = NULL;
  isInitialized = false;
  matchops_ignorecase = false;
}

ServiceProbeMatch::~ServiceProbeMatch() {
  if (!isInitialized) return;
  if (servicename) free(servicename);
  if (matchstr) free(matchstr);
  matchstrlen = 0;
  if (regex_compiled) pcre_free(regex_compiled);
  if (regex_extra) pcre_free(regex_extra);
  isInitialized = false;
  matchops_anchor = -1;
}

// match text from the nmap-service-probes file.  This must be called before 
// you try and do anything with this match.  This
// function should be passed the text remaining in the line right AFTER 
// "match " in nmap-service-probes.  The line number that the text is
// provided so that it can be reported in error messages.  This function will
// abort the program if there is a syntax problem.
void ServiceProbeMatch::InitMatch(const char *matchtext, int lineno) {
  char *p;
  char delimchar;
  int pcre_compile_ops = 0;
  const char *pcre_errptr = NULL;
  int pcre_erroffset = 0;
  char tmpbuf[256];
  unsigned int tmpbuflen = 0;

  if (isInitialized) fatal("Sorry ... ServiceProbeMatch::InitMatch does not yet support reinitializion");
  if (!matchtext || !*matchtext) 
    fatal("ServiceProbeMatch::InitMatch: no matchtext passed in (line %d of nmap-service-probes)", lineno);
  isInitialized = true;

  while(isspace(*matchtext)) matchtext++;

  // first comes the service name
  p = strchr(matchtext, ' ');
  if (!p) fatal("ServiceProbeMatch::InitMatch: parse error on line %d of nmap-service-probes", lineno);

  servicename = (char *) safe_malloc(p - matchtext + 1);
  memcpy(servicename, matchtext, p - matchtext);
  servicename[p - matchtext]  = '\0';

  // The next part is a perl style regular expression specifier, like:
  // m/^220 .*smtp/i
  // Where 'm' means a normal regular expressions is used, the char after
  // m can be anything (within reason, slash in this case) and tells us 
  // what delieates the end of the regex.  After the delineating character
  // are any single-character options ('i' in this case, meaning case 
  // insensitive)
  matchtext = p;
  while(isspace(*matchtext)) matchtext++;
  if (*matchtext == 'm') {
    if (!*(matchtext+1))
      fatal("ServiceProbeMatch::InitMatch: parse error on line %d of nmap-service-probes", lineno);
    matchtype = SERVICEMATCH_REGEX;
    delimchar = *(++matchtext);
    ++matchtext;
    // find the end of the regex
    p = strchr(matchtext, delimchar);
    if (!p) fatal("ServiceProbeMatch::InitMatch: parse error on line %d of nmap-service-probes", lineno);
    matchstrlen = p - matchtext;
    matchstr = (char *) safe_malloc(matchstrlen + 1);
    memcpy(matchstr, matchtext, matchstrlen);
    matchstr[matchstrlen]  = '\0';
    
    matchtext = p + 1; // skip past the delim
    // any options?
    while(*matchtext && !isspace(*matchtext)) {
      if (*matchtext == 'i')
	matchops_ignorecase = true;
      else fatal("ServiceProbeMatch::InitMatch: illegal regexp option on line %d of nmap-service-probes", lineno);
      matchtext++;
    }

    // Next we compile and study the regular expression to match
    if (matchops_ignorecase)
      pcre_compile_ops |= PCRE_CASELESS;
    
    regex_compiled = pcre_compile(matchstr, pcre_compile_ops, &pcre_errptr, 
				     &pcre_erroffset, NULL);
    
    if (regex_compiled == NULL)
      fatal("ServiceProbeMatch::InitMatch: illegal regexp on line %d of nmap-service-probes (at regexp offset %d): %s\n", lineno, pcre_erroffset, pcre_errptr);
    
    
    // Now study the regexp for greater efficiency
    regex_extra = pcre_study(regex_compiled, 0, &pcre_errptr);
    if (pcre_errptr != NULL)
      fatal("ServiceProbeMatch::InitMatch: failed to pcre_study regexp on line %d of nmap-service-probes: %s\n", lineno, pcre_errptr);
  } else if (*matchtext == 'q') {
    // The 'q' option is a simple C-like string for when regex would be overkill
    if (!*(matchtext+1))
      fatal("ServiceProbeMatch::InitMatch: parse error on line %d of nmap-service-probes", lineno);
    matchtype = SERVICEMATCH_STATIC;
    delimchar = *(++matchtext);
    ++matchtext;
    // find the end of the regex
    p = strchr(matchtext, delimchar);
    if (!p) fatal("ServiceProbeMatch::InitMatch: parse error on line %d of nmap-service-probes", lineno);
    tmpbuflen = p - matchtext;
    assert(tmpbuflen < sizeof(tmpbuf) - 1);
    memcpy(tmpbuf, matchtext, tmpbuflen);
    tmpbuf[tmpbuflen] = '\0';
    if (!cstring_unescape(tmpbuf, &tmpbuflen)) {
      fatal("ServiceProbeMatch::InitMatch: parse error on line %d of nmap-service-probes", lineno);
    }
    matchstr = (char *) safe_malloc(tmpbuflen + 1);
    memcpy(matchstr, tmpbuf, tmpbuflen);
    matchstrlen = tmpbuflen;
    matchstr[matchstrlen]  = '\0'; // matchstr[] may have embedded NUL - only terminated for ease of debugging
    matchtext = p + 1; // skip past the delim
    // any options?
    while(*matchtext && !isspace(*matchtext)) {
      if (*matchtext == 'a') {
	char *endptr = NULL;
	matchtext++;
	if (!isdigit(*matchtext))
	  fatal("ServiceProbeMatch::InitMatch: static match string option 'a' must be followed by a number - line %d of nmap-service-probes", lineno);
	matchops_ignorecase = true;
	matchops_anchor = strtol(matchtext, &endptr, 10);
	assert(matchops_anchor >= 0);
	matchtext = endptr - 1; // will be incremented momentarily anyway
      } else fatal("ServiceProbeMatch::InitMatch: illegal regexp option on line %d of nmap-service-probes", lineno);
      matchtext++;
    }
  } else {
    /* Invalid matchtext */
    fatal("ServiceProbeMatch::InitMatch: parse error on line %d of nmap-service-probes", lineno);
  }

  isInitialized = 1;
}

const char *ServiceProbeMatch::testMatch(const u8 *buf, int buflen) {
  int rc;
  char *bufc = (char *) buf;
  assert(isInitialized);

  if (matchtype == SERVICEMATCH_REGEX) {
    rc = pcre_exec(regex_compiled, regex_extra, bufc, buflen, 0, 0, NULL, 0);
    if (rc < 0) {
#ifdef PCRE_ERROR_MATCHLIMIT  // earlier PCRE versions lack this
      if (rc == PCRE_ERROR_MATCHLIMIT) {
	if (o.debugging || o.verbose > 1) 
	  error("Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service %s with the regex '%s'", servicename, matchstr);
      } else
#endif // PCRE_ERROR_MATCHLIMIT
	if (rc != PCRE_ERROR_NOMATCH) {
	  fatal("Unexpected PCRE error (%d) when probing for service %s with the regex '%s'", rc, servicename, matchstr);
	}
      return NULL;
    }
    // Yeah!  Match apparently succeeded.
    return servicename;
  } else {
    assert(matchtype == SERVICEMATCH_STATIC);
    if (matchops_anchor >= 0) {
      if (buflen < matchstrlen + matchops_anchor)
	return NULL; // no room to match
      if (memcmp(buf + matchops_anchor, matchstr, matchstrlen) != 0)
	return NULL; // TODO: I should somehow mark this as impossible to match
      // Yeah!  At this point the match must have succeeded
      return servicename;
    } else {
      for(int startpos = 0; startpos <= buflen - matchstrlen; startpos++) {
	if (memcmp(buf + startpos, matchstr, matchstrlen) == 0) {
	  // Yeah!  At this point the match must have succeeded
	  return servicename;
	}
      }
      // Went through all possible start positions (if any) and didn't find jack.
      return NULL;
    }
  }
  assert(0);
  return NULL; // unreached
}


ServiceProbe::ServiceProbe() {
  probename = NULL;
  probestring = NULL;
  totalwaitms = DEFAULT_SERVICEWAITMS;
  probestringlen = 0; probeprotocol = -1;
}

ServiceProbe::~ServiceProbe() {
  vector<ServiceProbeMatch *>::iterator vi;

  if (probename) free(probename);
  if (probestring) free(probestring);

  for(vi = matches.begin(); vi != matches.end(); vi++) {
    delete *vi;
  }
}

void ServiceProbe::setName(const char *name) {
  if (probename) free(probename);
  probename = strdup(name);
}

  // Parses the "probe " line in the nmap-service-probes file.  Pass the rest of the line
  // after "probe ".  The format better be:
  // [TCP|UDP] [probename] q|probetext|
  // Note that the delimiter (|) of the probetext can be anything (within reason)
  // the lineno is requested because this function will bail with an error
  // (giving the line number) if it fails to parse the string.
void ServiceProbe::setProbeDetails(char *pd, int lineno) {
  char *p;
  unsigned int len;
  char delimiter;

  if (!pd || !*pd)
    fatal("Parse error on line %d of nmap-services-probes", lineno);

  // First the protocol
  if (strncmp(pd, "TCP ", 4) == 0)
      probeprotocol = IPPROTO_TCP;
  else if (strncmp(pd, "UDP ", 4) == 0)
      probeprotocol = IPPROTO_UDP;
  else fatal("Parse error on line %d of nmap-services-probes: invalid protocol", lineno);
  pd += 4;

  // Next the service name
  if (!isalnum(*pd)) fatal("Parse error on line %d of nmap-services-probes", lineno);
  p = strchr(pd, ' ');
  if (!p) fatal("Parse error on line %d of nmap-services-probes", lineno);
  len = p - pd;
  probename = (char *) safe_malloc(len + 1);
  memcpy(probename, pd, len);
  probename[len]  = '\0';

  // Now for the probe itself
  pd = p+1;

  if (*pd != 'q') fatal("Parse error on line %d of nmap-services-probes", lineno);
  delimiter = *(++pd);
  p = strchr(++pd, delimiter);
  if (!p) fatal("Parse error on line %d of nmap-services-probes", lineno);
  *p = '\0';
  if (!cstring_unescape(pd, &len)) {
    fatal("Parse error on line %d of nmap-services-probes: bad probe string escaping", lineno);
  }
  setProbeString((const u8 *)pd, len);
}

void ServiceProbe::setProbeString(const u8 *ps, int stringlen) {
  if (probestringlen) free(probestring);
  probestringlen = stringlen;
  if (stringlen > 0) {
    probestring = (u8 *) safe_malloc(stringlen + 1);
    memcpy(probestring, ps, stringlen);
    probestring[stringlen] = '\0'; // but note that other \0 may be in string
  } else probestring = NULL;
}

  // Takes a string as given in the 'ports ' line of
  // nmap-services-probes.  Pass in any text after "ports ".  The line
  // number is requested because this function will bail with an error
  // (giving the line number) if it fails to parse the string.  Ports are
  // a comma seperated list of prots and ranges (e.g. 53,80,6000-6010)
void ServiceProbe::setProbablePorts(const char *portstr, int lineno) {
  const char *current_range;
  char *endptr;
  long int rangestart = 0, rangeend = 0;

  current_range = portstr;

  do {
    while(*current_range && isspace(*current_range)) current_range++;
    if (isdigit((int) *current_range)) {
      rangestart = strtol(current_range, &endptr, 10);
      if (rangestart < 0 || rangestart > 65535) {
	fatal("Parse error on line %d of nmap-services-probes: Ports must be between 0 and 65535 inclusive", lineno);
      }
      current_range = endptr;
      while(isspace((int) *current_range)) current_range++;
    } else {
      fatal("Parse error on line %d of nmap-services-probes: An example of proper portlist form is \"21-25,53,80\"", lineno);
    }

    /* Now I have a rangestart, time to go after rangeend */
    if (!*current_range || *current_range == ',') {
      /* Single port specification */
      rangeend = rangestart;
    } else if (*current_range == '-') {
      current_range++;
      if (isdigit((int) *current_range)) {
	rangeend = strtol(current_range, &endptr, 10);
	if (rangeend < 0 || rangeend > 65535 || rangeend < rangestart) {
	  fatal("Parse error on line %d of nmap-services-probes: Ports must be between 0 and 65535 inclusive", lineno);
	}
	current_range = endptr;
      } else {
	fatal("Parse error on line %d of nmap-services-probes: An example of proper portlist form is \"21-25,53,80\"", lineno);
      }
    } else {
      fatal("Parse error on line %d of nmap-services-probes: An example of proper portlist form is \"21-25,53,80\"", lineno);
    }

    /* Now I have a rangestart and a rangeend, so I can add these ports */
    while(rangestart <= rangeend) {
      probableports.push_back(rangestart);
      rangestart++;
    }
    
    /* Find the next range */
    while(isspace((int) *current_range)) current_range++;
    if (*current_range && *current_range != ',') {
      fatal("Parse error on line %d of nmap-services-probes: An example of proper portlist form is \"21-25,53,80\"", lineno);
    }
    if (*current_range == ',')
      current_range++;
  } while(current_range && *current_range);
}

// Returns true if the passed in port is on the list of probable ports for 
// this probe.
bool ServiceProbe::portIsProbable(u16 portno) {
  if (find(probableports.begin(), probableports.end(), portno) == probableports.end())
    return false;
  return true;
}


  // Takes a "match" line in a probe description and adds it to the list of 
  // matches for this probe.  Pass in any text after "match ".  The line
  // number is requested because this function will bail with an error
  // (giving the line number) if it fails to parse the string.
void ServiceProbe::addMatch(const char *match, int lineno) {
  ServiceProbeMatch *newmatch = new ServiceProbeMatch();
  newmatch->InitMatch(match, lineno);
  matches.push_back(newmatch);
}

// Parses the nmap-service-probes file, and adds each probe to
// the already-created 'probes' vector.
void parse_nmap_service_probes(AllProbes *AP) {
  char filename[256];
  ServiceProbe *newProbe;
  char line[512];
  int lineno = 0;
  FILE *fp;

  if (nmap_fetchfile(filename, sizeof(filename), "nmap-service-probes") == -1){
    fatal("Service scan requested but I cannot find nmap-service-probes file.  It should be in %s, ~/.nmap/ or .", NMAPDATADIR);
  }

  // We found the file, so let us read it.
  fp = fopen(filename, "r");

  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    
    if (*line == '\n' || *line == '#')
      continue;
  
  anotherprobe:
  
    if (strncmp(line, "Probe ", 6) != 0)
      fatal("Parse error on line %d of nmap-service-probes file: %s", lineno, filename);
    
    newProbe = new ServiceProbe();
    newProbe->setProbeDetails(line + 6, lineno);
    
    // Now we read the rest of the probe info
    while(fgets(line, sizeof(line), fp)) {
      lineno++;
      if (*line == '\n' || *line == '#')
	continue;
      
      if (strncmp(line, "Probe ", 6) == 0) {
	if (newProbe->isNullProbe()) {
	  assert(!AP->nullProbe);
	  AP->nullProbe = newProbe;
	} else {
	  AP->probes.push_back(newProbe);
	}
	goto anotherprobe;
      } else if (strncmp(line, "ports ", 6) == 0) {
	newProbe->setProbablePorts(line + 6, lineno);
      } else if (strncmp(line, "totalwaitms ", 12) == 0) {
	long waitms = strtol(line + 12, NULL, 10);
	if (waitms < 100 || waitms > 300000)
	  fatal("Error on line %d of nmap-service-probes file (%s): bad totalwaitms value.  Must be between 100 and 300000 milliseconds", lineno, filename);
	newProbe->totalwaitms = waitms;
      } else if (strncmp(line, "match ", 6) == 0) {
	newProbe->addMatch(line + 6, lineno);
      } else fatal("Parse error on line %d of nmap-service-probes file: %s", lineno, filename);
    }
  }

  assert(newProbe);
  if (newProbe->isNullProbe()) {
    assert(!AP->nullProbe);
    AP->nullProbe = newProbe;
  } else {
    AP->probes.push_back(newProbe);
  }
  
  fclose(fp);
}

  // Returns a service name if the givven buffer and length match one.  
  // Otherwise  returns NULL.
const char *ServiceProbe::testMatch(const u8 *buf, int buflen) {
  vector<ServiceProbeMatch *>::iterator vi;

  for(vi = matches.begin(); vi != matches.end(); vi++) {
    if ((*vi)->testMatch(buf, buflen))
      return (*vi)->getName();
  }

  return NULL;
}

AllProbes::AllProbes() {
  nullProbe = NULL;
}

AllProbes::~AllProbes() {
  vector<ServiceProbe *>::iterator vi;

  // Delete all the ServiceProbe's inside the probes vector
  for(vi = probes.begin(); vi != probes.end(); vi++)
    delete *vi;
}

ServiceNFO::ServiceNFO(AllProbes *newAP) {
  target = NULL;
  probe_matched = NULL;
  niod = NULL;
  probe_state = PROBESTATE_INITIAL;
  portno = proto = 0;
  AP = newAP;
  currentresp = NULL; 
  currentresplen = 0;
  port = NULL;
}

ServiceNFO::~ServiceNFO() {
  if (currentresp) free(currentresp);
}


ServiceProbe *ServiceNFO::currentProbe() {
  if (probe_state == PROBESTATE_INITIAL) {
    return nextProbe();
  } else if (probe_state == PROBESTATE_NULLPROBE) {
    assert(AP->nullProbe);
    return AP->nullProbe;
  } else if (probe_state == PROBESTATE_MATCHINGPROBES || 
	     probe_state == PROBESTATE_NONMATCHINGPROBES) {
    return *current_probe;
  }
  return NULL;
}

// computes the next probe to test, and ALSO CHANGES currentProbe() to
// that!
ServiceProbe *ServiceNFO::nextProbe() {
bool dropdown = false;

// This invalidates the probe response string if any
 if (currentresp) free(currentresp);
 currentresp = NULL; currentresplen = 0;

 if (probe_state == PROBESTATE_INITIAL) {
   probe_state = PROBESTATE_NULLPROBE;
   // This is the very first probe -- so we try to use the NULL probe
   // but obviously NULL probe only works with TCP
   if (proto == IPPROTO_TCP && AP->nullProbe)
     return AP->nullProbe;
   
   // No valid NULL probe -- we'll drop to the next state
 }
 
 if (probe_state == PROBESTATE_NULLPROBE) {
   // There can only be one (or zero) NULL probe.  So now we go through the
   // list looking for matching probes
   probe_state = PROBESTATE_MATCHINGPROBES;
   dropdown = true;
   current_probe = AP->probes.begin();
 }

 if (probe_state == PROBESTATE_MATCHINGPROBES) {
   if (!dropdown && current_probe != AP->probes.end()) current_probe++;
   while (current_probe != AP->probes.end()) {
     if ((proto == (*current_probe)->getProbeProtocol()) && 
	 (*current_probe)->portIsProbable(portno)) {
       // This appears to be a valid probe.  Let's do it!
       return *current_probe;
     }
     current_probe++;
   }
   // Tried all MATCHINGPROBES -- now we must move to nonmatching
   probe_state = PROBESTATE_NONMATCHINGPROBES;
   dropdown = true;
   current_probe = AP->probes.begin();
 }

 if (probe_state == PROBESTATE_NONMATCHINGPROBES) {
   if (!dropdown && current_probe != AP->probes.end()) current_probe++;
   while (current_probe != AP->probes.end()) {
     if ((proto == (*current_probe)->getProbeProtocol()) && 
	 !(*current_probe)->portIsProbable(portno)) {
       // Valid, nonmatching probe.  Let's do it!
       return *current_probe;
     }
     current_probe++;
   }

   // Tried all NONMATCHINGPROBES -- No luck - we're finished :(
   probe_state = PROBESTATE_FINISHED_NOMATCH;
   return NULL; 
 }

 fatal("ServiceNFO::nextProbe called for probe in state (%d)", (int) probe_state);
 return NULL;
}

int ServiceNFO::currentprobe_timemsleft(const struct timeval *now) {
  int timeused, timeleft;

  if (now)
    timeused = TIMEVAL_MSEC_SUBTRACT(*now, currentprobe_exec_time);
  else {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    timeused = TIMEVAL_MSEC_SUBTRACT(tv, currentprobe_exec_time);
  }

  timeleft = currentProbe()->totalwaitms - timeused;
  return (timeleft < 0)? 0 : timeleft;
}

void ServiceNFO::appendtocurrentproberesponse(const u8 *respstr, int respstrlen) {
  currentresp = (u8 *) realloc(currentresp, currentresplen + respstrlen);
  assert(currentresp);
  memcpy(currentresp + currentresplen, respstr, respstrlen);
  currentresplen += respstrlen;
}

// Get the full current response string.  Note that this pointer is 
// INVALIDATED if you call appendtocurrentproberesponse() or nextProbe()
u8 *ServiceNFO::getcurrentproberesponse(int *respstrlen) {
  *respstrlen = currentresplen;
  return currentresp;
}


ServiceGroup::ServiceGroup(Target *targets[], int num_targets, 
			   AllProbes *AP) {
  int targetno;
  ServiceNFO *svc;
  Port *nxtport;
  int desired_par;

  for(targetno = 0 ; targetno < num_targets; targetno++) {
    nxtport = NULL;
    while((nxtport = targets[targetno]->ports.nextPort(nxtport, 0, PORT_OPEN,
			      true))) {
      svc = new ServiceNFO(AP);
      svc->target = targets[targetno];
      svc->portno = nxtport->portno;
      svc->proto = nxtport->proto;
      svc->port = nxtport;
      services_remaining.push_back(svc);
    }
  }

  desired_par = 1;
  if (o.timing_level == 3) desired_par = 10;
  if (o.timing_level == 4) desired_par = 15;
  if (o.timing_level >= 5) desired_par = 20;
  // TODO: Come up with better ways to determine ideal_services
  ideal_parallelism = box(o.min_parallelism, o.max_parallelism? o.max_parallelism : 100, desired_par);
}

ServiceGroup::~ServiceGroup() {
  list<ServiceNFO *>::iterator i;

  for(i = services_finished.begin(); i != services_finished.end(); i++)
    delete *i;

  for(i = services_in_progress.begin(); i != services_in_progress.end(); i++)
    delete *i;

  for(i = services_remaining.begin(); i != services_remaining.end(); i++)
    delete *i;
}

  // Sends probe text to an open connection.  In the case of a NULL probe, there
  // may be no probe text
  static int send_probe_text(nsock_pool nsp, nsock_iod nsi, struct ServiceNFO *svc,
			     ServiceProbe *probe) {
    const u8 *probestring;
    int probestringlen;

    assert(probe);
    if (probe->isNullProbe())
      return 0; // No need to send anything for a NULL probe;
    probestring = probe->getProbeString(&probestringlen);
    assert(probestringlen > 0);
    // Now we write the string to the IOD
    nsock_write(nsp, nsi, servicescan_write_handler, svc->currentprobe_timemsleft(), svc,
		(const char *) probestring, probestringlen);
    return 0;
  }

// This simple helper function is used to start the next probe.  If
// the probe exists, execution begins (and the previous one is cleaned
// up if neccessary) .  Otherwise, the service is listed as finished
// and moved to the finished list
static void startNextProbe(nsock_pool nsp, nsock_iod nsi, ServiceGroup *SG, 
			   struct ServiceNFO *svc) {
  ServiceProbe *probe = svc->currentProbe();

  if (probe->isNullProbe()) {
    // The difference here is that we can reuse the same (TCP) connection
    // if the last probe was the NULL probe.
    probe = svc->nextProbe();
    if (probe) {
      svc->currentprobe_exec_time = *nsock_gettimeofday();
      send_probe_text(nsp, nsi, svc, probe);
      nsock_read(nsp, nsi, servicescan_read_handler, 
		 svc->currentprobe_timemsleft(nsock_gettimeofday()), svc);
    } else {
      // Should only happen if someone has a highly perverse nmap-service-probes
      // file.  Null scan should generally never be the only probe.
      end_svcprobe(PROBESTATE_FINISHED_NOMATCH, SG, svc, NULL);
    }
  } else {
    // The finisehd probe was not a NULL probe.  So we close the
    // connection, and if further probes are available, we launch the
    // next one.
    probe = svc->nextProbe();
    if (probe) {
      // For a TCP probe, we start by requesting a new connection to the target
      if (svc->proto == IPPROTO_TCP) {
	nsi_delete(nsi);
	if ((svc->niod = nsi_new(nsp, svc)) == NULL) {
	  fatal("Failed to allocate Nsock I/O descriptor in startNextProbe()");
	}

	nsock_connect_tcp(nsp, svc->niod, servicescan_connect_handler, 
			  DEFAULT_CONNECT_TIMEOUT, svc, svc->target->v4host(),
			  svc->portno);
      } else {
	assert(svc->proto == IPPROTO_UDP);
	/* Can maintain the same UDP "connection" */
	svc->currentprobe_exec_time = *nsock_gettimeofday();
	send_probe_text(nsp, nsi, svc, probe);
	// Now let us read any results
	nsock_read(nsp, nsi, servicescan_read_handler, 
		   svc->currentprobe_timemsleft(nsock_gettimeofday()), svc);
      }
    } else {
      // No more probes remaining!  Failed to match
      nsi_delete(nsi);
      end_svcprobe(PROBESTATE_FINISHED_NOMATCH, SG, svc, NULL);
    }
  }
  return;
}

// A simple helper function to cancel further work on a service and set it to the given probe_state
// pass NULL for nsi if you don't want it to be deleted (for example, if you already have done so).
void end_svcprobe(enum serviceprobestate probe_state, ServiceGroup *SG, ServiceNFO *svc, nsock_iod nsi) {
  list<ServiceNFO *>::iterator member;

  svc->probe_state = probe_state;
  member = find(SG->services_in_progress.begin(), SG->services_in_progress.end(),
		  svc);
  assert(*member);
  SG->services_in_progress.erase(member);
  SG->services_finished.push_back(svc);

  if (nsi)
    nsi_delete(nsi);

  return;
}

void servicescan_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata) {
  nsock_iod nsi = nse_iod(nse);
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  struct ServiceNFO *svc = (ServiceNFO *) mydata;
  ServiceProbe *probe = svc->currentProbe();
  ServiceGroup *SG = (ServiceGroup *) nsp_getud(nsp);

  assert(type == NSE_TYPE_CONNECT);

  if (status == NSE_STATUS_SUCCESS) {
    // Yeah!  Connection made to the port.  Send the appropriate probe
    // text (if any is needed -- might be NULL probe)
    svc->currentprobe_exec_time = *nsock_gettimeofday();
    send_probe_text(nsp, nsi, svc, probe);
    // Now let us read any results
    nsock_read(nsp, nsi, servicescan_read_handler, svc->currentprobe_timemsleft(nsock_gettimeofday()), svc);
  } else if (status == NSE_STATUS_TIMEOUT || status == NSE_STATUS_ERROR || 
	     status == NSE_STATUS_KILL) {
      // This is not good.  The connect() really shouldn't generally
      // be timing out like that.  We'll mark this svc as incomplete
      // and move it to the finished bin.
    if (o.debugging)
      error("Got nsock CONNECT response with status %s - aborting this service", nse_status2str(status));
    end_svcprobe(PROBESTATE_INCOMPLETE, SG, svc, nsi);
  } else fatal("Unexpected nsock status (%d) returned for connection attempt", (int) status);

  // We may have room for more pr0bes!
  launchSomeServiceProbes(nsp, SG);

  return;
}

void servicescan_write_handler(nsock_pool nsp, nsock_event nse, void *mydata) {
  enum nse_status status = nse_status(nse);
  nsock_iod nsi;
  struct ServiceNFO *svc = (struct ServiceNFO *)mydata;
  ServiceGroup *SG;

 if (status == NSE_STATUS_SUCCESS)
   return;

 SG = (ServiceGroup *) nsp_getud(nsp);
 nsi = nse_iod(nse);
 // Uh-oh.  Some sort of write failure ... maybe the connection closed on us unexpectedly?
 if (o.debugging) 
   error("Got nsock WRITE response with status %s - aborting this service", nse_status2str(status));
 end_svcprobe(PROBESTATE_INCOMPLETE, SG, svc, nsi);

 // We may have room for more pr0bes!
 launchSomeServiceProbes(nsp, SG);
 
 return;
}

void servicescan_read_handler(nsock_pool nsp, nsock_event nse, void *mydata) {
  nsock_iod nsi = nse_iod(nse);
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  struct ServiceNFO *svc = (ServiceNFO *) mydata;
  ServiceProbe *probe = svc->currentProbe();
  ServiceGroup *SG = (ServiceGroup *) nsp_getud(nsp);
  const char *matchname;
  const u8 *readstr;
  int readstrlen;

  assert(type == NSE_TYPE_READ);

  if (status == NSE_STATUS_SUCCESS) {
    // w00p, w00p, we read something back from the port.
    readstr = (u8 *) nse_readbuf(nse, &readstrlen);
    svc->appendtocurrentproberesponse(readstr, readstrlen);
    // now get the full version
    readstr = svc->getcurrentproberesponse(&readstrlen);
    // Now let us try to match it.
    matchname = probe->testMatch(readstr, readstrlen);

    if (matchname) {
      // WOO HOO!!!!!!  MATCHED!
      if (o.debugging > 1)
	printf("Service scan match: %s:%hi is %s\n", svc->target->NameIP(), svc->portno, matchname);
      svc->probe_matched = matchname;
      end_svcprobe(PROBESTATE_FINISHED_MATCHED, SG, svc, nsi);

    } else {
      // Didn't match... maybe reading more until timeout will help
      // TODO: For efficiency I should be able to test if enough data has been
      // received rather than always waiting for the reading to timeout
      nsock_read(nsp, nsi, servicescan_read_handler, svc->currentprobe_timemsleft(), svc);
    }

  } else if (status == NSE_STATUS_TIMEOUT) {
    // Failed to read enough to make a match in the given amount of time.  So we
    // move on to the next probe.  If this was a NULL probe, we can simply
    // send the new probe text immediately.  Oterwise we make a new connection.
    startNextProbe(nsp, nsi, SG, svc);
    
  } else if (status == NSE_STATUS_EOF) {
    // The jerk closed on us during read request!
    // If this was during the NULL probe, let's (for now) assume
    // the port is TCP wrapped.  Otherwise, we'll treat it as a nomatch
    if (probe->isNullProbe()) {
      // TODO:  Perhaps should do further verification before making this assumption
      end_svcprobe(PROBESTATE_FINISHED_TCPWRAPPED, SG, svc, nsi);
    } else {
      // Perhaps this service didn't like the particular probe text.  We'll try the 
      // next one
      startNextProbe(nsp, nsi, SG, svc);
    }
  } else if (status == NSE_STATUS_ERROR) {
    // Errors might happen in some cases ... I'll worry about later
    int err = nse_errorcode(nse);
    switch(err) {
    case ECONNRESET:
      // Jerk hung up on us.  Probably didn't like our probe.  We treat it as with EOF above.
      if (probe->isNullProbe()) {
	// TODO:  Perhaps should do further verification before making this assumption
	end_svcprobe(PROBESTATE_FINISHED_TCPWRAPPED, SG, svc, nsi);
      } else {
	// Perhaps this service didn't like the particular probe text.  We'll try the 
	// next one
	startNextProbe(nsp, nsi, SG, svc);
      }
      break;
    default:
      fatal("Unexpected error in NSE_TYPE_READ callback.  Error code: %d (%s)", err,
	    strerror(err));
    }
  } else {
    fatal("Unexpected status (%d) in NSE_TYPE_READ callback.", (int) status);
  }

  // We may have room for more pr0bes!
  launchSomeServiceProbes(nsp, SG);
  return;
}

// This is passed a completed ServiceGroup which contains the scanning results for every service.
// The function iterates through each finished service and adds the results to Target structure for
// Nmap to output later.

static void processResults(ServiceGroup *SG) {
list<ServiceNFO *>::iterator svc;

 for(svc = SG->services_finished.begin(); svc != SG->services_finished.end(); svc++) {
   if ((*svc)->probe_state == PROBESTATE_FINISHED_MATCHED) {
     (*svc)->port->setServiceProbeResults(PROBESTATE_FINISHED_MATCHED, (*svc)->probe_matched);
   }
 }
}


// This function consults the ServiceGroup to determine whether any
// more probes can be launched at this time.  If so, it determines the
// appropriate ones and then starts them up.
int launchSomeServiceProbes(nsock_pool nsp, ServiceGroup *SG) {
  ServiceNFO *svc;
  ServiceProbe *nextprobe;

  while (SG->services_in_progress.size() < SG->ideal_parallelism &&
	 !SG->services_remaining.empty()) {
    // Start executing a probe from the new list and move it to in_progress
    svc = SG->services_remaining.front();
    nextprobe = svc->nextProbe();
    // We start by requesting a connection to the target
    if ((svc->niod = nsi_new(nsp, svc)) == NULL) {
      fatal("Failed to allocate Nsock I/O descriptor in launchSomeServiceProbes()");
    }
    if (o.debugging > 1) {
      printf("Starting probes against new service: %s:%hi (%s)\n", svc->target->targetipstr(), svc->portno, (svc->proto == IPPROTO_TCP)? "tcp" : "udp");
    }
    if (svc->proto == IPPROTO_TCP)
      nsock_connect_tcp(nsp, svc->niod, servicescan_connect_handler, 
			DEFAULT_CONNECT_TIMEOUT, svc, svc->target->v4host(),
			svc->portno);
    else {
      assert(svc->proto == IPPROTO_UDP);
      nsock_connect_udp(nsp, svc->niod, servicescan_connect_handler, 
			svc, svc->target->v4host(),
			svc->portno);
    }
    // Now remove it from the remaining service list
    SG->services_remaining.pop_front();
    // And add it to the in progress list
    SG->services_in_progress.push_back(svc);
  }
  return 0;
}


/* Execute a service fingerprinting scan against all open ports of the
   targets[] specified. */
int service_scan(Target *targets[], int num_targets) {
  static AllProbes *AP;
  ServiceGroup *SG;
  nsock_pool nsp;
  struct timeval now;
  int timeout;
  enum nsock_loopstatus looprc;
  time_t starttime;

  if (num_targets <= 0)
    return 1;

  // TODO:  This might have to change once I actually start passing in
  // more than one target.
  if (targets[0]->timedout)
    return 1;

  if (!AP) {
    AP = new AllProbes();
    parse_nmap_service_probes(AP);
  }

  // Now I convert the targets into a new ServiceGroup
  SG = new ServiceGroup(targets, num_targets, AP);

  starttime = time(NULL);
  if (o.verbose) {
    struct tm *tm = localtime(&starttime);
    log_write(LOG_STDOUT, "Initiating service scan against %d %s on %d %s at %02d:%02d\n", SG->services_remaining.size(), (SG->services_remaining.size() == 1)? "service" : "services", num_targets, (num_targets == 1)? "host" : "hosts", tm->tm_hour, tm->tm_min);
  }

  // Lets create a nsock pool for managing all the concurrent probes
  // Store the servicegroup in there for availability in callbacks
  if ((nsp = nsp_new(SG)) == NULL) {
    fatal("service_scan() failed to create new nsock pool.");
  }

  if (o.packetTrace()) {
    nsp_settrace(nsp, 5, o.getStartTime());
  }

  launchSomeServiceProbes(nsp, SG);

  // How long do we have befor timing out?
  gettimeofday(&now, NULL);
  // TODO:  May need to change when multiple hosts are actually used
  if (!o.host_timeout)
    timeout= -1;
  else 
    timeout = TIMEVAL_MSEC_SUBTRACT(now, targets[0]->host_timeout);
    
  if (timeout >= 0 && timeout < 500) { // half a second or less just won't cut it
    targets[0]->timedout = 1;
  } else {
    // OK!  Lets start our main loop!
    looprc = nsock_loop(nsp, timeout);
    if (looprc == NSOCK_LOOP_ERROR) {
      pfatal("nsock_loop returned error when trying to do service scan");
    } else if (looprc == NSOCK_LOOP_TIMEOUT) {
      targets[0]->timedout = 1;
    } // else we succeeded!  Should we do something in that case?
  }

  nsp_delete(nsp);

  if (o.verbose) {
    long nsec = time(NULL) - starttime;
    log_write(LOG_STDOUT, "The service scan took %ld %s to scan %d %s on %d %s.\n", nsec, (nsec == 1)? "second" : "seconds", SG->services_finished.size(),  (SG->services_finished.size() == 1)? "service" : "services", num_targets, (num_targets == 1)? "host" : "hosts");
    }

  // Yeah - done with the service scan.  Now I go through the results
  // discovered, store the important info away, and free up everything
  // else.
  processResults(SG);

  delete SG;

  return 0;
}

