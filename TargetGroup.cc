
/***********************************************************************
 * TargetGroup.cc -- The "TargetGroup" class holds a group of IP       *
 * addresses, such as those from a '/16' or '10.*.*.*' specification.  *
 * It also has a trivial HostGroupState class which handles a bunch    *
 * of expressions that go into TargetGroup classes.                    *
 *                                                                     *
 ***********************************************************************
 *  The Nmap Security Scanner is (C) 1995-2002 Insecure.Com LLC. This  *
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

#include "TargetGroup.h"
#include "NmapOps.h"

extern NmapOps o;

TargetGroup::TargetGroup() {
  Initialize();
}

// Bring back (or start with) original state
void TargetGroup::Initialize() {
  targets_type = TYPE_NONE;
  bzero(addresses, sizeof(addresses));
  bzero(current, sizeof(current));
  bzero(last, sizeof(last));
  ipsleft = 0;
}

 /* Initializes (or reinitializes) the object with a new expression, such
    as 192.168.0.0/16 , 10.1.0-5.1-254 , or fe80::202:e3ff:fe14:1102 .  
    Returns 0 for success */  
int TargetGroup::parse_expr(const char * const target_expr, int af) {

  int i=0,j=0,k=0;
  int start, end;
  char *r,*s, *target_net;
  char *addy[5];
  char *hostexp = strdup(target_expr);
  struct hostent *target;
  unsigned long longtmp;
  int namedhost = 0;
  int rc = 0;

  if (targets_type != TYPE_NONE)
    Initialize();

  ipsleft = 0;

  if (af == AF_INET) {
  
    if (strchr(hostexp, ':'))
      fatal("Invalid host expression: %s -- colons only allowed in IPv6 addresses, and then you need the -6 switch", hostexp);

    /*strauct in_addr current_in;*/
    addy[0] = addy[1] = addy[2] = addy[3] = addy[4] = NULL;
    addy[0] = r = hostexp;
    /* First we break the expression up into the four parts of the IP address
       + the optional '/mask' */
    target_net = strtok(hostexp, "/");
    s = strtok(NULL, "");    /* find the end of the token from hostexp */
    netmask  = ( s ) ? atoi(s) : 32;
    if ((int) netmask < 0 || netmask > 32) {
      fprintf(stderr, "Illegal netmask value (%d), must be /0 - /32 .  Assuming /32 (one host)\n", netmask);
      netmask = 32;
    }
    for(i=0; *(hostexp + i); i++) 
      if (isupper((int) *(hostexp +i)) || islower((int) *(hostexp +i))) {
	namedhost = 1;
	break;
      }
    if (netmask != 32 || namedhost) {
      targets_type = IPV4_NETMASK;
      if (!inet_aton(target_net, &(startaddr))) {
	if ((target = gethostbyname(target_net)))
	  memcpy(&(startaddr), target->h_addr_list[0], sizeof(struct in_addr));
	else {
	  fprintf(stderr, "Failed to resolve given hostname/IP: %s.  Note that you can't use '/mask' AND '[1-4,7,100-]' style IP ranges\n", target_net);
	  free(hostexp);
	  return 1;
	}
      } 
      longtmp = ntohl(startaddr.s_addr);
      startaddr.s_addr = longtmp & (unsigned long) (0 - (1<<(32 - netmask)));
      endaddr.s_addr = longtmp | (unsigned long)  ((1<<(32 - netmask)) - 1);
      currentaddr = startaddr;
      if (startaddr.s_addr <= endaddr.s_addr) { 
	ipsleft = endaddr.s_addr - startaddr.s_addr + 1;
	free(hostexp); 
	return 0; 
      }
      fprintf(stderr, "Host specification invalid");
      free(hostexp);
      return 1;
    }
    else {
      i=0;
      targets_type = IPV4_RANGES;
      while(*++r) {
	if (*r == '.' && ++i < 4) {
	  *r = '\0';
	  addy[i] = r + 1;
	}
	else if (*r == '[') {
	  *r = '\0';
	  addy[i]++;
	}
	else if (*r == ']') *r = '\0';
	/*else if ((*r == '/' || *r == '\\') && i == 3) {
	 *r = '\0';
	 addy[4] = r + 1;
	 }*/
	else if (*r != '*' && *r != ',' && *r != '-' && !isdigit((int)*r)) fatal("Invalid character in  host specification.");
      }
      if (i != 3) fatal("Target host specification is illegal.");
      
      for(i=0; i < 4; i++) {
	j=0;
	while((s = strchr(addy[i],','))) {
	  *s = '\0';
	  if (*addy[i] == '*') { start = 0; end = 255; } 
	  else if (*addy[i] == '-') {
	    start = 0;
	    if (!addy[i] + 1) end = 255;
	    else end = atoi(addy[i]+ 1);
	  }
	  else {
	    start = end = atoi(addy[i]);
	    if ((r = strchr(addy[i],'-')) && *(r+1) ) end = atoi(r + 1);
	    else if (r && !*(r+1)) end = 255;
	  }
	  if (o.debugging)
	    log_write(LOG_STDOUT, "The first host is %d, and the last one is %d\n", start, end);
	  if (start < 0 || start > end) fatal("Your host specifications are illegal!");
	  for(k=start; k <= end; k++)
	    addresses[i][j++] = k;
	  addy[i] = s + 1;
	}
	if (*addy[i] == '*') { start = 0; end = 255; } 
	else if (*addy[i] == '-') {
	  start = 0;
	  if (!addy[i] + 1) end = 255;
	  else end = atoi(addy[i]+ 1);
	}
	else {
	  start = end = atoi(addy[i]);
	  if ((r =  strchr(addy[i],'-')) && *(r+1) ) end = atoi(r+1);
	  else if (r && !*(r+1)) end = 255;
	}
	if (o.debugging)
	  log_write(LOG_STDOUT, "The first host is %d, and the last one is %d\n", start, end);
	if (start < 0 || start > end) fatal("Your host specifications are illegal!");
	if (j + (end - start) > 255) fatal("Your host specifications are illegal!");
	for(k=start; k <= end; k++) 
	  addresses[i][j++] = k;
	last[i] = j - 1;
	
      }
    }
  bzero((char *)current, 4);
  ipsleft = (last[0] + 1) * (last[1] + 1) *
    (last[2] + 1) * (last[3] + 1);
  }
  else {
    assert(af == AF_INET6);
    if (strchr(hostexp, '/')) {
      fatal("Invalid host expression: %s -- slash not allowed.  IPv6 addresses can currently only be specified individually", hostexp);
    }
    targets_type = IPV6_ADDRESS;
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    bzero(&hints, sizeof(hints));
    hints.ai_family = PF_INET6;
    rc = getaddrinfo(hostexp, NULL, &hints, &result);
    if (rc != 0) {
      fprintf(stderr, "Failed to resolve given IPv6 hostname/IP: %s.  Note that you can't use '/mask' or '[1-4,7,100-]' style ranges for IPv6.  Error cod %d: %s\n", hostexp, rc, gai_strerror(rc));
      free(hostexp);
      if (result) freeaddrinfo(result);
      return 1;
    }
    assert(result->ai_addrlen == sizeof(struct sockaddr_in6));
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) result->ai_addr;
    memcpy(ip6.s6_addr, sin6->sin6_addr.s6_addr, 16);
    ipsleft = 1;
    freeaddrinfo(result);
  }

  free(hostexp);
  return 0;
}

 /* Grab the next host from this expression (if any) and uptdates its internal
    state to reflect the the IP was given out.  Returns 0 and
    fills in ss if successful.  ss must point to a pre-allocated
    sockaddr_storage structure */
int TargetGroup::get_next_host(struct sockaddr_storage *ss, size_t *sslen) {

  int octet;
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ss;
  startover: /* to handle nmap --resume where I have already
		scanned many of the IPs */  
  assert(ss);
  assert(sslen);


  if (ipsleft <= 0)
    return -1;
  
  if (targets_type == IPV4_NETMASK) {
    bzero(sin, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    *sslen = sizeof(struct sockaddr_in);
#if HAVE_SOCKADDR_SA_LEN
    sin->sin_len = *sslen;
#endif
    
    if (currentaddr.s_addr <= endaddr.s_addr) {
      sin->sin_addr.s_addr = htonl(currentaddr.s_addr++);
    } else {
      error("Bogus target structure passed to TargetGroup::get_next_host");
      ipsleft = 0;
      return -1;
    }
  }
  else if (targets_type == IPV4_RANGES) {
    bzero(sin, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    *sslen = sizeof(struct sockaddr_in);
#if HAVE_SOCKADDR_SA_LEN
    sin->sin_len = *sslen;
#endif
    if (o.debugging > 2) {
      log_write(LOG_STDOUT, "doing %d.%d.%d.%d = %d.%d.%d.%d\n", current[0], current[1], current[2], current[3], addresses[0][current[0]],addresses[1][current[1]],addresses[2][current[2]],addresses[3][current[3]]);
    }
    /* Set the IP to the current value of everything */
    sin->sin_addr.s_addr = htonl(addresses[0][current[0]] << 24 | 
			addresses[1][current[1]] << 16 |
			addresses[2][current[2]] << 8 | 
			addresses[3][current[3]]);
    
    /* Now we nudge up to the next IP */
    for(octet = 3; octet >= 0; octet--) {
      if (current[octet] < last[octet]) {
	/* OK, this is the column I have room to nudge upwards */
	current[octet]++;
	break;
      } else {
	/* This octet is finished so I reset it to the beginning */
	current[octet] = 0;
      }
    }
    if (octet == -1) {
      /* It didn't find anything to bump up, I muast have taken the last IP */
      assert(ipsleft == 1);
      /* So I set current to last with the very final octet up one ... */
      /* Note that this may make current[3] == 256 */
      current[0] = last[0]; current[1] = last[1];
      current[2] = last[2]; current[3] = last[3] + 1;
    } else {
      assert(ipsleft > 1); /* There must be at least one more IP left */
    }
  } else {
    assert(targets_type == IPV6_ADDRESS);
    assert(ipsleft == 1);
    bzero(sin6, sizeof(struct sockaddr_in6));
    sin6->sin6_family = AF_INET6;
#ifdef SIN_LEN
    sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
    memcpy(sin6->sin6_addr.s6_addr, ip6.s6_addr, 16);
  }
  ipsleft--;
  assert(ipsleft >= 0);
  
  /* If we are resuming from a previous scan, we have already finished
     scans up to o.resume_ip.  */
  if (sin->sin_family == AF_INET && o.resume_ip.s_addr) {
    if (o.resume_ip.s_addr == sin->sin_addr.s_addr)
      o.resume_ip.s_addr = 0; /* So that we will KEEP the next one */
    goto startover; /* Try again */
  }

  return 0;
}

/* Returns the last given host, so that it will be given again next
     time get_next_host is called.  Obviously, you should only call
     this if you have fetched at least 1 host since parse_expr() was
     called */
int TargetGroup::return_last_host() {
  int octet;

  ipsleft++;
  if (targets_type == IPV4_NETMASK) {
    assert(currentaddr.s_addr > startaddr.s_addr);
    currentaddr.s_addr--;
  } else if (targets_type == IPV4_RANGES) {
    for(octet = 3; octet >= 0; octet--) {
      if (current[octet] > 0) {
	/* OK, this is the column I have room to nudge downwards */
	current[octet]--;
	break;
      } else {
	/* This octet is already at the beginning, so I set it to the end */
	current[octet] = last[octet];
      }
    }
    assert(octet != -1);
  } else {
    assert(targets_type == IPV6_ADDRESS);
    assert(ipsleft == 1);    
  }
  return 0;
}

/* Lookahead is the number of hosts that can be
   checked (such as ping scanned) in advance.  Randomize causes each
   group of up to lookahead hosts to be internally shuffled around.
   The target_expressions array MUST REMAIN VALID IN MEMMORY as long as
   this class instance is used -- the array is NOT copied.
 */
HostGroupState::HostGroupState(int lookahead, int rnd, 
			       char *expr[], int numexpr) {
  assert(lookahead > 0);
  hostbatch = (Target **) safe_zalloc(sizeof(Target *) * lookahead);
  max_batch_sz = lookahead;
  current_batch_sz = 0;
  next_batch_no = 0;
  randomize = rnd;
  target_expressions = expr;
  num_expressions = numexpr;
  next_expression = 0;
}

HostGroupState::~HostGroupState() {
  free(hostbatch);
}
