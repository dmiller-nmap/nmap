
/***********************************************************************
 * protocols.cc -- Functions relating to the protocol scan and mapping *
 * between IPproto Number <-> name.                                    *
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

#include "protocols.h"
#include "NmapOps.h"

extern NmapOps o;
static int protocols_initialized = 0;
static int numipprots = 0;
static struct protocol_list *protocol_table[PROTOCOL_TABLE_SIZE];

static int nmap_protocols_init() {
  char filename[512];
  FILE *fp;
  char protocolname[128];
  unsigned short protno;
  char *p;
  char line[1024];
  int lineno = 0;
  struct protocol_list *current, *previous;
  int res;

  if (nmap_fetchfile(filename, sizeof(filename), "nmap-protocols") == -1) {
    error("Unable to find nmap-protocols!  Resorting to /etc/protocol");
    strcpy(filename, "/etc/protocols");
  }

  fp = fopen(filename, "r");
  if (!fp) {
    fatal("Unable to open %s for reading protocol information", filename);
  }

  memset(protocol_table, 0, sizeof(protocol_table));
  
  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    p = line;
    while(*p && isspace((int) *p))
      p++;
    if (*p == '#')
      continue;
    res = sscanf(line, "%127s %hu", protocolname, &protno);
    if (res !=2)
      continue;
    protno = htons(protno);

    /* Now we make sure our protocols don't have duplicates */
    for(current = protocol_table[0], previous = NULL;
	current; current = current->next) {
      if (protno == current->protoent->p_proto) {
	if (o.debugging) {
	  error("Protocol %d is duplicated in protocols file %s", ntohs(protno), filename);
	}
	break;
      }
      previous = current;
    }
    if (current)
      continue;

    numipprots++;

    current = (struct protocol_list *) cp_alloc(sizeof(struct protocol_list));
    current->protoent = (struct protoent *) cp_alloc(sizeof(struct protoent));
    current->next = NULL;
    if (previous == NULL) {
      protocol_table[protno] = current;
    } else {
      previous->next = current;
    }
    current->protoent->p_name = cp_strdup(protocolname);
    current->protoent->p_proto = protno;
    current->protoent->p_aliases = NULL;
  }
  fclose(fp);
  protocols_initialized = 1;
  return 0;
}


struct protoent *nmap_getprotbynum(int num) {
  struct protocol_list *current;

  if (!protocols_initialized)
    if (nmap_protocols_init() == -1)
      return NULL;

  for(current = protocol_table[num % PROTOCOL_TABLE_SIZE];
      current; current = current->next) {
    if (num == current->protoent->p_proto)
      return current->protoent;
  }

  /* Couldn't find it ... oh well. */
  return NULL;
  
}

/* Be default we do all prots 0-255. */
struct scan_lists *getdefaultprots(void) {
  int protindex = 0;
  struct scan_lists *scanlist;
  /*struct protocol_list *current;*/
  int bucket;
  int protsneeded = 256;

  if (!protocols_initialized)
    if (nmap_protocols_init() == -1)
      fatal("getdefaultprots(): Couldn't get protocol numbers");
  
  scanlist = (struct scan_lists *) safe_zalloc(sizeof(struct scan_lists));
  scanlist->prots = (unsigned short *) safe_zalloc((protsneeded) * sizeof(unsigned short));
  scanlist->prot_count = protsneeded;

  for(bucket = 0; bucket < protsneeded; bucket++) {
    scanlist->prots[protindex++] = bucket;
  }
  return scanlist;
}

struct scan_lists *getfastprots(void) {
  int protindex = 0;
  struct scan_lists *scanlist;
  char usedprots[256];
  struct protocol_list *current;
  int bucket;
  int protsneeded = 0;

  if (!protocols_initialized)
    if (nmap_protocols_init() == -1)
      fatal("Getfastprots: Couldn't get protocol numbers");
  
  memset(usedprots, 0, sizeof(usedprots));

  for(bucket = 0; bucket < PROTOCOL_TABLE_SIZE; bucket++) {  
    for(current = protocol_table[bucket % PROTOCOL_TABLE_SIZE];
	current; current = current->next) {
      if (!usedprots[ntohs(current->protoent->p_proto)])
	usedprots[ntohs(current->protoent->p_proto)] = 1;
	protsneeded++;
    }
  }

  scanlist = (struct scan_lists *) safe_zalloc(sizeof(struct scan_lists));
  scanlist->prots = (unsigned short *) safe_zalloc((protsneeded ) * sizeof(unsigned short));
  scanlist->prot_count = protsneeded;

  for(bucket = 0; bucket < 256; bucket++) {
    if (usedprots[bucket])
      scanlist->prots[protindex++] = bucket;
  }

  return scanlist;
}







