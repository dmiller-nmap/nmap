#include "protocols.h"

extern struct ops o;
static int protocols_initialized = 0;
static int numipprots = 0;
static struct protocol_list *protocol_table[PROTOCOL_TABLE_SIZE];

static int nmap_protocols_init() {
  char filename[512];
  FILE *fp;
  char protocolname[128], proto[16];
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

  bzero(protocol_table, sizeof(protocol_table));
  
  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    p = line;
    while(*p && isspace((int) *p))
      p++;
    if (*p == '#')
      continue;
    res = sscanf(line, "%s %hu", protocolname, &protno);
    if (res !=2)
      continue;
    protno = htons(protno);

    /* Now we make sure our protocols don't have duplicates */
    for(current = protocol_table[0], previous = NULL;
	current; current = current->next) {
      if (protno == current->protoent->p_proto) {
	if (o.debugging) {
	  error("Protocol %d is duplicated in protocols file %s", ntohs(protno), proto, filename);
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
unsigned short *getdefaultprots(void) {
  int protindex = 0;
  unsigned short *prots;
  char usedprots[256];
  /*struct protocol_list *current;*/
  int bucket;
  int protsneeded = 1; /* the 1 is for the terminating 0 */

  if (!protocols_initialized)
    if (nmap_protocols_init() == -1)
      fatal("getdefaultprots(): Couldn't get protocol numbers");
  
  bzero(usedprots, sizeof(usedprots));
  for(bucket = 1; bucket < 255; bucket++) {  
    usedprots[bucket] = 1;
    protsneeded++;
  }

  prots = (unsigned short *) cp_alloc(protsneeded * sizeof(unsigned short));
  o.numports = protsneeded - 1;

  for(bucket = 1; bucket < 255; bucket++) {
    if (usedprots[bucket])
      prots[protindex++] = bucket;
  }
  prots[protindex] = 0;

return prots;

}

unsigned short *getfastprots(void) {
  int protindex = 0;
  unsigned short *prots;
  char usedprots[256];
  struct protocol_list *current;
  int bucket;
  int protsneeded = 1; /* the 1 is for the terminating 0 */

  if (!protocols_initialized)
    if (nmap_protocols_init() == -1)
      fatal("Getfastprots: Couldn't get protocol numbers");
  
  bzero(usedprots, sizeof(usedprots));

  for(bucket = 0; bucket < PROTOCOL_TABLE_SIZE; bucket++) {  
    for(current = protocol_table[bucket % PROTOCOL_TABLE_SIZE];
	current; current = current->next) {
      if (!usedprots[ntohs(current->protoent->p_proto)])
	usedprots[ntohs(current->protoent->p_proto)] = 1;
	protsneeded++;
    }
  }

  prots = (unsigned short *) cp_alloc(protsneeded * sizeof(unsigned short));
  o.numports = protsneeded - 1;

  for(bucket = 1; bucket < 256; bucket++) {
    if (usedprots[bucket])
      prots[protindex++] = bucket;
  }
  prots[protindex] = 0;

return prots;
}







