#include "services.h"

extern struct ops o;
static int services_initialized = 0;
static int numtcpports = 0;
static int numudpports = 0;
static struct service_list *service_table[SERVICE_TABLE_SIZE];

static int nmap_services_init() {
  char filename[512];
  FILE *fp;
  char servicename[128], proto[16];
  unsigned short portno;
  char *p;
  char line[1024];
  int lineno = 0;
  struct service_list *current, *previous;
  int res;

  if (nmap_fetchfile(filename, sizeof(filename), "nmap-services") == -1) {
    error("Unable to find nmap-services!  Resorting to /etc/services");
    strcpy(filename, "/etc/services");
  }

  fp = fopen(filename, "r");
  if (!fp) {
    fatal("Unable to open %s for reading service information", filename);
  }

  bzero(service_table, sizeof(service_table));
  
  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    p = line;
    res = sscanf(line, "%s %hu/%s", servicename, &portno, proto);
    if (res !=3)
      continue;
    portno = htons(portno);

    /* Now we make sure our services doesn't have duplicates */
    for(current = service_table[portno % SERVICE_TABLE_SIZE], previous = NULL;
	current; current = current->next) {
      if (portno == current->servent->s_port &&
	  strcasecmp(proto, current->servent->s_proto) == 0) {
	if (o.debugging) {
	  error("Port %d proto %s is duplicated in services file %s", ntohs(portno), proto, filename);
	}
	break;
      }
      previous = current;
    }
    if (current)
      continue;

    if (strncasecmp(proto, "tcp", 3) == 0) {
      numtcpports++;
    } else if (strncasecmp(proto, "udp", 3) == 0) {
      numudpports++;
    } else {
      if (o.debugging)
	error("Unknown protocol (%s) on line %d of services file %s.", proto, lineno, filename);
      continue;
    }

    current = (struct service_list *) cp_alloc(sizeof(struct service_list));
    current->servent = (struct servent *) cp_alloc(sizeof(struct servent));
    current->next = NULL;
    if (previous == NULL) {
      service_table[portno % SERVICE_TABLE_SIZE] = current;
    } else {
      previous->next = current;
    }
    current->servent->s_name = cp_strdup(servicename);
    current->servent->s_port = portno;
    current->servent->s_proto = cp_strdup(proto);
    current->servent->s_aliases = NULL;
  }
  fclose(fp);
  services_initialized = 1;
  return 0;
}


struct servent *nmap_getservbyport(int port, const char *proto) {
  struct service_list *current;

  if (!services_initialized)
    if (nmap_services_init() == -1)
      return NULL;

  for(current = service_table[port % SERVICE_TABLE_SIZE];
      current; current = current->next) {
    if (port == current->servent->s_port &&
	strcmp(proto, current->servent->s_proto) == 0)
      return current->servent;
  }

  /* Couldn't find it ... oh well. */
  return NULL;
  
}

/* Be default we do all ports 1-1024 as well as any higher ports
   that are in /etc/services. */
unsigned short *getdefaultports(int tcpscan, int udpscan) {
  int portindex = 0;
  unsigned short *ports;
  char usedports[65536];
  struct service_list *current;
  int bucket;
  int portsneeded = 1; /* the 1 is for the terminating 0 */

  if (!services_initialized)
    if (nmap_services_init() == -1)
      fatal("Getfastports: Coudn't get port numbers");
  
  bzero(usedports, sizeof(usedports));
  for(bucket = 1; bucket < 1025; bucket++) {  
    usedports[bucket] = 1;
    portsneeded++;
  }

  for(bucket = 0; bucket < SERVICE_TABLE_SIZE; bucket++) {  
    for(current = service_table[bucket % SERVICE_TABLE_SIZE];
	current; current = current->next) {
      if (!usedports[ntohs(current->servent->s_port)] &&
	  ((tcpscan && !strncmp(current->servent->s_proto, "tcp", 3)) ||
	   (udpscan && !strncmp(current->servent->s_proto, "udp", 3)))) {      
	usedports[ntohs(current->servent->s_port)] = 1;
	portsneeded++;
      }
    }
  }

  ports = (unsigned short *) cp_alloc(portsneeded * sizeof(unsigned short));
  o.numports = portsneeded - 1;

  for(bucket = 1; bucket < 65536; bucket++) {
    if (usedports[bucket])
      ports[portindex++] = bucket;
  }
  ports[portindex] = 0;

return ports;

}

unsigned short *getfastports(int tcpscan, int udpscan) {
  int portindex = 0;
  unsigned short *ports;
  char usedports[65536];
  struct service_list *current;
  int bucket;
  int portsneeded = 1; /* the 1 is for the terminating 0 */

  if (!services_initialized)
    if (nmap_services_init() == -1)
      fatal("Getfastports: Coudn't get port numbers");
  
  bzero(usedports, sizeof(usedports));

  for(bucket = 0; bucket < SERVICE_TABLE_SIZE; bucket++) {  
    for(current = service_table[bucket % SERVICE_TABLE_SIZE];
	current; current = current->next) {
      if (!usedports[ntohs(current->servent->s_port)] &&
	  ((tcpscan && !strncmp(current->servent->s_proto, "tcp", 3)) ||
	   (udpscan && !strncmp(current->servent->s_proto, "udp", 3)))) {      
	usedports[ntohs(current->servent->s_port)] = 1;
	portsneeded++;
      }
    }
  }

  ports = (unsigned short *) cp_alloc(portsneeded * sizeof(unsigned short));
  o.numports = portsneeded - 1;

  for(bucket = 1; bucket < 65536; bucket++) {
    if (usedports[bucket])
      ports[portindex++] = bucket;
  }
  ports[portindex] = 0;

return ports;
}





