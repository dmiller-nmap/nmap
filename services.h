#ifndef SERVICES_H
#define SERVICES_H

#include <netdb.h>
#include "nmap.h"
#include "global_structures.h"
#include "charpool.h"
#include "error.h"
#include "utils.h"

#define SERVICE_TABLE_SIZE 1024

struct service_list {
  struct servent *servent;
  struct service_list *next;
};

struct servent *nmap_getservbyport(int port, const char *proto);
unsigned short *getfastports(int tcpscan, int udpscan);
unsigned short *getdefaultports(int tcpscan, int udpscan);


#endif
