#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <netdb.h>
#include "nmap.h"
#include "global_structures.h"
#include "charpool.h"
#include "error.h"
#include "utils.h"

#define PROTOCOL_TABLE_SIZE 256

struct protocol_list {
  struct protoent *protoent;
  struct protocol_list *next;
};

struct protoent *nmap_getprotbynum(int num);
unsigned short *getfastprots(void);
unsigned short *getdefaultprots(void);


#endif
