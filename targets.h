#ifndef TARGETS_H
#define TARGETS_H

#include "config.h"
/* This contains pretty much everythign we need ... */
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_SYS_PARAM_H   
#include <sys/param.h> /* Defines MAXHOSTNAMELEN on BSD*/
#endif


#include "nmap.h"
#include "global_structures.h"

/**************************STRUCTURES******************************/
struct pingtune {
  int up_this_block;
  int down_this_block;
  int block_tries;
  int block_unaccounted;
  int max_tries;
  int num_responses;
  int dropthistry;
  int group_size;
  int group_start;
  int group_end;
  int discardtimesbefore;
};

struct tcpqueryinfo {
  int *sockets;
  int maxsd;
  fd_set fds_r;
  fd_set fds_w;
  fd_set fds_x;
  int sockets_out;
};

struct pingtech {
  int icmpscan: 1,
    rawicmpscan: 1,
    connecttcpscan: 1,
    rawtcpscan: 1;
};


int get_ping_results(int sd, pcap_t *pd, struct hoststruct *hostbatch, struct timeval *time,  struct pingtune *pt, struct timeout_info *to, int id, struct pingtech *ptech, unsigned short *ports);
int hostupdate(struct hoststruct *hostbatch, struct hoststruct *target, 
	       int newstate, int dotimeout, int trynum, 
	       struct timeout_info *to, struct timeval *sent, 
	       struct pingtune *pt, struct tcpqueryinfo *tqi, int pingtype);
int sendpingquery(int sd, int rawsd, struct hoststruct *target,  
		  int seq, unsigned short id, struct scanstats *ss, 
		  struct timeval *time, struct pingtech ptech);
int sendrawtcppingquery(int rawsd, struct hoststruct *target, int seq,
			struct timeval *time, struct pingtune *pt);
int sendconnecttcpquery(struct hoststruct *hostbatch, struct tcpqueryinfo *tqi, struct hoststruct *target, 
			int seq, struct timeval *time, struct pingtune *pt, struct timeout_info *to, int max_width);
int get_connecttcpscan_results(struct tcpqueryinfo *tqi, 
			       struct hoststruct *hostbatch, 
			       struct timeval *time, struct pingtune *pt, 
			       struct timeout_info *to);
char *readhoststate(int state);
void massping(struct hoststruct *hostbatch, int numhosts, 
	      unsigned short *ports);
/* Fills up the hostgroup_state structure passed in (which must point
   to valid memory).  Lookahead is the number of hosts that can be
   checked (such as ping scanned) in advance.  Randomize causes each
   group of up to lookahead hosts to be internally shuffled around.
   The target_expressions array must remail valid in memory as long as
   this hostgroup_state structure is used -- the array is NOT copied */
int hostgroup_state_init(struct hostgroup_state *hs, int lookahead,
			 int randomize, char *target_expressions[],
			 int num_expressions);
/* If there is at least one IP address left in t, one is pulled out and placed
   in sin and then zero is returned and state information in t is updated
   to reflect that the IP was pulled out.  If t is empty, -1 is returned */
int target_struct_get(struct targets *t, struct in_addr *sin);
/* Undoes the previous target_struct_get operation */
void target_struct_return(struct targets *t);
void hoststructfry(struct hoststruct *hostbatch, int nelem);
/* Ports is the list of ports the user asked to be scanned (0 terminated),
   you can just pass NULL (it is only a stupid optimization that needs it) */
struct hoststruct *nexthost(struct hostgroup_state *hs, unsigned short *ports);
#endif /* TARGETS_H */










