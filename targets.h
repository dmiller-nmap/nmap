#ifndef TARGETS_H
#define TARGETS_H

/* This contains pretty much everythign we need ... */
#include "nmap.h"

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


int get_ping_results(int sd, pcap_t *pd, struct hoststruct *hostbatch, struct timeval *time,  struct pingtune *pt, struct timeout_info *to, int id, struct pingtech *ptech);
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
			int seq, struct timeval *time, struct pingtune *pt, struct timeout_info *to);
int get_connecttcpscan_results(struct tcpqueryinfo *tqi, 
			       struct hoststruct *hostbatch, 
			       struct timeval *time, struct pingtune *pt, 
			       struct timeout_info *to);
char *readhoststate(int state);
#endif /* TARGETS_H */










