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

int get_ping_results(int sd, struct hoststruct *hostbatch, struct timeval *time,  struct pingtune *pt, struct timeout_info *to, int id);
int hostupdate(struct hoststruct *hostbatch, struct hoststruct *target, 
	       int newstate, int dotimeout, int trynum, 
	       struct timeout_info *to, struct timeval *sent, 
	       struct pingtune *pt, int pingtype);


#endif /* TARGETS_H */







