#ifndef OSSCAN_H
#define OSSCAN_H

#include "nmap.h"
#include "tcpip.h"
#include "global_structures.h"

#define ENOMATCHESATALL -1
#define ETOOMANYMATCHES -2

/**********************  STRUCTURES  ***********************************/

/* moved to global_structures.h */

/**********************  PROTOTYPES  ***********************************/
int os_scan(struct hoststruct *target, unsigned short *portarray);
FingerPrint *get_fingerprint(struct hoststruct *target, struct seq_info *si, 
			     unsigned short *portarray);
struct AVal *fingerprint_iptcppacket(struct ip *ip, int mss, unsigned int syn);
struct AVal *fingerprint_portunreach(struct ip *ip, struct udpprobeinfo *upi);
struct udpprobeinfo *send_closedudp_probe(int rawsd, struct in_addr *dest,
					  unsigned short sport, unsigned short
					  dport);
unsigned int get_gcd_n_ulong(int numvalues, unsigned int *values);
unsigned int euclid_gcd(unsigned int a, unsigned int b);
char *fp2ascii(FingerPrint *FP);
FingerPrint **parse_fingerprint_reference_file();
FingerPrint **match_fingerprint(FingerPrint *FP, int *matches_found);
struct AVal *str2AVal(char *p);
struct AVal *gettestbyname(FingerPrint *FP, char *name);
int AVal_match(struct AVal *reference, struct AVal *fprint); 
void freeFingerPrint(FingerPrint *FP);
char *mergeFPs(FingerPrint *FPs[], int numFPs);
#endif /*OSSCAN_H*/





