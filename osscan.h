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
int os_scan(struct hoststruct *target);
FingerPrint *get_fingerprint(struct hoststruct *target, struct seq_info *si);
struct AVal *fingerprint_iptcppacket(struct ip *ip, int mss, unsigned long syn);
struct AVal *fingerprint_portunreach(struct ip *ip, struct udpprobeinfo *upi);
struct udpprobeinfo *send_closedudp_probe(int rawsd, struct in_addr *dest,
					  unsigned short sport, unsigned short
					  dport);
unsigned long get_gcd_n_ulong(int numvalues, unsigned long *values);
unsigned long euclid_gcd(unsigned long a, unsigned long b);
char *fp2ascii(FingerPrint *FP);
FingerPrint **parse_fingerprint_reference_file();
FingerPrint **match_fingerprint(FingerPrint *FP, int *matches_found);
struct AVal *str2AVal(char *p);
struct AVal *gettestbyname(FingerPrint *FP, char *name);
int AVal_match(struct AVal *reference, struct AVal *fprint); 
void freeFingerPrint(FingerPrint *FP);
char *mergeFPs(FingerPrint *FPs[], int numFPs);
#endif /*OSSCAN_H*/





