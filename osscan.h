#ifndef OSSCAN_H
#define OSSCAN_H

#include "nmap.h"
#include "tcpip.h"
#include "global_structures.h"

/**********************  STRUCTURES  ***********************************/

/* moved to global_structures.h */

/**********************  PROTOTYPES  ***********************************/
int os_scan(struct hoststruct *target);
FingerPrint *get_fingerprint(struct hoststruct *target);
struct AVal *fingerprint_iptcppacket(struct ip *ip, int mss, unsigned long syn);
unsigned long get_gcd_n_ulong(int numvalues, unsigned long *values);
unsigned long euclid_gcd(unsigned long a, unsigned long b);
char *fp2ascii(FingerPrint *FP);
FingerPrint **parse_fingerprint_reference_file();
FingerPrint **match_fingerprint(FingerPrint *FP);
struct AVal *str2AVal(char *p);
struct AVal *gettestbyname(FingerPrint *FP, char *name);
int AVal_match(struct AVal *reference, struct AVal *fprint); 
void freeFingerPrint(FingerPrint *FP);
#endif /*OSSCAN_H*/





