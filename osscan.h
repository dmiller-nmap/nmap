#ifndef OSSCAN_H
#define OSSCAN_H

#include "nmap.h"
#include "tcpip.h"
#include "global_structures.h"

#define OSSCAN_SUCCESS 0
#define OSSCAN_NOMATCHES -1
#define OSSCAN_TOOMANYMATCHES -2

/* We won't even consider matches with a lower accuracy than this */
#define OSSCAN_GUESS_THRESHOLD 0.85
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
/* Takes a fingerprint and returns the matches in FPR (which must
   point to an allocated FingerPrintResults structure) -- results will
   be reverse-sorted by accuracy.  No results below
   accuracy_threshhold will be included.  The max matches returned is
   the maximum that fits in a FingerPrintResults structure.  The
   allocated FingerPrintResults does not have to be initialized --
   that will be done in this function.  */

void match_fingerprint(FingerPrint *FP, struct FingerPrintResults *FPR, 
		       double accuracy_threshold);
struct AVal *str2AVal(char *p);
struct AVal *gettestbyname(FingerPrint *FP, const char *name);

/* Returns true if perfect match -- if num_subtests & num_subtests_succeeded are non_null it updates them.  if shortcircuit is zero, it does all the tests, otherwise it returns when the first one fails */

/* Returns true if perfect match -- if num_subtests &
   num_subtests_succeeded are non_null it ADDS THE NEW VALUES to what
   is already there.  So initialize them to zero first if you only
   want to see the results from this match.  if shortcircuit is zero,
   it does all the tests, otherwise it returns when the first one
   fails */
int AVal_match(struct AVal *reference, struct AVal *fprint, unsigned long *num_subtests, unsigned long *num_subtests_succeeded, int shortcut);

void freeFingerPrint(FingerPrint *FP);
char *mergeFPs(FingerPrint *FPs[], int numFPs);
#endif /*OSSCAN_H*/





