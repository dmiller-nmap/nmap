#ifndef WINCLUDE_H
#define WINCLUDE_H

#include "nbase.h"

#include <gnuc.h>

#include <pcap.h>
#include <packet32.h>
#include <netinet/tcp.h>  
#include <netinet/udp.h>  
#include <net/if.h>

//#include <packet_types.h>
#include "winip\winip.h"

/* This is kind of ugly ... and worse is that windows includes suply an errno that doesn't work as in UNIX, so if a file
	forgets to include this, it may use errno and get bogus results on Windows [shrug].  A better appraoch is probably
	the nsock_errno() I use in nsock. */
// #undef errno
// #define errno WSAGetLastError()

/* Disables VC++ warning:
  "integral size mismatch in argument; conversion supplied".  Perhaps
  I should try to fix this with casts at some point */
// #pragma warning(disable: 4761)

/* #define signal(x,y) ((void)0)	// ignore for now
                                // later release may set console handlers
*/

void win32_pcap_close(pcap_t *pd);

/* non-functioning stub function */
int fork();

#define pcap_close(pd) win32_pcap_close(pd)

#endif /* WINCLUDE_H */
