#ifndef WINCLUDE_H
#define WINCLUDE_H

#include "nbase.h"
#include <windows.h>
#include <string.h>
#include <gnuc.h>
#include <winsock2.h>
#include <time.h>
#include <assert.h>
#include <iptypes.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <process.h>
//#include <errno.h>
#include <limits.h>
#include <pcap.h>
#include <packet32.h>
#include <WINCRYPT.H>
#include <netinet/tcp.h>  
#include <netinet/udp.h>  
#include <net/if.h>
#include <winfix.h>
#include <math.h>
//#include <packet_types.h>
#include "winip\winip.h"

typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned long u_int32_t;
typedef unsigned int ssize_t;

//#define HAVE_STRUCT_IP
//#define HAVE_STRUCT_ICMP


#define SIOCGIFCONF     0x8912          /* get iface list */

#ifndef GLOBALS
#define GLOBALS 1

//extern struct interface_info global_adapter;
#endif

/* #pragma warning(disable: 4761)*/

/* #define signal(x,y) ((void)0)	// ignore for now
                                // later release may set console handlers
*/

extern struct winops wo;

#define munmap win32_munmap
int nmapwin_isroot();

#undef errno
#define errno WSAGetLastError()

#define close my_close
#define read(x,y,z) recv(x,(char*)(y),z,0)
inline int my_close(int sd);

typedef unsigned short u_short_t;

int win32_sendto(int sd, const char *packet, int len, 
	   unsigned int flags, struct sockaddr *to, int tolen);

int win32_socket(int af, int type, int proto);

void win32_pcap_close(pcap_t *pd);

#define socket win32_socket
#define sendto win32_sendto
#define pcap_close win32_pcap_close

#endif /* WINCLUDE_H */
