#ifndef WINCLUDE
#define WINCLUDE
#define BYTE_ORDER LITTLE_ENDIAN
#define WIN32_LEAN_AND_MEAN
#define _INC_ERRNO	//	supress errno.h

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

#define MAXPATHLEN 2048
#define     ECONNABORTED    WSAECONNABORTED
#define     ECONNRESET      WSAECONNRESET
#define     ECONNREFUSED    WSAECONNREFUSED
#define     EAGAIN			WSAEWOULDBLOCK
#define     EHOSTUNREACH	WSAEHOSTUNREACH
#define     ENETDOWN		WSAENETDOWN
#define     ENETUNREACH		WSAENETUNREACH
#define     ENETRESET		WSAENETRESET
#define     ETIMEDOUT		WSAETIMEDOUT
#define     EHOSTDOWN		WSAEHOSTDOWN
#define     EINPROGRESS		WSAEINPROGRESS
#define EINVAL          WSAEINVAL      /* Invalid argument */
#define     EPERM            WSAEACCES      /* Operation not permitted */
#define EINTR            WSAEINTR      /* Interrupted system call */
#define ENOBUFS         WSAENOBUFS     /* No buffer space available */
#define ENOENT           WSAENOENT      /* No such file or directory */


#define S_ISDIR(m)      (((m) & _S_IFMT) == _S_IFDIR)
//#define HAVE_STRUCT_IP
//#define HAVE_STRUCT_ICMP


#define PROT_READ       0x1             /* page can be read */
#define PROT_WRITE      0x2             /* page can be written */
#define PROT_EXEC       0x4             /* page can be executed */
#define PROT_NONE       0x0             /* page can not be accessed */

#define MAP_SHARED      0x01            /* Share changes */
#define SIOCGIFCONF     0x8912          /* get iface list               */

#define snprintf _snprintf

#ifndef GLOBALS
#define GLOBALS 1
extern char *NMAP_VERSION;
extern char *NMAP_NAME;
extern char *NMAP_URL;
extern char *NMAPDATADIR;
extern HANDLE gmap; 
//extern struct interface_info global_adapter;
#endif

#pragma warning(disable: 4761)

#define stat _stat // wtf was ms thinking?
#define execve _execve
#define signal(x,y) ((void)0)	//	ignore for now
//	later release may set console handlers

#define STDOUT_FILENO 1
#define STDERR_FILENO 2

extern struct winops wo;

#define WIN32_EXTRA_LONGOPT_LIST {"win_list_interfaces", no_argument, 0, 0},\
	{"win_norawsock", no_argument, 0, 0}, \
	{"win_forcerawsock", no_argument, 0, 0}, \
	{"win_nopcap", no_argument, 0, 0}, \
	{"win_nt4route", no_argument, 0, 0}, \
	{"win_noiphlpapi", no_argument, 0, 0}, \
	{"win_help", no_argument, 0, 0},

#define WIN32_EXTRA_LONGOPT_IMP \
	  } else if (strcmp(long_options[option_index].name, "win_list_interfaces") == 0 ) { \
	wo.listinterfaces = 1; \
	  } else if (strcmp(long_options[option_index].name, "win_norawsock") == 0 ) { \
	wo.norawsock = 1; \
	  } else if (strcmp(long_options[option_index].name, "win_forcerawsock") == 0 ) { \
	wo.forcerawsock = 1; \
	  } else if (strcmp(long_options[option_index].name, "win_nopcap") == 0 ) { \
	wo.nopcap = 1; \
	  } else if (strcmp(long_options[option_index].name, "win_nt4route") == 0 ) { \
	wo.nt4route = 1; \
	  } else if (strcmp(long_options[option_index].name, "win_noiphlpapi") == 0 ) { \
	wo.noiphlpapi = 1; \
	  } else if (strcmp(long_options[option_index].name, "win_help") == 0 ) { \
	printf("Windows-specific options:\n\n"); \
	printf(" --win_list_interfaces : list all network interfaces\n"); \
	printf(" --win_norawsock       : disable raw socket support\n"); \
	printf(" --win_forcerawsock    : try raw sockets even on non-W2K systems\n"); \
	printf(" --win_nopcap          : disable winpcap support\n"); \
	printf(" --win_nt4route        : test nt4 route code\n"); \
	printf(" --win_noiphlpapi      : test response to lack of iphlpapi.dll\n"); \
	exit(0);

#define munmap win32_munmap
int nmapwin_isroot();
#define vsnprintf _vsnprintf

#undef errno
#define errno WSAGetLastError()

#define close my_close
#define read(x,y,z) recv(x,(char*)(y),z,0)
inline int my_close(int sd);

typedef unsigned short u_short_t;

int win32_sendto(int sd, char *packet, int len, 
	   unsigned int flags, struct sockaddr *to, int tolen);

int win32_socket(int af, int type, int proto);

void win32_pcap_close(pcap_t *pd);

#define socket win32_socket
#define sendto win32_sendto
#define pcap_close win32_pcap_close

#endif //WINCLUDE
