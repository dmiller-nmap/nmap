/* #include <windows.h> */
/* #include "packet32.h" */
#include "winclude.h"
char *NMAP_VERSION ="2.54 BETA3";
char *NMAP_NAME ="nmap";
char *NMAP_URL="www.insecure.org/nmap/";
char *NMAPDATADIR="c:\nmap";
HANDLE gmap; 

/*	
struct interface_info {
    struct in_addr addr;
#ifdef WIN32
	char name[1024];
	char Wname[1024];
	LPADAPTER adapter;
	BYTE MAC[6];
	char Aname[512];
	char chopname[512];
	DWORD DefaultGateway;
	struct in_addr Gateway;
#else
	char name[64];
#endif

} global_adapter;*/