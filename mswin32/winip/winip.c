/*

winip.c: non-pcap-or-rawsock-specific code for the winip library
Copyright (C) 2000  Andy Lutomirski

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License, version 2.1, as published by the Free Software
Foundation, with the exception that if this copy of the library
is distributed under the Lesser GNU Public License (as opposed
to the ordinary GPL), you may ignore section 6b, and that all
copies distributed without exercising section 3 must retain this
paragraph in its entirety.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

This is designed to be used by nmap but should be
adaptable to anything.

This module implements the tables needed for
routing and interface selection

A winif is for iphlpapi
An ifindex is an index into iftable

Note: if used outside nmap in a non-GPL app, you need to reimplement
readip_pcap_real and my_real_open_pcap_live for licensing reasons.
If used outside nmap in a GPL'ed app, just copy them from wintcpip.c.

*/

#include "..\tcpip.h"
#include "winip.h"
#include <delayimp.h>

#undef socket
#undef sendto
#undef pcap_close

#define	IP_HDRINCL		2 /* header is included with data */

#define DLI_ERROR VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND)

extern struct ops o;

int pcap_avail = 0;
int rawsock_avail = 0;
int winbug = 0;

/*   internal functions   */
static void winip_cleanup(void);
static void winip_init_pcap(char *a);
static void winip_test(int needraw);
static void winip_list_interfaces();

//	The tables

typedef struct _WINIP_NAME {
	char name[16];
	int ifi;
} WINIP_NAME;

PCHAR iftnames[] =
{"net", "eth", "ppp", "loopback", "serial", "isdn", "slip"};
// 0      1      2         3         4         5       6

int iftypes[] = {0,
0, 0, 0, 0, 0,	//	1-5
1, 0, 0, 0, 0,	//	6-10
0, 0, 0, 0, 0,	//	11-15
0, 0, 0, 0, 5,	//	16-20
5, 4, 2, 3, 0,	//	21-25
1, 0, 6, 0, 0,	//	26-30
0, 0};			//	31-32

int iftnums[7];

static WINIP_IF *iftable;
static int numifs, numips;
static WINIP_NAME *nametable;

static int inited;
static char pcaplist[4096];

//	windows-specific options
struct winops wo;

//	Free this on cleanup
static IPNODE *ipblock;

void winip_barf(const char *msg)
{
	if(inited != 3) fatal("%s", msg);
	if(msg) printf("%s\n\n", msg);
	printf("\nYour system doesn't have iphlpapi.dll\n\nIf you have Win95, "
		"maybe you could grab it from a Win98 system\n"
		"If you have NT4, you need service pack 4 or higher\n"
		"If you have NT3.51, try grabbing it from an NT4 system\n"
		"Otherwise, your system has problems ;-)\n");
	exit(0);
}

void winip_init()
{
	if(inited != 0) return;
	inited = 1;

	ZeroMemory(&wo, sizeof(wo));
}

void winip_postopt_init()
{
	//	variables
	DWORD cb = 0;
	PMIB_IFTABLE pTable = (PMIB_IFTABLE)&cb;
	DWORD nRes;
	OSVERSIONINFOEX ver;
	PMIB_IPADDRTABLE pIp = 0;
	int i;
	IPNODE *nextip;
	int numipsleft;
	WORD werd;
	WSADATA data;

	if(inited != 1)
		return;
	inited = 2;

	werd = MAKEWORD( 2, 2 );
	if( (WSAStartup(werd, &data)) !=0 )
		fatal("failed to start winsock.\n");

	ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if(!GetVersionEx((LPOSVERSIONINFO)&ver))
	{
		ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		if(!GetVersionEx((LPOSVERSIONINFO)&ver))
			fatal("GetVersionEx failed\n");

		ver.wServicePackMajor = 0;
		ver.wServicePackMinor = 0;
	}

	//	Test for win_noiphlpapi
	if(wo.noiphlpapi)
	{
		o.isr00t = 0;
		inited = 3;
		if(wo.listinterfaces) winip_barf(0);
		return;
	}

	//	Read the size
	__try { nRes = GetIfTable(pTable, &cb, TRUE); }
	__except(GetExceptionCode() == DLI_ERROR)
	{
		//	we have no iphlpapi.dll
		o.isr00t = 0;
		inited = 3;
		if(wo.listinterfaces) winip_barf(0);
		return;
	}
	if(nRes != NO_ERROR && nRes != ERROR_INSUFFICIENT_BUFFER
		&& nRes != ERROR_BUFFER_OVERFLOW)
		fatal("failed to get size of interface table\n");

	//	Read the data
	pTable = (PMIB_IFTABLE)_alloca(cb + sizeof(MIB_IFROW));
	nRes = GetIfTable(pTable, &cb, TRUE);
	if(nRes != NO_ERROR)
		fatal("failed to read interface table -- try again\n");
	numifs = pTable->dwNumEntries;

	cb = 0;
	nRes = GetIpAddrTable(pIp, &cb, FALSE);
	if(nRes != NO_ERROR && nRes != ERROR_INSUFFICIENT_BUFFER)
		fatal("failed to get size of IP address table\n");

	//	Read the data
	pIp = (PMIB_IPADDRTABLE)_alloca(cb + sizeof(MIB_IPADDRROW));
	nRes = GetIpAddrTable(pIp, &cb, FALSE);
	if(nRes != NO_ERROR)
		fatal("failed to read IP address table\n");

	//	Allocate storage
	iftable = (WINIP_IF*)calloc(numifs, sizeof(WINIP_IF));
	nametable = (WINIP_NAME*)calloc(numifs, sizeof(WINIP_NAME));
	ipblock = (IPNODE*)calloc(pIp->dwNumEntries, sizeof(IPNODE));
	nextip = ipblock;
	numipsleft = pIp->dwNumEntries;
	numips = pIp->dwNumEntries;

	//	Fill in the table
	for(i = 0; i < numifs; i++)
	{
		struct in_addr addr;
		int ift;
		int j;

		iftable[i].winif = pTable->table[i].dwIndex;
		iftable[i].type = pTable->table[i].dwType;
		iftable[i].firstip = 0;

		nametable[i].ifi = i;

		memcpy(iftable[i].physaddr,
			pTable->table[i].bPhysAddr,
			pTable->table[i].dwPhysAddrLen);
		iftable[i].physlen = pTable->table[i].dwPhysAddrLen;

		ift = iftypes[iftable[i].type];
		sprintf(iftable[i].name, "%s%d", iftnames[ift], iftnums[ift]++);
		strcpy(nametable[i].name, iftable[i].name);

		//	Find an IP address
		for(j = 0; j < pIp->dwNumEntries; j++)
		{
			if(pIp->table[j].dwIndex == iftable[i].winif)
			{
				if(!numipsleft)
					fatal("internal error in winip_init\n");
				numipsleft--;

				nextip->ip = pIp->table[j].dwAddr;
				nextip->next = iftable[i].firstip;
				nextip->ifi = i;
				iftable[i].firstip = nextip;
				nextip++;
			}
		}
	}

	//	Try to initialize winpcap
	__try
	{
		ULONG len = sizeof(pcaplist);

		if(wo.nopcap)
		{
			if(o.debugging > 1)
				printf("winpcap support disabled\n");
			__leave;
		}

		pcap_avail = 1;
		PacketGetAdapterNames(pcaplist, &len);
		if(o.debugging > 1)
			printf("winpcap is present\n");
	}
	__except(GetExceptionCode() == DLI_ERROR)
	{
		pcap_avail = 0;
		if(o.debugging > 1)
			printf("winpcap is not present\n");
	}

	//	Do we have rawsock?
	if(wo.forcerawsock ||
		(ver.dwPlatformId == VER_PLATFORM_WIN32_NT
		&& ver.dwMajorVersion >= 5 && !wo.norawsock))
	{
		SOCKET s = INVALID_SOCKET;
		s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if(s != INVALID_SOCKET)
		{
			rawsock_avail = 1;
			closesocket(s);
			if(o.debugging > 1)
				printf("rawsock is available\n");
		}
		else if(o.debugging > 1)
			printf("rawsock is not available\n");
	}
	else if(o.debugging > 1)
		printf("didn't try rawsock\n");

	if(rawsock_avail && o.ipprotscan
		&& ver.dwPlatformId == VER_PLATFORM_WIN32_NT
		&& ver.dwMajorVersion == 5
		&& ver.dwMajorVersion == 0
		&& ver.wServicePackMajor == 0)
	{
		//	Prevent a BSOD (we're on W2K SP0)
		winbug = 1;
		rawsock_avail = 0;
	}

	if(pcap_avail)
	{
		if(ver.dwPlatformId == VER_PLATFORM_WIN32_NT)
		{
			//	NT version
			WCHAR *a = (WCHAR*)pcaplist;
			while(*a)
			{
				winip_init_pcap((char*)a);
				a += wcslen(a) + 1;
			}
		}
		else
		{
			//	9x/Me version
			char *a = pcaplist;
			while(*a)
			{
				winip_init_pcap(a);
				a += strlen(a) + 1;
			}
		}
	}

	o.isr00t = (pcap_avail | rawsock_avail);
	qsort(nametable, numifs, sizeof(WINIP_NAME), strcmp);
	atexit(winip_cleanup);

	if(wo.listinterfaces)
	{
		winip_list_interfaces();
		exit(0);
	}

	//	Check for NT4 (grr...)
	if(ver.dwPlatformId == VER_PLATFORM_WIN32_NT
		&& ver.dwMajorVersion < 5) wo.nt4route = 1;
}

static void winip_test(int needraw)
{
	if(inited < 2)
		fatal("winip not initialized yet\n");
	else if(needraw && inited == 3) winip_barf(0);
}

static void winip_init_pcap(char *a)
{
	//	Write the names to the cache
	PPACKET_OID_DATA OidData;
	int i;

	//	Get the physaddr from Packet32
	BYTE phys[MAXLEN_PHYSADDR];
	int len = 6;	//	Ethernet

	LPADAPTER pAdap;
	
	OidData=(struct _PACKET_OID_DATA *) _alloca(sizeof(PACKET_OID_DATA)+MAXLEN_PHYSADDR-1);

	//	The next line needs to be changed to support non-Ethernet devices
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	OidData->Length = len;

	pAdap = PacketOpenAdapter(a);
	if(!pAdap) return;	//	unopenable

	if(PacketRequest(pAdap,FALSE,OidData))
	{
		//	we have an supported device
		for(i = 0; i < numifs; i++)
		{
			if(iftable[i].physlen == 6
				&& 0 == memcmp(iftable[i].physaddr, OidData->Data, len))
			{
				iftable[i].pcapname = a;
				break;	//	Out of the j-loop
			}
		}
	}
	//	else ignore the non-Ethernet device

	PacketCloseAdapter(pAdap);
}

static void winip_cleanup(void)
{
	free(ipblock);

	WSACleanup();
}

//	name translation
int name2ifi(const char *name)
{
	WINIP_NAME *n = (WINIP_NAME*)bsearch(name, nametable, numifs,
		sizeof(WINIP_NAME), strcmp);
	if(!n) return -1;

	return n->ifi;
}

const char *ifi2name(int ifi)
{
	if(ifi < 0 || ifi >= numifs) return 0;

	return iftable[ifi].name;
}

int ifi2winif(int ifi)
{
	if(ifi < 0 || ifi >= numifs) return -1;

	return iftable[ifi].winif;
}

const WINIP_IF* ifi2ifentry(int ifi)
{
	if(ifi < 0 || ifi >= numifs) return 0;

	return iftable + ifi;
}

static int cmp_uint(const void *e1, const void *e2)
{
	return *(DWORD*)e1 - *(DWORD*)e2;
}

int winif2ifi(int winif)
{
	WINIP_IF *x = (WINIP_IF*)bsearch(&winif, iftable, numifs,
		sizeof(WINIP_IF), cmp_uint);
	if(!x) return -1;

	return x - iftable;
}

int ifi2ipaddr(int ifi, struct in_addr *addr)
{
	if(ifi < 0 || ifi >= numifs) return -1;

	if(!iftable[ifi].firstip) return -1;

	addr->s_addr = iftable[ifi].firstip->ip;
	return 0;
}

int ipaddr2ifi(DWORD ip)
{
	//	Amusing hack
	//	Note:  this is slow since I see no reason to make it fast
	int i;
	for(i = 0; i < numips; i++)
	{
		if(ipblock[i].ip == ip)
			return ipblock[i].ifi;
	}

	return -1;
}

int devname2ipaddr(char *dev, struct in_addr *addr)
{
	return ifi2ipaddr(name2ifi(dev), addr);
}

int ipaddr2devname( char *dev, struct in_addr *addr )
{
	int ifi = ipaddr2ifi(addr->s_addr);
	if(ifi == -1) return -1;

	strcpy(dev, iftable[ifi].name);
	return 0;
}

static void winip_list_interfaces()
{
	int i;

	if(inited == 3)
		winip_barf(0);

	printf("Available interfaces:\n\n");

	//      0000000000111111111122222222223333333333
	//      0123456789012345678901234567890123456789
	printf("Name        Raw send  Raw recieve  IP\n");

	for(i = 0; i < numifs; i++)
	{
/*		char *addr = "(query failed)";
		char extra[32];
		if(iftable[i].firstip)
			addr = inet_ntoa(*(struct in_addr*)&iftable[i].firstip->ip);
		if(iftable[i].pcapname)
			strcpy(extra, rawsock_avail ? "winpcap, rawsock" : "winpcap");
		else strcpy(extra, rawsock_avail ? "rawsock" : "no raw");
		printf("%s: %s (%s)\n", iftable[i].name,
			addr, extra);
		if(o.debugging && iftable[i].pcapname)
			printf(iftable[i].pcapname[1] ? " winpcap: %s\n"
			: " winpcap: %ls\n", iftable[i].pcapname);*/

		IPNODE *ip = iftable[i].firstip;

		printf("%-12s%-10s%-13s", iftable[i].name,
			(rawsock_avail ? "SOCK_RAW" : (iftable[i].pcapname ? "winpcap" : "none")),
			(iftable[i].pcapname ? "winpcap" : (rawsock_avail ? "SOCK_RAW" : "none")));
		if(!ip) printf("[none]\n");
		else while(ip)
		{
			if(ip != iftable[i].firstip) printf("                                -- ");
			printf("%s\n", inet_ntoa(*(struct in_addr*)&ip->ip));
			ip = ip->next;
		}

		if(o.debugging && iftable[i].pcapname)
			printf(iftable[i].pcapname[1] ? " winpcap: %s\n"
			: " winpcap: %ls\n", iftable[i].pcapname);
	}
}

//	Find a route to dest.  Fill in source, return device

//	I will fail this if no raw, so nmap will still work

typedef DWORD (__stdcall *PGBI)(IPAddr, PDWORD);
char *routethrough(struct in_addr *dest, struct in_addr *source)
{
/*
	In theory, GetBestInterface is ideal. But we need
	the source address. Even though GetBestInterface
	is still the fastest way to get the name,
	ipaddr2devname is fast enough.  So we use
	SIO_ROUTING_INTERFACE_QUERY.
	*/

	//	the raw senders tend to iterate this
	//	so we cache the results
	static DWORD last_dest = 0;
	static DWORD last_source;
	static char dev[128];
	struct sockaddr_in sin_dest, sin_source;

	winip_test(0);
	if(inited == 3)
	{
		static int warned = 0;
		if(!warned)
			printf("routethrough: failing due to lack of iphlpapi.dll\n");
		warned = 1;
	}

	if(last_dest == dest->s_addr)
	{
		source->s_addr = last_source;
		return dev;
	}

	ZeroMemory(&sin_dest, sizeof(sin_dest));
	sin_dest.sin_family = AF_INET;
	sin_dest.sin_addr = *dest;

	if(wo.nt4route)
	{
		MIB_IPFORWARDROW ir;
		int ifi;

		if(0 != get_best_route(sin_dest.sin_addr.s_addr, &ir))
		{
			if(o.debugging > 1)
				printf("get_best_route failed, so routethrough will fail\n");

			return NULL;
		}

		if(-1 == (ifi = winif2ifi(ir.dwForwardIfIndex)))
			fatal("routethrough: got unmappable (new?) interface\n");

		if(0 != ifi2ipaddr(ifi, &sin_source.sin_addr))
			fatal("routethrough: no IP for device %s\n", ifi2name(ifi));

		if(!rawsock_avail && !iftable[ifi].pcapname) return NULL;

		strcpy(dev, ifi2name(ifi));
	}
	else
	{
		SOCKET s;
		DWORD br;

		s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(s == INVALID_SOCKET)
			fatal("failed to create socket\n");

		if(0 != WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY,
			&sin_dest, sizeof(sin_dest),
			&sin_source, sizeof(sin_source), &br, 0, 0))
		{
			if(o.debugging)
				printf("SIO_ROUTING_INTERFACE_QUERY(%s) failed (%d)\n", inet_ntoa(*dest), WSAGetLastError());
			closesocket(s);
			return NULL;
		}

		closesocket(s);
	}

	//	localhost scan (fake) support
	//	this allows localhost, but not 127.0.0.1, scans to seem to work
	if(sin_source.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
		sin_source.sin_addr.s_addr = dest->s_addr;

	if(0 != ipaddr2devname(dev, &sin_source.sin_addr))
	{
		if(o.debugging)
		{
			printf("routethrough: %s routes through ", inet_ntoa(*dest));
			printf("%s, but inaddr2devname failed\n",
				inet_ntoa(sin_source.sin_addr));
		}

		return 0;
	}

	if(!rawsock_avail &&
		!iftable[ipaddr2ifi(sin_source.sin_addr.s_addr)].pcapname)
		return NULL;

	last_dest = dest->s_addr;
	last_source = sin_source.sin_addr.s_addr;
	*source = sin_source.sin_addr;

	if(o.debugging > 1)
	{
		printf("%s will use interface ", inet_ntoa(*(struct in_addr*)&last_dest));
		printf("%s\n", inet_ntoa(*(struct in_addr*)&last_source));
	}

	return dev;
}


//	socket and sendto replacements
int win32_sendto(int sd, const char *packet, int len, 
	   unsigned int flags, struct sockaddr *to, int tolen)
{
	if(sd == 501)
		return pcapsendraw(packet, len, to, tolen);
	else return sendto(sd, packet, len, flags, to, tolen);
}

int Sendto(char *functionname, int sd, const unsigned char *packet, int len, 
	   unsigned int flags, struct sockaddr *to, int tolen)
{
	return win32_sendto(sd, packet, len, flags, to, tolen);
}

int win32_socket(int af, int type, int proto)
{
	winip_test(0);

	if(type == SOCK_RAW && proto == IPPROTO_RAW && !rawsock_avail)
	{
		winip_test(1);
		pcapsend_init();
		return 501;
	}

	if(o.debugging > 1 && type == SOCK_RAW && proto == IPPROTO_RAW)
		printf("Opening a real raw socket\n");

	return socket(af, type, proto);
}

void win32_pcap_close(pcap_t *pd)
{
	if(-2 != (long)pd) pcap_close(pd);
	else rawrecv_close(pd);
}

pcap_t *my_pcap_open_live(char *device, int snaplen, int promisc, int to_ms)
{
	int ifi = name2ifi(device);
	if(ifi == -1)
		fatal("my_pcap_open_live: invalid device %s\n");

	winip_test(1);

	if(iftable[ifi].pcapname)
		return my_real_pcap_open_live(device, snaplen, promisc, to_ms);

	else if(rawsock_avail)
	{
		if(promisc)
			fatal("promiscuous capture not available on non-pcap device %s\n", device);
		return rawrecv_open(device);
	}

	else
		fatal(winbug ? "%s: rawsock disabled to avoid BSOD\n"
		: "%s: no raw access\n", device);

	return 0;	//	to make the compiler happy
}

inline void sethdrinclude(int sd) 
{
	int one = 1;
	if(sd != 501)
	{
//		error("sethdrinclude called -- this probably shouldn't happen\n");
		setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (void *) &one, sizeof(one));
	}
}

char *readip_pcap(pcap_t *pd, unsigned int *len, long to_usec)
{
	if(-2 == (long)pd)
		return rawrecv_readip(pd, len, to_usec);

	else return readip_pcap_real(pd, len, to_usec);
}

void set_pcap_filter(struct hoststruct *target,
					 pcap_t *pd, PFILTERFN filter, char *bpf, ...)
{
	va_list ap;
	char buf[512];
	struct bpf_program fcode;
	unsigned int localnet, netmask;
	char err0r[256];

	if(-2 == (long)pd)
	{
		rawrecv_setfilter(pd, filter);
		return;
	}

	if (pcap_lookupnet(target->device, &localnet, &netmask, err0r) < 0)
		fatal("Failed to lookup device subnet/netmask: %s", err0r);

	va_start(ap, bpf);
	vsprintf(buf, bpf, ap);
	va_end(ap);

	if (o.debugging)
		log_write(LOG_STDOUT, "Packet capture filter: %s\n", buf);

	/* Due to apparent bug in libpcap */
	if (islocalhost(&(target->host)))
		buf[0] = '\0';

	if (pcap_compile(pd, &fcode, buf, 0, netmask) < 0)
		fatal("Error compiling our pcap filter: %s\n", pcap_geterr(pd));
	if (pcap_setfilter(pd, &fcode) < 0 )
		fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));
}
