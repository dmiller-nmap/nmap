/*
	WinTcpip.c

  This file implements a (hopefully fully functional) replacement for
  tcpip.c.  It is based in part on nmapNT by ryan@eEye.com.

  */

#include "../tcpip.h"
#include "../NmapOps.h"
#include "winip\winip.h"

//	Note: we cheat with the timeouts here
#include "pcap-int.h"

extern NmapOps o;

void nmapwin_init();
void nmapwin_cleanup();
void nmapwin_list_interfaces();

int if2nameindex(int ifi);


//	Raw send helpers
//	All of these are modified from, but
//	based on, ryan@eeye.com's wintcpip.c

int send_ip_raw( int sd, struct in_addr *source, const struct in_addr *victim, 
		 int ttl, u8 proto, char *data, u16 datalen)
{
	char *packet = (char *) safe_malloc(sizeof(struct ip) + datalen);
	struct ip *ip = (struct ip *) packet;
	static int myttl = 0;
	int res = -1;
	struct sockaddr_in sock;
	int source_malloced = 0;
	/* check that required fields are there and not too silly */
	if ( !victim || sd < 0) 
	{
		fprintf(stderr, "send_ip_raw: One or more of your parameters suck!\n");
		free(packet);
		return -1;
	}

	/* Time to live */
	if (ttl == -1) {
		                myttl = (get_random_uint() % 23) + 37;
	} else {
		                myttl = ttl;
	}
	
	//	No sethdrinclude since it is implied by the WinIP library

	/* if they didn't give a source address, fill in our first address */
	if (!source) 
	{
		source_malloced = 1;
		source = (struct in_addr *) safe_malloc(sizeof(struct in_addr));
		if(!routethrough(victim, source))
		{
			error("send_ip_raw: failed to get a route\n");
			free(packet);
			free(source);
			return -1;
		}
#if ( TCPIP_DEBUGGING )
		printf("We skillfully deduced that your address is %s\n", inet_ntoa(*source));
#endif
	}
	/*do we even have to fill out this damn thing?  This is a raw packet, 
	after all */
	sock.sin_family = AF_INET;
	sock.sin_port = 0;
	sock.sin_addr.s_addr = victim->s_addr;
	bzero((char *) packet, sizeof(struct ip));
	/* Now for the ip header */
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_len= BSDFIX(sizeof(struct ip) + datalen);
	get_random_bytes(&(ip->ip_id), 2);
	ip->ip_ttl = myttl;
	ip->ip_p = proto;
	if(source->s_addr == victim->s_addr) source->s_addr++;
	ip->ip_src.s_addr = source->s_addr;
	ip->ip_dst.s_addr= victim->s_addr;
//#if HAVE_IP_IP_SUM
	ip->ip_sum = in_cksum((unsigned short *)ip, sizeof(struct ip));
//#endif

	/* We should probably copy the data over too */
	if (data) memcpy(packet + sizeof(struct ip), data, datalen);
	if (TCPIP_DEBUGGING > 1) 
	{
		printf("Raw IP packet creation completed!  Here it is:\n");
		hdump((unsigned char *) packet, BSDUFIX(ip->ip_len));
	}
	res = Sendto("send_ip_raw", sd, (unsigned char *) packet, BSDUFIX(ip->ip_len), 0,(struct sockaddr *)&sock,  (int)sizeof(struct sockaddr_in));
	if (source_malloced) free(source);
	free(packet); 
	return res;
}

int send_tcp_raw( int sd, const struct in_addr *source,
		  const struct in_addr *victim, int ttl,
		  u16 sport, u16 dport, u32 seq, u32 ack, u8 flags,
		  u16 window, u8 *options, int optlen, char *data, 
		  u16 datalen)
{

	struct pseudo_header 
	{ 
  /*for computing TCP checksum, see TCP/IP Illustrated p. 145 */
		unsigned int s_addy;
		unsigned int d_addr;
		char zer0;
		unsigned char protocol;
		unsigned short length;
	};
	unsigned char *packet = (unsigned char *) safe_malloc(sizeof(struct ip) + sizeof(struct tcphdr) + optlen + datalen);
	struct ip *ip = (struct ip *) packet;
	struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
	struct pseudo_header *pseudo =  (struct pseudo_header *) (packet + sizeof(struct ip) - sizeof(struct pseudo_header)); 
	static int myttl = 0;

	/*With these placement we get data and some field alignment so we aren't
	wasting too much in computing the checksum */
	int res = -1;
	struct sockaddr_in sock;

	/* check that required fields are there and not too silly */
	/* We used to check that sport and dport were nonzer0, but scr3w that! */
	if ( !victim || sd < 0) 
	{
		fprintf(stderr, "send_tcp_raw: One or more of your parameters suck!\n");
		free(packet);
		return -1;
	}

	if (optlen % 4) 
	{
		fatal("send_tcp_raw called with an option length argument of %d which is illegal because it is not divisible by 4", optlen);
	}

	/* Time to live */
	if (ttl == -1) {
		                myttl = (get_random_uint() % 23) + 37;
	} else {
		                myttl = ttl;
	}

	//	No sethdrinclude since it is implied by the WinIP library
    assert(source);

	/*do we even have to fill out this damn thing?  This is a raw packet, 
	after all */
	sock.sin_family = AF_INET;
	sock.sin_port = htons(dport);
	sock.sin_addr.s_addr = victim->s_addr;
	bzero((unsigned char *) packet, sizeof(struct ip) + sizeof(struct tcphdr));
	pseudo->s_addy = source->s_addr;
	pseudo->d_addr = victim->s_addr;
	pseudo->protocol = IPPROTO_TCP;
	pseudo->length = htons(sizeof(struct tcphdr) + optlen + datalen);

	tcp->th_sport = htons(sport);
	tcp->th_dport = htons(dport);
	if (seq) 
	{
		tcp->th_seq = htonl(seq);
	}
	else if (flags & TH_SYN) 
	{
		get_random_bytes(&(tcp->th_seq), 4);
	}

	if (ack) tcp->th_ack = htonl(ack);
	/*else if (flags & TH_ACK)
	tcp->th_ack = rand() + rand();*/

	tcp->th_off = 5 + (optlen /4) /*words*/;
	tcp->th_flags = flags;

	if (window) tcp->th_win = htons(window);
	else tcp->th_win = htons(1024 * (myttl % 4 + 1)); /* Who cares */

	/* We should probably copy the data over too */
	if (data && datalen) memcpy(packet + sizeof(struct ip) + sizeof(struct tcphdr) + optlen, data, datalen);
	/* And the options */
	if (optlen) 
	{
		memcpy(packet + sizeof(struct ip) + sizeof(struct tcphdr), options, optlen);
	}

	tcp->th_sum = in_cksum((unsigned short *)pseudo, sizeof(struct tcphdr) + optlen + sizeof(struct pseudo_header) + datalen);

	/* Now for the ip header */
	bzero(packet, sizeof(struct ip)); 
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_len = BSDFIX(sizeof(struct ip) + sizeof(struct tcphdr) + optlen + datalen);
	get_random_bytes(&(ip->ip_id), 2);
	ip->ip_ttl = myttl;
	ip->ip_p = IPPROTO_TCP;
	if (source->s_addr == victim->s_addr) {
		ip->ip_src.s_addr = source->s_addr + 1;
	} else
	ip->ip_src.s_addr = source->s_addr;
	ip->ip_dst.s_addr= victim->s_addr;

	ip->ip_sum = in_cksum((unsigned short *)ip, sizeof(struct ip));


	if (TCPIP_DEBUGGING > 1) 
	{
		log_write(LOG_STDOUT, "Raw TCP packet creation completed!  Here it is:\n");
		readtcppacket(packet,BSDUFIX(ip->ip_len));
	}

	res = Sendto("send_tcp_raw", sd, packet, BSDUFIX(ip->ip_len), 0, (struct sockaddr *)&sock,  (int)sizeof(struct sockaddr_in));
	free(packet);
	return res;
}

int send_udp_raw( int sd, struct in_addr *source, const struct in_addr *victim, 
		  int ttl, u16 sport, u16 dport, char *data, u16 datalen) 
{

	unsigned char *packet = (unsigned char *) safe_malloc(sizeof(struct ip) + sizeof(udphdr_bsd) + datalen);
	struct ip *ip = (struct ip *) packet;
	udphdr_bsd *udp = (udphdr_bsd *) (packet + sizeof(struct ip));
	static int myttl = 0;

	int res;
	struct sockaddr_in sock;
	int source_malloced = 0;
	struct pseudo_udp_hdr 
	{
		struct in_addr source;
		struct in_addr dest;        
		char zero;
		char proto;        
		unsigned short length;
	} *pseudo = (struct pseudo_udp_hdr *) ((char *)udp - 12) ;

	/* check that required fields are there and not too silly */
	if ( !victim || !sport || !dport || sd < 0) 
	{
		fprintf(stderr, "send_udp_raw: One or more of your parameters suck!\n");
		free(packet);
		return -1;
	}

	/* Time to live */
	if (ttl == -1) {
		                myttl = (get_random_uint() % 23) + 37;
	} else {
		                myttl = ttl;
	}

	//	No sethdrinclude since it is implied by the WinIP library

	/* if they didn't give a source address, fill in our first address */
	if (!source) 
	{
		source_malloced = 1;
		source = (struct in_addr *) safe_malloc(sizeof(struct in_addr));
		if(!routethrough(victim, source))
		{
			error("send_ip_raw: failed to get a route\n");
			free(packet);
			free(source);
			return -1;
		}
#if ( TCPIP_DEBUGGING )
		printf("We skillfully deduced that your address is %s\n", inet_ntoa(*source));
#endif
	}
	/*do we even have to fill out this damn thing?  This is a raw packet, 
	after all */
	sock.sin_family = AF_INET;
	sock.sin_port = htons(dport);
	sock.sin_addr.s_addr = victim->s_addr;
	bzero((char *) packet, sizeof(struct ip) + sizeof(udphdr_bsd));
	udp->uh_sport = htons(sport);
	udp->uh_dport = htons(dport);
	udp->uh_ulen = htons(8 + datalen);
	/* We should probably copy the data over too */
	if (data) memcpy(packet + sizeof(struct ip) + sizeof(udphdr_bsd), data, datalen);
	/* Now the psuedo header for checksuming */
	pseudo->source.s_addr = source->s_addr;
	pseudo->dest.s_addr = victim->s_addr;
	pseudo->proto = IPPROTO_UDP;
	pseudo->length = htons(sizeof(udphdr_bsd) + datalen);
	/* OK, now we should be able to compute a valid checksum */
	udp->uh_sum = in_cksum((unsigned short *)pseudo, 20 /* pseudo + UDP headers */ + datalen);
	/* Goodbye, pseudo header! */
	bzero(pseudo, 12);
	/* Now for the ip header */
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_len = BSDFIX(sizeof(struct ip) + sizeof(udphdr_bsd) + datalen);
	get_random_bytes(&(ip->ip_id), 2);
	ip->ip_ttl = myttl;
	ip->ip_p = IPPROTO_UDP;
	if(source->s_addr == victim->s_addr) source->s_addr++;
	ip->ip_src.s_addr = source->s_addr;
	ip->ip_dst.s_addr= victim->s_addr;
	ip->ip_sum = in_cksum((unsigned short *)ip, sizeof(struct ip));


	if (TCPIP_DEBUGGING > 1) 
	{
		printf("Raw UDP packet creation completed!  Here it is:\n");
		readudppacket(packet,1);
	}
	res = Sendto("send_udp_raw", sd, packet, BSDUFIX(ip->ip_len), 0, (struct sockaddr *)&sock,  (int)sizeof(struct sockaddr_in));
	if (source_malloced) free(source);
	free(packet);
	return res;
}

/* Much of this is swiped from my send_tcp_raw function above, which 
   doesn't support fragmentation */
int send_small_fragz( int sd, struct in_addr *source,
		      const struct in_addr *victim, u32 seq,
		      int ttl, u16 sport, u16 dport, int flags)
{
	struct pseudo_header 
	{ 
		/*for computing TCP checksum, see TCP/IP Illustrated p. 145 */
		unsigned long s_addy;
		unsigned long d_addr;
		char zer0;
		unsigned char protocol;
		unsigned short length;
	};
	/*In this placement we get data and some field alignment so we aren't wasting
	too much to compute the TCP checksum.*/
	unsigned char packet[sizeof(struct ip) + sizeof(struct tcphdr) + 100];
	struct ip *ip = (struct ip *) packet;
	struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
	struct pseudo_header *pseudo = (struct pseudo_header *) (packet + sizeof(struct ip) - sizeof(struct pseudo_header)); 
	unsigned char *frag2 = packet + sizeof(struct ip) + 16;
	struct ip *ip2 = (struct ip *) (frag2 - sizeof(struct ip));
	static int myttl = 0;
	int res;
	struct sockaddr_in sock;
	int id;
	int source_malloced = 0;

	/* Time to live */
	if (ttl == -1) {
		myttl = (time(NULL) % 14) + 51;
	} else {
		myttl = ttl;
	}

	/* It was a tough decision whether to do this here for every packet
	or let the calling function deal with it.  In the end I grudgingly decided
	to do it here and potentially waste a couple microseconds... */
	if (!source) 
	{
		source_malloced = 1;
		source = (struct in_addr *) safe_malloc(sizeof(struct in_addr));
		if(!routethrough(victim, source))
		{
			error("send_ip_raw: failed to get a route\n");
			free(packet);
			free(source);
			return -1;
		}
#if ( TCPIP_DEBUGGING )
		printf("We skillfully deduced that your address is %s\n", inet_ntoa(*source));
#endif
	}
	
	//	No sethdrinclude since it is implied by the WinIP library

	/*Why do we have to fill out this damn thing? This is a raw packet, after all */
	sock.sin_family = AF_INET;
	sock.sin_port = htons(dport);
	sock.sin_addr.s_addr = victim->s_addr;
	bzero((char *)packet, sizeof(struct ip) + sizeof(struct tcphdr));
	pseudo->s_addy = source->s_addr;
	pseudo->d_addr = victim->s_addr;
	pseudo->protocol = IPPROTO_TCP;
	pseudo->length = htons(sizeof(struct tcphdr));
	tcp->th_sport = htons(sport);
	tcp->th_dport = htons(dport);
	tcp->th_seq = (seq)? htonl(seq) : get_random_uint();
	tcp->th_off = 5 /*words*/;
	tcp->th_flags = flags;
	tcp->th_win = htons(2048); /* Who cares */
	tcp->th_sum = in_cksum((unsigned short *)pseudo, sizeof(struct tcphdr) + sizeof(struct pseudo_header));
	/* Now for the ip header of frag1 */
	bzero((char *) packet, sizeof(struct ip)); 
	ip->ip_v = 4;
	ip->ip_hl = 5;
	/*RFC 791 allows 8 octet frags, but I get "operation not permitted" (EPERM)
	when I try that.  */
	ip->ip_len = BSDFIX(sizeof(struct ip) + 16);
	id = ip->ip_id = get_random_uint();
	ip->ip_off = BSDFIX(MORE_FRAGMENTS);
	ip->ip_ttl = myttl;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_src.s_addr = source->s_addr;
	ip->ip_dst.s_addr = victim->s_addr;

	ip->ip_sum= in_cksum((unsigned short *)ip, sizeof(struct ip));
	if (o.debugging > 1) 
	{
		log_write(LOG_STDOUT, "Raw TCP packet fragment #1 creation completed!  Here it is:\n");
		log_write(LOG_STDOUT, "\nTrying sendto(%d , packet, %d, 0 , %s , %d)\n", sd, ntohs(ip->ip_len), inet_ntoa(*victim),(int) sizeof(struct sockaddr_in));
		hdump(packet,20);
	}

		
	/* Lets save this and send it AFTER we send the second one, just to be
	cute ;) */
		/*if ((res = sendto(sd, packet,sizeof(struct ip) + 16 , 0, (struct sockaddr *)&sock, sizeof(struct sockaddr_in))) == -1)*/
	if ((res = Sendto("send_small_fragz",sd, packet,sizeof(struct ip) + 16 , 0, (struct sockaddr *)&sock, sizeof(struct sockaddr_in))) == -1)
	{
		perror("sendto in send_syn_fragz");
		return -1;
	}
	if (o.debugging > 1) log_write(LOG_STDOUT, "successfully sent %d bytes of raw_tcp!\n", res);

	/* Create the second fragment */
	bzero((char *) ip2, sizeof(struct ip));
	ip2->ip_v= 4;
	ip2->ip_hl = 5;
	ip2->ip_len = BSDFIX(sizeof(struct ip) + 4); /* the rest of our TCP packet */
	ip2->ip_id = id;
	ip2->ip_off = BSDFIX(2);
	ip2->ip_ttl = myttl;
	ip2->ip_p = IPPROTO_TCP;
		if(source->s_addr == victim->s_addr) source->s_addr++;
	ip2->ip_src.s_addr = source->s_addr;
	ip2->ip_dst.s_addr = victim->s_addr;
	ip2->ip_sum = in_cksum((unsigned short *)ip2, sizeof(struct ip));
	if (o.debugging > 1) 
	{
		log_write(LOG_STDOUT, "Raw TCP packet fragment creation completed!  Here it is:\n");
		hdump(packet,20);
		log_write(LOG_STDOUT, "\nTrying sendto(%d , ip2, %d, 0 , %s , %d)\n", sd, ntohs(ip2->ip_len), inet_ntoa(*victim), (int) sizeof(struct sockaddr_in));
	}
		/*if ((res = sendto(sd, (void *)ip2,sizeof(struct ip) + 4 , 0, (struct sockaddr *)&sock, (int) sizeof(struct sockaddr_in))) == -1)*/
	if ((res = Sendto("send_small_fragz",sd, (unsigned char *)ip2,sizeof(struct ip) + 4 , 0, (struct sockaddr *)&sock, (int) sizeof(struct sockaddr_in))) == -1)
	{
		perror("sendto in send_tcp_raw frag #2");
		if(source_malloced) free(source);
		return -1;
	}

	if(source_malloced) free(source);
	return 1;
}


//	The remainder of the file is ripped mostly verbatim
//	from ryan@eeye.com's wintcpip.c

/* Tries to resolve given hostname and stores
   result in ip .  returns 0 if hostname cannot
   be resolved */
int resolve(char *hostname, struct in_addr *ip) 
{
	struct hostent *h;
	if (!hostname || !*hostname) fatal("NULL or zero-length hostname passed to resolve()");
	if (inet_aton(hostname, ip)) return 1; /* damn, that was easy ;) */
	if ((h = gethostbyname(hostname))) 
	{
		memcpy(ip, h->h_addr_list[0], sizeof(struct in_addr));
		return 1;
	}
	return 0;
}

int unblock_socket(int sd) 
{
	u_long one = 1;
	if(sd != 501)
		ioctlsocket (sd, FIONBIO, &one);
	return 1;
}


/* A simple function I wrote to help in debugging, shows the important fields
   of a TCP packet*/
int readtcppacket(const u8 *packet, int readdata) 
{
	struct ip *ip = (struct ip *) packet;
	struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
	const u8 *data = packet +  sizeof(struct ip) + sizeof(struct tcphdr);
	int tot_len;
	struct in_addr bullshit, bullshit2;
	char sourcehost[16];
	int i;
	int realfrag = 0;

	if (!packet) 
	{
		fprintf(stderr, "readtcppacket: packet is NULL!\n");
		return -1;
    }
	bullshit.s_addr = ip->ip_src.s_addr; bullshit2.s_addr = ip->ip_dst.s_addr;
	/* this is gay */
	realfrag = BSDFIX(ntohs(ip->ip_off) & 8191 /* 2^13 - 1 */);
	tot_len = BSDFIX(ip->ip_len);
	strncpy(sourcehost, inet_ntoa(bullshit), 16);
	i =  4 * (ntohs(ip->ip_hl) + ntohs(tcp->th_off));
	if (ip->ip_p== IPPROTO_TCP) 
	{
		if (realfrag) printf("Packet is fragmented, offset field: %u\n", realfrag);
		else 
		{
			printf("TCP packet: %s:%d -> %s:%d (total: %d bytes)\n", sourcehost, ntohs(tcp->th_sport), inet_ntoa(bullshit2), ntohs(tcp->th_dport), tot_len);
			printf("Flags: ");
			if (!tcp->th_flags) printf("(none)");
			if (tcp->th_flags & TH_RST) printf("RST ");
			if (tcp->th_flags & TH_SYN) printf("SYN ");
			if (tcp->th_flags & TH_ACK) printf("ACK ");
			if (tcp->th_flags & TH_PUSH) printf("PSH ");
			if (tcp->th_flags & TH_FIN) printf("FIN ");
			if (tcp->th_flags & TH_URG) printf("URG ");
			printf("\n");
			printf("ttl: %hu ", ip->ip_ttl);
			if (tcp->th_flags & (TH_SYN | TH_ACK)) printf("Seq: %u\tAck: %u\n", (unsigned int) ntohl(tcp->th_seq), (unsigned int) ntohl(tcp->th_ack));
			else if (tcp->th_flags & TH_SYN) printf("Seq: %u\n", (unsigned int) ntohl(tcp->th_seq));
			else if (tcp->th_flags & TH_ACK) printf("Ack: %u\n", (unsigned int) ntohl(tcp->th_ack));
		}
	}
	if (readdata && i < tot_len) 
	{
		printf("Data portion:\n");
		while(i < tot_len)  printf("%2X%c", data[i], (++i%16)? ' ' : '\n');
		printf("\n");
	}
	return 0;
}

/* A simple function I wrote to help in debugging, shows the important fields
   of a UDP packet*/
int readudppacket(const u8 *packet, int readdata) 
{

	struct ip *ip = (struct ip *) packet;
	udphdr_bsd *udp = (udphdr_bsd *) (packet + sizeof(struct ip));
	const u8 *data = packet +  sizeof(struct ip) + sizeof(udphdr_bsd);
	int tot_len;
	struct in_addr bullshit, bullshit2;
	char sourcehost[16];
	int i;
	int realfrag = 0;

	if (!packet) 
	{
		fprintf(stderr, "readudppacket: packet is NULL!\n");
		return -1;
	}

	bullshit.s_addr = ip->ip_src.s_addr; bullshit2.s_addr = ip->ip_dst.s_addr;
	/* this is gay */
	realfrag = BSDFIX(ntohs(ip->ip_off) & 8191 /* 2^13 - 1 */);
	tot_len = BSDFIX(ip->ip_len);
	strncpy(sourcehost, inet_ntoa(bullshit), 16);
	i =  4 * (ntohs(ip->ip_hl)) + 8;
	if (ip->ip_p== IPPROTO_UDP) 
	{
		if (realfrag) printf("Packet is fragmented, offset field: %u\n", realfrag);
		else 
		{
			printf("UDP packet: %s:%d -> %s:%d (total: %d bytes)\n", sourcehost, ntohs(udp->uh_sport), inet_ntoa(bullshit2), ntohs(udp->uh_dport), tot_len);
			printf("ttl: %hu ", ip->ip_ttl);
		}
	}
	if (readdata && i < tot_len) 
	{
		printf("Data portion:\n");
		while(i < tot_len)  printf("%2X%c", data[i], (++i%16)? ' ' : '\n');
		printf("\n");
	}
	return 0;
}

char *readip_pcap_real(pcap_t *pd, unsigned int *len, long to_usec) 
{
	int offset = -1;
	struct pcap_pkthdr head;
	char *p;
	int datalink;
	int timedout = 0;
	DWORD begin = GetTickCount();
	long to_left;

	if (!pd) fatal("NULL packet device passed to readip_pcap_real");

/* New packet capture device, need to recompute offset */
	if ( (datalink = pcap_datalink(pd)) < 0) fatal("Cannot obtain datalink information: %s", pcap_geterr(pd));
	switch(datalink) 
	{ 
		case DLT_EN10MB: 
			offset = 14; 
			break;
		case DLT_IEEE802: 
			offset = 22; 
			break;
#ifdef DLT_LOOP
		case DLT_LOOP:
#endif
		case DLT_NULL: 
			offset = 4; 
			break;
		case DLT_SLIP:
			offset = 24; /* Anyone use this??? */
			break;
		case DLT_PPP: 
			offset = 24; /* Anyone use this? */
			break;
		case DLT_RAW:
			offset = 0; 
			break;
		case DLT_FDDI:
			offset = 21; 
			break;
		default: 
			fatal("Unknown datalink type (%d)", datalink);
	}

	//	Switch to msec
	to_usec = (to_usec + 999) / 1000;
	to_left = to_usec;

	begin = GetTickCount();

	do 
	{
		//	Set the timeout (BUGBUG: this is cheating)
		PacketSetReadTimeout(pd->adapter, to_left);

		//	Do the read
		p = (char *) pcap_next(pd, &head);
		if (p) p += offset;
		if (!p || (*p & 0x40) != 0x40) 
		{
			/* Should we timeout? */
			to_left = to_usec - (GetTickCount() - begin);
			if (to_usec == 0) timedout = 1;
			else if ( to_left <= 0 ) timedout = 1;
		}
	} while(!timedout && (!p || (*p & 0x40) != 0x40)); /* Go until we get IPv4 packet */
	if (timedout) 
	{
		*len = 0;
		return NULL;
	}
	*len = head.caplen - offset;
	return p;
}


//	The decoy helpers
int send_tcp_raw_decoys( int sd, const struct in_addr *victim, int ttl,
			 u16 sport, u16 dport, u32 seq, u32 ack, u8 flags,
			 u16 window, u8 *options, int optlen, char *data,
			 u16 datalen) 
{
	int decoy;
	for(decoy = 0; decoy < o.numdecoys; decoy++) 
	{
		if (send_tcp_raw(sd, &o.decoys[decoy], victim, ttl, sport, dport, seq, ack, flags, window, options, optlen, (char *) data, datalen) == -1) return -1;
	}
	return 0;
}

int send_udp_raw_decoys( int sd, const struct in_addr *victim, int ttl,
			 u16 sport, u16 dport, char *data, u16 datalen) 
{
	int decoy;
  
	for(decoy = 0; decoy < o.numdecoys; decoy++)
	{
		if (send_udp_raw(sd, &o.decoys[decoy], victim, ttl, sport, dport, data, datalen) == -1) return -1;
	}
	return 0;
}

int send_small_fragz_decoys( int sd, const struct in_addr *victim, u32 seq, 
			     int ttl, u16 sport, u16 dport, int flags)
{
	int decoy;

	for(decoy = 0; decoy < o.numdecoys; decoy++)
	{
		if (send_small_fragz(sd, &o.decoys[decoy], victim, seq, ttl, sport, dport, flags) == -1) return -1;
	}
	return 0;
}

int send_ip_raw_decoys( int sd, const struct in_addr *victim, int ttl, u8 proto,
			char *data, u16 datalen) 
{
	int decoy;
	for(decoy = 0; decoy < o.numdecoys; decoy++)
	{
		if (send_ip_raw(sd, &o.decoys[decoy], victim, ttl, proto, data, datalen) == -1) return -1;
	}
	return 0;
}


/* Calls pcap_open_live and spits out an error (and quits) if the call faile.
   So a valid pcap_t will always be returned. */
pcap_t *my_real_pcap_open_live(char *device, int snaplen, int promisc, int to_ms) 
{
	char err0r[PCAP_ERRBUF_SIZE];
	pcap_t *pt;
	const WINIP_IF *ifentry;
	int ifi = name2ifi(device);

	if(ifi == -1)
		fatal("my_real_pcap_open_live: invalid device %s\n", device);

	if(o.debugging > 1)
		printf("Trying to open %s for recieve with winpcap.\n", device);

	ifentry = ifi2ifentry(ifi);

	//	check for bogus interface
	if(!ifentry->pcapname)
	{
		fatal("my_real_pcap_open_live: called with non-pcap interface %s!\n",
			device);
	}

	if (!((pt = pcap_open_live(ifentry->pcapname, snaplen, promisc, to_ms, err0r)))) 
	{
		fatal("pcap_open_live: %s\nThere are several possible reasons for this, depending on your operating system:\n"
          "LINUX: If you are getting Socket type not supported, try modprobe af_packet or recompile your kernel with SOCK_PACKET enabled.\n"
          "*BSD:  If you are getting device not configured, you need to recompile your kernel with Berkeley Packet Filter support.  If you are getting No such file or directory, try creating the device (eg cd /dev; MAKEDEV <device>; or use mknod).\n"
          "SOLARIS:  If you are trying to scan localhost and getting '/dev/lo0: No such file or directory', complain to Sun.  I don't think Solaris can support advanced localhost scans.  You can probably use \"-P0 -sT localhost\" though.\n\n", err0r);
	}

	//	This should help
	pcap_setmintocopy(pt, 1);

	return pt;
}


/* Tests whether a packet sent to  IP is LIKELY to route 
 through the kernel localhost interface */
int islocalhost(const struct in_addr * const addr) 
{
	char dev[128];
  /* If it is 0.0.0.0 or starts with 127.0.0.1 then it is 
     probably localhost */
	if ((addr->s_addr & htonl(0xFF000000)) == htonl(0x7F000000)) return 1;
	if (!addr->s_addr) return 1;
  /* If it is the same addy as a local interface, then it is
     probably localhost */
	if (ipaddr2devname(dev, addr) != -1) return 1;
  /* OK, so to a first approximation, this addy is probably not
     localhost */
	return 0;
}

