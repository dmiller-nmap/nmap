#ifndef GLOBAL_STRUCTURES_H
#define GLOBAL_STRUCTURES_H

typedef struct port {
  unsigned short portno;
  unsigned char proto;
  char *owner;
  int state; 
  int confidence; /* How sure are we about the state? */
  struct port *next;
} port;

struct ftpinfo {
  char user[64];
  char pass[256]; /* methinks you're paranoid if you need this much space */
  char server_name[MAXHOSTNAMELEN + 1];
  struct in_addr server;
  unsigned short port;
  int sd; /* socket descriptor */
};

struct AVal {
  char *attribute;
  char value[32];
  struct AVal *next;
};

typedef struct FingerTest {
  char OS_name[256];
  char *name;
  struct AVal *results;
  struct FingerTest *next;
 } FingerPrint;


struct timeout_info {
  int srtt; /* Smoothed rtt estimate (microseconds) */
  int rttvar; /* Rout trip time variance */
  int timeout; /* Current timeout threshold (microseconds) */
};

struct targets {
  /* These 4 are used for the '/mask' style of specifying target net*/
  unsigned int netmask;
  unsigned int maskformat;
  struct in_addr start;
  struct in_addr currentaddr;
  struct in_addr end;
  /* These two are for the '138.[1-7,16,91-95,200-].12.1 style */
  unsigned char addresses[4][256];
  unsigned int current[4];
  unsigned char last[4];
};

struct hoststruct {
  struct in_addr host;
  struct in_addr source_ip;
  char *name;
  struct {
    int class;
    int responses;
    unsigned long seqs[NUM_SEQ_SAMPLES];
    int index;
  } seq;
  FingerPrint **FP_matches;
  FingerPrint *FP;
  struct port *ports;
  /*
  unsigned int up;
  unsigned int down; */
  int wierd_responses; /* echo responses from other addresses, Ie a network broadcast address */
  unsigned int flags; /* HOST_UP, HOST_DOWN, HOST_FIREWALLED, HOST_BROADCAST (instead of HOST_BROADCAST use wierd_responses */
  struct timeout_info to;
  unsigned long rtt; /* microseconds */
  char device[64]; /* The device we transmit on */
};

struct ops /* someone took struct options, <grrr> */ {
  int debugging;
  int verbose;
  int spoofsource; /* -S used */
  char device[64];
  FingerPrint **reference_FPs;
  int number_of_ports;
  unsigned short magic_port;
  unsigned short magic_port_set; /* Was this set by user? */
  unsigned short tcp_probe_port;
  int max_sockets;
  int isr00t;
  struct in_addr decoys[MAX_DECOYS];
  int numdecoys;
  int decoyturn;
  int identscan;
  int osscan;
  enum { icmp, tcp, none} pingtype;
  int pingscan;
  int allowall;
  int wait;
  int ptime;
  int numports;
  int connectscan;
  int nullscan;
  int xmasscan;
  int fragscan;
  int synscan;
  int maimonscan;
  int finscan;
  int udpscan;
  int lamerscan;
  int noresolve;
  int force; /* force nmap to continue on even when the outcome seems somewhat certain */
  FILE *logfd; /* Output log file descriptor */
};
  
typedef port *portlist;
typedef enum { SYN_SCAN, FIN_SCAN, XMAS_SCAN, UDP_SCAN, CONNECT_SCAN, NULL_SCAN, MAIMON_SCAN } stype;

#endif /*GLOBAL_STRUCTURES_H */
