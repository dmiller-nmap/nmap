#ifndef RPC_H
#define RPC_H

#include "nmap.h"
#include "global_structures.h"
#include "charpool.h"
#include "error.h"
#include "utils.h"

/* rpc related #defines */
#define RECORD_MARKING 4        /* length of recoder marking (bytes)     */

/* defines used to check RPC answers */

#define RPC_MSG_CALL           0        /* RPC request                           */
#define RPC_MSG_REPLY          1        /* RPC answer                            */

#define MSG_ACCEPTED   0        /* RPC request was accepted              */
#define MSG_DENIED     1        /* RPC request was denied                */

#define SUCCESS        0        /* RPC proc_null request was a success   */
#define PROG_UNAVAIL   1        /* RPC prog not on this port             */
#define PROG_MISMATCH  2        /* RPC prog here but wrong version       */

/* structure used for RPC calls */
struct rpc_hdr                          
{       u_long  xid;                    /* xid number                    */
        u_long  type_msg;               /* request or answer             */
        u_long  version_rpc;            /* portmapper/rpcbind version    */
        u_long  prog_id;                /* rpc program id                */
        u_long  prog_ver;               /* rpc program version           */
        u_long  prog_proc;              /* remote procedure call number  */
        u_long  authcred_flavor;        /* credentials field             */
        u_long  authcred_length;
        u_long  authveri_flavor;        /* verification field            */
        u_long  authveri_length;
};

struct rpc_hdr_rcv {
  unsigned long xid;
  unsigned long type_msg;
  unsigned long rp_stat;
  unsigned long auth_flavor;
  unsigned long opaque_length;
  unsigned long accept_stat;
  unsigned long low_version;
  unsigned long high_version;
};

struct rpc_info {
  char **names;
  unsigned long *numbers;
  int num_used;
  int num_alloc;
};

struct rpcscaninfo {
  struct port *rpc_current_port;
  unsigned long *rpc_progs;
  int rpc_number;
  int valid_responses_this_port; /* Number of valid (RPC wise) responses we
				    have received on this particular port */
#define RPC_STATUS_UNTESTED 0
#define RPC_STATUS_UNKNOWN 1   /* Don't know yet */
#define RPC_STATUS_GOOD_PROG 2 /* the prog # specified in rpc_status_info and
                                  the version info is
				  valid for the rpc_current_port */
#define RPC_STATUS_NOT_RPC 4   /* This doesn't even seem to be an RPC port */
  int rpc_status;
  unsigned long rpc_program;
  unsigned long rpc_lowver; /* Lowest version number of program supported */
  unsigned long rpc_highver; /* Highest version supported */
};


int get_rpc_procs(unsigned long **programs, int *num_programs);
char *nmap_getrpcnamebynum(unsigned long num);
int send_rpc_query(struct in_addr *target_host, unsigned short portno,
		   int ipproto, unsigned long program, int scan_offset, 
		   int trynum);
void get_rpc_results(struct hoststruct *target, struct portinfo *scan,
		     struct scanstats *ss, struct portinfolist *pil, 
		     struct rpcscaninfo *rsi);
void close_rpc_query_sockets();

#endif







