
/***************************************************************************
 * osscan2.h -- Header info for 2nd Generation OS detection via TCP/IP     *
 * fingerprinting.  For more information on how this works in Nmap, see    *
 * http://insecure.org/osdetect/                                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id: osscan.h 3636 2006-07-04 23:04:56Z fyodor $ */

#ifndef OSSCAN2_H
#define OSSCAN2_H

#include "nmap.h"
#include "global_structures.h"
#include "nbase.h"
#include <vector>
#include <list>
#include "Target.h"
class Target;
using namespace std;


/******************************************************************************
 * CONSTANT DEFINITIONS                                                       *
 ******************************************************************************/

#define NUM_FPTESTS    13

/* The number of tries we normally do.  This may be increased if
   the target looks like a good candidate for fingerprint submission, or fewer
   if the user gave the --max-os-tries option */
#define STANDARD_OS2_TRIES 2

// The minimum (and target) amount of time to wait between probes
// sent to a single host, in milliseconds.
#define OS_PROBE_DELAY 25

// The target amount of time to wait between sequencing probes sent to
// a single host, in milliseconds.  The ideal is 500ms because of the
// common 2Hz timestamp frequencies.  Less than 500ms and we might not
// see any change in the TS counter (and it gets less accurate even if
// we do).  More than 500MS and we risk having two changes (and it
// gets less accurate even if we have just one).  So we delay 100MS
// between probes, leaving 500MS between 1st and 6th.
#define OS_SEQ_PROBE_DELAY 100


/******************************************************************************
 * TYPE AND STRUCTURE DEFINITIONS                                             *
 ******************************************************************************/

/* Performance tuning variable. */
typedef struct os_scan_performance_vars {
  int low_cwnd;            /* The lowest cwnd (congestion window) allowed */
  int host_initial_cwnd;   /* Initial congestion window for ind. hosts */
  int group_initial_cwnd;  /* Initial congestion window for all hosts as a group */
  int max_cwnd;            /* We should never have more than this many probes
                              outstanding */
  int quick_incr;          /* How many probes are incremented for each response
                              in quick start mode */
  int cc_incr;             /* How many probes are incremented per (roughly) rtt in
                              congestion control mode */
  int initial_ccthresh;
  double group_drop_cwnd_divisor;     /* all-host group cwnd divided by this
                                         value if any packet drop occurs */
  double group_drop_ccthresh_divisor; /* used to drop the group ccthresh when
                                         any drop occurs */
  double host_drop_ccthresh_divisor;  /* used to drop the host ccthresh when
                                         any drop occurs */
} os_scan_performance_vars_t;



/* Some of the algorithms used here are TCP congestion control techniques from RFC2581. */
typedef struct osscan_timing_vals {

  /* Congestion window - in probes */
  double cwnd;

  /* The threshold after which mode is changed from QUICK_START to
     CONGESTION_CONTROL */
  int ccthresh;

  /* Number of updates to this utv (generally packet receipts ) */
  int num_updates;

  /* Last time values were adjusted for a drop (you usually only want
     to adjust again based on probes sent after that adjustment so a
     sudden batch of drops doesn't destroy timing.  Init to now */
  struct timeval last_drop;
} osscan_timing_vals_t;


typedef enum OFProbeType {
  OFP_UNSET,
  OFP_TSEQ,
  OFP_TOPS,
  OFP_TECN,
  OFP_T1_7,
  OFP_TICMP,
  OFP_TUDP
} OFProbeType;

/******************************************************************************
 * FUNCTION PROTOTYPES                                                        *
 ******************************************************************************/

/* This is the primary OS detection function.  If many Targets are
   passed in (the threshold is based on timing level), they are
   processed as smaller groups to improve accuracy  */
void os_scan2(std::vector<Target *> &Targets);

int get_initial_ttl_guess(u8 ttl);
int get_ipid_sequence(int numSamples, int *ipids, int islocalhost);


/******************************************************************************
 * CLASS DEFINITIONS                                                          *
 ******************************************************************************/
class OFProbe;
class HostOsScanStats;
class HostOsScan;
class HostOsScanInfo;
class OsScanInfo;

class OFProbe
{
public:
  OFProbe();

  /* The literal string for the current probe type. */
  const char *typestr();

  /* Type of the probe: for what os fingerprinting test? */
  OFProbeType type;

  /* Subid of this probe to separate different tcp/udp/icmp. */
  int subid;

  int tryno; /* Try (retransmission) number of this probe */

  /* A packet may be timedout for a while before being retransmitted
     due to packet sending rate limitations */
  bool retransmitted;

  struct timeval sent;

  /* Time the previous probe was sent, if this is a retransmit (tryno > 0) */
  struct timeval prevSent;
};

/*
 * HostOsScanStats stores the status for a host being scanned
 * in a scan round.
 */
class HostOsScanStats
{
  friend class HostOsScan;
public:
  HostOsScanStats(Target *t);
  ~HostOsScanStats();
  void initScanStats();

  struct eth_nfo *fill_eth_nfo(struct eth_nfo *eth, eth_t *ethsd) const;

  void addNewProbe(OFProbeType type, int subid);
  void removeActiveProbe(list<OFProbe *>::iterator probeI);

/* Get an active probe from active probe list identified by probe type
   and subid.  returns probesActive.end() if there isn't one. */
  list<OFProbe *>::iterator getActiveProbe(OFProbeType type, int subid);
  void moveProbeToActiveList(list<OFProbe *>::iterator probeI);
  void moveProbeToUnSendList(list<OFProbe *>::iterator probeI);
  unsigned int numProbesToSend() {return probesToSend.size();}
  unsigned int numProbesActive() {return probesActive.size();}

  FingerPrint *getFP() {return FP;}

  Target *target; /* the Target */
  struct seq_info si;
  struct ipid_info ipid;

  /*
   * distance, distance_guess: hop count between us and the target.
   *
   * Possible values of distance:
   *   0: when scan self;
   *   1: when scan a target on the same network segment;
   * >=1: not self, not same network and nmap has got the icmp reply to the U1 probe.
   *  -1: none of the above situations.
   *
   * Possible values of distance_guess:
   *  -1: nmap fails to get a valid ttl by all kinds of probes.
   * >=1: a guessing value based on ttl.
   */
  int distance;
  int distance_guess;

  /* Returns the amount of time taken between sending 1st tseq probe
     and the last one.  Zero is
     returned if we didn't send the tseq probes because there was no
     open tcp port */
  double timingRatio();

private:
  /* Ports of the targets used in os fingerprinting. */
  int openTCPPort, closedTCPPort, closedUDPPort;

  /* Probe list used in tests. At first, probes are linked in
   * probesToSend; when a probe is sent, it will be removed from
   * probesToSend and appended to probesActive. If any probes in
   * probesActive are timedout, they will be moved to probesToSend and
   * sent again till expired.
   */
  list<OFProbe *> probesToSend;
  list<OFProbe *> probesActive;

  /* A record of total number of probes that have been sent to this
   * host, including restranmited ones. */
  unsigned int num_probes_sent;
  /* Delay between two probes. */
  unsigned int sendDelayMs;
  /* When the last probe is sent. */
  struct timeval lastProbeSent;

  osscan_timing_vals_t timing;

  /*
   * Fingerprint of this target. When a scan is completed, it'll
   * finally be passed to hs->target->FPR->FPs[x].
   */
  FingerPrint *FP;
  FingerTest *FPtests[NUM_FPTESTS];
#define FP_TSeq  FPtests[0]
#define FP_TOps  FPtests[1]
#define FP_TWin  FPtests[2]
#define FP_TEcn  FPtests[3]
#define FP_T1_7_OFF 4
#define FP_T1    FPtests[4]
#define FP_T2    FPtests[5]
#define FP_T3    FPtests[6]
#define FP_T4    FPtests[7]
#define FP_T5    FPtests[8]
#define FP_T6    FPtests[9]
#define FP_T7    FPtests[10]
#define FP_TUdp  FPtests[11]
#define FP_TIcmp FPtests[12]
  struct AVal *TOps_AVs[6]; /* 6 AVs of TOps */
  struct AVal *TWin_AVs[6]; /* 6 AVs of TWin */

  /* The following are variables to store temporary results
   * during the os fingerprinting process of this host.
   */
  u16 lastipid;
  struct timeval seq_send_times[NUM_SEQ_SAMPLES];

  int TWinReplyNum; /* how many TWin replies are received. */
  int TOpsReplyNum; /* how many TOps replies are received. Actually it is the same with TOpsReplyNum. */

  struct ip *icmpEchoReply; /* To store one of the two icmp replies */
  int storedIcmpReply; /* Which one of the two icmp replies is stored? */

  struct udpprobeinfo upi; /* info of the udp probe we sent */
};

/* These are statistics for the whole group of Targets */
class ScanStats {
public:
  ScanStats();

  /* Returns true if the system says that sending is OK. */
  bool sendOK();

  osscan_timing_vals_t timing;
  struct timeout_info to; /* rtt/timeout info */

  /* Total number of active probes */
  int num_probes_active;
  /* Number of probes sent in total. */
  int num_probes_sent;
  int num_probes_sent_at_last_wait;
};

/*
 * HostOsScan does the scan job, setting and using the status of a host in
 * the host's HostOsScanStats.
 */
class HostOsScan
{
public:
  HostOsScan(Target *t); /* OsScan need a target to set eth stuffs */
  ~HostOsScan();

  pcap_t *pd;
  ScanStats *stats;

  /* (Re)Initial the parameters that will be used during the scan.*/
  void reInitScanSystem();

  void buildSeqProbeList(HostOsScanStats *hss);
  void updateActiveSeqProbes(HostOsScanStats *hss);

  void buildTUIProbeList(HostOsScanStats *hss);
  void updateActiveTUIProbes(HostOsScanStats *hss);

  /* send the next probe in the probe list of the hss */
  void sendNextProbe(HostOsScanStats *hss);

  /* Process one response.
   * If the response is useful, return true. */
  bool processResp(HostOsScanStats *hss, struct ip *ip, unsigned int len, struct timeval *rcvdtime);

  /* Make up the fingerprint. */
  void makeFP(HostOsScanStats *hss);

  /* Check whether the host is sendok. If not, fill _when_ with the
   * time when it will be sendOK and return false; else, fill it with
   * now and return true.
   */
  bool hostSendOK(HostOsScanStats *hss, struct timeval *when);

  /* Check whether it is ok to send the next seq probe to the host. If
   * not, fill _when_ with the time when it will be sendOK and return
   * false; else, fill it with now and return true.
   */
  bool hostSeqSendOK(HostOsScanStats *hss, struct timeval *when);


  /* How long I am currently willing to wait for a probe response
     before considering it timed out.  Uses the host values from
     target if they are available, otherwise from gstats.  Results
     returned in MICROseconds.  */
  unsigned long timeProbeTimeout(HostOsScanStats *hss);

  /* If there are pending probe timeouts, fills in when with the time
   * of the earliest one and returns true.  Otherwise returns false
   * and puts now in when.
   */
  bool nextTimeout(HostOsScanStats *hss, struct timeval *when);

  /* Adjust various timing variables based on pcket receipt. */
  void adjust_times(HostOsScanStats *hss, OFProbe *probe, struct timeval *rcvdtime);

private:
  /* Probe send functions. */
  void sendTSeqProbe(HostOsScanStats *hss, int probeNo);
  void sendTOpsProbe(HostOsScanStats *hss, int probeNo);
  void sendTEcnProbe(HostOsScanStats *hss);
  void sendT1_7Probe(HostOsScanStats *hss, int probeNo);
  void sendTUdpProbe(HostOsScanStats *hss, int probeNo);
  void sendTIcmpProbe(HostOsScanStats *hss, int probeNo);
  /* Response process functions. */
  bool processTSeqResp(HostOsScanStats *hss, struct ip *ip, int replyNo);
  bool processTOpsResp(HostOsScanStats *hss, struct tcp_hdr *tcp, int replyNo);
  bool processTWinResp(HostOsScanStats *hss, struct tcp_hdr *tcp, int replyNo);
  bool processTEcnResp(HostOsScanStats *hss, struct ip *ip);
  bool processT1_7Resp(HostOsScanStats *hss, struct ip *ip, int replyNo);
  bool processTUdpResp(HostOsScanStats *hss, struct ip *ip);
  bool processTIcmpResp(HostOsScanStats *hss, struct ip *ip, int replyNo);

  /* Generic sending functions used by the above probe functions. */
  int send_tcp_probe(HostOsScanStats *hss,
                     int ttl, bool df, u8* ipopt, int ipoptlen,
                     u16 sport, u16 dport, u32 seq, u32 ack,
                     u8 reserved, u8 flags, u16 window, u16 urp,
                     u8 *options, int optlen,
                     char *data, u16 datalen);
  int send_icmp_echo_probe(HostOsScanStats *hss,
                           u8 tos, bool df, u8 pcode,
                           unsigned short id, u16 seq, u16 datalen);
  int send_closedudp_probe(HostOsScanStats *hss,
                           int ttl, u16 sport, u16 dport);

  void makeTSeqFP(HostOsScanStats *hss);
  void makeTOpsFP(HostOsScanStats *hss);
  void makeTWinFP(HostOsScanStats *hss);

  bool get_tcpopt_string(struct tcp_hdr *tcp, int mss, char *result, int maxlen);

  int rawsd; /* raw socket descriptor */
  eth_t *ethsd; /* Ethernet handle */

  unsigned int tcpSeqBase, tcpAck; /* Seq&Ack value used in TCP probes */
  int tcpMss; /* tcp Mss value used in TCP probes */
  int udpttl; /* ttl value used in udp probe. */
  unsigned short icmpEchoId, icmpEchoSeq; /* Icmp Echo Id&Seq value used in ICMP probes*/

  /* Source port number in TCP probes. Different probe will use
   * arbitrary offset value of it. */
  int tcpPortBase;
  int udpPortBase;
};



/*
 * Maintain a link of incomplete HostOsScanInfo.
 */
class OsScanInfo
{
public:
  OsScanInfo(vector<Target *> &Targets);
  ~OsScanInfo();

  /* If you remove from this, you had better adjust nextI too (or call
     resetHostIterator() afterward). Don't let this list get empty,
     then add to it again, or you may mess up nextI (I'm not sure) */
  list<HostOsScanInfo *> incompleteHosts;
  float starttime;

  unsigned int numIncompleteHosts() {return incompleteHosts.size();}
  HostOsScanInfo *findIncompleteHost(struct sockaddr_storage *ss);
  /* A circular buffer of the incompleteHosts.  nextIncompleteHost() gives
     the next one.  The first time it is called, it will give the
     first host in the list.  If incompleteHosts is empty, returns
     NULL. */
  HostOsScanInfo *nextIncompleteHost();
  /* Resets the host iterator used with nextIncompleteHost() to the
     beginning.  If you remove a host from incompleteHosts, call this
     right afterward */
  void resetHostIterator() { nextI = incompleteHosts.begin(); }

  int removeCompletedHosts();
private:
  unsigned int numInitialTargets;
  list<HostOsScanInfo *>::iterator nextI;
};


/*
 * The overall os scan information of a host:
 *  - Fingerprints gotten from every scan round;
 *  - Maching results of these fingerprints.
 *  - Is it timeout/completed?
 *  - ...
 */
class HostOsScanInfo
{
public:
  HostOsScanInfo(Target *t, OsScanInfo *OSI);
  ~HostOsScanInfo();

  Target *target; /* the Target */
  OsScanInfo *OSI; /* The OSI which contains this HostOsScanInfo */
  FingerPrint **FPs; /* Fingerprints of the host */
  FingerPrintResults *FP_matches; /* Fingerprint-matching results */
  bool timedOut;
  bool isCompleted;
  HostOsScanStats *hss; /* Scan status of the host in one scan round */
};


#endif /*OSSCAN2_H*/

