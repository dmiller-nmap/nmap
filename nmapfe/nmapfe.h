/***********************************************************************/
/* nmapfe.c -- Handles widget placement for drawing the main NmapFE    */
/* GUI interface.                                                      */
/*                                                                     */
/***********************************************************************/
/*  The Nmap Security Scanner is (C) 1995-2001 Insecure.Com LLC. This  */
/*  program is free software; you can redistribute it and/or modify    */
/*  it under the terms of the GNU General Public License as published  */
/*  by the Free Software Foundation; Version 2.  This guarantees your  */
/*  right to use, modify, and redistribute this software under certain */
/*  conditions.  If this license is unacceptable to you, we may be     */
/*  willing to sell alternative licenses (contact sales@insecure.com). */
/*                                                                     */
/*  If you received these files with a written license agreement       */
/*  stating terms other than the (GPL) terms above, then that          */
/*  alternative license agreement takes precendence over this comment. */
/*                                                                     */
/*  Source is provided to this software because we believe users have  */
/*  a right to know exactly what a program is going to do before they  */
/*  run it.  This also allows you to audit the software for security   */
/*  holes (none have been found so far).                               */
/*                                                                     */
/*  Source code also allows you to port Nmap to new platforms, fix     */
/*  bugs, and add new features.  You are highly encouraged to send     */
/*  your changes to fyodor@insecure.org for possible incorporation     */
/*  into the main distribution.  By sending these changes to Fyodor or */
/*  one the insecure.org development mailing lists, it is assumed that */
/*  you are offering Fyodor the unlimited, non-exclusive right to      */
/*  reuse, modify, and relicense the code.  This is important because  */
/*  the inability to relicense code has caused devastating problems    */
/*  for other Free Software projects (such as KDE and NASM).  Nmap     */
/*  will always be available Open Source.  If you wish to specify      */
/*  special license conditions of your contributions, just say so      */
/*  when you send them.                                                */
/*                                                                     */
/*  This program is distributed in the hope that it will be useful,    */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of     */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  */
/*  General Public License for more details (                          */
/*  http://www.gnu.org/copyleft/gpl.html ).                            */
/*                                                                     */
/***********************************************************************/

/* $Id$ */

/* Original Author: Zach
 * Mail: key@aye.net
 * IRC: EFNet as zach` or key in #bastards or #neatoelito
 * AIM (Aol): GoldMatrix
 *
 * Change the source as you wish, but leave these comments..
 *
 * Long live Aol and pr: Phreak. <grins>
 */

#ifndef NMAP_H
#define NMAP_H

#if MISSING_GTK
#error "Your system does not appear to have GTK (www.gtk.org) installed.  Thus the Nmap X Front End will not compile.  You should still be able to use Nmap the normal way (via text console).  GUIs are for wimps anyway :)"
#endif

#include <nbase.h>
#include <gtk/gtk.h>

/* #define DEBUG(str) { fprintf(stderr, str); fflush(stderr); } */


/* main menu entries */
enum {
  NO_MENU,
  SEP_MENU,
  FILE_MENU	= 100,
  FILEOPEN_MENU,
  FILESAVE_MENU,
  FILEQUIT_MENU,
  VIEW_MENU	= 300,
  VIEWMONO_MENU,
  VIEWCOLOR_MENU,
  VIEWAPPEND_MENU,
  HELP_MENU	= 400,
  HELPHELP_MENU,
  HELPVERSION_MENU,
  HELPABOUT_MENU,
};


/* define this > 0 to be able to use the comfortable callback */
#define SCAN_OFFSET  1

/* scan types: used as actions in a factory-generated menu */
enum {
  NO_SCAN,
  CONNECT_SCAN = SCAN_OFFSET,
  SYN_SCAN,
  PING_SCAN,
  UDP_SCAN,
  FIN_SCAN,
  XMAS_SCAN,
  MAIMON_SCAN,
  NULL_SCAN,
  ACK_SCAN,
  WIN_SCAN,
  PROT_SCAN,
  LIST_SCAN,
  IDLE_SCAN,
  BOUNCE_SCAN
};


/* define this > 0 to be able to use the comfortable callback */
#define THROTTLE_OFFSET  1

/* throttle types: used as actions in a factory-generated menu */
enum {
  NO_THROTTLE,
  PARANOID_THROTTLE = THROTTLE_OFFSET,
  SNEAKY_THROTTLE,
  POLITE_THROTTLE,
  NORMAL_THROTTLE,
  AGRESSIVE_THROTTLE,
  INSANE_THROTTLE
};


/* define this > 0 to be able to use the comfortable callback */
#define RESOLVE_OFFSET 1

/* reverse resolving options */
enum {
  NO_RESOLVE,
  ALWAYS_RESOLVE = RESOLVE_OFFSET,
  DEFAULT_RESOLVE,
  NEVER_RESOLVE
};


/* define this > 0 to be able to use the comfortable callback */
#define PROTPORT_OFFSET 1

/* scanning mode (which ports/protocols) options */
enum {
  NO_PROTPORT,
  DEFAULT_PROTPORT = PROTPORT_OFFSET,
  ALL_PROTPORT,
  FAST_PROTPORT,
  GIVEN_PROTPORT
};


/* define this > 0 to be able to use the comfortable callback */
#define VERBOSE_OFFSET 1

/* verbosity options */
enum {
  NO_VERBOSE,
  QUIET_VERBOSE = VERBOSE_OFFSET,
  V1_VERBOSE,
  V2_VERBOSE,
  D1_VERBOSE,
  D2_VERBOSE
};


/* define this > 0 to be able to use the comfortable callback */
#define OUTPUT_OFFSET 1

/* output format options */
enum {
  NO_OUTPUT,
  NORMAL_OUTPUT = OUTPUT_OFFSET,
  GREP_OUTPUT,
  XML_OUTPUT,
  ALL_OUTPUT,
  SKIDS_OUTPUT
};


struct NmapFEoptions {
  GtkWidget *scanButton;
  GtkWidget *output;
  GtkWidget *targetHost;
  GtkWidget *commandEntry;
  gboolean appendLog;
  guint viewValue;
  guint uid;
  /* scan types */
  GtkWidget *scanType;
  guint scanValue;
  GtkWidget *scanRelayLabel;
  GtkWidget *scanRelay;
  /* Port/Protocol options */
  GtkWidget *protportFrame;
  GtkWidget *protportLabel;
  GtkWidget *protportRange;
  GtkWidget *protportType;
  guint protportValue;
  /* optional scan extensions */
  GtkWidget *RPCInfo;
  GtkWidget *IdentdInfo;
  GtkWidget *OSInfo;
  /* ping types */
  GtkWidget *dontPing;
  GtkWidget *icmpechoPing;
  GtkWidget *icmptimePing;
  GtkWidget *icmpmaskPing;
  GtkWidget *tcpPing;
  GtkWidget *tcpPingLabel;
  GtkWidget *tcpPingPorts;
  GtkWidget *synPing;
  GtkWidget *synPingLabel;
  GtkWidget *synPingPorts;
  GtkWidget *udpPing;
  GtkWidget *udpPingLabel;
  GtkWidget *udpPingPorts;
  /* timing_options */
  GtkWidget *throttleType;
  guint throttleValue;
  GtkWidget *startRtt;
  GtkWidget *startRttTime;
  GtkWidget *minRtt;
  GtkWidget *minRttTime;
  GtkWidget *maxRtt;
  GtkWidget *maxRttTime;
  GtkWidget *hostTimeout;
  GtkWidget *hostTimeoutTime;
  GtkWidget *scanDelay;
  GtkWidget *scanDelayTime;
  GtkWidget *ipv4Ttl;
  GtkWidget *ipv4TtlValue;
  GtkWidget *minPar;
  GtkWidget *minParSocks;
  GtkWidget *maxPar;
  GtkWidget *maxParSocks;
  /* file options */
  GtkWidget *useInputFile;
  GtkWidget *inputFilename;
  GtkWidget *inputBrowse;
  GtkWidget *useOutputFile;
  GtkWidget *outputFilename;
  GtkWidget *outputBrowse;
  GtkWidget *outputFormatLabel;
  GtkWidget *outputFormatType;
  GtkWidget *outputAppend;
  guint outputFormatValue;
  /* DNS options */
  GtkWidget *resolveType;
  guint resolveValue;
  /* verbosity options */
  GtkWidget *verboseType;
  guint verboseValue;
  /* source options */
  GtkWidget *useSourceDevice;
  GtkWidget *SourceDevice;
  GtkWidget *useSourcePort;
  GtkWidget *SourcePort;
  GtkWidget *useSourceIP;
  GtkWidget *SourceIP;
  GtkWidget *useDecoy;
  GtkWidget *Decoy;
  /* misc. options */
  GtkWidget *useFragments;
  GtkWidget *useIPv6;
  GtkWidget *useOrderedPorts;
};

GtkWidget* create_main_win (void);
GtkWidget* create_aboutDialog(void);
GtkWidget* create_fileSelection(const char *title, char *filename, void (*action)(), GtkEntry *entry);
GtkWidget* create_helpDialog(void);
GtkWidget* create_machine_parse_selection (void);

#endif /* NMAP_H */
