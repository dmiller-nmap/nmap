
/***************************************************************************
 * scanengine.h -- Includes much of the "engine" functions for scanning,   *
 * such as pos_scan and super_scan.  It also includes dependant functions  *
 * such as those for collectiong SYN/connect scan responses.               *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *  The Nmap Security Scanner is (C) 1995-2001 Insecure.Com LLC. This  *
 *  program is free software; you can redistribute it and/or modify    *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; Version 2.  This guarantees your  *
 *  right to use, modify, and redistribute this software under certain *
 *  conditions.  If this license is unacceptable to you, we may be     *
 *  willing to sell alternative licenses (contact sales@insecure.com). *
 *                                                                     *
 *  If you received these files with a written license agreement       *
 *  stating terms other than the (GPL) terms above, then that          *
 *  alternative license agreement takes precendence over this comment. *
 *                                                                     *
 *  Source is provided to this software because we believe users have  *
 *  a right to know exactly what a program is going to do before they  *
 *  run it.  This also allows you to audit the software for security   *
 *  holes (none have been found so far).                               *
 *                                                                     *
 *  Source code also allows you to port Nmap to new platforms, fix     *
 *  bugs, and add new features.  You are highly encouraged to send     *
 *  your changes to fyodor@insecure.org for possible incorporation     *
 *  into the main distribution.  By sending these changes to Fyodor or *
 *  one the insecure.org development mailing lists, it is assumed that *
 *  you are offering Fyodor the unlimited, non-exclusive right to      *
 *  reuse, modify, and relicense the code.  This is important because  *
 *  the inability to relicense code has caused devastating problems    *
 *  for other Free Software projects (such as KDE and NASM).  Nmap     *
 *  will always be available Open Source.  If you wish to specify      *
 *  special license conditions of your contributions, just say so      *
 *  when you send them.                                                *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  *
 *  General Public License for more details (                          *
 *  http://www.gnu.org/copyleft/gpl.html ).                            *
 *                                                                     *
 ***************************************************************************/

/* $Id$ */

#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

#include "portlist.h"
#include "tcpip.h"
#include "global_structures.h"

/* Handles the "positive-response" scans (where we get a response
   telling us that the port is open based on the probe.  This includes
   SYN Scan, Connect Scan, RPC scan, Window Scan, and ACK scan */
void pos_scan(Target *target, u16 *portarray, int numports, stype scantype);

/* FTP bounce attack scan.  This function is rather lame and should be
   rewritten.  But I don't think it is used much anyway.  If I'm going to
   allow FTP bounce scan, I should really allow SOCKS proxy scan.  */
void bounce_scan(Target *target, u16 *portarray, int numports,
		 struct ftpinfo *ftp);

/* Handles the scan types where no positive-acknowledgement of open
   port is received (those scans are in pos_scan).  Super_scan
   includes scans such as FIN/XMAS/NULL/Maimon/UDP and IP Proto scans */
void super_scan(Target *target, u16 *portarray, int numports,
		stype scantype);

#endif /* SCAN_ENGINE_H */
