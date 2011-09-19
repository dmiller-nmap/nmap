
/***************************************************************************
 * ICMPv6RRBody.cc -- The ICMPv6RRBody Class represents an ICMP version 6  *
 * Router Renumbering message body. It contains methods to set any header  *
 * field. In general, these  methods do error checkings and byte order     *
 * conversions.                                                            *
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
/* This code was originally part of the Nping tool.                        */

#ifndef ICMPv6HEADER_H
#define ICMPv6HEADER_H 1

#include "NetworkLayerElement.h"

/* Packet header diagrams included in this file have been taken from the
 * following IETF RFC documents: RFC 2894 */

/* Nping ICMPv6RRBody Class internal definitions */
#define ICMPv6_RR_MATCH_PREFIX_LEN 24
#define ICMPv6_RR_USE_PREFIX_LEN   32
#define ICMPv6_RR_RESULT_MSG_LEN   24
/* This must the MAX() of all values defined above*/
#define ICMPv6_RR_MAX_LENGTH (ICMPv6_RR_USE_PREFIX_LEN)
#define ICMPv6_RR_MIN_LENGTH (ICMPv6_RR_MATCH_PREFIX_LEN)


class ICMPv6RRBody : public NetworkLayerElement {

    private:

        /**********************************************************************/
        /* COMMON ICMPv6 OPTION HEADER                                        */
        /**********************************************************************/

        struct nping_icmpv6_rr_body{
            u8 data[ICMPv6_RR_MAX_LENGTH];
        }__attribute__((__packed__));
        typedef struct nping_icmpv6_rr_body nping_icmpv6_rr_body_t;

        /**********************************************************************/
        /* ICMPv6 OPTION FORMATS                                              */
        /**********************************************************************/


        /* Match-Prefix Part

          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |    OpCode     |   OpLength    |    Ordinal    |   MatchLen    |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |    MinLen     |    MaxLen     |           reserved            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-                         MatchPrefix                         -+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
        struct rr_match_prefix{
            u8 op_code;
            u8 op_length;
            u8 ordinal;
            u8 match_length;
            u8 min_length;
            u8 max_length;
            u16 reserved;
            u8 match_prefix[16];
        }__attribute__((__packed__));
        typedef struct rr_match_prefix rr_match_prefix_t;


        /* Use-Prefix Part
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |    UseLen     |    KeepLen    |   FlagMask    |    RAFlags    |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                        Valid Lifetime                         |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                      Preferred Lifetime                       |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |V|P|                         reserved                          |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-                          UsePrefix                          -+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
        struct rr_use_prefix{
            u8 use_len;
            u8 keep_len;
            u8 flag_mask;
            u8 ra_flags;
            u32 valid_lifetime;
            u32 preferred_lifetime;
            u8 flags;
            u8 reserved[3];
            u8 use_prefix[16];
        }__attribute__((__packed__));
        typedef struct rr_use_prefix rr_use_prefix_t;


        /* Result Message

          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |         reserved          |B|F|    Ordinal    |  MatchedLen   |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                         InterfaceIndex                        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-                        MatchedPrefix                        -+
          |                                                               |
          +-                                                             -+
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct rr_result_msg{
            u8 reserved;
            u8 flags;
            u8 ordinal;
            u8 matched_length;
            u32 interface_index;
            u8 matched_prefix[16];
        }__attribute__((__packed__));
        typedef struct rr_result_msg rr_result_msg_t;

        nping_icmpv6_rr_body_t h;

        rr_match_prefix_t *h_mp;
        rr_use_prefix_t   *h_up;
        rr_result_msg_t   *h_r;

    public:
        ICMPv6RRBody();
        ~ICMPv6RRBody();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);

}; /* End of class ICMPv6RRBody */

#endif
