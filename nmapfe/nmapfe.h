/***********************************************************************/
/* nmapfe.c -- Handles widget placement for drawing the main NmapFE    */
/* GUI interface.                                                      */
/*                                                                     */
/***********************************************************************/
/*  The Nmap Security Scanner is (C) 1995-2000 Insecure.Org.  This     */
/*  program is free software; you can redistribute it and/or modify    */
/*  it under the terms of the GNU General Public License as published  */
/*  by the Free Software Foundation; Version 2.  This guarantees your  */
/*  right to use, modify, and redistribute this software under certain */
/*  conditions.  If this license is unacceptable to you,               */
/*  Insecure.Com LLC may be willing to sell alternative licenses       */
/*  (contact sales@insecure.com ).                                     */
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

#if MISSING_GTK
#error "Your system does not appear to have GTK (www.gtk.org) installed.  Thus the Nmap X Front End will not compile.  You should still be able to use Nmap the normal way (via text console).  GUIs are for wimps anyway :)"
#endif

#include <gtk/gtk.h>

/* #define DEBUG(str) { fprintf(stderr, str); fflush(stderr); } */

struct MyWidgets {
  GtkWidget *output;
  GtkWidget *host_text;
  GtkWidget *fast_check;
  GtkWidget *resolve_check;
  GtkWidget *Verbose;
  GtkWidget *Append;
  GtkWidget *range_check;
  GtkWidget *start_scan;
  GtkWidget *range_text;
  GtkWidget *decoy_check;
  GtkWidget *decoy_text;
  GtkWidget *tcp_check;
  GtkWidget *fingerprinting_check;
  GtkWidget *icmp_check;
  GtkWidget *ping_check;
  GtkWidget *input_check;
  GtkWidget *input_text;
  GtkWidget *fragment_check;
  GtkWidget *identd_check;
  GtkWidget *resolveall_check;
  GtkWidget *tcpicmp_check;
  GtkWidget *device_check;
  GtkWidget *device_text;
  GtkWidget *bounce_check;
  GtkWidget *bounce_text;
  GtkWidget *connect_scan;
  GtkWidget *syn_scan;
  GtkWidget *ping_scan;
  GtkWidget *udp_scan;
  GtkWidget *fin_scan;
  GtkWidget *output_label;
  GtkWidget *browse;
  GtkWidget *file_entry;
  GtkWidget *done;
  GtkWidget *cancel;
  char *machine_file;
  GtkWidget *rpc;
};

GtkWidget*
get_widget                             (GtkWidget       *widget,
                                        gchar           *widget_name);

void
set_notebook_tab                       (GtkWidget       *notebook,
                                        gint             page_num,
                                        GtkWidget       *widget);

GtkWidget* create_main_win (void);
GtkWidget* create_about_window (void);
GtkWidget* create_fileselection1 (void);
GtkWidget* create_help_window (void);
GtkWidget* create_machine_parse_selection (void);
