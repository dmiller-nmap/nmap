
/***********************************************************************/
/* nmapfe_sig.c -- Signal handlers for NmapFE                          */
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
 * Long live Aol and pr: Phreak.  :-)
 */

#ifndef NMAPFE_SIG_H
#define NMAPFE_SIG_H

#if MISSING_GTK
#error "Your system does not appear to have GTK (www.gtk.org) installed.  Thus the Nmap X Front End will not compile.  You should still be able to use Nmap the normal way (via text console).  GUIs are for wimps anyway :)"
#endif

void
on_delete_event                        (GtkWidget     *widget,
                                        GdkEvent      *event,
                                        gpointer      data);


#include <gtk/gtk.h>
#include <nbase.h>

#include "nmapfe_error.h"

void build_tree(char *buf);
void stop_scan();
gint read_data(gpointer data);
void entry_toggle_checkbox (GtkWidget *entry, GtkWidget *checkbox);
void validate_option_change(GtkWidget *target_option, char *ignored);
void display_nmap_command_callback(GtkWidget *target_option, char *ignored);
void display_nmap_command();
void scan_options(GtkWidget *widget, int *the_option);
char *build_command();
void kill_output();
int execute(char *command);
void func_start_scan();
void on_done_clicked(GtkButton *button, GtkWidget *widget);
void on_cancel_clicked(GtkButton *button, GtkWidget *widget);
void on_machine_activate();
void on_rpc_activate (GtkMenuItem *menuitem, gpointer user_data);

void
on_start_scan_clicked                  (GtkButton       *button,
                                        GtkWidget        *entry);

void on_verb_activate			(GtkMenuItem	*menuitem, gpointer user_data);

void on_Append_activate			(GtkMenuItem	*menuitem, gpointer user_data);

void
on_exit_me_clicked                        (GtkButton       *button,
									gpointer	user_data);

void
on_About_activate                      (GtkMenuItem     *menuitem,
                                        GtkWidget        *about);

void
on_Close_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_about_ok_clicked                    (GtkButton       *button,
								GtkWidget	*about);

void
on_help_ok_clicked                    (GtkButton       *button,
								GtkWidget	*help);

void
on_Save_Log_activate                   (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_Open_Log_activate                   (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_Help_Main_activate                  (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_Help_activate                       (GtkMenuItem     *menuitem,
                                        GtkWidget        *help);
void
on_View_Main_activate                  (GtkMenuItem     *menuitem,
                                        gpointer         user_data);
                                        
void on_Trad_activate                  (GtkMenuItem *menuitem, GtkWidget *trad);
void on_CTrad_activate                  (GtkMenuItem *menuitem, GtkWidget *ctrad);
void on_Tree_activate                  (GtkMenuItem *menuitem, GtkWidget *tree);

void
on_Start_Scan_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_Get_Nmap_Version_activate           (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_ok_button1_clicked                  (GtkButton       *button,
                                        GtkWidget	 *window);

void
on_cancel_button1_clicked              (GtkButton       *button,
                                        GtkWidget         *window);

/* A few functions that should be in a util file (in fact, they should
   share the same util file Nmap uses IMHO */
int arg_parse(const char *command, char ***argv);
void arg_parse_free(char **argv);

#endif /*  NMAPFE_SIG_H */

