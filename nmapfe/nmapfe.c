
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
#else

#include "nmapfe.h"
#include "nmapfe_sig.h"

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#include <nbase.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>


/* Keep this global */
int our_uid;

struct MyWidgets *MW;
int view_type = 1;
GtkWidget*
get_widget                             (GtkWidget       *widget,
                                        gchar           *widget_name)
{
  GtkWidget *found_widget;

  if (widget->parent)
    widget = gtk_widget_get_toplevel (widget);
  found_widget = (GtkWidget*) gtk_object_get_data (GTK_OBJECT (widget),
                                                   widget_name);
  if (!found_widget)
    g_warning ("Widget not found: %s", widget_name);
  return found_widget;
}

/* This is an internally used function to set notebook tab widgets. */
void
set_notebook_tab                       (GtkWidget       *notebook,
                                        gint             page_num,
                                        GtkWidget       *widget)
{
  GtkNotebookPage *page;
  GtkWidget *notebook_page;

  page = (GtkNotebookPage*) g_list_nth (GTK_NOTEBOOK (notebook)->children, page_num)->data;
  notebook_page = page->child;
  gtk_widget_ref (notebook_page);
  gtk_notebook_remove_page (GTK_NOTEBOOK (notebook), page_num);
  gtk_notebook_insert_page (GTK_NOTEBOOK (notebook), notebook_page,
                            widget, page_num);
  gtk_widget_unref (notebook_page);
}

GtkWidget*
create_main_win ()
{
  GtkWidget *main_win;
  GtkWidget *fixed1;
  GSList *fixed1_group = NULL;
  GSList *ping_group = NULL;
  GtkWidget *vscroll;
  GtkWidget *exit_me;
  GtkWidget *hseparator2;
  GtkWidget *label2;
  GtkWidget *menubar1;
  GtkWidget *File;
  GtkWidget *menu5;
/*New for 1.0*/
  GtkWidget *view_m;
  GtkWidget *View_Main;
  GtkWidget *Trad;
  GtkWidget *CTrad;
  /*GtkWidget *Tree;*/
  GtkWidget *machine;
  GtkWidget *extra;
  GtkWidget *extra_menu;
/*End new*/
  GtkWidget *Save_Log;
  GtkWidget *Open_Log;
  GtkWidget *separator1;
  GtkWidget *Close;
  GtkWidget *Help_Main;
  GtkWidget *menu6;
  GtkWidget *menu7;
  GtkWidget *hbox1;
  GtkWidget *Help;
  GtkWidget *Other;
  GtkWidget *Get_Nmap_Version;
  GtkWidget *separator2;
  GtkWidget *About;
  GtkWidget *vseparator1;
  GtkWidget *hseparator1;
  GtkWidget *label3;
  GtkWidget *vbox2;
  GtkWidget *label1;
  char title[256];

  our_uid = getuid();

  main_win = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_object_set_data (GTK_OBJECT (main_win), "main_win", main_win);
  /* Need to integrate with nmapfe so I can use snprintf() */
  sprintf(title, "Nmap Front End v%s", VERSION);
  gtk_window_set_title (GTK_WINDOW (main_win), title);
  gtk_window_position (GTK_WINDOW (main_win), GTK_WIN_POS_CENTER);
  gtk_signal_connect (GTK_OBJECT (main_win), "delete_event",
					  GTK_SIGNAL_FUNC (on_delete_event), NULL);
  
  vbox2 = gtk_vbox_new (FALSE, 0);
  gtk_object_set_data (GTK_OBJECT (main_win), "vbox2", vbox2);
  gtk_widget_show (vbox2);
  gtk_container_add (GTK_CONTAINER (main_win), vbox2);
  
  menubar1 = gtk_menu_bar_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "menubar1", menubar1);
  gtk_widget_show (menubar1);
  gtk_box_pack_start (GTK_BOX (vbox2), menubar1, FALSE, TRUE, 0);

  fixed1 = gtk_fixed_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "fixed1", fixed1);
  gtk_widget_show (fixed1);
  gtk_box_pack_start (GTK_BOX (vbox2), fixed1, FALSE, TRUE, 0);
  gtk_widget_set_usize (fixed1, -2, 233);

  hbox1 = gtk_hbox_new (FALSE, 0);
  gtk_object_set_data (GTK_OBJECT (main_win), "hbox1", hbox1);
  gtk_widget_show (hbox1);
  gtk_box_pack_start (GTK_BOX (vbox2), hbox1, TRUE, TRUE, 0);

  MW->output = gtk_text_new (NULL, NULL);
  gtk_object_set_data (GTK_OBJECT (main_win), "output", MW->output);
  gtk_widget_show (MW->output);
  gtk_box_pack_start (GTK_BOX (hbox1), MW->output, TRUE, TRUE, 0);
  gtk_text_set_word_wrap(GTK_TEXT(MW->output), 1);
  gtk_widget_set_usize (MW->output, 464, 248);
  gtk_widget_realize (MW->output);
  
  vscroll = gtk_vscrollbar_new (GTK_TEXT (MW->output)->vadj);
  gtk_object_set_data (GTK_OBJECT (main_win), "vscroll", vscroll);
  gtk_widget_show (vscroll);
  gtk_box_pack_end (GTK_BOX (hbox1), vscroll, FALSE, FALSE, 0);
  
  MW->host_text = gtk_entry_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "host_text", MW->host_text);
  gtk_widget_show (MW->host_text);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->host_text, 56, 22);
  gtk_widget_set_usize (MW->host_text, 272, 22);
  GTK_WIDGET_SET_FLAGS (MW->host_text, GTK_CAN_DEFAULT);
  gtk_widget_grab_focus (MW->host_text);
  gtk_widget_grab_default (MW->host_text);
  gtk_entry_set_text (GTK_ENTRY (MW->host_text), "127.0.0.1");
  gtk_signal_connect(GTK_OBJECT(MW->host_text), "changed",
			GTK_SIGNAL_FUNC(display_nmap_command_callback), NULL);

  MW->connect_scan = gtk_radio_button_new_with_label (fixed1_group, "connect()");
  fixed1_group = gtk_radio_button_group (GTK_RADIO_BUTTON (MW->connect_scan));
  gtk_object_set_data (GTK_OBJECT (main_win), "connect", MW->connect_scan);
  gtk_widget_show (MW->connect_scan);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->connect_scan, 8, 74);
  gtk_signal_connect(GTK_OBJECT(MW->connect_scan), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  gtk_widget_set_usize (MW->connect_scan, 104, 19);

if(our_uid == 0) {
  MW->syn_scan = gtk_radio_button_new_with_label (fixed1_group, "SYN Stealth");
  fixed1_group = gtk_radio_button_group (GTK_RADIO_BUTTON (MW->syn_scan));
  gtk_object_set_data (GTK_OBJECT (main_win), "syn", MW->syn_scan);
  gtk_widget_show (MW->syn_scan);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->syn_scan, 8,  91);
  gtk_signal_connect(GTK_OBJECT(MW->syn_scan), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  gtk_widget_set_usize (MW->syn_scan, 104, 19);
  gtk_toggle_button_set_state (GTK_TOGGLE_BUTTON (MW->syn_scan), TRUE);
} /* end uid check */

  MW->ping_scan = gtk_radio_button_new_with_label (fixed1_group, "Ping Sweep");
  fixed1_group = gtk_radio_button_group (GTK_RADIO_BUTTON (MW->ping_scan));
  gtk_object_set_data (GTK_OBJECT (main_win), "ping", MW->ping_scan);
  gtk_widget_show (MW->ping_scan);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->ping_scan, 8, 108);
  gtk_signal_connect(GTK_OBJECT(MW->ping_scan), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  gtk_widget_set_usize (MW->ping_scan, 104, 19);

if (our_uid == 0){
  MW->udp_scan = gtk_radio_button_new_with_label (fixed1_group, "UDP Port Scan");
  fixed1_group = gtk_radio_button_group (GTK_RADIO_BUTTON (MW->udp_scan));
  gtk_object_set_data (GTK_OBJECT (main_win), "udp", MW->udp_scan);
  gtk_widget_show (MW->udp_scan);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->udp_scan, 8, 126);
  gtk_signal_connect(GTK_OBJECT(MW->udp_scan), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  gtk_widget_set_usize (MW->udp_scan, 104, 17);

  MW->fin_scan = gtk_radio_button_new_with_label (fixed1_group, "FIN Stealth");
  fixed1_group = gtk_radio_button_group (GTK_RADIO_BUTTON (MW->fin_scan));
  gtk_object_set_data (GTK_OBJECT (main_win), "fin", MW->fin_scan);
  gtk_widget_show (MW->fin_scan);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->fin_scan, 8, 142);
  gtk_signal_connect(GTK_OBJECT(MW->fin_scan), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  gtk_widget_set_usize (MW->fin_scan, 104, 19);
} /*end uid check*/

  MW->resolve_check = gtk_check_button_new_with_label ("Don't Resolve");
  gtk_object_set_data (GTK_OBJECT (main_win), "resolve_check", MW->resolve_check);
  gtk_widget_show (MW->resolve_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->resolve_check, 136, 70);
  gtk_widget_set_usize (MW->resolve_check, 104, 24);
  gtk_signal_connect(GTK_OBJECT(MW->resolve_check), "released",
			GTK_SIGNAL_FUNC(display_nmap_command_callback), NULL);

  MW->fast_check = gtk_check_button_new_with_label ("Fast Scan");
  gtk_object_set_data (GTK_OBJECT (main_win), "fast_check", MW->fast_check);
  gtk_widget_show (MW->fast_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->fast_check, 136,  94);
  gtk_widget_set_usize (MW->fast_check, 104, 24);
  gtk_signal_connect(GTK_OBJECT(MW->fast_check), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);


  MW->range_check = gtk_check_button_new_with_label ("Range of Ports:");
  gtk_object_set_data (GTK_OBJECT (main_win), "range_check", MW->range_check);
  gtk_widget_show (MW->range_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->range_check, 136, 118);
  gtk_widget_set_usize (MW->range_check, 104, 24);
  gtk_signal_connect(GTK_OBJECT(MW->range_check), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);


  MW->range_text = gtk_entry_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "range_text", MW->range_text);
  gtk_widget_show (MW->range_text);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->range_text, 136, 142);
  gtk_widget_set_usize (MW->range_text, 104, 21);
  gtk_signal_connect (GTK_OBJECT(MW->range_text), "changed",
		      GTK_SIGNAL_FUNC(entry_toggle_checkbox), MW->range_check);


  MW->decoy_check = gtk_check_button_new_with_label ("Use Decoy(s):");
  gtk_object_set_data (GTK_OBJECT (main_win), "decoy_check", MW->decoy_check);
  if (our_uid == 0)
    gtk_widget_show (MW->decoy_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->decoy_check, 136, 165);
  gtk_widget_set_usize (MW->decoy_check, 104, 16);
  gtk_signal_connect(GTK_OBJECT(MW->decoy_check), "released",
		     GTK_SIGNAL_FUNC(validate_option_change), NULL);

  MW->decoy_text = gtk_entry_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "decoy_text", MW->decoy_text);
  if (our_uid == 0)
    gtk_widget_show (MW->decoy_text);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->decoy_text, 136, 182);  
  gtk_widget_set_usize (MW->decoy_text, 104, 21);
  gtk_signal_connect (GTK_OBJECT(MW->decoy_text), "changed",
		      GTK_SIGNAL_FUNC(entry_toggle_checkbox), MW->decoy_check);


  MW->tcp_check = gtk_radio_button_new_with_label (ping_group, "TCP Ping");
  ping_group = gtk_radio_button_group (GTK_RADIO_BUTTON (MW->tcp_check));
  gtk_object_set_data (GTK_OBJECT (main_win), "tcp_check", MW->tcp_check);
  gtk_widget_show (MW->tcp_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->tcp_check, 248, 70);
  gtk_widget_set_usize (MW->tcp_check, 99, 24);
  gtk_signal_connect(GTK_OBJECT(MW->tcp_check), "released",
			GTK_SIGNAL_FUNC(display_nmap_command_callback), NULL);

  MW->icmp_check = gtk_radio_button_new_with_label (ping_group, "ICMP Ping");
  ping_group = gtk_radio_button_group (GTK_RADIO_BUTTON (MW->icmp_check));
  gtk_object_set_data (GTK_OBJECT (main_win), "icmp_check", MW->icmp_check);
	if(our_uid == 0)
	  gtk_widget_show (MW->icmp_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->icmp_check, 248, 118);
  gtk_widget_set_usize (MW->icmp_check, 99, 24);
  gtk_signal_connect(GTK_OBJECT(MW->icmp_check), "released",
			GTK_SIGNAL_FUNC(display_nmap_command_callback), NULL);


  MW->tcpicmp_check = gtk_radio_button_new_with_label (ping_group, "TCP&ICMP");
  ping_group = gtk_radio_button_group (GTK_RADIO_BUTTON (MW->tcpicmp_check));
  gtk_object_set_data (GTK_OBJECT (main_win), "tcpicmp_check", MW->tcpicmp_check);
	if(our_uid == 0){
	  gtk_widget_show (MW->tcpicmp_check);
	  /*	  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(MW->tcpicmp_check), 1);*/
	  gtk_toggle_button_set_state( GTK_TOGGLE_BUTTON(MW->tcpicmp_check), TRUE);
	  }
  gtk_fixed_put (GTK_FIXED (fixed1), MW->tcpicmp_check, 248,  94);
  gtk_widget_set_usize (MW->tcpicmp_check, 99, 24);
  gtk_signal_connect(GTK_OBJECT(MW->tcpicmp_check), "released",
			GTK_SIGNAL_FUNC(display_nmap_command_callback), NULL);


  MW->ping_check = gtk_radio_button_new_with_label (ping_group, "Don't Ping");
  ping_group = gtk_radio_button_group (GTK_RADIO_BUTTON (MW->ping_check));
  gtk_object_set_data (GTK_OBJECT (main_win), "ping_check", MW->ping_check);
  gtk_widget_show (MW->ping_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->ping_check, 248, 140);
  gtk_widget_set_usize (MW->ping_check, 99, 24);
  gtk_signal_connect(GTK_OBJECT(MW->ping_check), "released",
			GTK_SIGNAL_FUNC(display_nmap_command_callback), NULL);


  MW->input_check = gtk_check_button_new_with_label ("Input File:");
  gtk_object_set_data (GTK_OBJECT (main_win), "input_check", MW->input_check);
  gtk_widget_show (MW->input_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->input_check, 248, 165);
  gtk_widget_set_usize (MW->input_check, 99, 16);
  gtk_signal_connect(GTK_OBJECT(MW->input_check), "released",
		     GTK_SIGNAL_FUNC(validate_option_change), NULL);


  MW->input_text = gtk_entry_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "input_text", MW->input_text);
  gtk_widget_show (MW->input_text);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->input_text, 248, 182);
  gtk_widget_set_usize (MW->input_text, 96, 21);
  gtk_signal_connect (GTK_OBJECT(MW->input_text), "changed",
		      GTK_SIGNAL_FUNC(entry_toggle_checkbox), MW->input_check);

  MW->fragment_check = gtk_check_button_new_with_label ("Fragmentation");
  gtk_object_set_data (GTK_OBJECT (main_win), "fragment_check", MW->fragment_check);
	if(our_uid == 0)
	  gtk_widget_show (MW->fragment_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->fragment_check, 352, 70);
  gtk_widget_set_usize (MW->fragment_check, 112, 24);
  gtk_signal_connect(GTK_OBJECT(MW->fragment_check), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);


  MW->identd_check = gtk_check_button_new_with_label ("Get Identd Info");
  gtk_object_set_data (GTK_OBJECT (main_win), "identd_check", MW->identd_check);
  gtk_widget_show (MW->identd_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->identd_check, 352,  94);
  gtk_widget_set_usize (MW->identd_check, 112, 24);
  gtk_signal_connect(GTK_OBJECT(MW->identd_check), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);


  MW->resolveall_check = gtk_check_button_new_with_label ("Resolve All");
  gtk_object_set_data (GTK_OBJECT (main_win), "resolveall_check", MW->resolveall_check);
  gtk_widget_show (MW->resolveall_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->resolveall_check, 352, 118);
  gtk_widget_set_usize (MW->resolveall_check, 112, 24);
  gtk_signal_connect(GTK_OBJECT(MW->resolveall_check), "released",
		     GTK_SIGNAL_FUNC(display_nmap_command_callback), NULL);


  MW->fingerprinting_check = gtk_check_button_new_with_label ("OS Detection");
  gtk_object_set_data (GTK_OBJECT (main_win), "fingerprinting_check",    MW->fingerprinting_check);
	if(our_uid == 0){
	  gtk_widget_show (MW->fingerprinting_check);
	  /*	  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(MW->fingerprinting_check), 1);*/
	  gtk_toggle_button_set_state( GTK_TOGGLE_BUTTON(MW->fingerprinting_check), TRUE);
	}
  gtk_fixed_put (GTK_FIXED (fixed1), MW->fingerprinting_check, 352, 140);
  gtk_widget_set_usize (MW->fingerprinting_check, 112, 24);
  gtk_signal_connect(GTK_OBJECT(MW->fingerprinting_check), "released",
		     GTK_SIGNAL_FUNC(display_nmap_command_callback), NULL);


  MW->device_check = gtk_check_button_new_with_label ("Send on Device:");
  gtk_object_set_data (GTK_OBJECT (main_win), "device_check", MW->device_check);
  if (our_uid == 0)
    gtk_widget_show (MW->device_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->device_check, 352, 165);
  gtk_widget_set_usize (MW->device_check, 112, 17);
  gtk_signal_connect(GTK_OBJECT(MW->device_check), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);


  MW->device_text = gtk_entry_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "device_text", MW->device_text);
  if (our_uid == 0)
    gtk_widget_show (MW->device_text);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->device_text, 352, 182);
  gtk_widget_set_usize (MW->device_text, 112, 21);
  gtk_signal_connect (GTK_OBJECT(MW->device_text), "changed",
		      GTK_SIGNAL_FUNC(entry_toggle_checkbox), MW->device_check);


  MW->start_scan = gtk_toggle_button_new_with_label("Scan.");
  gtk_object_set_data (GTK_OBJECT (main_win), "start_scan", MW->start_scan);
  gtk_widget_show (MW->start_scan);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->start_scan, 344, 22);
  gtk_widget_set_usize (MW->start_scan, 72, 24);
  gtk_signal_connect (GTK_OBJECT (MW->start_scan), "toggled",
                      GTK_SIGNAL_FUNC (on_start_scan_clicked),
                      MW->host_text);

  exit_me = gtk_button_new_with_label ("Exit");
  gtk_object_set_data (GTK_OBJECT (main_win), "exit", exit_me);
  gtk_widget_show (exit_me);
  gtk_fixed_put (GTK_FIXED (fixed1), exit_me, 424, 22);
  gtk_widget_set_usize (exit_me, 48, 24);
  gtk_signal_connect (GTK_OBJECT (exit_me), "clicked",
                      GTK_SIGNAL_FUNC (on_exit_me_clicked),
                      NULL);

  MW->bounce_check = gtk_check_button_new_with_label ("Bounce Scan:");
  gtk_object_set_data (GTK_OBJECT (main_win), "bounce_check", MW->bounce_check);
  gtk_widget_show (MW->bounce_check);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->bounce_check, 8, 165);
  gtk_widget_set_usize (MW->bounce_check, 104, 17);
  gtk_signal_connect(GTK_OBJECT(MW->bounce_check), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);

  MW->bounce_text = gtk_entry_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "bounce_text", MW->bounce_text);
  gtk_widget_show (MW->bounce_text);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->bounce_text, 8, 182);
  gtk_widget_set_usize (MW->bounce_text, 104, 21);
  gtk_signal_connect (GTK_OBJECT(MW->bounce_text), "changed",
		      GTK_SIGNAL_FUNC(entry_toggle_checkbox), MW->bounce_check);


  hseparator2 = gtk_hseparator_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "hseparator2", hseparator2);
  gtk_widget_show (hseparator2);
  gtk_fixed_put (GTK_FIXED (fixed1), hseparator2, 8, 54);
  gtk_widget_set_usize (hseparator2, 114, 16);

  label2 = gtk_label_new ("Scan Options:");
  gtk_object_set_data (GTK_OBJECT (main_win), "label2", label2);
  gtk_widget_show (label2);
  gtk_fixed_put (GTK_FIXED (fixed1), label2, 8, 46);
  gtk_widget_set_usize (label2, 104, 16);


  File = gtk_menu_item_new_with_label ("File");
  gtk_object_set_data (GTK_OBJECT (main_win), "File", File);
  gtk_widget_show (File);
  gtk_container_add (GTK_CONTAINER (menubar1), File);

  menu5 = gtk_menu_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "menu5", menu5);
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (File), menu5);

  Save_Log = gtk_menu_item_new_with_label ("Save Log");
  gtk_object_set_data (GTK_OBJECT (main_win), "Save_Log", Save_Log);
  gtk_widget_show (Save_Log);
  gtk_container_add (GTK_CONTAINER (menu5), Save_Log);
  gtk_signal_connect (GTK_OBJECT (Save_Log), "activate",
                      GTK_SIGNAL_FUNC (on_Save_Log_activate),
                      NULL);

  Open_Log = gtk_menu_item_new_with_label ("Open Log");
  gtk_object_set_data (GTK_OBJECT (main_win), "Open_Log", Open_Log);
  gtk_widget_show (Open_Log);
  gtk_container_add (GTK_CONTAINER (menu5), Open_Log);
  gtk_signal_connect (GTK_OBJECT (Open_Log), "activate",
                      GTK_SIGNAL_FUNC (on_Open_Log_activate),
                      NULL);

  separator1 = gtk_menu_item_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "separator1", separator1);
  gtk_widget_show (separator1);
  gtk_container_add (GTK_CONTAINER (menu5), separator1);

  Close = gtk_menu_item_new_with_label ("Close");
  gtk_object_set_data (GTK_OBJECT (main_win), "Close", Close);
  gtk_widget_show (Close);
  gtk_container_add (GTK_CONTAINER (menu5), Close);
  gtk_signal_connect (GTK_OBJECT (Close), "activate",
                      GTK_SIGNAL_FUNC (on_Close_activate),
                      NULL);

  Other = gtk_menu_item_new_with_label ("Output");
  gtk_object_set_data (GTK_OBJECT (main_win), "Other", Other);
  gtk_widget_show (Other);
  gtk_container_add (GTK_CONTAINER (menubar1), Other);
  gtk_signal_connect (GTK_OBJECT (Other), "activate", NULL, NULL);

  menu7 = gtk_menu_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "menu7", menu7);
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (Other), menu7);

  MW->Verbose = gtk_check_menu_item_new_with_label("Verbose Output");
  gtk_object_set_data (GTK_OBJECT (main_win), "Verbose", MW->Verbose);
  gtk_widget_show (MW->Verbose);
  gtk_container_add (GTK_CONTAINER (menu7), MW->Verbose);
  gtk_signal_connect (GTK_OBJECT (MW->Verbose), "activate",
                      GTK_SIGNAL_FUNC (on_verb_activate),
                      NULL);

  MW->Append = gtk_check_menu_item_new_with_label("Append Output");
  gtk_object_set_data (GTK_OBJECT (main_win), "Append", MW->Append);
  gtk_widget_show (MW->Append);
  gtk_container_add (GTK_CONTAINER (menu7), MW->Append);
  gtk_signal_connect (GTK_OBJECT (MW->Append), "activate",
                      GTK_SIGNAL_FUNC (on_Append_activate),
                      NULL);
                      
  machine = gtk_menu_item_new_with_label("Machine Parsable Log");
  gtk_object_set_data (GTK_OBJECT (main_win), "Machine", machine);
  gtk_widget_show (machine);
  gtk_container_add (GTK_CONTAINER (menu7), machine);
  gtk_signal_connect (GTK_OBJECT (machine), "activate",
                      GTK_SIGNAL_FUNC (on_machine_activate),
                      NULL);                   
                      
	/** NEW CODE FOR V1.0 ***************************************************/
	View_Main = gtk_menu_item_new_with_label ("View");
  	gtk_object_set_data (GTK_OBJECT (main_win), "View_Main", View_Main);
  	gtk_widget_show (View_Main);
  	gtk_container_add (GTK_CONTAINER (menubar1), View_Main);
  	gtk_signal_connect (GTK_OBJECT (View_Main), "activate",
                      GTK_SIGNAL_FUNC (on_View_Main_activate),
                      NULL);
	
	view_m = gtk_menu_new();
	gtk_object_set_data(GTK_OBJECT(main_win), "view_m", view_m);
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (View_Main), view_m);

	Trad = gtk_menu_item_new_with_label ("Traditional");
  	gtk_object_set_data (GTK_OBJECT (main_win), "Trad",Trad);
  	gtk_widget_show (Trad);
  	gtk_container_add (GTK_CONTAINER (view_m), Trad);
  	gtk_signal_connect (GTK_OBJECT (Trad), "activate", GTK_SIGNAL_FUNC (on_Trad_activate), NULL);

	CTrad = gtk_menu_item_new_with_label ("Colored Traditional");
  	gtk_object_set_data (GTK_OBJECT (main_win), "CTrad",CTrad);
  	gtk_widget_show (CTrad);
  	gtk_container_add (GTK_CONTAINER (view_m), CTrad);
  	gtk_signal_connect (GTK_OBJECT (CTrad), "activate", GTK_SIGNAL_FUNC (on_CTrad_activate), NULL);

	/**** This doesn't work yet, that's why it's commented out ***      	
	*	Tree = gtk_menu_item_new_with_label ("Tree");
 	* 	gtk_object_set_data (GTK_OBJECT (main_win), "Tree",Tree);
 	*	gtk_widget_show (Tree);
 	* 	gtk_container_add (GTK_CONTAINER (view_m), Tree);
 	* 	gtk_signal_connect (GTK_OBJECT (Tree), "activate", GTK_SIGNAL_FUNC (on_Tree_activate), NULL);
 	**************************************************************/

  	extra = gtk_menu_item_new_with_label ("BETA Options");
  	gtk_object_set_data (GTK_OBJECT (main_win), "EXTRA", extra);
  	gtk_widget_show (extra);
  	gtk_container_add (GTK_CONTAINER (menubar1), extra);

  	extra_menu = gtk_menu_new ();
  	gtk_object_set_data (GTK_OBJECT (main_win), "extra_menu", extra_menu);
  	gtk_menu_item_set_submenu (GTK_MENU_ITEM (extra), extra_menu);

  	MW->rpc = gtk_check_menu_item_new_with_label("RPC Scan (only 2.3BETA4!)");
  	gtk_object_set_data (GTK_OBJECT (main_win), "RPC", MW->rpc);
  	gtk_widget_show (MW->rpc);
  	gtk_container_add (GTK_CONTAINER (extra_menu), MW->rpc);
  	gtk_signal_connect (GTK_OBJECT (MW->rpc), "activate",
  	                    GTK_SIGNAL_FUNC (on_rpc_activate),
  	                    NULL);

	/********END NEW CODE **********************************************/
  Help_Main = gtk_menu_item_new_with_label ("Help");
  gtk_object_set_data (GTK_OBJECT (main_win), "Help_Main", Help_Main);
  gtk_widget_show (Help_Main);
  gtk_container_add (GTK_CONTAINER (menubar1), Help_Main);
  gtk_signal_connect (GTK_OBJECT (Help_Main), "activate",
                      GTK_SIGNAL_FUNC (on_Help_Main_activate),
                      NULL);
  gtk_menu_item_right_justify (GTK_MENU_ITEM (Help_Main));

  menu6 = gtk_menu_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "menu6", menu6);
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (Help_Main), menu6);

  Help = gtk_menu_item_new_with_label ("Help");
  gtk_object_set_data (GTK_OBJECT (main_win), "Help", Help);
  gtk_widget_show (Help);
  gtk_container_add (GTK_CONTAINER (menu6), Help);
  gtk_signal_connect (GTK_OBJECT (Help), "activate",
                      GTK_SIGNAL_FUNC (on_Help_activate),
                      NULL);

  Get_Nmap_Version = gtk_menu_item_new_with_label ("Get Nmap Version");
  gtk_object_set_data (GTK_OBJECT (main_win), "Get_Nmap_Version", Get_Nmap_Version);
  gtk_widget_show (Get_Nmap_Version);
  gtk_container_add (GTK_CONTAINER (menu6), Get_Nmap_Version);
  gtk_signal_connect (GTK_OBJECT (Get_Nmap_Version), "activate",
                      GTK_SIGNAL_FUNC (on_Get_Nmap_Version_activate),
                      NULL);

  separator2 = gtk_menu_item_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "separator2", separator2);
  gtk_widget_show (separator2);
  gtk_container_add (GTK_CONTAINER (menu6), separator2);

  About = gtk_menu_item_new_with_label ("About");
  gtk_object_set_data (GTK_OBJECT (main_win), "About", About);
  gtk_widget_show (About);
  gtk_container_add (GTK_CONTAINER (menu6), About);
  gtk_signal_connect (GTK_OBJECT (About), "activate",
                      GTK_SIGNAL_FUNC (on_About_activate),
                      About);

  vseparator1 = gtk_vseparator_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "vseparator1", vseparator1);
  gtk_widget_show (vseparator1);
  gtk_fixed_put (GTK_FIXED (fixed1), vseparator1, 116, 62);
  gtk_widget_set_usize (vseparator1, 16, 144);

  hseparator1 = gtk_hseparator_new ();
  gtk_object_set_data (GTK_OBJECT (main_win), "hseparator1", hseparator1);
  gtk_widget_show (hseparator1);
  gtk_fixed_put (GTK_FIXED (fixed1), hseparator1, 127, 54);
  gtk_widget_set_usize (hseparator1, 336, 16);

  label3 = gtk_label_new ("General Options:");
  gtk_object_set_data (GTK_OBJECT (main_win), "label3", label3);
  gtk_widget_show (label3);
  gtk_fixed_put (GTK_FIXED (fixed1), label3, 128, 46);
  gtk_widget_set_usize (label3, 344, 16);

  label1 = gtk_label_new ("Host(s):");
  gtk_object_set_data (GTK_OBJECT (main_win), "label1", label1);
  gtk_widget_show (label1);
  gtk_fixed_put (GTK_FIXED (fixed1), label1, 0, 22);
  gtk_widget_set_usize (label1, 64, 17);

  MW->output_label = gtk_label_new ("Output from Nmap:");
  gtk_object_set_data (GTK_OBJECT (main_win), "Output Label", MW->output_label);
  gtk_label_set_justify( GTK_LABEL(MW->output_label), GTK_JUSTIFY_LEFT );
  gtk_widget_show (MW->output_label);
  gtk_fixed_put (GTK_FIXED (fixed1), MW->output_label, 0, 206);
  gtk_widget_set_usize (MW->output_label, 480, 16);
  display_nmap_command();

  return main_win;
}

GtkWidget*
create_about_window ()
{
  GtkWidget *about_window;
  GtkWidget *vbox1;
  GtkWidget *notebook1;
  GtkWidget *text1;
  GtkWidget *text2;
  GtkWidget *label1;
  GtkWidget *label2;
  GtkWidget *hbox1;
  GtkWidget *about_ok;

  about_window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_object_set_data (GTK_OBJECT (about_window), "about_window", about_window);
  gtk_widget_set_usize (about_window, 200, 200);
  gtk_window_set_title (GTK_WINDOW (about_window), "About NmapFE and Nmap");
  gtk_window_set_policy (GTK_WINDOW (about_window), FALSE, FALSE, FALSE);
  gtk_window_position (GTK_WINDOW (about_window), GTK_WIN_POS_CENTER);

  vbox1 = gtk_vbox_new (FALSE, 0);
  gtk_object_set_data (GTK_OBJECT (about_window), "vbox1", vbox1);
  gtk_widget_show (vbox1);
  gtk_container_add (GTK_CONTAINER (about_window), vbox1);

  notebook1 = gtk_notebook_new ();
  gtk_object_set_data (GTK_OBJECT (about_window), "notebook1", notebook1);
  gtk_widget_show (notebook1);
  gtk_box_pack_start (GTK_BOX (vbox1), notebook1, TRUE, TRUE, 0);

  text1 = gtk_text_new (NULL, NULL);
  gtk_object_set_data (GTK_OBJECT (about_window), "text1", text1);
  gtk_widget_show (text1);
  gtk_container_add (GTK_CONTAINER (notebook1), text1);
  gtk_widget_realize (text1);
  gtk_text_insert (GTK_TEXT (text1), NULL, NULL, NULL,
                   "\nAuthor: Zach Smith\nE-mail: key@aye.net\nHTTP: a.linuxbox.com\nWritten in: C/GTK\nGUI was built with Glade:\nhttp://glade.pn.org", 124);

  text2 = gtk_text_new (NULL, NULL);
  gtk_object_set_data (GTK_OBJECT (about_window), "text2", text2);
  gtk_widget_show (text2);
  gtk_container_add (GTK_CONTAINER (notebook1), text2);
  gtk_widget_realize (text2);
  gtk_text_insert (GTK_TEXT (text2), NULL, NULL, NULL,
                   "\n\nAuthor: Fyodor\nEmail: fyodor@insecure.org\nhttp://www.insecure.org/nmap\nWritten in: C", 77);

  label1 = gtk_label_new ("About NmapFE");
  gtk_object_set_data (GTK_OBJECT (about_window), "label1", label1);
  gtk_widget_show (label1);
  set_notebook_tab (notebook1, 0, label1);

  label2 = gtk_label_new ("About Nmap");
  gtk_object_set_data (GTK_OBJECT (about_window), "label2", label2);
  gtk_widget_show (label2);
  set_notebook_tab (notebook1, 1, label2);

  hbox1 = gtk_hbox_new (FALSE, 0);
  gtk_object_set_data (GTK_OBJECT (about_window), "hbox1", hbox1);
  gtk_widget_show (hbox1);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox1, FALSE, TRUE, 0);

  about_ok = gtk_button_new_with_label ("Ok");
  gtk_object_set_data (GTK_OBJECT (about_window), "about_ok", about_ok);
  gtk_widget_show (about_ok);
  gtk_box_pack_start (GTK_BOX (hbox1), about_ok, TRUE, TRUE, 0);
  gtk_signal_connect (GTK_OBJECT (about_ok), "clicked",
                      GTK_SIGNAL_FUNC (on_about_ok_clicked),
                      about_window);

  return about_window;
}

GtkWidget*
create_fileselection1 ()
{
  GtkWidget *fileselection1;
  GtkWidget *ok_button1;
  GtkWidget *cancel_button1;

  fileselection1 = gtk_file_selection_new ("Select File");
  gtk_object_set_data (GTK_OBJECT (fileselection1), "fileselection1", fileselection1);
  gtk_container_border_width (GTK_CONTAINER (fileselection1), 10);
  GTK_WINDOW (fileselection1)->type = GTK_WINDOW_DIALOG;
  gtk_window_set_policy (GTK_WINDOW (fileselection1), TRUE, TRUE, FALSE);

  ok_button1 = GTK_FILE_SELECTION (fileselection1)->ok_button;
  gtk_object_set_data (GTK_OBJECT (fileselection1), "ok_button1", ok_button1);
  gtk_widget_show (ok_button1);
  GTK_WIDGET_SET_FLAGS (ok_button1, GTK_CAN_DEFAULT);
  gtk_signal_connect (GTK_OBJECT (ok_button1), "clicked",
                      GTK_SIGNAL_FUNC (on_ok_button1_clicked),
                      fileselection1);

  cancel_button1 = GTK_FILE_SELECTION (fileselection1)->cancel_button;
  gtk_object_set_data (GTK_OBJECT (fileselection1), "cancel_button1", cancel_button1);
  gtk_widget_show (cancel_button1);
  GTK_WIDGET_SET_FLAGS (cancel_button1, GTK_CAN_DEFAULT);
  gtk_signal_connect (GTK_OBJECT (cancel_button1), "clicked",
                      GTK_SIGNAL_FUNC (on_cancel_button1_clicked),
                      fileselection1);

  return fileselection1;
}

GtkWidget*
create_help_window ()
{
  GtkWidget *help_window;
  GtkWidget *vbox1;
  GtkWidget *notebook1;
  GtkWidget *text1;
  GtkWidget *text2;
  GtkWidget *text3;
  GtkWidget *label1;
  GtkWidget *label2;
  GtkWidget *label3;
  GtkWidget *hbox1;
  GtkWidget *help_ok;

  help_window = gtk_window_new (GTK_WINDOW_DIALOG);
  gtk_object_set_data (GTK_OBJECT (help_window), "help_window", help_window);
  gtk_widget_set_usize (help_window, 400, 300);
  gtk_window_set_title (GTK_WINDOW (help_window), "Help With NmapFE");
  gtk_window_set_policy (GTK_WINDOW (help_window), FALSE, FALSE, FALSE);
  gtk_window_position (GTK_WINDOW (help_window), GTK_WIN_POS_CENTER);

  vbox1 = gtk_vbox_new (FALSE, 0);
  gtk_object_set_data (GTK_OBJECT (help_window), "vbox1", vbox1);
  gtk_widget_show (vbox1);
  gtk_container_add (GTK_CONTAINER (help_window), vbox1);

  notebook1 = gtk_notebook_new ();
  gtk_object_set_data (GTK_OBJECT (help_window), "notebook1", notebook1);
  gtk_widget_show (notebook1);
  gtk_box_pack_start (GTK_BOX (vbox1), notebook1, TRUE, TRUE, 0);

  text1 = gtk_text_new (NULL, NULL);
  gtk_object_set_data (GTK_OBJECT (help_window), "text1", text1);
  gtk_widget_show (text1);
  gtk_container_add (GTK_CONTAINER (notebook1), text1);
  gtk_widget_realize (text1);
  gtk_text_insert (GTK_TEXT (text1), NULL, NULL, NULL,
                   "Starting a scan:\n1) Put the host(s) name(s) of which to scan in the \"Host\" text box.\n2) Pick the scan options you would like\n3) Pick the view you want from the \"View\" menu option.\n4) Click \"Start Scan\"\n\nStopping a Scan:\nAfter clicking \"Start Scan\", the button will remain depressed. \nIf you would like to stop the scan, simply click that button again.\nThe button will pop up, and the scan will be stopped.\n", 406);

  text2 = gtk_text_new (NULL, NULL);
  gtk_object_set_data (GTK_OBJECT (help_window), "text2", text2);
  gtk_widget_show (text2);
  gtk_container_add (GTK_CONTAINER (notebook1), text2);
  gtk_widget_realize (text2);
  gtk_text_insert (GTK_TEXT (text2), NULL, NULL, NULL,
                   "To log a scan in human-readable form:\n1) After finishing a scan, click 'Save Log' from the 'File' menu.\n\nTo re-open a human-readable log:\n1) Click 'Open Log' from the 'File' menu.\n2) If you have color coding enabled, the log will be opened in \ncolor. If not, it will be opened in plain text.\n\nTo log a machine parsable scan:\n1) After finishing a scan, click 'Machine Parsable Log' from the \n'Output' menu.", 405);

  text3 = gtk_text_new (NULL, NULL);
  gtk_object_set_data (GTK_OBJECT (help_window), "text3", text3);
  gtk_widget_show (text3);
  gtk_container_add (GTK_CONTAINER (notebook1), text3);
  gtk_widget_realize (text3);
  gtk_text_insert (GTK_TEXT (text3), NULL, NULL, NULL,
                   "Bold Red - Services that would allow execution of commands \nand/or logging directly into the system. Telnet, FTP, rsh, ssh, \netc... are covered by this. Not *every* single service is covered,\nthe code base would be huge if they were.\n\nBold Blue - Mail services. IMAP, SMTP, POP3, etc... \nOnce again, not all are covered, just the common ones.\n\nBold Black - Services users could get information from.\nfinger, http, X11, etc...\n\nRegular Black - Services I had nothing better to do with :)\n\nIf you have ideas on how to color code more, please let me know:\nkey@aye.net", 564);

  label1 = gtk_label_new ("Scanning");
  gtk_object_set_data (GTK_OBJECT (help_window), "label1", label1);
  gtk_widget_show (label1);
  set_notebook_tab (notebook1, 0, label1);

  label2 = gtk_label_new ("Logging");
  gtk_object_set_data (GTK_OBJECT (help_window), "label2", label2);
  gtk_widget_show (label2);
  set_notebook_tab (notebook1, 1, label2);

  label3 = gtk_label_new ("Colors");
  gtk_object_set_data (GTK_OBJECT (help_window), "label3", label3);
  gtk_widget_show (label3);
  set_notebook_tab (notebook1, 2, label3);

  hbox1 = gtk_hbox_new (FALSE, 0);
  gtk_object_set_data (GTK_OBJECT (help_window), "hbox1", hbox1);
  gtk_widget_show (hbox1);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox1, FALSE, TRUE, 0);

  help_ok = gtk_button_new_with_label ("Ok.");
  gtk_object_set_data (GTK_OBJECT (help_window), "help_ok", help_ok);
  gtk_widget_show (help_ok);
  gtk_box_pack_start (GTK_BOX (hbox1), help_ok, TRUE, TRUE, 0);
  gtk_signal_connect (GTK_OBJECT (help_ok), "clicked",
                      GTK_SIGNAL_FUNC (on_help_ok_clicked),
                      help_window);

  return help_window;
}

GtkWidget*
create_machine_parse_selection ()
{
  GtkWidget *machine_parse_selection;
  GtkWidget *hbox1;
  GtkWidget *label1;

  machine_parse_selection = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_object_set_data (GTK_OBJECT (machine_parse_selection), "machine_parse_selection", machine_parse_selection);
  gtk_window_set_title (GTK_WINDOW (machine_parse_selection), "Machine Parsable Log Selection");
  gtk_window_set_policy (GTK_WINDOW (machine_parse_selection), FALSE, FALSE, FALSE);
  gtk_window_position (GTK_WINDOW (machine_parse_selection), GTK_WIN_POS_CENTER);

  hbox1 = gtk_hbox_new (FALSE, 0);
  gtk_object_set_data (GTK_OBJECT (machine_parse_selection), "hbox1", hbox1);
  gtk_widget_show (hbox1);
  gtk_container_add (GTK_CONTAINER (machine_parse_selection), hbox1);

  label1 = gtk_label_new ("File:");
  gtk_object_set_data (GTK_OBJECT (machine_parse_selection), "label1", label1);
  gtk_widget_show (label1);
  gtk_box_pack_start (GTK_BOX (hbox1), label1, TRUE, TRUE, 0);

  MW->file_entry = gtk_entry_new ();
  gtk_object_set_data (GTK_OBJECT (machine_parse_selection), "file_entry", MW->file_entry);
  gtk_entry_set_text(GTK_ENTRY(MW->file_entry), "parsable.log");
  gtk_widget_show (MW->file_entry);
  gtk_box_pack_start (GTK_BOX (hbox1), MW->file_entry, TRUE, TRUE, 0);
                      
  MW->done = gtk_button_new_with_label ("Done");
  gtk_object_set_data (GTK_OBJECT (machine_parse_selection), "button3", MW->done);
  gtk_widget_show (MW->done);
  gtk_box_pack_start (GTK_BOX (hbox1), MW->done, TRUE, TRUE, 0);
  gtk_container_border_width (GTK_CONTAINER (MW->done), 10);
  gtk_signal_connect (GTK_OBJECT (MW->done), "clicked",
                      GTK_SIGNAL_FUNC (on_done_clicked),
                      machine_parse_selection);
                      
  MW->cancel = gtk_button_new_with_label ("Cancel");
  gtk_object_set_data (GTK_OBJECT (machine_parse_selection), "button3", MW->cancel);
  gtk_widget_show (MW->cancel);
  gtk_box_pack_start (GTK_BOX (hbox1), MW->cancel, TRUE, TRUE, 0);
  gtk_container_border_width (GTK_CONTAINER (MW->cancel), 10);
  gtk_signal_connect (GTK_OBJECT (MW->cancel), "clicked",
                      GTK_SIGNAL_FUNC (on_cancel_clicked),
                      machine_parse_selection); 
  return machine_parse_selection;
}

#endif /* MISSING_GTK */
