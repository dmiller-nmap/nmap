/* Author: Zach
 * Mail: key@aye.net
 * IRC: EFNet as zach` or key in #bastards or #neatoelito
 * AIM (Aol): GoldMatrix
 *
 * Change the source as you wish, but leave these comments..
 *
 * Long live Aol and pr: Phreak.  :-)
 */
#if MISSING_GTK
#error "Your system does not appear to have GTK (www.gtk.org) installed.  Thus the Nmap X Front End will not compile.  You should still be able to use Nmap the normal way (via text console).  GUIs are for wimps anyway :)"
#endif


#include <gtk/gtk.h>
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
