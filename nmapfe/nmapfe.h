/* Author: Zach
 * Mail: key@aye.net
 * IRC: EFNet as zach` or key in #bastards or #neatoelito
 * AIM (Aol): GoldMatrix
 *
 * Change the source as you wish, but leave these comments..
 *
 * Long live Aol and pr: Phreak. <grins>
 */

#include <gtk/gtk.h>

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
