/* Author: Zach
 * Mail: key@aye.net
 * IRC: EFNet as zach` or key in #bastards or #neatoelito
 * AIM (Aol): GoldMatrix
 *
 * Change the source as you wish, but leave these comments..
 *
 * Long live Aol and pr: Phreak. <grins>
 */
#if MISSING_GTK
/* Do nothing, nmapfe.c will spit out an error */
#else

#include <gtk/gtk.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "nmapfe.h"
#include "nmapfe_sig.h"

/*This is for our timeout function. */
guint32 time_out = 125; /* 1/8 a second */
gint tag; /*tag for the gdk* funcs */
gpointer *data;
int save_open;
extern struct MyWidgets *MW;
extern int our_uid;
extern int view_type;
int machine_yn = 0;
/* Variables for piping */
int pid;
int pid2;
int pipes[2];
int count = 0;
char buf[9024];
char buf2[9024] = "hello";
int verb = 0;
int append = 0;
int rpc_var = 0;
int ping_h = 0;
int which_scan = 1;
extern char **environ;

int
main (int argc, char *argv[])
{
  GtkWidget *main_win;

  gtk_set_locale ();
  gtk_init (&argc, &argv);

  MW = (struct MyWidgets *) malloc(sizeof(struct MyWidgets));
  bzero(MW, sizeof(struct MyWidgets));
  
  main_win = create_main_win ();
  gtk_widget_show (main_win);

  our_uid = getuid();

  if(our_uid == 0){
    gtk_text_insert(GTK_TEXT(MW->output), NULL, NULL, NULL, "You are root - All options granted.", -1);
  } else {
    gtk_text_insert(GTK_TEXT(MW->output), NULL, NULL, NULL, "You are *NOT* root - Some options aren't available.", -1);
  }


  if(our_uid == 0){
    which_scan = 2;
  } else {
    which_scan = 1;
  }


  gtk_main ();
  return 0;
}

void
on_exit_me_clicked                        (GtkButton       *button,
					   gpointer        user_data)
{
  gtk_main_quit();
}


void
on_start_scan_clicked                  (GtkButton       *button,
                                        GtkWidget        *entry)
{
  func_start_scan();
}

void
on_Close_activate                      (GtkMenuItem    *menuitem,
                                        gpointer        user_data)
{
  gtk_main_quit();
}

void
on_Start_Scan_activate                      (GtkMenuItem    *menuitem,
                                             gpointer        user_data)
{
  gtk_main_quit();
}

void
on_about_ok_clicked                    (GtkButton       *button,
                                        GtkWidget        *about)
{
  gtk_widget_hide(about);
}

void
on_Save_Log_activate                   (GtkMenuItem    *menuitem,
                                        gpointer        user_data)
{
  GtkWidget *save_file;
  save_file = create_fileselection1();
  gtk_widget_show(save_file);
  save_open = 0;
}


void
on_Open_Log_activate                   (GtkMenuItem    *menuitem,
                                        gpointer        user_data)
{
  GtkWidget *open_file;
  open_file = create_fileselection1();
  gtk_widget_show(open_file);
  save_open = 1;
}


void
on_Help_Main_activate                  (GtkMenuItem    *menuitem,
                                        gpointer        user_data)
{

}

void
on_View_Main_activate                  (GtkMenuItem    *menuitem,
                                        gpointer        user_data)
{

}

void
on_Help_activate                       (GtkMenuItem    *menuitem,
                                        GtkWidget        *help)
{
  GtkWidget *help_win;
  help_win = create_help_window();
  gtk_widget_show(help_win);
}


void
on_Get_Nmap_Version_activate           (GtkMenuItem    *menuitem,
                                        gpointer        user_data)
{
  execute("nmap -V");
}


void
on_About_activate                      (GtkMenuItem    *menuitem,
                                        GtkWidget        *about)
{
  GtkWidget *about_win;
  about_win = create_about_window();
  gtk_widget_show(about_win);
}

void
on_ok_button1_clicked                  (GtkButton       *button,
                                        GtkWidget        *window)
{
  char ch[50];
  char *filename, *text_contents, *str, *newstr;
  FILE *file;
  GdkFont *fixed, *bold;
  GdkColormap *cmap;
  GdkColor red, blue, green;
  	  	
  /* Get fonts ready */
  cmap = gdk_colormap_get_system();
  red.red = 0xffff;
  red.green = 0;
  red.blue = 0;	
  if (!gdk_color_alloc(cmap, &red)) {
    g_error("couldn't allocate red");
  }
	  
  blue.red = 0;
  blue.green = 0;
  blue.blue = 0xffff;	
  if (!gdk_color_alloc(cmap, &blue)) {
    g_error("couldn't allocate blue");
  }
  
  green.red = 0x0000;
  green.green = 0xffff;
  green.blue = 0x0000;	
  if (!gdk_color_alloc(cmap, &green)) {
    g_error("couldn't allocate green");
  }
	  
  bold = gdk_font_load("-misc-fixed-bold-r-normal-*-*-120-*-*-*-*-*-*");  
  fixed = gdk_font_load ("-misc-fixed-medium-r-*-*-*-120-*-*-*-*-*-*");
  filename = gtk_file_selection_get_filename(GTK_FILE_SELECTION (window));

  if(save_open == 0) {
    text_contents = gtk_editable_get_chars(GTK_EDITABLE(MW->output), 0, -1);
    if((file = fopen(filename, "w"))){
      fputs(text_contents, file);
      fclose(file);
    }
    free(text_contents);
  } else {
     
    if(!append)
      kill_output(NULL);
	
    gtk_text_freeze(GTK_TEXT(MW->output));
    if((file = fopen(filename, "r"))){
      while(fgets(ch, 50, file) != NULL) {
	str = ch;
	if(view_type == 1){
	  newstr = strtok(str, " ");
	  gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, newstr, -1); 
	  gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	  do {
	    newstr = strtok(NULL, " ");
	    if(newstr != NULL){
	      /********* CATCH STUFF ****************************/
	      if(strstr(newstr, "http://")){
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, "http://", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "fingerprint")){
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, "fingerprint:", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
		/********* BEGIN PORT COLOR CODING ****************/
	      }else if(strstr(newstr, "sftp")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "sftp", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	      }else if(strstr(newstr, "mftp")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "mftp", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	      }else if(strstr(newstr, "bftp")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "bftp", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	      }else if(strstr(newstr, "NetBus")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "NetBus", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	      }else if(strstr(newstr, "kshell")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "kshell", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	      }else if(strstr(newstr, "klogin")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "klogin", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	      }else if(strstr(newstr, "rtelnet")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "rtelnet", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	      }else if(strstr(newstr, "telnet")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "telnet", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "X11")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "X11", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "tftp")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "tftp", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "login")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "login", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "imap2")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "imap2", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "ftp")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "ftp", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "pop-3")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "pop-3", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "exec")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "exec", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "imap3")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "imap3", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);					
	      }else if(strstr(newstr, "smtps")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "smtps", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	      }else if(strstr(newstr, "smtp")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "smtp", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "pop-2")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "pop-2", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "systat")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "systat", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "netstat")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "netstat", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "cfingerd")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "cfingerd", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "finger")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "finger", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "netbios")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "netbios-ssn", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "X11")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "X11", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "nfs")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "nfs", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "sunrpc")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "sunrpc", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "https")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "https", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "kpasswds")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "kpasswd", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);					
	      }else if(strstr(newstr, "http")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, "http", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "ssh")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "ssh", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "shell")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "shell", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	      }else if(strstr(newstr, "linuxconf")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, "linuxconf", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	

				/******* END PORT COLOR CODING, BEGIN OS COLORS *****************/
	      }else if(strstr(newstr, "Linux")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "Linux", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "FreeBSD")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "FreeBSD", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "Win")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "Win", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "MacOS")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "MacOS", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "OpenBSD")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "OpenBSD", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "IRIX")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "IRIX", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }else if(strstr(newstr, "Windows")){
		gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, "Windows", -1);
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
					
	      }else{ 
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, newstr, -1); 
		gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      }
	    }
	  }while(newstr);
	}else if(view_type == 0){			
	  while(fgets(ch, 50, file) != NULL){
	    gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, ch, -1);
	  }
	}
      }
      gtk_text_thaw(GTK_TEXT(MW->output));
      fclose(file);
    } /*end if for file */
  }
  gtk_widget_hide(window);
}


void
on_cancel_button1_clicked              (GtkButton       *button,
                                        GtkWidget        *window)
{
  gtk_widget_hide(window);
}

void func_start_scan()
{
  char *command;

  if(GTK_TOGGLE_BUTTON(MW->start_scan)->active){

    command = build_command(NULL);
	
    /*printf("%s\n", command);*/

    if(!(append))
      kill_output(NULL);

    execute(command);

  } else {
    stop_scan(NULL);
  }
}

void kill_output()
{

  guint length;
  length = gtk_text_get_length(GTK_TEXT(MW->output));
  gtk_text_backward_delete (GTK_TEXT(MW->output), length);
}

int execute(char *command) {
  /* Many thanks to Fyodor for helping with the piping */

  if(pipe(pipes) == -1)
    perror("poopy pipe error");

  if (!(pid = fork())) {
    char *argv[4];

    argv[0] = "sh";
    argv[1] = "-c";
    argv[2] = command;
    argv[3] = 0;
    dup2(pipes[1], 1);
    dup2(pipes[1], 2);
    fcntl(pipes[0], F_SETFL, O_NDELAY);
    execve("/bin/sh", argv, environ);
    /*exit(127);*/
  }
  close(pipes[1]);
  tag = gtk_timeout_add(time_out, read_data, data);

  return(pid);
}

char *build_command() {

  int size;
  static char *command = NULL;
  static int command_size = 0;
  char *val = NULL;
  /* Find how much to malloc() */
  size = 	strlen(gtk_entry_get_text(GTK_ENTRY(MW->range_text))) +
    strlen(gtk_entry_get_text(GTK_ENTRY(MW->decoy_text))) +
    strlen(gtk_entry_get_text(GTK_ENTRY(MW->input_text))) +
    strlen(gtk_entry_get_text(GTK_ENTRY(MW->device_text)))+
    strlen(gtk_entry_get_text(GTK_ENTRY(MW->bounce_text)))+
    strlen(gtk_entry_get_text(GTK_ENTRY(MW->host_text))) +
    60;
  /* We get 60 from the chars required for each option */

  if (size > command_size)
    command = realloc(command, size);

  strcpy(command, "nmap ");
  /*Uhm... yeah.. Spit out which scan to perform based
    on the which_scan variable */
 
  if (GTK_TOGGLE_BUTTON(MW->connect_scan)->active) {
    strncat(command, "-sT ", 4);
  } else if (GTK_TOGGLE_BUTTON(MW->ping_scan)->active) {
    strncat(command, "-sP ", 4);
  } else if (GTK_TOGGLE_BUTTON(MW->udp_scan)->active) {
    strncat(command, "-sU ", 4);
  } else if (GTK_TOGGLE_BUTTON(MW->fin_scan)->active) {
    strncat(command, "-sF ", 4);
  } else if (GTK_TOGGLE_BUTTON(MW->syn_scan)->active) {
    strncat(command, "-sS ", 4);
  }
 
  if (rpc_var)
    strncat(command, " -sR ", 5);
   
  if (GTK_TOGGLE_BUTTON(MW->fast_check)->active)
    strncat(command, " -F ", 4);
 
  if (GTK_TOGGLE_BUTTON(MW->range_check)->active) {
    val = gtk_entry_get_text(GTK_ENTRY(MW->range_text));
    if (val && *val) {   
      strncat(command, " -p ", 4);
      strcat(command, val);
      strncat(command, " ", 1);
    }
  }

  if(machine_yn){
    val = MW->machine_file;
    strncat(command, " -m ", 4);
    strcat(command, val);
    strncat(command, " ", 1);
  }

  if (GTK_TOGGLE_BUTTON(MW->bounce_check)->active){
    val = gtk_entry_get_text(GTK_ENTRY(MW->bounce_text));
    if (val && *val) {   
      strncat(command, " -b ", 4);
      strcat(command, val);
      strncat(command, " ", 1);
    }
  }

  if (GTK_TOGGLE_BUTTON(MW->tcp_check)->active)
    strncat(command, "-PT ", 4);
  if (GTK_TOGGLE_BUTTON(MW->fingerprinting_check)->active)
    strncat(command, "-O ", 4);
  if (GTK_TOGGLE_BUTTON(MW->icmp_check)->active)
    strncat(command, "-PI ", 4);
  if (GTK_TOGGLE_BUTTON(MW->ping_check)->active)
    strncat(command, "-P0 ", 4);
  if (GTK_TOGGLE_BUTTON(MW->fragment_check)->active)
    strncat(command, "-f ", 3);
  if (GTK_TOGGLE_BUTTON(MW->identd_check)->active)
    strncat(command, "-I ", 3);
  if (GTK_TOGGLE_BUTTON(MW->resolveall_check)->active)
    strncat(command, "-R ", 3);
  if (GTK_TOGGLE_BUTTON(MW->resolve_check)->active)
    strncat(command, "-n ", 3);		
  if (GTK_TOGGLE_BUTTON(MW->decoy_check)->active) {
    val = gtk_entry_get_text(GTK_ENTRY(MW->decoy_text));
    if (val && *val) {   
      strncat(command, "-D", 2);
      strcat(command, val);
      strncat(command, " ", 1);
    }
  }

  if (GTK_TOGGLE_BUTTON(MW->input_check)->active) {
    val = gtk_entry_get_text(GTK_ENTRY(MW->input_text));
    if (val && *val) {   
      strncat(command, "-i ", 3);
      strcat(command, val);
      strncat(command, " ", 1);
    }
  }

  if (GTK_TOGGLE_BUTTON(MW->device_check)->active){
    val = gtk_entry_get_text(GTK_ENTRY(MW->device_text));
    if (val && *val) {   
      strncat(command, "-e ", 3);
      strcat(command, val);
      strncat(command, " ", 1);
    }
  }
 
  if (verb){
    strcat(command, "-v ");
  }

  strcat(command, gtk_entry_get_text(GTK_ENTRY(MW->host_text)));

  return(command);
}

void display_nmap_command() {
  char buf[80];
  int len;

  len = snprintf(buf, sizeof(buf), "Output from:  %s", build_command());
  if (len < 0 || len >= sizeof(buf)) {
    strcpy(buf, "Output from Nmap");
  }
  gtk_label_set( GTK_LABEL(MW->output_label), buf);
}



void entry_toggle_checkbox (GtkWidget *entry,
			    GtkWidget *checkbox)
{
  char *txt = gtk_entry_get_text(GTK_ENTRY(entry));
  if (!txt || !*txt)
    return;
  gtk_toggle_button_set_state (GTK_TOGGLE_BUTTON (checkbox), TRUE);
  display_nmap_command();
}

void display_nmap_command_callback(GtkWidget *target_option, char *ignored) {
  display_nmap_command();
  return;
}

void validate_option_change(GtkWidget *target_option, char *ignored)
{	

  if (GTK_TOGGLE_BUTTON(target_option)->active)  {
    if (target_option == MW->connect_scan) {
      gtk_entry_set_text( GTK_ENTRY(MW->decoy_text), "");
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->decoy_check), FALSE);
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->fragment_check), FALSE);
      gtk_entry_set_text( GTK_ENTRY(MW->device_text), "");
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->device_check), FALSE);
    } else if (target_option == MW->syn_scan || target_option == MW->fin_scan) {
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->identd_check), FALSE);
    } else if (target_option == MW->udp_scan) {
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->identd_check), FALSE);
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->fragment_check), FALSE);
    } else if (target_option == MW->bounce_check) {
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->identd_check), FALSE);
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->fragment_check), FALSE);
      gtk_entry_set_text( GTK_ENTRY(MW->device_text), "");
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->device_check), FALSE);
      gtk_entry_set_text( GTK_ENTRY(MW->decoy_text), "");
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->decoy_check), FALSE);
    } else if (target_option == MW->ping_scan) {
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->identd_check), FALSE);
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->fragment_check), FALSE);
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->fast_check), FALSE);
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->range_check), FALSE);
      gtk_entry_set_text( GTK_ENTRY(MW->range_text), "");
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->fingerprinting_check), FALSE);
    } else if (target_option == MW->fast_check) {
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->range_check), FALSE);
      gtk_entry_set_text( GTK_ENTRY(MW->range_text), "");
    } else if (target_option == MW->range_check) {
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->fast_check), FALSE);
    } else if (target_option == MW->identd_check) {
      gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->connect_scan), TRUE);
      validate_option_change(MW->connect_scan, NULL);
    } else if (target_option == MW->decoy_check ||
	       target_option == MW->device_check ||
	       target_option == MW->fragment_check ) {
      if (GTK_TOGGLE_BUTTON(MW->connect_scan)->active) {
	gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->syn_scan), TRUE);      
	validate_option_change(MW->syn_scan, NULL); 
      } else if (GTK_TOGGLE_BUTTON(MW->bounce_check)->active) {
	gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->syn_scan), TRUE);
	gtk_entry_set_text( GTK_ENTRY(MW->bounce_text), "");
	validate_option_change(MW->syn_scan, NULL);
      } 
    } else if (target_option == MW->input_check) {
      gtk_entry_set_text( GTK_ENTRY(MW->host_text), "");
    }
  }
  display_nmap_command();
}



void scan_options(GtkWidget *widget, int *the_option)
{
  which_scan = (int)the_option;
}

gint read_data(gpointer data)
{
  char *str;
  char *newstr;	
  char *tmpstr;
  GdkFont *fixed;
  GdkFont *bold;
  GdkColormap *cmap;
  GdkColor red, blue, green;
  	  	
  /* Get fonts ready */
  cmap = gdk_colormap_get_system();
  red.red = 0xffff;
  red.green = 0;
  red.blue = 0;	
  if (!gdk_color_alloc(cmap, &red)) {
    g_error("couldn't allocate red");
  }
  
  blue.red = 0;
  blue.green = 0;
  blue.blue = 0xffff;	
  if (!gdk_color_alloc(cmap, &blue)) {
    g_error("couldn't allocate blue");
  }
  
  green.red = 0x0000;
  green.green = 0xffff;
  green.blue = 0x0000;	
  if (!gdk_color_alloc(cmap, &green)) {
    g_error("couldn't allocate green");
  }  
  
  
  fixed = gdk_font_load ("-misc-fixed-medium-r-*-*-*-120-*-*-*-*-*-*");
  bold = gdk_font_load("-misc-fixed-bold-r-normal-*-*-120-*-*-*-*-*-*");

  if((count = read(pipes[0], buf, sizeof(buf)-1))) {
    buf[count] = '\0';
    if((strcmp(buf, buf2)) == 0){
      return(1);
    } else {
      if(view_type == 1){
	str = buf;
	newstr = strtok(str, " ");
	if(newstr) gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, newstr, -1); 
	gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	do{
 	  tmpstr = newstr;
	  newstr = strtok(NULL, " ");
      if(tmpstr) tmpstr += strlen(tmpstr)+1; /* position on the start of next token */
	  while(tmpstr && (tmpstr++)[0] == 0x20) /* print the leading spaces */
	  	gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);

	  if(newstr != NULL){
	    /********* CATCH STUFF ****************************/
		if(newstr[0] == '('){
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, newstr, -1); 
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "http://")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "fingerprint")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	      /********* BEGIN PORT COLOR CODING ****************/
	    }else if(strstr(newstr, "sftp")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	    }else if(strstr(newstr, "mftp")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	    }else if(strstr(newstr, "bftp")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	    }else if(strstr(newstr, "NetBus")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	    }else if(strstr(newstr, "kshell")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	    }else if(strstr(newstr, "klogin")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	    }else if(strstr(newstr, "rtelnet")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	    }else if(strstr(newstr, "telnet")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "X11")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "tftp")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "login")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "imap2")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "ftp")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "pop-3")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "exec")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "imap3")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);					
	    }else if(strstr(newstr, "smtps")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);			
	    }else if(strstr(newstr, "smtp")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "pop-2")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "systat")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "netstat")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "cfingerd")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "finger")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "netbios")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "X11")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "nfs")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "sunrpc")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "https")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "kpasswds")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);					
	    }else if(strstr(newstr, "http")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, NULL, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "ssh")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "shell")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	
	    }else if(strstr(newstr, "linuxconf")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &red, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);	

				/******* END PORT COLOR CODING, BEGIN OS COLORS *****************/		
	    }else if(strstr(newstr, "Linux")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "FreeBSD")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "Win")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "MacOS")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "OpenBSD")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "IRIX")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }else if(strstr(newstr, "Windows")){
	      gtk_text_insert(GTK_TEXT(MW->output), bold, &blue, NULL, newstr, -1);
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
					
	    }else{ 
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, newstr, -1); 
	      gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, " ", -1);
	    }
	  }
	}while(newstr);
      } /* END VIEW_TYPE == 1 IF */
		
      if(view_type == 0){
	gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, buf, -1);
      }
      /* END VIEW_TYPE == 0 IF */
		 
      if(view_type == 2) {
	build_tree(buf);
      }
		
      strcpy(buf2, buf);
      waitpid(0, NULL, WNOHANG);
    } /*end if*/
  } else {
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->start_scan), 0);
    return(0);
  }/* end if */

  return(1);	
}

void stop_scan()
{
  kill(pid, 1);
}

void
on_verb_activate			(GtkMenuItem	*menuitem,
					 gpointer	user_data)
{
  if(verb){
    verb = 0;
  } else {
    verb = 1;
  }
  display_nmap_command();
}

void
on_Append_activate			(GtkMenuItem	*menuitem,
					 gpointer	user_data)
{
  if(append){
    append = 0;
  } else {
    append = 1;
  }	
}

void
on_rpc_activate			(GtkMenuItem	*menuitem,
				 gpointer	user_data)
{
  if(rpc_var){
    rpc_var = 0;
  } else {
    rpc_var = 1;
  }	
  display_nmap_command();
}

void on_Trad_activate	(GtkMenuItem *menuitem, GtkWidget *trad)
{
  view_type = 0;
}

void on_CTrad_activate	(GtkMenuItem *menuitem, GtkWidget *ctrad)
{
  view_type = 1;
}

void on_Tree_activate	(GtkMenuItem *menuitem, GtkWidget *tree)
{
  view_type = 2;
}

void build_tree(char *buf)
{
  /******************************* THIS IS BROKE RIGHT NOW :) *************************
				   char *str, *token;
				   GdkFont *fixed;
				   fixed = gdk_font_load ("-misc-fixed-medium-r-*-*-*-120-*-*-*-*-*-*");
	
				   str = buf;
				   token = strtok(str, " ");
	
				   do{
				   token = strtok(NULL, " ");
	
				   if(strstr(token, "Service")){
				   printf("Wh00p!");
				   token = strtok(NULL, " \t");
				   printf("%s", token);		
				   token = strtok(NULL, " \t");
				   printf("%s", token);
				   printf("That's three\n");
				   }
		
				   gtk_text_freeze(GTK_TEXT(MW->output));
				   gtk_text_insert(GTK_TEXT(MW->output), fixed, NULL, NULL, "hello", -1);
		
				   }while(token);
	
				   gtk_text_thaw(GTK_TEXT(MW->output));
  *****************************************************************************************/
}

void on_done_clicked(GtkButton *button, GtkWidget *widget)
{
  MW->machine_file = gtk_entry_get_text(GTK_ENTRY(MW->file_entry));
  machine_yn = 1;
  gtk_widget_hide(widget);
  display_nmap_command();
}

void on_cancel_clicked(GtkButton *button, GtkWidget *widget)
{
  machine_yn = 0;
  gtk_widget_hide(widget);
}

void on_machine_activate()
{     
  GtkWidget *save_file;
  save_file = create_machine_parse_selection();
  gtk_widget_show(save_file);
}

void on_help_ok_clicked(GtkButton *button, GtkWidget	*help)
{
  gtk_widget_destroy(help);
}
/***************************************************************/

#endif /* MISSING_GTK */
