
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
 * Long live Aol and pr: Phreak. <grins>
 */

#ifndef MAX_PARSE_ARGS
#define MAX_PARSE_ARGS 512
#endif

#if MISSING_GTK
/* Do nothing, nmapfe.c will spit out an error */
#else

#include <nbase.h>

#include <gtk/gtk.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <fcntl.h>
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>


#ifdef WIN32
#include <windows.h>
#endif

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
/* FIXME: All this should be redone in a much more elegant manner <sigh> */
int nmap_pid = 0;
#ifdef WIN32
HANDLE NmapHandle;
#endif
int pid;
int pid2;
#ifdef WIN32
HANDLE pipes[2]; /* 0 == read; 1 == write */
#else
int pipes[2] = {-1,-1};
#endif
int count = 0;
char buf[9024] = "hello";
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

#ifndef WIN32
  signal(SIGPIPE, SIG_IGN);
  our_uid = getuid();
#else
  our_uid = 0; /* With Windows (in general), ever user is a Super User! */
#endif
  main_win = create_main_win ();
  gtk_widget_show (main_win);


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
  /* First we want to kill the Nmap process that is running */
  stop_scan();
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
	  
  bold = gdk_fontset_load("-misc-fixed-bold-r-normal-*-*-120-*-*-*-*-*-*");  
  fixed = gdk_fontset_load ("-misc-fixed-medium-r-*-*-*-120-*-*-*-*-*-*");
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
  /*  fprintf(stderr, "start_scan called\n"); */
  if(GTK_TOGGLE_BUTTON(MW->start_scan)->active){

    command = build_command(NULL);
	
    /*printf("%s\n", command);*/

    if(!(append))
      kill_output(NULL);

    nmap_pid = execute(command);

  } else {
    stop_scan();
  }
}

void kill_output()
{

  guint length;
  length = gtk_text_get_length(GTK_TEXT(MW->output));
  gtk_text_backward_delete (GTK_TEXT(MW->output), length);
}

/* The idea of execute() is to create an Nmap process running in the background with its stdout
    connected to a pipe we can poll many times per second to collect any new output.  Admittedly 
	there are much more elegant ways to do this, but this is how it works now.  The functions
	return the process ID of nmap.  This process is
	different enough between windows & UNIX that I have two functions for doing it: */
int execute_unix(char *command);
int execute_win(char *command);
int execute(char *command) {
   int pid;
#ifdef WIN32
    pid = execute_win(command);
#else
	pid = execute_unix(command);
#endif /* WIN32 */

	/* Add a timer for calling our read function to poll for new data */
   tag = gtk_timeout_add(time_out, read_data, data);

  return(pid);
}

int execute_unix(char *command) {
#ifdef WIN32
	fatal("The execute_unix function should not be called from Windows!");
	return -1;
#else
  /* Many thanks to Fyodor for helping with the piping */
	if(pipe(pipes) == -1) {
    perror("poopy pipe error");
		exit(1);
	}

  if (!(pid = fork())) {
    char **argv;
    int argc;

    argc = arg_parse(command, &argv);
		
    if (argc <= 0)
      exit(1);
    dup2(pipes[1], 1);
    dup2(pipes[1], 2);
    fcntl(pipes[0], F_SETFL, O_NDELAY);
    if (execvp("nmap", argv) == -1) {
      fprintf(stderr, "Nmap execution failed.  errno=%d (%s)\n", errno, strerror(errno));
      exit(1);
    }
    /*exit(127);*/
  }
  if (pid == -1) {
    fprintf(stderr, "fork() failed.  errno=%d (%s)", errno, strerror(errno));
    pid = 0;
    close(pipes[0]);
    pipes[0] = -1;
  }
  close(pipes[1]);
  pipes[1] = -1;

  return(pid);
#endif /* WIN32 exclusion */
}

/* Parts cribbed from _Win32 System Programming Second Edition_ pp 304 */
int execute_win(char *command) {
#ifndef WIN32
	fatal("The execute_win function should ONLY be called from Windows!");
	return -1;
#else
/* For pipes[] array:  0 == READ; 1 == WRITE */

	/* To ensure pipe handles are inheritable */
	SECURITY_ATTRIBUTES PipeSA = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	PROCESS_INFORMATION Nmap_Proc;
	STARTUPINFO Nmap_Start;

	GetStartupInfo(&Nmap_Start);

	/* Create our pipe for reading Nmap output */
	if (!CreatePipe(&pipes[0], &pipes[1], &PipeSA, 8196)) {
		pfatal("execute_win: Failed to create pipes!");
	}

	/* Insure that stdout/stderr for Nmap will go to our pipe */
	Nmap_Start.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	Nmap_Start.hStdError = pipes[1];
	Nmap_Start.hStdOutput = pipes[1];
	Nmap_Start.dwFlags = STARTF_USESTDHANDLES;

	/* Start up Nmap! */
	if (!CreateProcess ( NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &Nmap_Start,
		&Nmap_Proc)) {
		pfatal("execute_win: Failed to start Nmap process with command '%s'", command);
	}

     /* I don't care about the thread handle or the write pipe anymore */
	 CloseHandle(Nmap_Proc.hThread);
     CloseHandle(pipes[1]);

	 /* I'm gonna squirrel away the Nmap process handle in a global variable.  All this nonsense
	    needs to be redone */
     NmapHandle = Nmap_Proc.hProcess;

	 return Nmap_Proc.dwProcessId;

#endif /* UNIX Exclusion */
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
  char *p;

  /* Need to use the snprintf which comes with nmap ... */
  strcpy(buf, "Output from: ");
  p = build_command();
  if (strlen(p) < (sizeof(buf) - strlen(buf) - 2))
    strcat(buf, p);
  else {
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


/* The read_from_pipe functions (UNIX & Win versions) do a non-blocking read from the pipe
   given into the buffer given up to a maximum read length of bufsz.  The number of bytes 
   read is returned.  -1 is returned in the case of heinous error.  Returned buffer is NOT
   NUL terminated */
#ifdef WIN32

static int read_from_pipe(HANDLE pipe, char *buf, int bufsz) {
	int ret;
	int count = 0;
	/* First lets check if anything is ready for us (Note: I don't know if this technique
	even works! */
	ret = WaitForSingleObject(pipe, 0);
	if ( ret == WAIT_OBJECT_0 ) {
		/* Apparently the pipe is available for reading -- Read up to # of bytes in buffer */
		if (!ReadFile(pipe, buf, bufsz, &count, NULL)) {
			if (GetLastError() != ERROR_BROKEN_PIPE)
				pfatal("ReadFile on Nmap process pipe failed!");
		}
	}
	return count;
}

#else
/* NOTE:  pipefd must be in O_NONBLOCK mode ( via fcntl ) */
static int read_from_pipe(int pipefd, char *buf, int bufsz) {
	int count;

	if (pipefd == -1) return -1;
	count = read(pipefd, buf, bufsz);
	if (count == -1 && errno != EINTR && errno != EAGAIN) {
		pfatal("Failed to read from nmap process pipe");
	}
	return count;
}
#endif /* read_from_pipe Win32/UNIX selector */


gint read_data(gpointer data)
{
  char *str;
  char *newstr;	
  char *tmpstr;
  GdkFont *fixed;
  GdkFont *bold;
  GdkColormap *cmap;
  GdkColor red, blue, green;
#ifdef WIN32
  int rc;
  char *p=NULL, *q=NULL;
#endif /* WIN32 */
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
  
  
  fixed = gdk_fontset_load ("-misc-fixed-medium-r-*-*-*-120-*-*-*-*-*-*");
  bold = gdk_fontset_load("-misc-fixed-bold-r-normal-*-*-120-*-*-*-*-*-*");


  while((count = read_from_pipe(pipes[0], buf, sizeof(buf) - 1 )) > 0) {
    /*    fprintf(stderr, "Count was %d\n", count); */
    buf[count] = '\0';
#ifdef WIN32
/* For windows, I have to squeeze \r\n back into \n */
p = q = buf;
while(*q) { if (*q == '\r') q++; else *p++ = *q++; }
*p = '\0';
#endif /* WIN32 */
    if((strcmp(buf, buf2)) == 0) {
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
		
    } /*end if*/
  } 

  /*  fprintf(stderr, "Below loop: Count was %d\n", count); */

#ifdef WIN32
  if (nmap_pid) {
	rc = WaitForSingleObject(NmapHandle, 0);
	if (rc == WAIT_FAILED) {
		pfatal("Failed in WaitForSingleObject to see if Nmap process has died");
	}
  }
  if (!nmap_pid || rc == WAIT_OBJECT_0) {
	  CloseHandle(NmapHandle);
	  CloseHandle(pipes[0]);
	  nmap_pid = 0;
	  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->start_scan), 0);
	  return 0;
  }

#else
  if (!nmap_pid || (waitpid(0, NULL, WNOHANG) == nmap_pid)) {
    /*    fprintf(stderr, "Program gone, dead, kablooey!\n"); */
    nmap_pid = 0;
	if (pipes[0] != -1) { close(pipes[0]); pipes[0] = -1; }
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(MW->start_scan), 0);
    return 0;
  }
#endif /* waitpid unix/windoze selector */

  return(1);	
}

void stop_scan()
{
  /*  fprintf(stderr, "stop scan called -- pid == %d\n", nmap_pid); */
	if (nmap_pid) {
#ifdef WIN32
		TerminateProcess(NmapHandle, 1);
		CloseHandle(NmapHandle);
		CloseHandle(pipes[0]);
#else
    kill(nmap_pid, 9);
  if (pipes[0] != -1) {
    close(pipes[0]);
    pipes[0] = -1;
  }
#endif /* Win32/UNIX Selector for killing Nmap */
		nmap_pid = 0;
	}
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
				   fixed = gdk_fontset_load ("-misc-fixed-medium-r-*-*-*-120-*-*-*-*-*-*");
	
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

void
on_delete_event (GtkWidget *widget, GdkEvent *event, gpointer data)
{
  /* First we want to kill the Nmap process that is running */
  stop_scan();
  gtk_main_quit ();
}


/***************************************************************/

/* This function takes a command and the address of an uninitialized
   char ** .  It parses the command (by seperating out whitespace)
   into an argv[] style char **, which it sets the argv parameter to.
   The function returns the number of items filled up in the array
   (argc), or -1 in the case of an error.  This function allocates
   memmory for argv and thus it must be freed -- use argv_parse_free()
   for that.  If arg_parse returns <1, then argv does not need to be freed.
   The returned arrays are always terminated with a NULL pointer */
int arg_parse(const char *command, char ***argv) {
  char **myargv = NULL;
  int argc = 0;
  char mycommand[4096];
  unsigned char *start, *end;
  char oldend;

  *argv = NULL;
  if (Strncpy(mycommand, command, 4096) == -1) {      
    return -1;
  }
  myargv = malloc((MAX_PARSE_ARGS + 2) * sizeof(char *));
  bzero(myargv, (MAX_PARSE_ARGS+2) * sizeof(char *));
  myargv[0] = (char *) 0x123456; /* Integrity checker */
  myargv++;
  start = mycommand;
  while(start && *start) {
    while(*start && isspace(*start))
      start++;
    if (*start == '"') {
      start++;
      end = strchr(start, '"');
    } else if (*start == '\'') {
      start++;
      end = strchr(start, '\'');      
    } else if (!*start) {
      continue;
    } else {
      end = start+1;
      while(*end && !isspace(*end)) {      
	end++;
      }
    }
    if (!end) {
      arg_parse_free(myargv);
      return -1;
    }
    if (argc >= MAX_PARSE_ARGS) {
      arg_parse_free(myargv);
      return -1;
    }
    oldend = *end;
    *end = '\0';
    myargv[argc++] = strdup(start);
    if (oldend)
      start = end + 1;
    else start = end;
  }
  myargv[argc+1] = 0;
  *argv = myargv;
  return argc;
}

/* Free an argv allocated inside arg_parse */
void arg_parse_free(char **argv) {
  char **current;
  /* Integrity check */
  argv--;
  assert(argv[0] == (char *) 0x123456);
  current = argv + 1;
  while(*current) {
    free(*current);
    current++;
  }
  free(argv);
}



#endif /* MISSING_GTK */
