
CC=gcc
INCLUDE_FLAGS= -I.. -I../nbase -I../libpcap-possiblymodified
LINK_FLAGS=-L.. -L../nbase -L../libpcap-possiblymodified
NMAP_OBJS=../osscan.o ../nmap_error.o ../utils.o ../tcpip.o ../output.o ../nmap.o ../scan_engine.o ../portlist.o ../timing.o ../nmap_rpc.o ../charpool.o ../services.o ../targets.o ../idle_scan.o ../protocols.o
DEFINES=-DHAVE_CONFIG_H=1

all: fingermatch

dummy:

fingermatch: fingermatch.c dummy
	$(CC) -Wall $(INCLUDE_FLAGS) $(LINK_FLAGS) $(DEFINES) -o $@ $@.c $(NMAP_OBJS) -lm -lnbase -lpcap