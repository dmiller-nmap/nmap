#ifndef UTILS_H
#define UTILS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>
#if MISSING_USLEEP
#include <time.h>
#endif
#include "error.h"
#include "config.h"

#ifndef MAX
#define MAX(x,y) (((x)>(y))?(x):(y))
#endif
#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif
#ifndef ABS
#define ABS(x) (((x) >= 0)?(x):(-x)) 
#endif
#ifndef MOD_DIFF
#define MOD_DIFF(a,b) (unsigned long) (MIN((unsigned long)(a) - (unsigned long ) (b), (unsigned long )(b) - (unsigned long) (a)))
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define NIPQUAD(addr) \
        (((addr) >> 0)  & 0xff), \
        (((addr) >> 8)  & 0xff), \
        (((addr) >> 16) & 0xff), \
        (((addr) >> 24) & 0xff)

#define TIMEVAL_SUBTRACT(a,b) (((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec)

void *safe_malloc(int size);
char *strcasestr(char *haystack, char *pneedle);
void hdump(unsigned char *packet, int len);
void lamont_hdump(unsigned char *bp, int length);
void Strncpy(char *dest, const char *src, size_t n);
#ifndef HAVE_USLEEP
#ifdef HAVE_NANOSLEEP
void usleep(unsigned long usec);
#endif
#endif

#endif

