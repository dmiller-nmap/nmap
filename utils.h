#ifndef UTILS_H
#define UTILS_H
#include <stdio.h>
#include <stdlib.h>
#if MISSING_USLEEP
#include <time.h>
#endif
#include "error.h"

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

#define TIMEVAL_SUBTRACT(a,b) (((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec)

void *safe_malloc(int size);
void hdump(unsigned char *packet, int len);

#if MISSING_USLEEP
void usleep(unsigned long usec);
#endif

#endif
