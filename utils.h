#ifndef UTILS_H
#define UTILS_H
#include <stdio.h>
#include <stdlib.h>
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
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define TIMEVAL_SUBTRACT(a,b) ((a.tv_sec - b.tv_sec) * 1e6 + a.tv_usec - b.tv_usec)

void *safe_malloc(int size);
void hdump(unsigned char *packet, int len);

#endif
