#include <stdio.h>

#include "error.h"
#include "charpool.h"

#define SNPRINTF_BUFSIZE 8192

int snprintf ( char *str, size_t n, const char *format, ... ) {
static char *buf = NULL;
static int warning = 0;
int len;
va_list ap;
int res = 0;

va_start(ap, format);

if (!warning) {
  error("WARNING:  your system apparently does not offer snprintf().  Reverting to less secure version");
  warning = 1;
}

if (!buf) {
  buf = (char *) cp_alloc(SNPRINTF_BUFSIZE);
}

#ifndef SPRINTF_RETURNS_STRING
res = vsprintf(buf, format, ap);
if (res >= SNPRINTF_BUFSIZE || res < 0) {
  fatal("Our bufferZ may have been overfl0wed!!@#$!@#");
}
#else
res = 4; /* avoid compiler warnings */
vsprintf(buf, format, ap);  /* Oh well -- at least they were warned */
#endif
len = strlen(buf);
if (len >= SNPRINTF_BUFSIZE)
  fatal("Our bufferZ may have been overfl0wed!!@#$!@#");


Strncpy(str, buf, n);
va_end (ap);
if (len >= n) return -1;
return len;
}
