#include "error.h"

void fatal(char *fmt, ...) {
va_list  ap;
va_start(ap, fmt);
fflush(stdout);
vfprintf(stderr, fmt, ap);
fprintf(stderr, "\nQUITTING!\n");
va_end(ap);
exit(1);
}

void error(char *fmt, ...) {
va_list  ap;
va_start(ap, fmt);
fflush(stdout);
vfprintf(stderr, fmt, ap);
fprintf(stderr, "\n");
va_end(ap);
return;
}


void pfatal(char *err) {
  perror(err);
  fprintf(stderr, "\n");
  exit(1);
}

