#ifndef ERROR_H
#define ERROR_H
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

void fatal(char *fmt, ...);
void error(char *fmt, ...);
void pfatal(char *err);
#endif /* ERROR_H */

