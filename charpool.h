#ifndef CHARPOOL_H
#define CHARPOOL_H

#include "utils.h"
#include "error.h"

void *cp_alloc(int sz);
char *cp_strdup(const char *src);
#endif
