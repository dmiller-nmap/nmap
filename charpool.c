#include "charpool.h"

static char *charpool[16];
static int currentcharpool;
static int currentcharpoolsz;
static char *nextchar;
static int charpool_initialized = 0;

#define ALIGN_ON sizeof(char *)

static int cp_init(void) {
  /* Create our char pool */
  currentcharpool = 0;
  currentcharpoolsz = 16384;
  nextchar = charpool[0] = (char *) safe_malloc(currentcharpoolsz);
  charpool_initialized = 1;
  return 0;
}

static inline void cp_grow(void) {
  /* Doh!  We've got to make room */
  if (++currentcharpool > 15) {
    fatal("Character Pool is out of buckets!");
  }
  currentcharpoolsz <<= 1;

  nextchar = charpool[currentcharpool] = (char *)
    safe_malloc(currentcharpoolsz);
}

static inline void cp_align(void) {
  int res;
  if ((res = (nextchar - charpool[currentcharpool]) % ALIGN_ON)) {
    nextchar += ALIGN_ON - res;
  }
  return;
}

void *cp_alloc(int sz) {
  char *p;
  int modulus;

  if (!charpool_initialized) cp_init();

  if ((modulus = sz % ALIGN_ON))
    sz += modulus;
  
  if ((nextchar - charpool[currentcharpool]) + sz <= currentcharpoolsz) {
    p = nextchar;
    nextchar += sz;
    return p;
  }
  /* Doh!  We've got to make room */
  cp_grow();

 return cp_alloc(sz);
 
}

char *cp_strdup(const char *src) {
const char *p;
char *q;
/* end points to the first illegal char */
char *end;
int modulus;

 if (!charpool_initialized) 
   cp_init();

 end = charpool[currentcharpool] + currentcharpoolsz;
 q = nextchar;
 p = src;
 while((nextchar < end) && *p) {
   *nextchar++ = *p++;
 }

 if (nextchar < end) {
   /* Goody, we have space */
   *nextchar++ = '\0';
   if ((modulus = (nextchar - q) % ALIGN_ON))
     nextchar += ALIGN_ON - modulus;
   return q;
 }

 /* Doh!  We ran out -- need to allocate more */
 cp_grow();

 return cp_strdup(src);
}
