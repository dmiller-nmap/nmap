#include "utils.h"



void *safe_malloc(int size)
{
  void *mymem;
  if (size < 0)
    fatal("Tried to malloc negative amount of memmory!!!");
  if ((mymem = malloc(size)) == NULL)
    fatal("Malloc Failed! Probably out of space.");
  return mymem;
}

/* Hex dump */
void hdump(unsigned char *packet, int len) {
unsigned int i=0, j=0;

printf("Here it is:\n");

for(i=0; i < len; i++){
  j = (unsigned) (packet[i]);
  printf("%-2X ", j);
  if (!((i+1)%16))
    printf("\n");
  else if (!((i+1)%4))
    printf("  ");
}
printf("\n");
}


#if MISSING_USLEEP
void usleep(unsigned long usec) {
struct timespec ts; 
ts.tv_sec = usec / 1000000; 
ts.tv_nsec = (usec % 1000000) * 1000; 
nanosleep(&tsfoo, NULL);
}
#endif

void Strncpy(char *dest, const char *src, size_t n) {
  strncpy(dest, src, n);
  dest[n] = '\0';
}
