#include "utils.h"


void *safe_malloc(int size)
{
  void *mymem;
  fflush(stdout);
  if (size < 0)
    fatal("Tried to malloc negative amount of memory!!!");
  mymem = malloc(size);
  if (mymem == NULL)
    fatal("Malloc Failed! Probably out of space.");
  fflush(stdout);
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

/* A better version of hdump, from Lamont Granquist.  Modified slightly
   by Fyodor (fyodor@DHP.com) */
void lamont_hdump(unsigned char *bp, int length) {

  /* stolen from tcpdump, then kludged extensively */

  static const char asciify[] = "................................ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................";

  register const u_short *sp;
  register const u_char *ap;
  register u_int i, j;
  register int nshorts, nshorts2;
  register int padding;

  printf("\n\t");
  padding = 0;
  sp = (u_short *)bp;
  ap = (u_char *)bp;
  nshorts = (u_int) length / sizeof(u_short);
  nshorts2 = (u_int) length / sizeof(u_short);
  i = 0;
  j = 0;
  while(1) {
    while (--nshorts >= 0) {
      printf(" %04x", ntohs(*sp));
      sp++;
      if ((++i % 8) == 0)
        break;
    }
    if (nshorts < 0) {
      if ((length & 1) && (((i-1) % 8) != 0)) {
        printf(" %02x  ", *(u_char *)sp);
        padding++;
      }
      nshorts = (8 - (nshorts2 - nshorts));
      while(--nshorts >= 0) {
        printf("     ");
      }
      if (!padding) printf("     ");
    }
    printf("  ");

    while (--nshorts2 >= 0) {
      printf("%c%c", asciify[*ap], asciify[*(ap+1)]);
      ap += 2;
      if ((++j % 8) == 0) {
        printf("\n\t");
        break;
      }
    }
    if (nshorts2 < 0) {
      if ((length & 1) && (((j-1) % 8) != 0)) {
        printf("%c", asciify[*ap]);
      }
      break;
    }
  }
  if ((length & 1) && (((i-1) % 8) == 0)) {
    printf(" %02x", *(u_char *)sp);
    printf("                                       %c", asciify[*ap]);
  }
  printf("\n");
}

char *strcasestr(char *haystack, char *pneedle) {
char buf[512];
unsigned int needlelen;
char *needle, *p, *q, *foundto;

/* Should crash if !pneedle -- this is OK */
if (!*pneedle) return haystack;
if (!haystack) return NULL;

needlelen = strlen(pneedle);
 if (needlelen >= sizeof(buf)) {
   needle = (char *) malloc(needlelen + 1);
 } else needle = buf;
 p = pneedle; q = needle;
 while((*q++ = tolower(*p++)))
   ;
 p = haystack - 1; foundto = needle;
 while(*++p) {
   if(tolower(*p) == *foundto) {
     if(!*++foundto) {
       /* Yeah, we found it */
       if (needlelen >= sizeof(buf))
         free(needle);
       return p - needlelen + 1;
     }
   } else foundto = needle;
 }
 if (needlelen >= sizeof(buf))
   free(needle);
 return NULL;
}

void Strncpy(char *dest, const char *src, size_t n) {
  strncpy(dest, src, n);
  dest[n] = '\0';
}

#ifndef HAVE_USLEEP
#ifdef HAVE_NANOSLEEP
void usleep(unsigned long usec) {
struct timespec ts; 
ts.tv_sec = usec / 1000000; 
ts.tv_nsec = (usec % 1000000) * 1000; 
nanosleep(&ts, NULL);
}
#endif
#endif

#ifndef HAVE_STRERROR
char *strerror(int errnum) {
  static char buf[1024];
  sprintf(buf, "your system is too old for strerror of errno %d\n", errnum);
  return buf;
}
#endif

int get_random_int() {
int i;
get_random_bytes(&i, sizeof(int));
return i;
}

unsigned int get_random_uint() {
unsigned int i;
get_random_bytes(&i, sizeof(unsigned int));
return i;
}

int get_random_bytes(void *buf, int numbytes) {
static char bytebuf[2048];
static char badrandomwarning = 0;
static int bytesleft = 0;
int res;
int tmp;
struct timeval tv;
FILE *fp = NULL;
int i;
int *iptr;

if (numbytes < 0 || numbytes > 0xFFFF) return -1;

if (bytesleft == 0) {
  fp = fopen("/dev/urandom", "r");
  if (!fp) fp = fopen("/dev/random", "r");
  if (fp) {
    res = fread(bytebuf, 1, sizeof(bytebuf), fp);
    if (res != sizeof(bytebuf)) {    
      error("Failed to read from /dev/urandom or /dev/random");
      fclose(fp);
      fp = NULL;
    }      
    bytesleft = sizeof(bytebuf);
  }
  if (!fp) {  
    if (badrandomwarning == 0) {
      badrandomwarning++;
      error("Could not open and read from /dev/urandom or /dev/random!  Using (probably) insecure random number source!");
    }
    /* Seed our random generator */
    gettimeofday(&tv, NULL);
    srand((tv.tv_sec ^ tv.tv_usec) ^ getpid());

    for(i=0; i < sizeof(bytebuf) / sizeof(int); i++) {
      iptr = (int *) ((char *)bytebuf + i * sizeof(int));
      *iptr = rand();
    }
    bytesleft = (sizeof(bytebuf) / sizeof(int)) * sizeof(int);
    /*    ^^^^^^^^^^^^^^^not as meaningless as it looks  */
  } else fclose(fp);
}

if (numbytes <= bytesleft) { /* we can cover it */
  memcpy(buf, bytebuf + (sizeof(bytebuf) - bytesleft), numbytes);
  bytesleft -= numbytes;
  return 0;
}

/* We don't have enough */
memcpy(buf, bytebuf + (sizeof(bytebuf) - bytesleft), bytesleft);
tmp = bytesleft;
bytesleft = 0;
return get_random_bytes((char *)buf + tmp, numbytes - tmp);
}


