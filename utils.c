#include "utils.h"


void *safe_malloc(int size)
{
  void *mymem;
  if (size < 0)
    fatal("Tried to malloc negative amount of memory!!!");
  mymem = malloc(size);
  if (mymem == NULL)
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

#ifndef HAVE_STRCASESTR
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
#endif

int Strncpy(char *dest, const char *src, size_t n) {
  strncpy(dest, src, n);
  if (dest[n-1] == '\0')
    return 0;
  dest[n-1] = '\0';
  return -1;
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

/* Like the perl equivialent -- It removes the terminating newline from string
   IF one exists.  It then returns the POSSIBLY MODIFIED string */
char *chomp(char *string) {
  int len;
  len = strlen(string);
  if (len < 1)
    return string;
  if (string[len - 1] != '\n')
    return string;  
  if (len > 1 && string[len-2] == '\r') {
    string[len-2] = '\0';
  } else string[len-1] = '\0';
  return string;
}


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

unsigned short get_random_ushort() {
unsigned short s;
get_random_bytes(&s, sizeof(unsigned short));
return s;
}

int get_random_bytes(void *buf, int numbytes) {
static char bytebuf[2048];
static char badrandomwarning = 0;
static int bytesleft = 0;
int res;
int tmp;
struct timeval tv;
FILE *fp = NULL;
unsigned int i;
short *iptr;

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
      /*      error("WARNING: your system apparently does not offer /dev/urandom or /dev/random.  Reverting to less secure version."); */
    }
    /* Seed our random generator */
    gettimeofday(&tv, NULL);
    srand((tv.tv_sec ^ tv.tv_usec) ^ getpid());

    for(i=0; i < sizeof(bytebuf) / sizeof(short); i++) {
      iptr = (short *) ((char *)bytebuf + i * sizeof(short));
      *iptr = rand();
    }
    bytesleft = (sizeof(bytebuf) / sizeof(short)) * sizeof(short);
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

/* Scramble the contents of an array*/
void genfry(unsigned char *arr, int elem_sz, int num_elem) {
int i;
unsigned int pos;
unsigned char *bytes;
unsigned char *cptr;
unsigned short *sptr;
unsigned int *iptr;
unsigned char *tmp;
int bpe;

if (sizeof(unsigned char) != 1)
  fatal("genfry() requires 1 byte chars");

if (num_elem < 2)
  return;

 if (elem_sz == sizeof(unsigned short)) {
   shortfry((unsigned short *)arr, num_elem);
   return;
 }

/* OK, so I am stingy with the random bytes! */
if (num_elem < 256) 
  bpe = sizeof(unsigned char);
else if (num_elem < 65536)
  bpe = sizeof(unsigned short);
else bpe = sizeof(unsigned int);

bytes = malloc(bpe * num_elem);
tmp = malloc(elem_sz);

get_random_bytes(bytes, bpe * num_elem);
cptr = bytes;
sptr = (unsigned short *)bytes;
iptr = (unsigned int *) bytes;

 for(i=num_elem - 1; i > 0; i--) {
   if (num_elem < 256) {
     pos = *cptr; cptr++;
   }
   else if (num_elem < 65536) {
     pos = *sptr; sptr++;
   } else {
     pos = *iptr; iptr++;
   }
   pos %= i+1;
   memcpy(tmp, arr + elem_sz * i, elem_sz);
   memcpy(arr + elem_sz * i, arr + elem_sz * pos, elem_sz);
   memcpy(arr + elem_sz * pos, tmp, elem_sz);
 }
 free(bytes);
 free(tmp);
}

void shortfry(unsigned short *arr, int num_elem) {
int num;
unsigned short tmp;
int i;

if (num_elem < 2)
  return;
 
 for(i= num_elem - 1; i > 0 ; i--) {
   num = get_random_ushort() % (i + 1);
   tmp = arr[i];
   arr[i] = arr[num];
   arr[num] = tmp;
 } 

 return;
}

ssize_t Write(int fd, const void *buf, size_t count) {
  int res;
  unsigned int len;

  len = 0;
  do {
    res = write(fd,(char *) buf + len,count - len);
    if (res > 0)
      len += res;
  } while(len < count && (res != -1 || errno == EINTR));

  return res;
}


/* gcd_1 and gcd_n_long were sent in by Peter Kosinar <goober@gjh.sk> 
   Not needed for gcd_n_long, just for the case you'd want to have gcd
   for two arguments too. */
unsigned long gcd_ulong(unsigned long a, unsigned long b)
{
  /* Shorter
     while (b) { a%=b; if (!a) return b; b%=a; } */
  
  /* Faster */
  unsigned long c; 
  if (a<b) { c=a; a=b; b=c; }
  while (b) { c=a%b; a=b; b=c; }
  
  /* Common for both */
  return a;
}

unsigned long gcd_n_ulong(long nvals, unsigned long *val)
 {
   unsigned long a,b,c;
   
   if (!nvals) return 1;
   a=*val;
   for (nvals--;nvals;nvals--)
     {
       b=*++val;
       if (a<b) { c=a; a=b; b=c; }
       while (b) { c=a%b; a=b; b=c; }
     }
   return a;
 }

unsigned int gcd_uint(unsigned int a, unsigned int b)
{
  /* Shorter
     while (b) { a%=b; if (!a) return b; b%=a; } */
  
  /* Faster */
  unsigned int c; 
  if (a<b) { c=a; a=b; b=c; }
  while (b) { c=a%b; a=b; b=c; }
  
  /* Common for both */
  return a;
}

unsigned int gcd_n_uint(int nvals, unsigned int *val)
 {
   unsigned int a,b,c;
   
   if (!nvals) return 1;
   a=*val;
   for (nvals--;nvals;nvals--)
     {
       b=*++val;
       if (a<b) { c=a; a=b; b=c; }
       while (b) { c=a%b; a=b; b=c; }
     }
   return a;
 }

/* This function takes a command and the address of an uninitialized
   char ** .  It parses the command (by seperating out whitespace)
   into an argv[] style char **, which it sets the argv parameter to.
   The function returns the number of items filled up in the array
   (argc), or -1 in the case of an error.  This function allocates
   memmory for argv and thus it must be freed -- use argv_parse_free()
   for that.  If arg_parse returns <1, then argv does not need to be freed.
   The returned arrays are always terminated with a NULL pointer */
int arg_parse(const char *command, char ***argv) {
  char **myargv = NULL;
  int argc = 0;
  char mycommand[4096];
  unsigned char *start, *end;
  char oldend;

  *argv = NULL;
  if (Strncpy(mycommand, command, 4096) == -1) {      
    return -1;
  }
  myargv = malloc((MAX_PARSE_ARGS + 2) * sizeof(char *));
  bzero(myargv, (MAX_PARSE_ARGS+2) * sizeof(char *));
  myargv[0] = (char *) 0x123456; /* Integrity checker */
  myargv++;
  start = mycommand;
  while(start && *start) {
    while(*start && isspace(*start))
      start++;
    if (*start == '"') {
      start++;
      end = strchr(start, '"');
    } else if (*start == '\'') {
      start++;
      end = strchr(start, '\'');      
    } else if (!*start) {
      continue;
    } else {
      end = start+1;
      while(*end && !isspace(*end)) {      
	end++;
      }
    }
    if (!end) {
      arg_parse_free(myargv);
      return -1;
    }
    if (argc >= MAX_PARSE_ARGS) {
      arg_parse_free(myargv);
      return -1;
    }
    oldend = *end;
    *end = '\0';
    myargv[argc++] = strdup(start);
    if (oldend)
      start = end + 1;
    else start = end;
  }
  myargv[argc+1] = 0;
  *argv = myargv;
  return argc;
}

/* Free an argv allocated inside arg_parse */
void arg_parse_free(char **argv) {
  char **current;
  /* Integrity check */
  argv--;
  assert(argv[0] == (char *) 0x123456);
  current = argv + 1;
  while(*current) {
    free(*current);
    current++;
  }
  free(argv);
}


/* mmap() an entire file into the address space.  Returns a pointer
   to the beginning of the file.  The mmap'ed length is returned
   inside the length parameter.  If there is a problem, NULL is
   returned, the value of length is undefined, and errno is set to
   something appropriate.  The user is responsible for doing
   an munmap(ptr, length) when finished with it.  openflags should 
   be O_RDONLY or O_RDWR, or O_WRONLY
*/
char *mmapfile(char *fname, int *length, int openflags) {
  struct stat st;
  int fd;
  char *fileptr;

  if (!length || !fname) {
    errno = EINVAL;
    return NULL;
  }

  *length = -1;

  if (stat(fname, &st) == -1) {
    errno = ENOENT;
    return NULL;
  }

  fd = open(fname, openflags);
  if (fd == -1) {
    return NULL;
  }

  fileptr = (char *) mmap(0, st.st_size, (openflags & O_RDONLY)? PROT_READ :
                 (openflags & O_RDWR)? (PROT_READ|PROT_WRITE) : PROT_WRITE,
                 MAP_SHARED, fd, 0);

  close(fd);

  if (fileptr == MAP_FAILED) {
    return NULL;
  }

  *length = st.st_size;
  return fileptr;
}
