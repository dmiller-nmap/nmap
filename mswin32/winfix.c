#include <winclude.h>
#include <sys/timeb.h>

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
//	time_t ltime;
	struct _timeb timebuffer;

	_ftime( &timebuffer );

	tv->tv_sec=timebuffer.time;
	tv->tv_usec=((timebuffer.time * 1000)+timebuffer.millitm)*1000;
	return 0;
};

unsigned int sleep(unsigned int seconds)
{
	Sleep(1000*seconds);
	return(0);
};

void usleep(unsigned long usec)
{
	int actual;

	actual = usec/1000;

	Sleep(actual);
	return;
};

//strcasecmp

int strcasecmp(const char *s1, const char *s2)
{
	int ret;

	char *cp1,*cp2;
	int i=0;

	cp1=malloc(strlen(s1)+1);
	memset(cp1,0,strlen(s1)+1);
	memcpy(cp1,s1,strlen(s1));
    for (i=0; cp1[i]>0; i++)
    {
        if ('a' <= cp1[i] && cp1[i] <= 'z')
            cp1[i] -= 32;
    }

	cp2=malloc(strlen(s2)+1);
	memset(cp2,0,strlen(s2)+1);
	memcpy(cp2,s2,strlen(s2));
    for (i=0; cp2[i]>0; i++)
    {
        if ('a' <= cp2[i] && cp2[i] <= 'z')
            cp2[i] -= 32;
    }


	ret=strcmp(cp1,cp2);
	return ret;
}

int strncasecmp(const char *s1, const char *s2, size_t n)
{
	int ret;
		char *cp1,*cp2;
	int i=0;

	cp1=malloc(strlen(s1)+1);
	memset(cp1,0,strlen(s1)+1);
	memcpy(cp1,s1,strlen(s1));
    for (i=0; cp1[i]>0; i++)
    {
        if ('a' <= cp1[i] && cp1[i] <= 'z')
            cp1[i] -= 32;
    }

	cp2=malloc(strlen(s2)+1);
	memset(cp2,0,strlen(s2)+1);
	memcpy(cp2,s2,strlen(s2));
    for (i=0; cp2[i]>0; i++)
    {
        if ('a' <= cp2[i] && cp2[i] <= 'z')
            cp2[i] -= 32;
    }



	ret=strncmp(cp1,cp2,n);
	return ret;
}

inline int my_close(int sd)
{
	if(sd == 501) return 0;
	return closesocket(sd);
}

int fork()
{
	fatal("no fork for you!\n");
	return 0;
}

HANDLE gmap = 0;
char *mmapfile(char *fname, int *length, int openflags) {
	HANDLE fd;
	char *fileptr;

	if (!length || !fname) {
		WSASetLastError(EINVAL);
		return NULL;
	}

	*length = -1;

	fd= CreateFile(fname,
		openflags,                // open for writing 
		0,                            // do not share 
		NULL,                         // no security 
		OPEN_EXISTING,                // overwrite existing 
		FILE_ATTRIBUTE_NORMAL,
		NULL);                        // no attr. template 

	gmap=CreateFileMapping(fd,NULL, (openflags & O_RDONLY)? PAGE_READONLY:(openflags & O_RDWR)? (PAGE_READONLY|PAGE_READWRITE) : PAGE_READWRITE,0,0,NULL);

	fileptr = (char *)MapViewOfFile(gmap, FILE_MAP_ALL_ACCESS,0,0,0);
	*length = (int) GetFileSize(fd,NULL);
	CloseHandle(fd);

	#ifdef MAP_FAILED
	if (fileptr == MAP_FAILED) return NULL;
	#else
	if (fileptr == (char *) -1) return NULL;
	#endif
	return fileptr;
}

int win32_munmap(char *filestr, int filelen)
{
	if(gmap == 0)
		fatal("win32_munmap: no current mapping !\n");
	FlushViewOfFile(filestr, filelen);
	UnmapViewOfFile(filestr);
	CloseHandle(gmap);
	gmap = 0;
	return 0;
}
