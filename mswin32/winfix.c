#include <winclude.h>
#include <sys/timeb.h>

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
