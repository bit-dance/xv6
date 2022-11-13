#include "types.h"
#include "stat.h"
#include "user.h"

#define SIZE 7461

int 
main()
{
	// allocate space for buffer
	void *buf = malloc(SIZE);

	// wolfie will ready image of wolfie to buf
	// it returns -1 if buffer size is smaller than image size
	int bytesRead = wolfie(buf, SIZE);
	if(bytesRead > -1) 
		printf(1, "%s\n", buf);

	exit();
}
