#ifndef    __COMMON__
#define    __COMMON__

#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>



#ifndef  S_IRWXU
#define  S_IRWXU  00700
#endif
#ifndef  S_IRUSR
#define  S_IRUSR  00400
#endif
#ifndef  S_IWUSR
#define  S_IWUSR  00200
#endif
#ifndef  S_IXUSR
#define  S_IXUSR  00100
#endif
#ifndef  S_IRWXG
#define  S_IRWXG  00070
#endif
#ifndef  S_IRGRP
#define  S_IRGRP  00040
#endif
#ifndef  S_IWGRP
#define  S_IWGRP  00020
#endif
#ifndef  S_IXGRP
#define  S_IXGRP  00010
#endif
#ifndef  S_IRWXO
#define  S_IRWXO  00007
#endif
#ifndef  S_IROTH
#define  S_IROTH  00004
#endif
#ifndef  S_IWOTH
#define  S_IWOTH  00002
#endif
#ifndef  S_IXOTH
#define  S_IXOTH  00001
#endif


/*
 * print data by hex-format
 */
static void hexdump(char *title, unsigned char *data, long size) {
	
    int line = 0;
    int i    = 0;

    while(i < size) {
        while(0 == i%16) {
            if(0 == i) {
                printf("\n<%s>\n", title);
                printf("%08x\t",line);	 
                break;   
            }
            line += 0x10;
            printf("\n%08x\t",line);	
            break;    
        } 
        printf("%02x ", *(data+i));
        i++;	    
    }
    printf("\n\n");	    
}


/*
 * padding the plain text
 */
static unsigned char* padding(const unsigned char *in, long size, long *p_size, int padding) {
    
    char p_value = 0;       // the padding value
    long index   = 0;
    unsigned char *out   = NULL;
    
    if( padding <= 0 ) {
        padding = 16;
    }
    *p_size = (size / padding + 1) * padding;  // datat size after padding, padding equeals 16 by default
    out    = (unsigned char*)malloc(*p_size);
    /* copy char by char */
    while(index < size) {
        out[index] = in[index];
		index++;
    }
    p_value = (*p_size - index) % padding;
    while(index < *p_size) {
        out[index++] = p_value;
    }
    return out;
}



#endif

