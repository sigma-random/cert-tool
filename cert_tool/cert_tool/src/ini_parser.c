#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>


#define MAX_LINE_BUFSIZE 1024

char tmpLine[MAX_LINE_BUFSIZE] = {0};
char tmpstr[MAX_LINE_BUFSIZE]  = {0};

char* rstrip(char *word) {

    int len = 0;
    int i = 0;
    int badnum = 0;
    char *p = NULL;
    assert(word != NULL);
    len = strlen(word);
    p = word+len;
    for(p = word+len-1; p>=word; p--) {
        if(strchr(" \t;#", *(p)) > 0 ) {
            badnum++; 
            *p = 0;
        }
    }
    len = strlen(word);
    p = (char*)malloc(len+1);
    memset(p,0,len+1);
    strncpy(p,word,len);
    return p;
}


char* get_section_item(const char *filename, const char *section, const char *item) {

    FILE *fp;
    char *tmp = NULL;
    int rtnval;
    int i = 0;
    int flag = 0;
    char *retstr = NULL;
    int line_cnt = 0;

    memset(tmpLine,0,sizeof(tmpLine));
    memset(tmpstr,0,sizeof(tmpstr));
 
    if ((fp = fopen(filename, "r")) == NULL) {
        printf("fail to open file: %s\n", filename);
        exit(EXIT_FAILURE);
    }
    flag = 0;
    while (!feof(fp)) {

        rtnval = fgetc(fp);
        if( i >= MAX_LINE_BUFSIZE) {
            printf("detect buffer overwrite!\n");
            exit(EXIT_FAILURE);
        }
        line_cnt++;
        tmpLine[i++] = rtnval;
        if (rtnval == 0x0a || rtnval == 0x0d || rtnval == EOF) {
            tmpLine[--i] = 0;
            i = 0;
            if (tmpLine[0] == 0 || strchr("#;", tmpLine[0]) != NULL) {
                continue;         // Skip null line or comment line
            }
            if (tmpLine[0] == '[') {
                tmp = NULL;
            } 
            else {
                tmp = strchr(tmpLine, '=');
            }
            if ((tmp != NULL) && (flag == 1)) {
                *tmp = 0;    // erase '=', spilte item and Value
                char *p = strstr(tmpLine, item);
                if (p != NULL) {
                    if (p > tmpLine && strchr(" \t", *(p - 1)) == NULL) {
                        continue;    // exist prefix, mishit item
                    }
                    p += strlen(item);
                    if (*p == 0 || strchr(" \t", *p) != NULL) {
                        tmp++;    // Skip '='
                        while (*tmp == ' ' || *tmp == '\t') {
                            tmp++;    // Skip left lead ' ' or '\t'
                        }
                        tmp = rstrip(tmp);
                        fclose(fp);
                        return tmp;
                    }
                }
            } 
            else {
                strcpy(tmpstr, "[");
                strcat(tmpstr, section);
                strcat(tmpstr, "]");
                if (strcmp(tmpstr, tmpLine) == 0) {
                    flag = 1;
                }
            }

        }
    
    }   
    fclose(fp);
    printf("can't get value of [%s]->%s\n", section, item);
    return "";
}


int 
_main(int argc, char **argv) {
    printf("%s\n",get_section_item("test.conf","x509","country"));
    return 0;
}
