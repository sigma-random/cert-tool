#ifndef    __DIGTAL_SIGN__
#define    __DIGTAL_SIGN__

#include "config.h"
#include "common.h"
#include "debug.h"


#define  RES_SUCCESS  0
#define  RES_FAILURE  -1

#define _OUT_
#define _IN_

#define FI_MAG0    0
#define FI_MAG1    1
#define FI_MAG2    2
#define FI_MAG3    3
#define FI_MAG4    4
#define FI_MAG5    5
#define FI_MAG6    6
#define FI_MAG7    7

#define F_MAG0    '?'
#define F_MAG1    'E'
#define F_MAG2    'N'
#define F_MAG3    'C'
#define F_MAG4    '-'
#define F_MAG5    'A'
#define F_MAG6    'P'
#define F_MAG7    'K'

#define F_MNUM   8

typedef struct enc_file_hdr_st {
    unsigned char f_magic[F_MNUM];    // magic numbers
    long  enc_data_size;              // encrypted data length
    long  sig_size;                   // signature length
}ENC_FILE_HDR;

typedef struct enc_file_st {
    ENC_FILE_HDR  *header;
    unsigned char *enc_data;  // encrypted data
    unsigned char *signature; // signature
}ENC_FILE;

#define INIT_F_HDR(name) \
        ENC_FILE_HDR name = \
        { {F_MAG0, \
           F_MAG1, \
           F_MAG2, \
           F_MAG3, \
           F_MAG4, \
           F_MAG5, \
           F_MAG6, \
           F_MAG7},\
           0,      \
           0       \
        };


typedef struct mapping_file_st {
    void *vm_start;     // virtual memory address of the mapping file 
    int  fd;            // file descriptor
    long size;          // size of the file 
    long p_size;        // size of the file by AES_BLOCK_SIZE padding 
    char *fullname;     // full name of the file
}M_FILE_INFO;




typedef struct cert_info_st{
    long    version;
    long    days;
    char   *country;
    char   *province;
    char   *org;       //organization;
    char   *common;
    union {
            unsigned char issuer_ID[16];
            unsigned char owner_ID[64];
    } ID; 
} CERT_INFO;


/* export function */
//========================================================================================//

int create_cert_file(int isCA, int sn, CERT_INFO *cert_info, const char *ca_certfile, 
                                         const char *ca_keyfile, const char *outfile);

int print_x509(int mode, void *x509);


int encrypt_sign_file( const char *infile, const char *server_keyfile , const char *outfile);


int verify_decrypt_file( const char *infile, const char* server_cert , 
                             const char* ca_cert, const char *outfile );

int verify_enc_file_format( void *ptr );

//=======================================================================================//

#endif

