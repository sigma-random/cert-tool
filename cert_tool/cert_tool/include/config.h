#ifndef __CONFIG__
#define __CONFIG__

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* AES key config */
#define AES_KEY_BITS    128
#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE  16       // AES_BLOCK_SIZE=16
#endif

static unsigned char aes_key[AES_BLOCK_SIZE] = "\x1\x2\x3\x4\x5\x6\x7\x8\x8\x7\x6\x5\x4\x3\x2\x1";


/* RSA key config */
#define RSA_KEY_BITS    1024
#define RSA_E           65537L  //(0x10001)
#define RSA_SIGN_TYPE   NID_sha256

/* X509 Cert config */
#define SERVER_CNF_FILE "conf/server.conf"
#define CA_CNF_FILE     "conf/ca.conf"


#endif
