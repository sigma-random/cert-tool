
#include <digital_sign.h>

//========== File Module ==========//

/*
 * mapping the targetfile
 */
int mapping_file(const char *filename, M_FILE_INFO *m_file_info) {
    
    if(!filename ||!m_file_info) {
        return RES_FAILURE;
    }
    /* check the file */
    if ( 0 > (m_file_info->fd = open(filename,O_RDONLY))) {
        logger(stderr, "can't open file: %s\n",filename);
        return RES_FAILURE;
    }
    m_file_info->size   = lseek(m_file_info->fd, 0L, SEEK_END);  
    /* mapping the file */
    m_file_info->vm_start = mmap(NULL, m_file_info->size, PROT_READ|PROT_WRITE, 
                                MAP_PRIVATE, m_file_info->fd, 0);
    
    return RES_SUCCESS;
}
int unmapping_file(M_FILE_INFO *m_file_info) {
    
    if(!m_file_info) {
        return RES_FAILURE;
    }
    if( m_file_info->size<=0 && !m_file_info->vm_start) {
        return RES_FAILURE;
    }
    /* umapping the file */
    if( 0 != munmap(m_file_info->vm_start, m_file_info->size)){
        return RES_FAILURE;
    }

    return RES_SUCCESS;
}

/*
 *  save data as file 
 */
int save2file(const char *filename, unsigned char *start, long size) {
    
    int fd = -1;

    if(0 > (fd = open(filename,O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IROTH))) {
        logger(stderr, "can't create file: %s!\n\n",filename);
        return RES_FAILURE;
    }
    write(fd, start, size);
    logger(stdout, "save as file: %s\n\n",filename);
    close(fd);

    return RES_SUCCESS;
}

/*
 * save encrypt data into file
 */
int save_enc_file(const char *filename, unsigned char *enc_data, long enc_size, 
                unsigned char *sign, long signsize) {
    
    int fd  = -1;

    INIT_F_HDR(header);

    if(0 > (fd = open(filename,O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IROTH))) {
        logger(stderr, "can't create file: %s!\n\n",filename);
        return RES_FAILURE;
    }
    header.enc_data_size = enc_size;
    header.sig_size      = signsize;
    write(fd, (unsigned char*)&header, sizeof(ENC_FILE_HDR));
    write(fd, enc_data, enc_size);
    write(fd, sign, signsize);
    logger(stdout, "save as encrypted file: %s\n\n",filename);
    close(fd);

    return RES_SUCCESS;
}


//========== AES module ==========//

#define _MODE_ECB_          // using ECB Mode

#ifdef  _MODE_ECB_
#define _AES_ENCRYPT_F_ AES_ecb_encrypt
#else
#define _AES_ENCRYPT_F_ AES_encrypt
#endif

#ifdef  _MODE_ECB_
#define _AES_DECRYPT_F_ AES_ecb_encrypt
#else
#define _AES_DECRYPT_F_ AES_decrypt
#endif

int aes_encrypt(const unsigned char *in, const unsigned char *key, unsigned char *out, long size) {
    
    int  en_size = 0;
    AES_KEY aes;  
    
    if( !in || !key || !out || size<=0 ) {
        logger(stderr, "encryption error!\n");
        return RES_FAILURE;
    }
    if( 0 > AES_set_encrypt_key(key, AES_KEY_BITS, &aes)) {
        logger(stderr, "AES_set_encrypt_key error!\n");
        return RES_FAILURE;
    }
    while(en_size < size) {
        #ifdef  _MODE_ECB_
            _AES_ENCRYPT_F_(in, out, &aes, AES_ENCRYPT);
        #else
            _AES_ENCRYPT_F_(in, out, &aes);
        #endif
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
        en_size += AES_BLOCK_SIZE;
    }
    logger(stdout, "AES encryption... \n");

    return RES_SUCCESS;
}


int aes_decrypt(const unsigned char *in, const unsigned char *key, unsigned char *out, long size) {
    
    int  de_size = 0;
    AES_KEY aes;  
    
    if( !in || !key || !out || size<=0 ) {
        logger(stderr, "encryption error!\n");
        return RES_FAILURE;
    }
    if( 0 > AES_set_decrypt_key(key, AES_KEY_BITS, &aes)) {
        logger(stderr, "AES_set_decrypt_key error!\n");
        return RES_FAILURE;
    }
    while(de_size < size) {
        #ifdef  _MODE_ECB_
            _AES_DECRYPT_F_(in, out, &aes, AES_DECRYPT);
        #else
            _AES_DECRYPT_F_(in, out, &aes);
        #endif
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
        de_size += AES_BLOCK_SIZE;
    }
    logger(stdout, "AES decryption... \n");

    return RES_SUCCESS;
}


//========== RSA Module ==========//

X509* load_x509(const char* certfile);

/* load public key from x509 cert */
EVP_PKEY * load_x509_key(const char *certfile, int is_pubkey) {

    X509     *x509 = NULL;
    EVP_PKEY *key  = NULL;
    
    if( !certfile) {
        logger(stderr,"load_x509_key(): certfile is NULL\n");
        return NULL;
    }
    x509 = load_x509(certfile);
    if(!x509) {
        logger(stderr,"load_x509_key(): x509 is NULL\n");
        return NULL;
    }
    if(is_pubkey != 1){
        // get private key
    }else{
        key = X509_get_pubkey(x509);
    }
    X509_free(x509);

    return key;
}

/* load private key from rsa keyfile in DER format */
EVP_PKEY* load_der_prikey(const char *der_keyfile) {

    EVP_PKEY *key = NULL;
    BIO      *bio = NULL;
    
    if(!der_keyfile) {
        logger(stderr,"load_der_prikey(): der_keyfile is NULL\n");
        goto _ret_;
    }
    bio = BIO_new_file(der_keyfile,"rb");
    if(!bio) {
        logger(stderr,"can't open file: %s\n", der_keyfile);
        goto _ret_;
    }
    key = d2i_PrivateKey_bio(bio, NULL);
    if(!key) {
        logger(stderr,"can't get private key from file: %s\n", der_keyfile);
        goto _ret_;
    }

_ret_:
    
    if(bio) {
        //BIO_free(bio);    
    }
    return key;
}

/* load rsa key from cert in DER format */
RSA* load_rsa_certfile(const char *certfile, int is_pubkey) {
	
    RSA      *rsa = NULL;
    EVP_PKEY *key = NULL;

    rsa = RSA_new();
    if(!rsa) {
        logger(stderr,"RSA_new()\n");
        goto _ret_;
    }
    key = load_x509_key(certfile, is_pubkey);
    if(!key){
        logger(stderr,"load_x509_key()\n");
        goto _ret_;
    }
    rsa = EVP_PKEY_get1_RSA(key);
    if(!rsa) {
        logger(stderr,"EVP_PKEY_get1_RSA()\n");
        goto _ret_;     
    }    

_ret_:

    if(key) {
        EVP_PKEY_free(key);        
    }

    return rsa;
}

int dump_rsa_key(RSA *rsa) {
    
    long  len;
    unsigned char buf[512] = {0};

    if(!rsa) {
        logger(stderr, "rsa is NULL!\n");
        return RES_FAILURE;
    }else {
        if(rsa->n) {
            memset(buf,0,512);
            BN_bn2bin(rsa->n,buf);
            len = BN_num_bytes(rsa->n);
            hexdump("N:" ,buf,  len);
        }else {
            logger(stdout, "N is NULL!\n");
        }
        if(rsa->p) {
            memset(buf,0,512);
            BN_bn2bin(rsa->p,buf);
            len = BN_num_bytes(rsa->p);
            hexdump("P:" ,buf,  len);
        }else {
            logger(stdout, "P is NULL!\n");
        }
        if(rsa->q) {
            memset(buf,0,512);
            BN_bn2bin(rsa->q,buf);
            len = BN_num_bytes(rsa->q);
            hexdump("Q:" ,buf,  len);
        }else {
            logger(stdout, "Q is NULL!\n");
        }
        if(rsa->e) {
            memset(buf,0,512);
            BN_bn2bin(rsa->e,buf);
            len = BN_num_bytes(rsa->e);
            hexdump("E:" ,buf,  len);
        }else {
            logger(stdout, "E is NULL!\n");
        }
        if(rsa->d) {
            memset(buf,0,512);
            BN_bn2bin(rsa->d,buf);
            len = BN_num_bytes(rsa->d);
            hexdump("D:" ,buf,  len);
        }else {
            logger(stdout, "D is NULL!\n");
        }
    }

    return RES_SUCCESS;
}

RSA* gen_rsa_key(int bits, unsigned long e_value) {

    RSA     *rsa     = NULL;
    BIGNUM  *big_e   = NULL;
    unsigned char   buf[512] = {0};
    long    len;
    
    if(0 == bits) bits = RSA_KEY_BITS;    
    if(0 == e_value) e_value = RSA_E;    
    rsa = RSA_new();
    if(!rsa) {
        logger(stderr,"gen_rsa_key(): rsa is NULL\n");
        return NULL;
    }
    big_e = BN_new(); 
    if(!big_e) {
        logger(stderr,"BN_new()\n");
        return NULL;
    }
    // rand() ?
    BN_set_word(big_e, e_value);
    RSA_generate_key_ex(rsa, bits, big_e, NULL);
    BN_free(big_e);

    return rsa;
}

/* save rsa keys as file in DER format */
int save_rsa_key(RSA *rsa, const char *keyfile, int is_pubkey) {
    
    BIO *out = NULL;

    if(!rsa || !keyfile) {
        logger(stderr, "save_rsa_key(0x%08x, \"%s\")\n",rsa, keyfile);
        return RES_FAILURE;
    }
    out = BIO_new_file(keyfile,"wb");
    if(!out) {
        return RES_FAILURE;
    }
    if(1 != is_pubkey){
        i2d_RSAPrivateKey_bio(out, rsa);
        logger(stdout, "save private key as: %s\n",keyfile);
    }else{
        i2d_RSAPublicKey_bio(out, rsa);
        logger(stdout, "save public key as: %s\n",keyfile);
    }
    BIO_free(out);

    return RES_SUCCESS;
}

/* load rsa keys from file in DER format */
RSA* load_rsa_key(const char *der_keyfile, int is_pubkey) {
    
    RSA *rsa = NULL;
    BIO *in  = NULL;

    if(!der_keyfile) {
        return NULL;
    }
    in = BIO_new_file(der_keyfile,"rb");
    if(!in) {
        logger(stdout, "BIO_new_file\n");
        return NULL;
    }
    rsa = RSA_new();
    if(!rsa) {
        logger(stdout, "RSA_new!\n");
        goto _ret_;
    }
    if(1 != is_pubkey){
        d2i_RSAPrivateKey_bio(in, &rsa);
    }else{
        d2i_RSAPublicKey_bio(in, &rsa);
    }

_ret_:

    if(in){
        BIO_free(in);
    }

    return rsa;
}



//========== X509 Cert Module ==========//

/* init configuration from file */
int init_config(const char *config, CERT_INFO *cert_info) {
   
    cert_info->version  = atol((char*)get_section_item(config, "x509", "version"));
    cert_info->days     = atol((char*)get_section_item(config, "x509", "days"));
    cert_info->country  = (char*)get_section_item(config, "x509", "country");
    cert_info->province = (char*)get_section_item(config, "x509", "province");
    cert_info->org      = (char*)get_section_item(config, "x509", "org");
    cert_info->common   = (char*)get_section_item(config, "x509", "common");

    return RES_SUCCESS;
}

X509* load_x509(const char* certfile) {
    
    X509 *p_x509 = NULL;
    BIO  *in     = NULL;

    if(!certfile) {
        return NULL;
    }
    p_x509 = X509_new();   
    if(!p_x509) {
        return NULL;
    }
    in = BIO_new_file(certfile,"rb");
    if(!in) {
        logger(stderr, "can't open cert file: %s\n",certfile);
        return NULL;
    }
    p_x509 = d2i_X509_bio(in, &p_x509);
    if(!p_x509) {
        logger(stderr, "can't read certfile: %s\n",certfile);
        return NULL;
    }
    BIO_free(in);        

    return p_x509;
}

/* 
 * -print x509 cert info
 * @mode = 0  -- printX509 info from the cert file
 *  mode = 1  -- printX509 info from memory
 */
int print_x509(int mode, void *x509) {
    
    BIO  *bio    = NULL;
    X509 *p_x509 = NULL;

    if(!x509) {
        return RES_FAILURE;
    }
    switch(mode) {
        case 0:     // load x509 from file (in DER format)
            p_x509 = load_x509((char*)x509);       
            break;
        default:    // load x509 from memory
            p_x509 = (X509*)x509;
            break;
    }
    if(!p_x509) {
        return RES_FAILURE;
    }
    bio = BIO_new(BIO_s_file());
    if(!bio) {
        return RES_FAILURE;
    }
    BIO_set_fp(bio, stdout, BIO_NOCLOSE);
    X509_print(bio, p_x509); 
    BIO_free(bio);
    X509_free(p_x509);

    return RES_SUCCESS;
}
        

int verify_x509(X509 *ca_cert, X509 *server_cert) {

    STACK_OF(X509) *stack    = NULL;
    X509_STORE     *ca_store = NULL;
    X509_STORE_CTX *ctx      = NULL;

    if(!ca_cert ||!server_cert) {
        return RES_FAILURE;
    }
    /* init */
    ca_store = X509_STORE_new();
    if(!ca_store) {
        return RES_FAILURE;
    }
    if(X509_STORE_add_cert(ca_store, ca_cert) <= 0) {
        X509_STORE_free(ca_store);
        return RES_FAILURE;
    }
    ctx = X509_STORE_CTX_new();
    if(!ctx) {
        return RES_FAILURE;
    }
    if(X509_STORE_CTX_init(ctx, ca_store, ca_cert, stack) <= 0) {
        X509_STORE_CTX_cleanup(ctx);
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(ca_store);
        return RES_FAILURE;
    }
    if(X509_verify_cert(ctx) <= 0) {
        X509_STORE_CTX_cleanup(ctx);
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(ca_store);
        return RES_FAILURE;
    }
    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(ca_store);

    return RES_SUCCESS;
}

int verify_x509_life() {

    //todo...
    return RES_SUCCESS;
}

int verify_x509cert(const char *ca_certfile, const char *server_certfile) {
     
    X509 *ca_x509cert      = NULL;
    X509 *server_x509cert = NULL;
    int res = RES_SUCCESS;

    ca_x509cert = load_x509(ca_certfile);
    if(!ca_x509cert) {
        res = RES_FAILURE;
        goto _ret_;
    }
    server_x509cert = load_x509(server_certfile);
    if(!server_x509cert) {
        res = RES_FAILURE;
        goto _ret_;
    }
    if( RES_SUCCESS == verify_x509(ca_x509cert,server_x509cert) ) {
        res = RES_SUCCESS;
        logger(stdout, "%s has verified %s\n",ca_certfile, server_certfile);
    }else {
        logger(stderr, "%s can't verify %s\n",ca_certfile, server_certfile);
        res = RES_FAILURE;
        goto _ret_;
    }

_ret_:

    if(ca_x509cert){
        X509_free(ca_x509cert);
    }
    if(server_x509cert){
        X509_free(server_x509cert);
    }   

    return res;
}


/*
 * mode = 1  : data from file
 * mode = 0  : data from memory
 */
int sign_data(int mode, const char *in, unsigned int size, const char *der_keyfile,
                        _OUT_ unsigned char **p_sign, _OUT_ unsigned int *sign_size) {
    
    unsigned char *data  = NULL;    
    M_FILE_INFO m_file_info;
    EVP_PKEY  *prikey; 
    RSA  *rsa;  
    int res;

    if( !in || !p_sign || (size<=0&&mode==0) ) {
        return RES_FAILURE;
    }
    if(1 == mode ) { // load data from file
        memset(&m_file_info, 0 ,sizeof(m_file_info));
        if( RES_FAILURE == mapping_file(in, &m_file_info) ) {
            return RES_FAILURE;
        }
        data  = m_file_info.vm_start;
        size  = m_file_info.size;
    } else { // load data from memory
        data = (unsigned char *)in;
    }

    prikey = load_der_prikey(der_keyfile);
    if(!prikey) {
        goto _ret_;
    }
    rsa = load_rsa_key(der_keyfile, 0);
    if(!rsa) {
        goto _ret_;
    }   

    *sign_size = RSA_size(rsa);
    *p_sign  = (unsigned char*)malloc(*sign_size + 1);
    if(!*p_sign) {
        goto _ret_;
    }
    memset(*p_sign, 0, *sign_size + 1);
    res = rsa_sign(rsa, data, size, *p_sign, sign_size);
    if(RES_FAILURE == res) {
        free(*p_sign);
        *p_sign = NULL; 
    }

_ret_:

    unmapping_file(&m_file_info);
    if(prikey) {
        EVP_PKEY_free(prikey);
    }
    if(rsa) {
        RSA_free(rsa);
    }

    return res;
}

/*
 * @mode = 1 : data from file
 *  mode = 0 : data from memory
 */
int verify_data(int mode, const char *in, unsigned int size,  const char *certfile, 
                unsigned char *sign, unsigned int signsize) {
    
    unsigned char *data = NULL; 
    M_FILE_INFO m_file_info;
    EVP_PKEY  *pubkey = NULL; 
    RSA  *rsa = NULL;
    int res;

    if(!in ||!sign ||!certfile || (0>size && mode==0)) {
        return RES_FAILURE;
    }
    if(1 == mode) {
        memset(&m_file_info, 0 ,sizeof(m_file_info));
        if( RES_FAILURE == mapping_file(in, &m_file_info) ) {
            return RES_FAILURE;
        }
        data = m_file_info.vm_start; 
        size = m_file_info.p_size;
    }else {
        data = (unsigned char *)in;
    }
    pubkey = load_x509_key(certfile, 1);
    if(!pubkey) {
        logger(stderr, "load pubkey error!\n");
        res = RES_FAILURE;
        goto _ret_;
    }
    rsa = EVP_PKEY_get1_RSA(pubkey);    
    if(!rsa) {
        res = RES_FAILURE;
        goto _ret_;
    } 

    res = rsa_verify(rsa, data, size, sign, signsize);

_ret_:

    unmapping_file(&m_file_info);
    if(pubkey) {
        //EVP_PKEY_free(pubkey);
    }
    if(rsa) {
       RSA_free(rsa);
    }

    return res;
}



int rsa_sign(RSA *rsa, unsigned char *data, unsigned int size, 
            _OUT_ unsigned char *sign, unsigned int *signsize ) {
    int res;

    if(!rsa ||!data || size<=0 ||!sign ) {
        return RES_FAILURE;
    } 
    if(*signsize != RSA_size(rsa)) {
        return RES_FAILURE;
    }
    res = RSA_sign(RSA_SIGN_TYPE, data, size, sign, signsize, rsa);

    return res == 1 ? RES_SUCCESS : RES_FAILURE;
}


int rsa_verify(RSA *rsa, unsigned char *data, unsigned int size, 
                unsigned char *sign, unsigned int signsize) {
    int res;

    if(!rsa ||!data || size<=0 ||!sign ) {
        return RES_FAILURE;
    } 
    if(signsize != RSA_size(rsa)) {
        return RES_FAILURE;
    }
    res = RSA_verify(NID_sha256, data, size, sign, signsize, rsa);

    return res == 1 ? RES_SUCCESS : RES_FAILURE;
}


/* Add extension : set the config file as NULL
 * because we won't reference any other sections
 */
int add_req_extension(STACK_OF(X509_EXTENSION) *sk, int nid, char *value) {

    X509_EXTENSION *ex;

    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if(!ex) {
        return RES_FAILURE;
    }
    sk_X509_EXTENSION_push(sk, ex);

    return RES_SUCCESS;
}


X509_REQ* create_cert_req(CERT_INFO *cert_info, RSA* rsa) {
    
    X509_REQ* req = NULL;
    X509_NAME_ENTRY *entry = NULL;
    X509_NAME *name = NULL;
    EVP_PKEY  *pkey = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
   
    const EVP_MD *md = NULL;
    int len;
    int res;
 
    if(!cert_info || !rsa) {
        return NULL;
    }
    req = X509_REQ_new(); 
    if(!req ) {
        logger(stdout, "X509_REQ_new RES_FAILURE!\n");
        return NULL;
    } 

    res = X509_REQ_set_version(req, cert_info->version);

    name=X509_NAME_new();
    assert( name != NULL );
    if( ( len = strlen(cert_info->country) ) > 0) {
        entry = X509_NAME_ENTRY_create_by_txt( &entry, "countryName", V_ASN1_UTF8STRING, 
                            cert_info->country, len);
        res = X509_NAME_add_entry(name, entry, -1, 0);
        assert( res == 1 );
    }
    if( ( len = strlen(cert_info->common) ) > 0) {
        entry = X509_NAME_ENTRY_create_by_txt( &entry, "commonName", V_ASN1_UTF8STRING, 
                            cert_info->common, len);
        res = X509_NAME_add_entry(name, entry,-1, 0);
        assert( res == 1 );
    }
    if( ( len = strlen(cert_info->org) ) > 0) {
        entry = X509_NAME_ENTRY_create_by_txt( &entry, "organizationName", V_ASN1_UTF8STRING, 
                            cert_info->org, len);
        res = X509_NAME_add_entry(name, entry, -1, 0);
        assert( res == 1 );
    }
    if( ( len = strlen(cert_info->province) ) > 0) {
        entry = X509_NAME_ENTRY_create_by_txt( &entry, "stateOrProvinceName", V_ASN1_UTF8STRING, 
                            cert_info->province, len);
        res = X509_NAME_add_entry(name, entry, -1, 0);
        assert( res == 1 );
    }

    /* subject name */
    res = X509_REQ_set_subject_name(req, name); 
    assert( res == 1 );

    /* extension info */
#define __REQUEST_EXTENSIONS__
#ifdef  __REQUEST_EXTENSIONS__

    exts = sk_X509_EXTENSION_new_null();
    /* Standard extenions */
    add_req_extension(exts, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    //add_req_extension(exts, NID_subject_alt_name, "email:steve@openssl.org");
    //add_req_extension(exts, NID_netscape_cert_type, "client,email");

#define __CUSTOM_EXTENSIONS__
#ifdef  __CUSTOM_EXTENSIONS__
    
    int nid;
    nid = OBJ_create("1.1.1.0", "a", "My Test Alias Extension a");
    X509V3_EXT_add_alias(nid, NID_netscape_comment);
    add_req_extension(exts, nid, "00000000");
    
    nid = OBJ_create("1.1.1.1", "b", "My Test Alias Extension b");
    X509V3_EXT_add_alias(nid, NID_netscape_comment);
    add_req_extension(exts, nid, "11111111");

#endif
    X509_REQ_add_extensions(req, exts);
#endif

    /* pub key */
    pkey = EVP_PKEY_new();
    assert( pkey != NULL );
    EVP_PKEY_assign_RSA(pkey, rsa);
    res = X509_REQ_set_pubkey(req, pkey);

    /* sha1 digist */
    //md = EVP_sha1(); 
    md = EVP_sha256();
    assert( md != NULL );
    res = X509_REQ_sign(req, pkey, md);
    if(!res) {
        logger(stdout, "sign err!\n");
        X509_REQ_free(req);
        return NULL;
    }

    return req;
}

/*
 * save cert req as file in DER format
 *
 */
int save_cert_req(X509_REQ* req, const char *filename) {

    BIO *out = NULL;
    int cnt = 0;

    if(!req ||!filename) {
        logger(stderr, "save_cert_req(0x%08x, \"%s)\"\n",req, filename);
        return RES_FAILURE;
    }
    out = BIO_new_file(filename,"wb");
    if(!out) {
        logger(stderr, "BIO_new_file(\"%s\",\"wb\")\n",filename);
        return RES_FAILURE;
    }
    cnt = i2d_X509_REQ_bio(out, req);
    logger(stdout, "save cert request file as: %s\n",filename);
    BIO_free(out);

    return RES_SUCCESS;
}

/*
 * load request cert from  file in DER format
 *
 */
X509_REQ* load_cert_req(const char *filename) {

    X509_REQ *req = NULL;
    BIO *in  = NULL;
    
    in  = BIO_new_file(filename,"rb");
    if(!in) {
        logger(stderr, "BIO_new_file RES_FAILURE!\n");
        return NULL;
    }
    req = X509_REQ_new();
    if(req == NULL) {
        logger(stderr, "Load DER ERROR!\n");
        return NULL;
    }
    req = d2i_X509_REQ_bio(in, &req); 
    BIO_free(in);
    assert( req != NULL );

    return req;
}

X509* sign_cert_req(int isCA, int sn, X509_REQ *req, X509 *ca_cert, EVP_PKEY *ca_prikey) {
 
    X509 *tmp_cert = NULL;
    X509_NAME *name = NULL;
    EVP_PKEY  *tmp_key = NULL;
    int res = 0;

    if(!req ||!ca_prikey) {
        return NULL;
    }
    if(!isCA) {
        if(!ca_cert) {
            logger(stdout, "ca_cert not found!\n");
            return NULL;
        }
    } 

    tmp_cert = X509_new();
    assert(tmp_cert != NULL);
    
    res = X509_set_version(tmp_cert, X509_REQ_get_version(req)); 
    assert(res != 0);
  
    res = ASN1_INTEGER_set(X509_get_serialNumber(tmp_cert), sn);
    assert(res != 0);

    X509_gmtime_adj(X509_get_notBefore(tmp_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(tmp_cert), (long)60*60*24*365 );
    
    res = X509_set_subject_name(tmp_cert, X509_REQ_get_subject_name(req));
    assert(res != 0);


    tmp_key = X509_REQ_get_pubkey(req); 
    assert(tmp_key != NULL);
    res = X509_set_pubkey(tmp_cert, tmp_key);
    assert(res != 0);
    EVP_PKEY_free(tmp_key);   

    if(isCA) {
        name = X509_REQ_get_subject_name(req);
    }
    else {
        name = X509_get_subject_name(ca_cert);
    }
    if(!name) {
        logger(stdout, "name is NULL!\n");
        return NULL;
    }
    res = X509_set_issuer_name(tmp_cert, name);
    assert(res != 0);

    res = X509_sign(tmp_cert, ca_prikey, EVP_sha256()/*EVP_sha1()*/);
    assert(res != 0);
    
    return tmp_cert;
}


X509* sign_cert_req_file(int isCA, int sn, const char *req_file, const char *ca_cert_file, const char *ca_prikey_file) {
    
    X509_REQ *req  = NULL;
    X509 *ca_cert  = NULL;
    X509 *tmp_cert = NULL;
    EVP_PKEY *ca_prikey = NULL;

    req = load_cert_req(req_file); 
    ca_cert = load_x509(ca_cert_file);
    ca_prikey = load_der_prikey(ca_prikey_file);
    if(!ca_prikey) {
        return NULL;
    }
    tmp_cert =  sign_cert_req(isCA, sn, req, ca_cert, ca_prikey);
    X509_REQ_free(req);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_prikey);
    return tmp_cert;
}

/* 
 * >print x509 cert request info
 *    mode = 0  -- printX509 info from the cert file
 *    mode = 1  -- printX509 info from memory
 */
int print_cert_req(int mode, void *req) {
    
    BIO  *bio    = NULL;
    X509_REQ *p_req = NULL;

    if(!req) {
        logger(stdout, "req is NULL!\n");
        return RES_FAILURE;
    }
    switch(mode) {
        case 0:     // load x509 from file (in DER format)
            p_req = load_cert_req((char*)req);       
            break;
        default:    // load x509 from memory
            p_req = (X509_REQ*)req;
            break;
    }
    if(!p_req) {
        return RES_FAILURE;
    }
    bio = BIO_new(BIO_s_file());
    if(!bio) {
        return RES_FAILURE;
    }
    BIO_set_fp(bio, stdout, BIO_NOCLOSE);
    X509_REQ_print(bio, p_req); 
    BIO_free(bio);
    X509_REQ_free(p_req);

    return RES_SUCCESS;
}
        
int save_certfile(X509 *x509, const char* certfile) {

    BIO *bio = NULL;
    int cnt = 0;
    int res = RES_SUCCESS;
 
    if(!x509 ||!certfile) {
        return RES_FAILURE;
    }
    bio = BIO_new_file(certfile,"wb");
    if(!bio ) {
        logger(stderr, "BIO_new_file(\"%s\",\"wb\")\n",certfile);
        return RES_FAILURE;
    }
    cnt = i2d_X509_bio(bio, x509);
    if( cnt <= RES_FAILURE ) {
        logger(stderr, "cnt <= 0\n");
        res = RES_FAILURE;
        goto _ret_;
    }
    logger(stdout, "save as cert file: %s\n",certfile);

_ret_:

    if(bio) {
        BIO_free(bio);        
    }

    return res;
}

int create_cert_file(int isCA, int sn, CERT_INFO *cert_info, const char *ca_certfile, 
                    const char *ca_keyfile, const char *outfile) {

    RSA *rsa = NULL;
    X509_REQ *req  = NULL;
    X509  *ca_cert = NULL;  
    EVP_PKEY *ca_prikey = NULL;
    int res;

    rsa = gen_rsa_key(0,0);
    if(!rsa) {
        return RES_FAILURE;
    }
    //dump_rsa_key(rsa);

    if(isCA) {
        save_rsa_key(rsa, "ca.key", 0); 
    }
    else {
        save_rsa_key(rsa, "server.key", 0); 
    }
    req = create_cert_req(cert_info, rsa);
    if(!req) {
        res = RES_FAILURE;
        goto _ret_;
    }

    if(isCA) {
        ca_prikey = load_der_prikey("ca.key");
        ca_cert = NULL;
    }
    else {
        ca_prikey = load_der_prikey(ca_keyfile);
        ca_cert  = load_x509(ca_certfile);
    }
    res = save_certfile( sign_cert_req(isCA, sn, req, ca_cert, ca_prikey), outfile);

_ret_:

    if(rsa) {
        RSA_free(rsa);        
    }
    if(req) {
        X509_REQ_free(req);        
    }
    if(ca_cert) {
        X509_free(ca_cert);
    }
    if(ca_prikey) {
        EVP_PKEY_free(ca_prikey);
    }

    return res;
}


//========== Sha256 Module ==========//
unsigned char* gen_sha256(unsigned char *data, long size, unsigned char *md) {

    SHA256_CTX ctx;

    if(!data || 0 == size ||!md) {
        return NULL;
    }     
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, size);
    SHA256_Final(md, &ctx);
    OPENSSL_cleanse(&ctx,sizeof(ctx));  
   
    return md;
}

unsigned char* gen_file_sha256(const char *infile, unsigned char *md) {

    M_FILE_INFO   m_file_info;

    if(!md ||!infile) {
        logger(stderr, "gen_file_sha256 error!\n");
        return NULL;
    }
    memset(&m_file_info, 0 ,sizeof(m_file_info));
    if( RES_FAILURE == mapping_file(infile,&m_file_info) ) {
        return NULL;
    }
    hexdump("original file", m_file_info.vm_start, m_file_info.size);
    gen_sha256(m_file_info.vm_start, m_file_info.size, md);
	
    return md;
}



//========== encrypt-sign / verify-decrypt Module ==========//

int verify_enc_file_format(void *ptr) {
    int ret = RES_FAILURE;
    char *p = NULL;

    assert(ptr != NULL);
    p = (char*)ptr;
    ret = (p[FI_MAG0] == F_MAG0) &&
          (p[FI_MAG1] == F_MAG1) &&
          (p[FI_MAG2] == F_MAG2) &&
          (p[FI_MAG3] == F_MAG3) &&
          (p[FI_MAG4] == F_MAG4) &&
          (p[FI_MAG5] == F_MAG5) &&
          (p[FI_MAG6] == F_MAG6) &&
          (p[FI_MAG7] == F_MAG7) ;

    return ret ? RES_SUCCESS : RES_FAILURE;
}


int encrypt_sign_file( const char *infile, const char *server_keyfile, const char *outfile) {

    int res = RES_SUCCESS;
    unsigned char *plain  = NULL;
    unsigned char *cipher = NULL; 
    unsigned char *md     = NULL;
    unsigned char *sign   = NULL;
    long  encsize = 0;
    unsigned int mdsize = 0;
    unsigned int signsize = 0;
    M_FILE_INFO  m_file_info;

    if(!infile) {
        logger(stderr, "infile is NULL!\n");
        return RES_FAILURE;
    }
    memset(&m_file_info, 0 ,sizeof(m_file_info));
    if( RES_FAILURE == mapping_file(infile,&m_file_info) ) {
        return RES_FAILURE;
    }
    plain   = padding(m_file_info.vm_start, m_file_info.size, &m_file_info.p_size, AES_BLOCK_SIZE); // AES_BLOCK_SIZE = 16 by default
    encsize = m_file_info.p_size;
    //hexdump("palin data", plain, encsize);
    hexdump("AES key", aes_key, AES_KEY_BITS / 8); 
    cipher  = (unsigned char*)malloc(encsize);
    if(!cipher) {
        res = RES_FAILURE;
        goto _ret_;
    }
    res = aes_encrypt(plain, aes_key, cipher, encsize);
    if(res == RES_FAILURE) {
        res = RES_FAILURE;
        goto _ret_;        
    }
    mdsize = SHA256_DIGEST_LENGTH;
    md  = (unsigned char*)malloc(mdsize + 1);
    if(!md) {
        res = RES_FAILURE;
        goto _ret_;
    }
    memset(md, 0 , mdsize + 1);
    gen_sha256(cipher, encsize, md);
    hexdump("cipher digist", md, mdsize);

    res = sign_data(0, md, mdsize, server_keyfile, &sign, &signsize);
    if(res == RES_FAILURE) {
        logger(stderr, "can't sign file: %s\n",infile);
        goto _ret_;
    }
    hexdump("sign data", sign, signsize);
    /* save encrypted and signed data as file */
    save_enc_file(outfile, cipher, encsize, sign, signsize);

_ret_:

    unmapping_file(&m_file_info);
    if(cipher) {
        free(cipher);
    }
    if(md) {
        free(md);
    }
    if(sign) {
        free(sign);
    }

    return res;
}

int verify_decrypt_file(const char *infile, const char* server_cert ,
                const char* ca_cert, const char *outfile) {

    int res = RES_SUCCESS;
    unsigned char *plain  = NULL;
    unsigned char *cipher = NULL; 
    unsigned char *md     = NULL; 
    unsigned char *sign   = NULL;  
    unsigned int mdsize   = 0;
    unsigned int encsize  = 0;
    unsigned int orisize  = 0;
    unsigned int signsize = 0;
    ENC_FILE_HDR *header  = NULL;
    M_FILE_INFO  m_file_info;
    
    /* verify server cert */
    if( RES_FAILURE == verify_x509cert(ca_cert, server_cert)) {
        return RES_FAILURE;
    }
    if(!infile) {
        logger(stderr, "infile is error!\n");
        return RES_FAILURE;
    }
    memset(&m_file_info, 0 ,sizeof(m_file_info));
    if( RES_FAILURE == mapping_file(infile,&m_file_info) ) {
        return RES_FAILURE;
    }
    header  = (ENC_FILE_HDR*)m_file_info.vm_start;
    if(!header) {
        return RES_FAILURE;
    }
    if( RES_FAILURE == verify_enc_file_format(header) ) {
        logger(stderr, "unknown encrypted file format!\n");
        return RES_FAILURE;
    }
    encsize  = header->enc_data_size;
    signsize = header->sig_size;
    cipher   = (unsigned char*)header + sizeof(ENC_FILE_HDR);
    sign     = cipher + encsize;
    hexdump("sign data", sign, signsize);

    mdsize = SHA256_DIGEST_LENGTH;
    md  = (unsigned char*)malloc(mdsize + 1);
    if(!md) {
        res = RES_FAILURE;
        goto _ret_;
    }
    memset(md, 0 , mdsize + 1);
    gen_sha256(cipher, encsize, md);
    hexdump("cipher digist", md, mdsize);

    res = verify_data(0, md, mdsize, server_cert, sign, signsize);
    if(res == RES_FAILURE) {
        logger(stderr,"%s can't verify sign data!\n", server_cert);
        goto _ret_;
    }
    logger(stdout, "%s verify sign data!\n\n", server_cert);
    hexdump("decrypt key", aes_key, 16); 
    plain = (unsigned char*)malloc(encsize + 1);
    if(!plain) {
        res = RES_FAILURE;
        goto _ret_;
    }
    memset(plain, 0 , encsize + 1);
    res = aes_decrypt(cipher, aes_key, plain, encsize);
    if(res == RES_FAILURE) {
        res = RES_FAILURE;
        goto _ret_;        
    }
    //hexdump("decrypt data", plain, encsize);
    orisize = plain[encsize-1] !=0 ? plain[encsize-1] : AES_BLOCK_SIZE;
    orisize = encsize - orisize;
    if(orisize <= 0 ) {
        res = RES_FAILURE;
        goto _ret_;
    }

    /* save decrypted data as file */
    save2file(outfile, plain, orisize);

_ret_:
    
    unmapping_file(&m_file_info);
    if(md) {
        free(md);
    }
    if(plain) {
        free(plain);
    }
    
    return res;
}
