#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <digital_sign.h>


typedef struct {
    char operation;
    char *sub_oper;    // sub operation
    char *in;
    char *out;
    char *key_file;
    char *ca_cert;
    char *ser_cert;
    int  opt_num;
}OPTIONS;


/* global options struct */
OPTIONS options;
extern int opterr;
/* ca cert's base info */
CERT_INFO  ca_cert_info;
/* server cert's base info */
CERT_INFO  serv_cert_info;


int usage()  {

    printf("[usage]\n");

    /* make cert */
    printf("    -p     -i certfile                                         --  print x509 certfile (DER format)\n");
    printf("    -g ca  -o ca_cert                                          --  gen CA certfile (DER format)\n");
    printf("    -g ser -c ca_cert  -k ca_keyfile  -o ser_cert              --  gen Server certfile (DER format)\n");

    /* digital sign */ 
    printf("    -e     -i infile   -k keyfile     -o outfile               --  encrypt & sign    file\n");
    printf("    -d     -i infile   -s ser_cert    -c ca_cert   -o outfile  --  verify  & decrypt file\n");

    printf("\n");

}


int parse_options(int argc, char **argv) {
    
    const char *optstr = "pgedi:o:c:k:s:";
    int ch = 0;
    
    /* skip the error msg of getopt() */
    opterr = 0;
    options.sub_oper = NULL;
    while( (ch = getopt(argc, argv, optstr)) != -1 ) {
        options.opt_num++;
        switch(ch) {
            case 'p': {  // print
                options.operation = 'p';
                break;
            }
            case 'g': { // generation
                options.operation = 'g';
                options.sub_oper = argv[2];
                break;
            }
            case 'e': {  // encryption
                options.operation = 'e';
                break;
            }
            case 'd': {  // decryption
                options.operation = 'd';
                break;
            }
            case 'i': { // in file
                options.in = optarg; 
                break;
            }
            case 'o': { // out file
                options.out = optarg;
                break;
            }
            case 's': { // server cert file
                options.ser_cert = optarg;
                break;
            }
            case 'c': { // ca cert file
                options.ca_cert = optarg;
                break;
            }
            case 'k': { // private key file
                options.key_file = optarg;
                break;
            }
            default: {
                break;
            }
        }
    }

    return 0;
}


int run(int argc, char **argv) {

    parse_options(argc, argv);    

    if(options.operation > 0 && options.opt_num > 0) {

        switch(options.operation) {
            case 'p': {    // print
                /* print cert file (DER format) */
                if( options.opt_num == 2 ){
                    return print_x509(0, options.in);
                }
                break;
            }
            case 'g': {    // generate
                /* generate ca cert file directly (DER format) */
                if( (!strcmp("ca", options.sub_oper) ) && (options.opt_num == 2) ){
                    int isCA = 1;
                    int sn = 0x00000000;
                    init_config(CA_CNF_FILE, &ca_cert_info);
                    return create_cert_file(isCA, sn, &ca_cert_info, options.ca_cert, options.key_file, options.out);
                }
                /* generate server cert file directly (DER format) */
                if( (!strcmp("ser", options.sub_oper) ) && (options.opt_num == 4) ){
                    int isCA = 0;
                    int sn = 0x01010101;
                    init_config(SERVER_CNF_FILE, &serv_cert_info);
                    return create_cert_file(isCA, sn, &serv_cert_info, options.ca_cert, options.key_file, options.out);
                }
                break;
            }
            case 'e': {    // encrypt and  sign file
                if(options.opt_num == 4){
                    return encrypt_sign_file(options.in, options.key_file, options.out);
                }
                break;
            }
            case 'd': {    //  verify  and decrypt file 
                if(options.opt_num == 5){
                    return verify_decrypt_file(options.in, options.ser_cert, options.ca_cert, options.out);
                }
                break;
            }

            default : {
                break;
            }

        }

    }
    usage();

    return 0;
}

                                              
// end
