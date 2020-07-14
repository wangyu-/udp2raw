#ifndef UDP2RAW_ENCRYPTION_H_
#define UDP2RAW_ENCRYPTION_H_



//#include "aes.h"
//#include "md5.h"
#include "common.h"


//using namespace std;
//extern char key[16];

const int aes_key_optimize=1; //if enabled,once you used a key for aes,you cant change it anymore

int my_init_keys(const char *,int);

int my_encrypt(const char *data,char *output,int &len);
int my_decrypt(const char *data,char *output,int &len);


unsigned short csum(const unsigned short *ptr,int nbytes) ;


enum auth_mode_t {auth_none=0,auth_md5,auth_crc32,auth_simple,auth_hmac_sha1,auth_end};


enum cipher_mode_t {cipher_none=0,cipher_aes128cbc,cipher_xor,cipher_aes128cfb,cipher_end};


extern auth_mode_t auth_mode;
extern cipher_mode_t cipher_mode;

extern unordered_map<int, const char *> auth_mode_tostring;
extern unordered_map<int, const char *> cipher_mode_tostring;

extern char gro_xor[256+100];

int cipher_decrypt(const char *data,char *output,int &len,char * key);//internal interface ,exposed for test only
int cipher_encrypt(const char *data,char *output,int &len,char * key);//internal interface ,exposed for test only

#endif
