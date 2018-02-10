#ifndef UDP2RAW_ENCRYPTION_H_
#define UDP2RAW_ENCRYPTION_H_



//#include "aes.h"
//#include "md5.h"
#include "common.h"


//using namespace std;


const int aes_key_optimize=1; //if enabled,once you used a key for aes,you cant change it anymore
extern char key[16];

int my_encrypt(const char *data,char *output,int &len,char * key);
int my_decrypt(const char *data,char *output,int &len,char * key);

int my_encrypt_pesudo_header(uint8_t *data,uint8_t *output,int &len,uint8_t * key,uint8_t *header,int hlen);
int my_decrypt_pesudo_header(uint8_t *data,uint8_t *output,int &len,uint8_t * key,uint8_t *header,int hlen);


unsigned short csum(const unsigned short *ptr,int nbytes) ;


enum auth_mode_t {auth_none=0,auth_md5,auth_crc32,auth_simple,auth_end};


enum cipher_mode_t {cipher_none=0,cipher_aes128cbc,cipher_xor,cipher_end};


extern auth_mode_t auth_mode;
extern cipher_mode_t cipher_mode;

extern unordered_map<int, const char *> auth_mode_tostring;
extern unordered_map<int, const char *> cipher_mode_tostring;




int cipher_decrypt(const char *data,char *output,int &len,char * key);//internal interface ,exposed for test only
int cipher_encrypt(const char *data,char *output,int &len,char * key);//internal interface ,exposed for test only

#endif
