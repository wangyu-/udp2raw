#include <aes.h>
#include <md5.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <encrypt.h>

#include "log.h"

//static uint64_t seq=1;

static int8_t zero_iv[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0};//this prog use zero iv,you should make sure first block of data contains a random/nonce data

static const int disable_all=0;

static const int disable_aes=0;


int auth_mode=auth_md5;
int cipher_mode=cipher_aes128cbc;

//int auth(uint8_t *data,)
/*
int my_encrypt(uint8_t *data,uint8_t *output,int &len,uint8_t * key)
{

	return 0;
}
int my_decrypt(uint8_t *data,uint8_t *output,int &len,uint8_t * key)
{
	return 0;
}
*/
unsigned int crc32h(unsigned char *message,int len) {
   int i, crc;
   unsigned int byte, c;
   const unsigned int g0 = 0xEDB88320,    g1 = g0>>1,
      g2 = g0>>2, g3 = g0>>3, g4 = g0>>4, g5 = g0>>5,
      g6 = (g0>>6)^g0, g7 = ((g0>>6)^g0)>>1;

   i = 0;
   crc = 0xFFFFFFFF;
   while (i!=len) {    // Get next byte.
	   byte = message[i];
      crc = crc ^ byte;
      c = ((crc<<31>>31) & g7) ^ ((crc<<30>>31) & g6) ^
          ((crc<<29>>31) & g5) ^ ((crc<<28>>31) & g4) ^
          ((crc<<27>>31) & g3) ^ ((crc<<26>>31) & g2) ^
          ((crc<<25>>31) & g1) ^ ((crc<<24>>31) & g0);
      crc = ((unsigned)crc >> 8) ^ c;
      i = i + 1;
   }
   return ~crc;
}

int auth_md5_cal(const char *data,char * output,int &len)
{
	memcpy(output,data,len);//TODO inefficient code

	md5((unsigned char *)output,len,(unsigned char *)(output+len));
	len+=16;
	return 0;
}

int auth_none_cal(const char *data,char * output,int &len)
{
	memcpy(output,data,len);
	return 0;
}
int auth_md5_verify(const char *data,int &len)
{
	if(len<16)
	{
		log(log_trace,"auth_md5_verify len<16\n");
		return -1;
	}
	char md5_res[16];

	md5((unsigned char *)data,len-16,(unsigned char *)md5_res);

	if(memcmp(md5_res,data+len-16,16)!=0)
	{
		log(log_trace,"auth_md5_verify md5 check failed\n");
		return -2;
	}
	len-=16;
	return 0;
}
int auth_none_verify(const char *data,int &len)
{
	return 0;
}
int cipher_aes128cbc_encrypt(const char *data,char *output,int &len,char * key)
{
	char buf[65535+100];
	memcpy(buf,data,len);//TODO inefficient code

	int ori_len=len;
	len+=2;//length
	if(len%16!=0)
	{
		len= (len/16)*16+16;
	}
	if(len>65535) return -1;

	buf[len-2]= (unsigned char)( (uint16_t(ori_len))>>8);
	buf[len-1]=(unsigned char)( ((uint16_t(ori_len))<<8)>>8) ;

	AES_CBC_encrypt_buffer((unsigned char *)output,(unsigned char *)buf,len,(unsigned char *)key,(unsigned char *)zero_iv);
	return 0;
}
int cipher_none_encrypt(const char *data,char *output,int &len,char * key)
{
	memcpy(output,data,len);
	return 0;
}
int cipher_aes128cbc_decrypt(const char *data,char *output,int &len,char * key)
{
	if(len%16 !=0) {log(log_trace,"len%16!=0");return -1;}
	if(len<2) {log(log_trace,"len <2 ");return -1;}return -1;
	AES_CBC_decrypt_buffer((unsigned char *)output,(unsigned char *)data,len,(unsigned char *)key,(unsigned char *)zero_iv);
	len=((unsigned char)output[len-2])*256u+((unsigned char)output[len-1]);
	return 0;
}

int cipher_none_decrypt(const char *data,char *output,int &len,char * key)
{
	memcpy(output,data,len);
	return 0;
}

int auth_cal(const char *data,char * output,int &len)
{
	if(auth_mode==auth_md5)return auth_md5_cal(data,output,len);
	else if(auth_mode==auth_none ) return auth_none_cal(data,output,len);

	return auth_md5_cal(data,output,len);//default
}
int auth_verify(const char *data,int &len)
{
	if(auth_mode==auth_md5)return auth_md5_verify(data,len);
	else if(auth_mode==auth_none )return auth_none_verify(data,len);

	return auth_md5_verify(data,len);
}
int cipher_encrypt(const char *data,char *output,int &len,char * key)
{
	if(cipher_mode==cipher_aes128cbc)return cipher_aes128cbc_encrypt(data,output,len, key);
	if(cipher_mode==cipher_none)return cipher_none_encrypt(data,output,len, key);

	return cipher_aes128cbc_encrypt(data,output,len, key);
}
int cipher_decrypt(const char *data,char *output,int &len,char * key)
{
	if(cipher_mode==cipher_aes128cbc)return cipher_aes128cbc_decrypt(data,output,len, key);
	if(cipher_mode==cipher_none)return cipher_none_decrypt(data,output,len, key);
	return cipher_aes128cbc_decrypt(data,output,len,key);
}


int my_encrypt(const char *data,char *output,int &len,char * key)
{
	if(len<0) {log(log_trace,"len<0");return -1;}
	if(len>65535) {log(log_trace,"len>65535");return -1;}

	char buf[65535+100];
	char buf2[65535+100];
	memcpy(buf,data,len);
	if(auth_cal(buf,buf2,len)!=0) {log(log_trace,"auth_cal failed ");return -1;}
	if(cipher_encrypt(buf2,output,len,key) !=0) {log(log_trace,"auth_cal failed ");return -1;}
	return 0;

}
int my_decrypt(const char *data,char *output,int &len,char * key)
{
	if(len<0) return -1;
	if(len>65535) return -1;

	if(cipher_decrypt(data,output,len,key) !=0) {log(log_trace,"cipher_decrypt failed "); return -1;}
	if(auth_verify(output,len)!=0) {log(log_trace,"auth_verify failed ");return -1;}

	return 0;
}

int my_encrypt_old(const char *data0,char *output,int &len,char * key)
{
	char data[65535+100];
	memcpy(data,data0,len);

	if(disable_all)
	{
		memcpy(output,data,len);
		return 0;
	}

	int ori_len=len;

	len=len+16;//md5
	len+=2;//length

	if(len%16!=0)
	{
		len= (len/16)*16+16;
	}

	if(len>65535) return -1;

	data[len-16-2]= (unsigned char)( (uint16_t(ori_len))>>8);
	data[len-16-1]=(unsigned char)( ((uint16_t(ori_len))<<8)>>8) ;


	//printf("%d %d\n",data[len-16-2],data[len-16-1]);
	md5((unsigned char *)data,len-16,(unsigned char *)(data+len-16));

	//memcpy(buf,data,len);  //not thread safe

	if(disable_aes)
	{
		memcpy(output,data,len);

	}
	else
	{
		AES_CBC_encrypt_buffer((unsigned char *)output,(unsigned char *)data,len,(unsigned char *)key,(unsigned char *)zero_iv);
		//it doesnt allow over lap
	}


	return 0;
}
int my_decrypt_old(const char *data0,char *output,int &len,char * key)
{
	char data[65535+100];
	memcpy(data,data0,len);

	if(disable_all)
	{
		memcpy(output,data,len);
		return 0;
	}
	uint8_t md5_res[16];
	if(len>65535) return -1;
	if(len<32) return -1;
	if(len%16 !=0) return -1;


	if(disable_aes)
	{
		memcpy(output,data,len);
	}
	else
	{
		AES_CBC_decrypt_buffer((unsigned char *)output,(unsigned char *)data,len,(unsigned char *)key,(unsigned char *)zero_iv);
	}


	//printf("%d %d\n",data[len-16-2],data[len-16-1]);

	//printf("<<%d>>",len);

	md5((unsigned char *)output,len-16,(unsigned char *)md5_res);

	if(memcmp(output+len-16,md5_res,16)!=0)
	{
		return -2;
	}

	len=((unsigned char)output[len-16-2])*256u+((unsigned char)output[len-16-1]);  //this may be broken because of sign

	return 0;
}

int my_encrypt_pesudo_header(uint8_t *data,uint8_t *output,int &len,uint8_t * key,uint8_t *header,int hlen)
{

	return 0;
}
int my_decrypt_pesudo_header(uint8_t *data,uint8_t *output,int &len,uint8_t * key,uint8_t *header,int hlen)
{
	return 0;
}

