#include "lib/aes.h"
#include "lib/md5.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "encrypt.h"
#include "common.h"
#include "log.h"

//static uint64_t seq=1;

static int8_t zero_iv[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0};//this prog use zero iv,you should make sure first block of data contains a random/nonce data
/****
 * security of zero_iv + nonce first data block
 * https://crypto.stackexchange.com/questions/5421/using-cbc-with-a-fixed-iv-and-a-random-first-plaintext-block
****/

char key[16];//generated from key_string by md5.
//TODO key derive function

unordered_map<int, const char *> auth_mode_tostring = {{auth_none, "none"}, {auth_md5, "md5"}, {auth_crc32, "crc32"},{auth_simple,"simple"}};
//TODO HMAC-md5 ,HMAC-sha1

unordered_map<int, const char *> cipher_mode_tostring={{cipher_none,"none"},{cipher_aes128cbc,"aes128cbc"},{cipher_xor,"xor"}};
//TODO aes-gcm

auth_mode_t auth_mode=auth_md5;
cipher_mode_t cipher_mode=cipher_aes128cbc;


/*
 *  this function comes from  http://www.hackersdelight.org/hdcodetxt/crc.c.txt
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

/*
 void sum(const unsigned  char *data,int len,unsigned char*  res) {
   memset(res,0,sizeof(int));
   for(int i=0,j=0;i<len;i++,j++)
   {
	   if(j==4) j=0;
	   res[j]+=data[i];
   }

   return ;
}*/

void simple_hash(unsigned char *str,int len,unsigned char res[8])   //djb2+ sdbm
{
	 u32_t hash = 5381;
     u32_t hash2 = 0;
     int c;
     int i=0;
    while(c = *str++,i++!=len)
    {
        // hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
         hash = ((hash << 5) + hash)^c; /* (hash * 33) ^ c */
         hash2 = c + (hash2 << 6) + (hash2 << 16) - hash2;
    }

     hash=htonl(hash);
     hash2=htonl(hash2);
     memcpy(res,&hash,sizeof(hash));
     memcpy(res+sizeof(hash),&hash2,sizeof(hash2));
 }

int auth_md5_cal(const char *data,char * output,int &len)
{
	memcpy(output,data,len);//TODO inefficient code
	md5((unsigned char *)output,len,(unsigned char *)(output+len));
	len+=16;
	return 0;
}

int auth_crc32_cal(const char *data,char * output,int &len)
{
	memcpy(output,data,len);//TODO inefficient code
	unsigned int  ret=crc32h((unsigned char *)output,len);
	unsigned int  ret_n=htonl(ret);
	memcpy(output+len,&ret_n,sizeof(unsigned int));
	len+=sizeof(unsigned int);
	return 0;
}

int auth_simple_cal(const char *data,char * output,int &len)
{
	//char res[4];
	memcpy(output,data,len);//TODO inefficient code
	simple_hash((unsigned char *)output,len,(unsigned char *)(output+len));
	len+=8;
	return 0;
}
int auth_simple_verify(const char *data,int &len)
{
	if(len<8) return -1;
	unsigned char res[8];
	len-=8;
	simple_hash((unsigned char *)data,len,res);
	if(memcmp(res,data+len,8)!=0)
		return -1;
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
		mylog(log_trace,"auth_md5_verify len<16\n");
		return -1;
	}
	char md5_res[16];

	md5((unsigned char *)data,len-16,(unsigned char *)md5_res);

	if(memcmp(md5_res,data+len-16,16)!=0)
	{
		mylog(log_trace,"auth_md5_verify md5 check failed\n");
		return -2;
	}
	len-=16;
	return 0;
}
int auth_none_verify(const char *data,int &len)
{
	return 0;
}

int cipher_xor_encrypt(const char * data, char *output,int &len, char *key) {
        int i, j;
        for (i = 0, j = 0; i < len; i++, j++) {
        	if(j==16) j=0;
                output[i] = data[i]^key[j];
        }
        return 0;
}
int cipher_xor_decrypt(const char * data, char *output,int &len, char *key) {
        int i, j;
        //char tmp[buf_len];
        //len=len/16*16+1;
        //AES128_CBC_decrypt_buffer((uint8_t *)tmp, (uint8_t *)input, len, (uint8_t *)key, (uint8_t *)iv);
        //for(i=0;i<len;i++)
        //input[i]=tmp[i];
        for (i = 0, j = 0; i < len; i++, j++) {
        	if(j==16) j=0;
        	output[i] = data[i]^key[j];
        }
        return 0;
}

int padding(char *data ,int &data_len,int padding_num)
{
	int old_len=data_len;
	data_len+=1;
	if(data_len%padding_num!=0)
	{
		data_len= (data_len/padding_num)*padding_num+padding_num;
	}
	data[data_len-1]= (data_len-old_len);
	return 0;
}

int de_padding(const char *data ,int &data_len,int padding_num)
{
	if((uint8_t)data[data_len-1]  >padding_num) return -1;
	data_len-=(uint8_t)data[data_len-1];
	if(data_len<0)
	{
		return -1;
	}
	return 0;
}
int cipher_aes128cbc_encrypt(const char *data,char *output,int &len,char * key)
{
	static int first_time=1;

	char buf[buf_len];
	memcpy(buf,data,len);//TODO inefficient code


	/*
	int ori_len=len;
	len+=2;//length
	if(len%16!=0)
	{
		len= (len/16)*16+16;
	}
	//if(len>max_data_len) return -1;

	buf[len-2]= (unsigned char)( (uint16_t(ori_len))>>8);
	buf[len-1]=(unsigned char)( ((uint16_t(ori_len))<<8)>>8) ;*/
	if(padding(buf,len,16)<0) return -1;

	if(aes_key_optimize)
	{
		if(first_time==0) key=0;
		else first_time=0;
	}

	AES_CBC_encrypt_buffer((unsigned char *)output,(unsigned char *)buf,len,(unsigned char *)key,(unsigned char *)zero_iv);
	return 0;
}
int auth_crc32_verify(const char *data,int &len)
{
	if(len<int(sizeof(unsigned int)))
	{
		mylog(log_debug,"auth_crc32_verify len<%d\n",int(sizeof(unsigned int)));
		return -1;
	}
	unsigned int  ret=crc32h((unsigned char *)data,len-sizeof(unsigned int));
	unsigned int  ret_n=htonl(ret);

	if(memcmp(data+len-sizeof(unsigned int),&ret_n,sizeof(unsigned int))!=0)
	{
		mylog(log_debug,"auth_crc32_verify memcmp fail\n");
		return -1;
	}
	len-=sizeof(unsigned int);
	return 0;
}
int cipher_none_encrypt(const char *data,char *output,int &len,char * key)
{
	memcpy(output,data,len);
	return 0;
}
int cipher_aes128cbc_decrypt(const char *data,char *output,int &len,char * key)
{
	static int first_time=1;
	if(len%16 !=0) {mylog(log_debug,"len%%16!=0\n");return -1;}
	//if(len<0) {mylog(log_debug,"len <0\n");return -1;}
	if(aes_key_optimize)
	{
		if(first_time==0) key=0;
		else first_time=0;
	}
	AES_CBC_decrypt_buffer((unsigned char *)output,(unsigned char *)data,len,(unsigned char *)key,(unsigned char *)zero_iv);
	if(de_padding(output,len,16)<0) return -1;
	return 0;
}

int cipher_none_decrypt(const char *data,char *output,int &len,char * key)
{
	memcpy(output,data,len);
	return 0;
}

int auth_cal(const char *data,char * output,int &len)
{
	mylog(log_trace,"auth:%d\n",auth_mode);
	switch(auth_mode)
	{
	case auth_crc32:return auth_crc32_cal(data, output, len);
	case auth_md5:return auth_md5_cal(data, output, len);
	case auth_simple:return auth_simple_cal(data, output, len);
	case auth_none:return auth_none_cal(data, output, len);
	default:	return auth_md5_cal(data,output,len);//default
	}

}
int auth_verify(const char *data,int &len)
{
	mylog(log_trace,"auth:%d\n",auth_mode);
	switch(auth_mode)
	{
	case auth_crc32:return auth_crc32_verify(data, len);
	case auth_md5:return auth_md5_verify(data, len);
	case auth_simple:return auth_simple_verify(data, len);
	case auth_none:return auth_none_verify(data, len);
	default:	return auth_md5_verify(data,len);//default
	}

}
int cipher_encrypt(const char *data,char *output,int &len,char * key)
{
	mylog(log_trace,"cipher:%d\n",cipher_mode);
	switch(cipher_mode)
	{
	case cipher_aes128cbc:return cipher_aes128cbc_encrypt(data,output,len, key);
	case cipher_xor:return cipher_xor_encrypt(data,output,len, key);
	case cipher_none:return cipher_none_encrypt(data,output,len, key);
	default:return cipher_aes128cbc_encrypt(data,output,len, key);
	}

}
int cipher_decrypt(const char *data,char *output,int &len,char * key)
{
	mylog(log_trace,"cipher:%d\n",cipher_mode);
	switch(cipher_mode)
	{
		case cipher_aes128cbc:return cipher_aes128cbc_decrypt(data,output,len, key);
		case cipher_xor:return cipher_xor_decrypt(data,output,len, key);
		case cipher_none:return cipher_none_decrypt(data,output,len, key);
		default:	return cipher_aes128cbc_decrypt(data,output,len,key);
	}

}


int my_encrypt(const char *data,char *output,int &len,char * key)
{
	if(len<0) {mylog(log_trace,"len<0");return -1;}
	if(len>max_data_len) {mylog(log_warn,"len>max_data_len");return -1;}

	char buf[buf_len];
	char buf2[buf_len];
	memcpy(buf,data,len);
	if(auth_cal(buf,buf2,len)!=0) {mylog(log_debug,"auth_cal failed ");return -1;}
	if(cipher_encrypt(buf2,output,len,key) !=0) {mylog(log_debug,"cipher_encrypt failed ");return -1;}
	return 0;

}

int my_decrypt(const char *data,char *output,int &len,char * key)
{
	if(len<0) return -1;
	if(len>max_data_len) {mylog(log_warn,"len>max_data_len");return -1;}

	if(cipher_decrypt(data,output,len,key) !=0) {mylog(log_debug,"cipher_decrypt failed \n"); return -1;}
	if(auth_verify(output,len)!=0) {mylog(log_debug,"auth_verify failed\n");return -1;}

	return 0;
}

int encrypt_AE(const char *data,char *output,int &len,char * key)
{
	//TODO
	//use encrypt-then-MAC scheme
	return -1;
}

int decrypt_AE(const char *data,char *output,int &len,char * key)
{
	//TODO
	return -1;
}

int encrypt_AEAD(uint8_t *data,uint8_t *output,int &len,uint8_t * key,uint8_t *header,int hlen)
{
	//TODO
	return -1;
}

int decrypt_AEAD(uint8_t *data,uint8_t *output,int &len,uint8_t * key,uint8_t *header,int hlen)
{
	//TODO
	return -1;
}

