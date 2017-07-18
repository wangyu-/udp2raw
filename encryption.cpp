#include <aes.h>
#include <md5.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

//static uint64_t seq=1;

static uint8_t zero_iv[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0};//this prog use zero iv,you should make sure first block of data contains a random/nonce data

static uint8_t g_key[]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,   0,0,0,0};

static uint8_t buf[65535+100];


int my_encrypt(uint8_t *data,uint8_t *output,int &len,uint8_t * key)
{
	memcpy(output,data,len);
	return 0;

	int ori_len=len;

	len=len+16;//md5
	len+=2;//length

	if(len%16!=0)
	{
		len= (len/16)*16+16;
	}

	if(len>65535) return -1;

	data[len-16-2]=(uint16_t(ori_len))>>8;
	data[len-16-1]=((uint16_t(ori_len))<<8)>>8;


	//printf("%d %d\n",data[len-16-2],data[len-16-1]);
	md5(data,len-16,data+len-16);

	//memcpy(buf,data,len);  //not thread safe

	AES_CBC_encrypt_buffer((unsigned char *)output,(unsigned char *)data,len,(unsigned char *)key,(unsigned char *)zero_iv);
	//it doesnt allow over lap

	return 0;
}
int my_decrypt(uint8_t *data,uint8_t *output,int &len,uint8_t * key)
{
	memcpy(output,data,len);
	return 0;

	uint8_t md5_res[16];
	if(len>65535) return -1;
	if(len<32) return -1;
	if(len%16 !=0) return -1;

	//memcpy(buf,data,len);

	AES_CBC_decrypt_buffer((unsigned char *)output,(unsigned char *)data,len,(unsigned char *)key,(unsigned char *)zero_iv);

	//printf("%d %d\n",data[len-16-2],data[len-16-1]);

	//printf("<<%d>>",len);
	md5(output,len-16,md5_res);

	if(memcmp(output+len-16,md5_res,16)!=0)
	{
		return -2;
	}

	len=output[len-16-2]*256u+output[len-16-1];

	return 0;
}

