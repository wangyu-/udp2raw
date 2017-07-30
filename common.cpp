/*
 * comm.cpp
 *
 *  Created on: Jul 29, 2017
 *      Author: wangyu
 */

#include "common.h"
#include "log.h"


raw_mode_t raw_mode=mode_faketcp;
unordered_map<int, const char*> raw_mode_tostring = {{mode_faketcp, "faketcp"}, {mode_udp, "udp"}, {mode_icmp, "icmp"}};
int socket_buf_size=1024*1024;
static int random_number_fd=-1;


uint64_t get_current_time()
{
	timespec tmp_time;
	clock_gettime(CLOCK_MONOTONIC, &tmp_time);
	return tmp_time.tv_sec*1000+tmp_time.tv_nsec/(1000*1000l);
}

uint64_t pack_u64(uint32_t a,uint32_t b)
{
	uint64_t ret=a;
	ret<<=32u;
	ret+=b;
	return ret;
}
uint32_t get_u64_h(uint64_t a)
{
	return a>>32u;
}
uint32_t get_u64_l(uint64_t a)
{
	return (a<<32u)>>32u;
}

char * my_ntoa(uint32_t ip)
{
	in_addr a;
	a.s_addr=ip;
	return inet_ntoa(a);
}



void myexit(int a)
{
    if(enable_log_color)
    	 printf(RESET);
	exit(a);
}



void init_random_number_fd()
{
	random_number_fd=open("/dev/urandom",O_RDONLY);
	if(random_number_fd==-1)
	{
		mylog(log_fatal,"error open /dev/urandom\n");
		myexit(-1);
	}
}
uint64_t get_true_random_number_64()
{
	uint64_t ret;
	read(random_number_fd,&ret,sizeof(ret));
	return ret;
}
uint32_t get_true_random_number()
{
	uint32_t ret;
	read(random_number_fd,&ret,sizeof(ret));
	return ret;
}
uint32_t get_true_random_number_nz() //nz for non-zero
{
	uint32_t ret=0;
	while(ret==0)
	{
		ret=get_true_random_number();
	}
	return ret;
}
uint64_t ntoh64(uint64_t a)
{
	if(__BYTE_ORDER == __LITTLE_ENDIAN)
	{
		return __bswap_64( a);
	}
	else return a;

}
uint64_t hton64(uint64_t a)
{
	if(__BYTE_ORDER == __LITTLE_ENDIAN)
	{
		return __bswap_64( a);
	}
	else return a;

}

void setnonblocking(int sock) {
	int opts;
	opts = fcntl(sock, F_GETFL);

	if (opts < 0) {
    	mylog(log_fatal,"fcntl(sock,GETFL)\n");
		//perror("fcntl(sock,GETFL)");
		myexit(1);
	}
	opts = opts | O_NONBLOCK;
	if (fcntl(sock, F_SETFL, opts) < 0) {
    	mylog(log_fatal,"fcntl(sock,SETFL,opts)\n");
		//perror("fcntl(sock,SETFL,opts)");
		myexit(1);
	}

}

/*
    Generic checksum calculation function
*/
unsigned short csum(const unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

int set_buf_size(int fd)
{
    if(setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
    {
    	mylog(log_fatal,"SO_SNDBUFFORCE fail\n");
    	myexit(1);
    }
    if(setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
    {
    	mylog(log_fatal,"SO_RCVBUFFORCE fail\n");
    	myexit(1);
    }
	return 0;
}

void  INThandler(int sig)
{
     if(enable_log_color)
    	 printf(RESET);
     myexit(0);
}

int numbers_to_char(id_t id1,id_t id2,id_t id3,char * &data,int &len)
{
	static char buf[buf_len];
	data=buf;
	id_t tmp=htonl(id1);
	memcpy(buf,&tmp,sizeof(tmp));

	tmp=htonl(id2);
	memcpy(buf+sizeof(tmp),&tmp,sizeof(tmp));

	tmp=htonl(id3);
	memcpy(buf+sizeof(tmp)*2,&tmp,sizeof(tmp));

	len=sizeof(id_t)*3;
	return 0;
}


int char_to_numbers(const char * data,int len,id_t &id1,id_t &id2,id_t &id3)
{
	if(len<int(sizeof(id_t)*3)) return -1;
	id1=ntohl(  *((id_t*)(data+0)) );
	id2=ntohl(  *((id_t*)(data+sizeof(id_t))) );
	id3=ntohl(  *((id_t*)(data+sizeof(id_t)*2)) );
	return 0;
}


program_mode_t program_mode=unset_mode;//0 unset; 1client 2server
