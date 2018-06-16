/*
 * common.h
 *
 *  Created on: Jul 29, 2017
 *      Author: wangyu
 */

#ifndef UDP2RAW_COMMON_H_
#define UDP2RAW_COMMON_H_
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<getopt.h>

#include<unistd.h>
#include<errno.h>
//#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/socket.h>    //for socket ofcourse
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netdb.h> // for gethostbyname()
//#include <netinet/tcp.h>   //Provides declarations for tcp header
//#include <netinet/udp.h>
//#include <netinet/ip.h>    //Provides declarations for ip header
//#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <fcntl.h>
//#include <byteswap.h>
#include <arpa/inet.h>
//#include <linux/if_ether.h>
//#include <linux/filter.h>
#include <sys/time.h>
#include <time.h>
//#include <sys/timerfd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <assert.h>
//#include <linux/if_packet.h>
//#include <byteswap.h>
#include <pthread.h>

#ifndef __CYGWIN__
#include <pcap.h>
#else
#include <pcap_wrapper.h>
#define NO_LIBNET
#endif

#ifndef NO_LIBNET
#include <libnet.h>
#endif

#include <my_ev.h>

#include<unordered_map>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
using  namespace std;

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN || \
    defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ || \
    defined(__BIG_ENDIAN__) || \
    defined(__ARMEB__) || \
    defined(__THUMBEB__) || \
    defined(__AARCH64EB__) || \
    defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__)
#define UDP2RAW_BIG_ENDIAN 1
#endif


#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
    defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ || \
    defined(__LITTLE_ENDIAN__) || \
    defined(__ARMEL__) || \
    defined(__THUMBEL__) || \
    defined(__AARCH64EL__) || \
    defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
#define UDP2RAW_LITTLE_ENDIAN 1
#endif

#if defined(UDP2RAW_BIG_ENDIAN) &&defined(UDP2RAW_LITTLE_ENDIAN)
#error "endian detection conflicts"
#endif


#if !defined(UDP2RAW_BIG_ENDIAN) && !defined(UDP2RAW_LITTLE_ENDIAN)
#error "endian detection failed"
#endif


typedef unsigned long long u64_t;   //this works on most platform,avoid using the PRId64
typedef long long i64_t;

typedef unsigned int u32_t;
typedef int i32_t;

typedef u32_t my_id_t;

typedef u64_t iv_t;

typedef u64_t padding_t;

typedef u64_t anti_replay_seq_t;


struct ip_port_t
{
	u32_t ip;
	int port;
	void from_u64(u64_t u64);
	u64_t to_u64();
	char * to_s();
};


typedef u64_t fd64_t;

const int max_data_len=1800;
const int buf_len=max_data_len+400;
const int max_address_len=512;
const int queue_len=2000;

struct queue_t
{
	char data[queue_len][buf_len];
	int data_len[queue_len];

	int head=0;
	int tail=0;
	void clear()
	{
		head=tail=0;
	}
	int empty()
	{
		if(head==tail) return 1;
		else return 0;
	}
	int full()
	{
		if( (tail+1)%queue_len==head  ) return 1;
		else return 0;
	}
	void peek_front(char * & p,int &len)
	{
		assert(!empty());
		p=data[head];
		len=data_len[head];
	}
	void pop_front()
	{
		assert(!empty());
		head++;head%=queue_len;
	}
	void push_back(char * p,int len)
	{
		assert(!full());
		memcpy(data[tail],p,len);
		data_len[tail]=len;
		tail++;tail%=queue_len;
	}
};


u64_t get_current_time();
u64_t pack_u64(u32_t a,u32_t b);

u32_t get_u64_h(u64_t a);

u32_t get_u64_l(u64_t a);

char * my_ntoa(u32_t ip);

void init_random_number_fd();
u64_t get_true_random_number_64();
u32_t get_true_random_number();
u32_t get_true_random_number_nz();
u64_t ntoh64(u64_t a);
u64_t hton64(u64_t a);
bool larger_than_u16(uint16_t a,uint16_t b);
bool larger_than_u32(u32_t a,u32_t b);
void setnonblocking(int sock);
int set_buf_size(int fd,int socket_buf_size,int force_socket_buf);

void myexit(int a);

unsigned short csum(const unsigned short *ptr,int nbytes);

int numbers_to_char(my_id_t id1,my_id_t id2,my_id_t id3,char * &data,int &len);
int char_to_numbers(const char * data,int len,my_id_t &id1,my_id_t &id2,my_id_t &id3);

const int show_none=0;
const int show_command=0x1;
const int show_log=0x2;
const int show_all=show_command|show_log;

int run_command(string command,char * &output,int flag=show_all);
//int run_command_no_log(string command,char * &output);
int read_file(const char * file,string &output);

vector<string> string_to_vec(const char * s,const char * sp);
vector< vector <string> > string_to_vec2(const char * s);

string trim(const string& str, char c);

string trim_conf_line(const string& str);

vector<string> parse_conf_line(const string& s);

int hex_to_u32_with_endian(const string & a,u32_t &output);
int hex_to_u32(const string & a,u32_t &output);
//extern string iptables_pattern;

int create_fifo(char * file);

#endif /* COMMON_H_ */
