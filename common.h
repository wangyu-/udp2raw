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
#include <sys/stat.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>
#include <pthread.h>

#if defined(UDP2RAW_MP)

#if !defined(__CYGWIN__) && !defined(__MINGW32__)
#include <pcap.h>
#else
#include <pcap_wrapper.h>
#define NO_LIBNET
#endif

#ifndef NO_LIBNET
#include <libnet.h>
#endif

#else

//#include <linux/if_ether.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <sys/epoll.h>
//#include <sys/wait.h> //signal
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/timerfd.h>

#endif

#include <my_ev.h>

#if defined(__MINGW32__)
#include <winsock2.h>
#include <ws2ipdef.h>
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif


#include<unordered_map>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <list>
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


#if defined(__MINGW32__)
int inet_pton(int af, const char *src, void *dst);
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
#define setsockopt(a,b,c,d,e) setsockopt(a,b,c,(const char *)(d),e)
#endif

char *get_sock_error();
int get_sock_errno();

#if defined(__MINGW32__)
typedef SOCKET my_fd_t;
inline int sock_close(my_fd_t fd)
{
	return closesocket(fd);
}
#else
typedef int my_fd_t;
inline int sock_close(my_fd_t fd)
{
	return close(fd);
}

#endif


typedef unsigned long long u64_t;   //this works on most platform,avoid using the PRId64
typedef long long i64_t;

typedef unsigned int u32_t;
typedef int i32_t;

typedef unsigned short u16_t;
typedef short i16_t;

typedef u32_t my_id_t;

typedef u64_t iv_t;

typedef u64_t padding_t;

typedef u64_t anti_replay_seq_t;

typedef u64_t my_time_t;

const int max_addr_len=100;

extern int force_socket_buf;

extern int g_fix_gro;

/*
struct ip_port_t
{
	u32_t ip;
	int port;
	void from_u64(u64_t u64);
	u64_t to_u64();
	char * to_s();
};*/

typedef u64_t fd64_t;

u32_t djb2(unsigned char *str,int len);
u32_t sdbm(unsigned char *str,int len);

struct address_t  //TODO scope id
{
	struct hash_function
	{
	    u32_t operator()(const address_t &key) const
		{
	    	return sdbm((unsigned char*)&key.inner,sizeof(key.inner));
		}
	};

	union storage_t //sockaddr_storage is too huge, we dont use it.
	{
		sockaddr_in ipv4;
		sockaddr_in6 ipv6;
	};
	storage_t inner;

	address_t()
	{
		clear();
	}
	void clear()
	{
		memset(&inner,0,sizeof(inner));
	}
	int from_ip_port(u32_t  ip, int port)
	{
		clear();
		inner.ipv4.sin_family=AF_INET;
		inner.ipv4.sin_port=htons(port);
		inner.ipv4.sin_addr.s_addr=ip;
		return 0;
	}

	int from_ip_port_new(int type, void *  ip, int port)
	{
		clear();
		if(type==AF_INET)
		{
			inner.ipv4.sin_family=AF_INET;
			inner.ipv4.sin_port=htons(port);
			inner.ipv4.sin_addr.s_addr=*((u32_t *)ip);
		}
		else if(type==AF_INET6)
		{
			inner.ipv6.sin6_family=AF_INET6;
			inner.ipv6.sin6_port=htons(port);
			inner.ipv6.sin6_addr=*((in6_addr*)ip);
		}
		return 0;
	}

	int from_str(char * str);

	int from_str_ip_only(char * str);

	int from_sockaddr(sockaddr *,socklen_t);

	char* get_str();
	void to_str(char *);

	inline u32_t get_type()
	{
		u32_t ret=((sockaddr*)&inner)->sa_family;
		assert(ret==AF_INET||ret==AF_INET6);
		return ret;
	}

	inline u32_t get_len()
	{
		u32_t type=get_type();
		switch(type)
		{
			case AF_INET:
				return sizeof(sockaddr_in);
			case AF_INET6:
				return sizeof(sockaddr_in6);
			default:
				assert(0==1);
		}
		return -1;
	}

	inline u32_t get_port()
	{
		u32_t type=get_type();
		switch(type)
		{
			case AF_INET:
				return ntohs(inner.ipv4.sin_port);
			case AF_INET6:
				return ntohs(inner.ipv6.sin6_port);
			default:
				assert(0==1);
		}
		return -1;
	}

	inline void set_port(int port)
	{
		u32_t type=get_type();
		switch(type)
		{
			case AF_INET:
				inner.ipv4.sin_port=htons(port);
				break;
			case AF_INET6:
				inner.ipv6.sin6_port=htons(port);
				break;
			default:
				assert(0==1);
		}
		return ;
	}

    bool operator == (const address_t &b) const
    {
    	//return this->data==b.data;
        return memcmp(&this->inner,&b.inner,sizeof(this->inner))==0;
    }

    int new_connected_udp_fd();

    char* get_ip();
};

namespace std {
template <>
 struct hash<address_t>
 {
   std::size_t operator()(const address_t& key) const
   {

	 //return address_t::hash_function(k);
	   return sdbm((unsigned char*)&key.inner,sizeof(key.inner));
   }
 };
}

union my_ip_t //just a simple version of address_t,stores ip only
{
	u32_t v4;
	in6_addr v6;

    bool equal (const my_ip_t &b) const;

    //int from_str(char * str);
    char * get_str1() const;
    char * get_str2() const;

    int from_address_t(address_t a);

};

struct not_copy_able_t
{
	not_copy_able_t()
	{

	}
	not_copy_able_t(const not_copy_able_t &other)
	{
		assert(0==1);
	}
	const not_copy_able_t & operator=(const not_copy_able_t &other)
	{
		assert(0==1);
		return other;
	}
};

const int huge_data_len=65535+100; //a packet with link level header might be larger than 65535
const int huge_buf_len=huge_data_len+100;

const int max_data_len=1800;
const int buf_len=max_data_len+400;

//const int max_address_len=512;

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

void write_u16(char *,u16_t a);// network order
u16_t read_u16(char *);
void write_u32(char *,u32_t a);// network order
u32_t read_u32(char *);
void write_u64(char *,u64_t a);
u64_t read_u64(char *);

bool larger_than_u16(uint16_t a,uint16_t b);
bool larger_than_u32(u32_t a,u32_t b);
void setnonblocking(int sock);
int set_buf_size(int fd,int socket_buf_size);

void myexit(int a);

unsigned short csum(const unsigned short *ptr,int nbytes);
unsigned short csum_with_header(char* header,int hlen,const unsigned short *ptr,int nbytes);

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

void print_binary_chars(const char * a,int len);

template <class key_t>
struct lru_collector_t:not_copy_able_t
{
	//typedef void* key_t;
//#define key_t void*
	struct lru_pair_t
	{
		key_t key;
		my_time_t ts;
	};

	unordered_map<key_t,typename list<lru_pair_t>::iterator> mp;

	list<lru_pair_t> q;
	int update(key_t key)
	{
		assert(mp.find(key)!=mp.end());
		auto it=mp[key];
		q.erase(it);

		my_time_t value=get_current_time();
		if(!q.empty())
		{
			assert(value >=q.front().ts);
		}
		lru_pair_t tmp; tmp.key=key; tmp.ts=value;
		q.push_front( tmp);
		mp[key]=q.begin();

		return 0;
	}
	int new_key(key_t key)
	{
		assert(mp.find(key)==mp.end());

		my_time_t value=get_current_time();
		if(!q.empty())
		{
			assert(value >=q.front().ts);
		}
		lru_pair_t tmp; tmp.key=key; tmp.ts=value;
		q.push_front( tmp);
		mp[key]=q.begin();

		return 0;
	}
	int size()
	{
		return q.size();
	}
	int empty()
	{
		return q.empty();
	}
	void clear()
	{
		mp.clear(); q.clear();
	}
	my_time_t ts_of(key_t key)
	{
		assert(mp.find(key)!=mp.end());
		return mp[key]->ts;
	}

	my_time_t peek_back(key_t &key)
	{
		assert(!q.empty());
		auto it=q.end(); it--;
		key=it->key;
		return it->ts;
	}
	void erase(key_t key)
	{
		assert(mp.find(key)!=mp.end());
		q.erase(mp[key]);
		mp.erase(key);
	}
	/*
	void erase_back()
	{
		assert(!q.empty());
		auto it=q.end(); it--;
		key_t key=it->key;
		erase(key);
	}*/
};


#endif /* COMMON_H_ */
