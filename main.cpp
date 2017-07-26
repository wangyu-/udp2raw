#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<getopt.h>
#include <unistd.h>
#include<errno.h>
 
#include <fcntl.h>

#include <sys/epoll.h>
#include <sys/wait.h>

#include<map>
#include<string>
#include<vector>


#include <sys/socket.h>    //for socket ofcourse
#include <sys/types.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/udp.h>
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <byteswap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

#include <sys/time.h>
#include <time.h>

#include <sys/timerfd.h>
#include <set>
#include <encrypt.h>
#include <inttypes.h>

#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include "log.h"

#include <unordered_map>


/*
#include <ext/hash_map>

using namespace __gnu_cxx;*/
using namespace std;

/*
#if __cplusplus <= 199711L
#define my_hash_map map
#else
#define my_hash_map unordered_map
#end*/

enum raw_mode_t{mode_faketcp=1,mode_udp,mode_icmp,mode_end};
raw_mode_t raw_mode=mode_faketcp;
map<int, string> raw_mode_tostring = {{mode_faketcp, "faketcp"}, {mode_udp, "udp"}, {mode_icmp, "icmp"}};

char local_address[100]="0.0.0.0", remote_address[100]="255.255.255.255",source_address[100]="0.0.0.0";
uint32_t local_address_uint32,remote_address_uint32,source_address_uint32;

uint32_t source_port=0;
int filter_port=-1;

int local_port = -1, remote_port = -1;


typedef uint32_t id_t;

typedef uint64_t iv_t;

typedef uint64_t anti_replay_seq_t;

anti_replay_seq_t anti_replay_seq=0;

id_t const_id=0;

id_t oppsite_const_id=0;

id_t my_id=0;
id_t oppsite_id=0;

uint32_t conv_num=0;

uint32_t link_level_header_len=0;//set it to 14 if SOCK_RAW is used in socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));

const int handshake_timeout=2000;

const int heartbeat_timeout=10000;
const int udp_timeout=3000;

const int heartbeat_interval=1000;

const int timer_interval=500;

const int RETRY_TIME=3;

//const uint16_t tcp_window=50000;
extern const int max_data_len=65535;
extern const int buf_len = max_data_len+100;


enum program_mode_t {unset_mode=0,client_mode,server_mode};
program_mode_t program_mode=unset_mode;//0 unset; 1client 2server




int disable_bpf_filter=0;  //for test only,most time no need to disable this

const int disable_conv_clear=0;



int first_data_packet=0;

int seq_mode=2;  //0  dont  increase /1 increase   //increase randomly,about every 5 packet

const uint64_t epoll_timer_fd_sn=1;
const uint64_t epoll_raw_recv_fd_sn=2;
const uint64_t epoll_udp_fd_sn_begin=0xFFFFFFFFllu+1;
uint64_t epoll_udp_fd_sn=epoll_udp_fd_sn_begin;  //all udp_fd_sn > max uint32


enum server_current_state_t {server_nothing=0,server_syn_ack_sent,server_handshake_sent,server_ready};
server_current_state_t server_current_state=server_nothing;

long long last_hb_recv_time=0;
long long last_udp_recv_time=0;

int socket_buf_size=1024*1024;

int udp_fd=-1;
int raw_recv_fd;
int raw_send_fd;
int bind_fd;
int epollfd ;

enum client_current_state_t {client_nothing=0,client_syn_sent,client_ack_sent,client_handshake_sent,client_ready};
client_current_state_t client_current_state=client_nothing;

int retry_counter;

long long last_state_time=0;

long long last_hb_sent_time=0;


struct sock_filter code_tcp_old[] = {
		{ 0x28, 0, 0, 0x0000000c },//0
		{ 0x15, 0, 10, 0x00000800 },//1
		{ 0x30, 0, 0, 0x00000017 },//2
		{ 0x15, 0, 8, 0x00000006 },//3
		{ 0x28, 0, 0, 0x00000014 },//4
		{ 0x45, 6, 0, 0x00001fff },//5
		{ 0xb1, 0, 0, 0x0000000e },//6
		{ 0x48, 0, 0, 0x0000000e },//7
		{ 0x15, 2, 0, 0x0000ef32 },//8
		{ 0x48, 0, 0, 0x00000010 },//9
		{ 0x15, 0, 1, 0x0000ef32 },//10
		{ 0x6, 0, 0, 0x0000ffff },//11
		{ 0x6, 0, 0, 0x00000000 },//12
};
struct sock_filter code_tcp[] = {
{ 0x5, 0, 0, 0x00000001 },//0    //jump to 2,dirty hack from tcpdump -d's output
{ 0x5, 0, 0, 0x00000000 },//1
{ 0x30, 0, 0, 0x00000009 },//2
{ 0x15, 0, 6, 0x00000006 },//3
{ 0x28, 0, 0, 0x00000006 },//4
{ 0x45, 4, 0, 0x00001fff },//5
{ 0xb1, 0, 0, 0x00000000 },//6
{ 0x48, 0, 0, 0x00000002 },//7
{ 0x15, 0, 1, 0x0000fffe },//8
{ 0x6, 0, 0, 0x0000ffff },//9
{ 0x6, 0, 0, 0x00000000 },//10
};
int code_tcp_port_index=8;

struct sock_filter code_udp[] = {
{ 0x5, 0, 0, 0x00000001 },
{ 0x5, 0, 0, 0x00000000 },
{ 0x30, 0, 0, 0x00000009 },
{ 0x15, 0, 6, 0x00000011 },
{ 0x28, 0, 0, 0x00000006 },
{ 0x45, 4, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x00000000 },
{ 0x48, 0, 0, 0x00000002 },
{ 0x15, 0, 1, 0x0000fffe },
{ 0x6, 0, 0, 0x0000ffff },
{ 0x6, 0, 0, 0x00000000 },
};
int code_udp_port_index=8;
struct sock_filter code_icmp[] = {
{ 0x5, 0, 0, 0x00000001 },
{ 0x5, 0, 0, 0x00000000 },
{ 0x30, 0, 0, 0x00000009 },
{ 0x15, 0, 1, 0x00000001 },
{ 0x6, 0, 0, 0x0000ffff },
{ 0x6, 0, 0, 0x00000000 },
};

/*

tcpdump -i eth1  ip and icmp -d
(000) ldh      [12]
(001) jeq      #0x800           jt 2    jf 5
(002) ldb      [23]
(003) jeq      #0x1             jt 4    jf 5
(004) ret      #65535
(005) ret      #0

tcpdump -i eth1  ip and icmp -dd
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 3, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 1, 0x00000001 },
{ 0x6, 0, 0, 0x0000ffff },
{ 0x6, 0, 0, 0x00000000 },


 */
/*
  tcpdump -i eth1 ip and tcp and dst port 65534 -dd

{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 8, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 6, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 4, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x0000fffe },
{ 0x6, 0, 0, 0x0000ffff },
{ 0x6, 0, 0, 0x00000000 },

 (000) ldh      [12]
(001) jeq      #0x800           jt 2    jf 10
(002) ldb      [23]
(003) jeq      #0x6             jt 4    jf 10
(004) ldh      [20]
(005) jset     #0x1fff          jt 10   jf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 16]
(008) jeq      #0xfffe          jt 9    jf 10
(009) ret      #65535
(010) ret      #0

 */
sock_fprog bpf;


//

//struct sockaddr_in udp_old_addr_in;

char key_string[1000]= "secret key";
char key[]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,   0,0,0,0};

char key2[16];

//uint8_t key_oppsite[16];

const int anti_replay_window_size=1000;


int random_number_fd=-1;

const int conv_timeout=60000; //60 second
const int conv_clear_ratio=10;



//sockaddr_in g_tmp_sockaddr;  //global  sockaddr_in for efficiency,so that you wont need to create it everytime

int VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV;
////////==============================variable divider=============================================================


struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
struct icmphdr
{
	uint8_t type;
	uint8_t code;
	uint16_t check_sum;
	uint16_t id;
	uint16_t seq;
};

struct anti_replay_t
{
	uint64_t max_packet_received;
	char window[anti_replay_window_size];
	char disabled;
	anti_replay_t()
	{
		disabled=0;
		max_packet_received=0;
		//memset(window,0,sizeof(window)); //not necessary
	}
	void re_init()
	{
		disabled=0;
		max_packet_received=0;
		//memset(window,0,sizeof(window));
	}
	void disable()
	{
		disabled=1;
	}
	void enable()
	{
		disabled=0;
	}

	int is_vaild(uint64_t seq)
	{
		//if(disabled) return 0;

		if(seq==max_packet_received) return 0||disabled;
		else if(seq>max_packet_received)
		{
			if(seq-max_packet_received>=anti_replay_window_size)
			{
				memset(window,0,sizeof(window));
				window[seq%anti_replay_window_size]=1;
			}
			else
			{
				for (int i=max_packet_received+1;i<seq;i++)
					window[i%anti_replay_window_size]=0;
				window[seq%anti_replay_window_size]=1;
			}
			max_packet_received=seq;
			return 1;
		}
		else if(seq<max_packet_received)
		{
			if(max_packet_received-seq>=anti_replay_window_size) return 0||disabled;
			else
			{
				if (window[seq%anti_replay_window_size]==1) return 0||disabled;
				else
				{
					window[seq%anti_replay_window_size]=1;
					return 1;
				}
			}
		}


		return 0; //for complier check
	}
}anti_replay;

uint32_t get_true_random_number_nz();
long long get_current_time();



struct conv_manager_t  //TODO change map to unordered map
{
	//typedef hash_map map;
	unordered_map<uint64_t,uint32_t> u64_to_conv;  //conv and u64 are both supposed to be uniq
	unordered_map<uint32_t,uint64_t> conv_to_u64;

	unordered_map<uint32_t,uint64_t> conv_last_active_time;

	unordered_map<uint32_t,uint64_t>::iterator clear_it;

	unordered_map<uint32_t,uint64_t>::iterator it;
	unordered_map<uint32_t,uint64_t>::iterator old_it;

	void (*clear_function)(uint64_t u64) ;


	conv_manager_t()
	{
		clear_it=conv_last_active_time.begin();
		clear_function=0;
	}

	void set_clear_function(void (*a)(uint64_t u64))
	{
		clear_function=a;
		u64_to_conv.reserve(100007);
		conv_to_u64.reserve(100007);
		conv_last_active_time.reserve(100007);
	}
	void clear()
	{
		if(disable_conv_clear) return ;

		if(clear_function!=0)
		{
			for(it=conv_to_u64.begin();it!=conv_to_u64.end();it++)
			{
				//int fd=int((it->second<<32u)>>32u);
				clear_function(  it->second);
			}
		}
		u64_to_conv.clear();
		conv_to_u64.clear();
		conv_last_active_time.clear();

		clear_it=conv_last_active_time.begin();

	}
	uint32_t get_new_conv()
	{
		uint32_t conv=get_true_random_number_nz();
		while(conv!=0&&conv_to_u64.find(conv)!=conv_to_u64.end())
		{
			conv=get_true_random_number_nz();
		}
		return conv;
	}
	int is_conv_used(uint32_t conv)
	{
		return conv_to_u64.find(conv)!=conv_to_u64.end();
	}
	int is_u64_used(uint64_t u64)
	{
		return u64_to_conv.find(u64)!=u64_to_conv.end();
	}
	uint32_t find_conv_by_u64(uint64_t u64)
	{
		return u64_to_conv[u64];
	}
	uint64_t find_u64_by_conv(uint32_t conv)
	{
		return conv_to_u64[conv];
	}
	int update_active_time(uint32_t conv)
	{
		return conv_last_active_time[conv]=get_current_time();
	}
	int insert_conv(uint32_t conv,uint64_t u64)
	{
		u64_to_conv[u64]=conv;
		conv_to_u64[conv]=u64;
		conv_last_active_time[conv]=get_current_time();
		return 0;
	}
	int erase_conv(uint32_t conv)
	{
		if(disable_conv_clear) return 0;
		uint64_t u64=conv_to_u64[conv];
		if(clear_function!=0)
		{
			clear_function(u64);
		}
		conv_to_u64.erase(conv);
		u64_to_conv.erase(u64);
		conv_last_active_time.erase(conv);
		mylog(log_info,"conv %x cleared\n");
		return 0;
	}
	int clean_inactive( )
	{
		if(disable_conv_clear) return 0;


		//map<uint32_t,uint64_t>::iterator it;
		int cnt=0;
		it=clear_it;
		int size=conv_last_active_time.size();
		int num_to_clean=size/conv_clear_ratio;   //clear 1/10 each time,to avoid latency glitch

		uint64_t current_time=get_current_time();
		for(;;)
		{
			if(cnt>=num_to_clean) break;
			if(conv_last_active_time.begin()==conv_last_active_time.end()) break;

			if(it==conv_last_active_time.end())
			{
				it=conv_last_active_time.begin();
			}

			if( current_time -it->second  >conv_timeout )
			{
				mylog(log_info,"inactive conv %u cleared \n",it->first);
				old_it=it;
				it++;
				erase_conv(old_it->first);

			}
			else
			{
				it++;
			}
			cnt++;
		}
		return 0;
	}
}conv_manager;


struct packet_info_t
{
	uint8_t protocol;
	//ip_part:
	uint32_t src_ip;
	uint16_t src_port;

	uint32_t dst_ip;
	uint16_t dst_port;

	//tcp_part:
	bool syn,ack,psh,rst;

	uint32_t seq,ack_seq;

	uint32_t ts,ts_ack;


	uint16_t icmp_seq;

	bool has_ts;

}g_packet_info_send,g_packet_info_recv;

int TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT;
////////==========================type divider=======================================================


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
uint32_t get_true_random_number_0()
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
		ret=get_true_random_number_0();
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


int pre_send_deprecate(char * data, int &data_len)
{
	const int disable_encrypt=0;
	const int disable_anti_replay=0;
	char replay_buf[buf_len];
	//return 0;
	if(data_len<0) return -3;

	if(disable_encrypt&&disable_anti_replay) return 0;

	if(!disable_anti_replay)
	{
		anti_replay_seq++;
		uint32_t seq_high= htonl(anti_replay_seq>>32u);

		uint32_t seq_low= htonl((anti_replay_seq<<32u)>>32u);

		memcpy(replay_buf,&seq_high,sizeof(uint32_t));
		memcpy(replay_buf+sizeof(uint32_t),&seq_low,sizeof(uint32_t));

		memcpy(replay_buf+sizeof(uint32_t)*2,data,data_len);

		data_len+=sizeof(uint32_t)*2;
	}
	else
	{
		memcpy(replay_buf,data,data_len);
	}

	if(!disable_encrypt)
	{
		if(my_encrypt(replay_buf,data,data_len,key2) <0)
		{
			mylog(log_debug,"encrypt fail\n");
			return -1;
		}
	}
	else
	{
		memcpy(data,replay_buf,data_len);
	}
	return 0;
}

int pre_recv_deprecated(char * data, int &data_len)
{
	const int disable_encrypt=0;
	const int disable_anti_replay=0;

	char replay_buf[buf_len];
	//return 0;
	if(data_len<0) return -1;

	if(disable_encrypt&&disable_anti_replay) return 0;

	if(!disable_encrypt)
	{
		if(my_decrypt(data,replay_buf,data_len,key2) <0)
		{
			mylog(log_debug,"decrypt fail\n");
			return -1;
		}
		else
		{
			mylog(log_debug,"decrypt succ\n");
		}
	}
	else
	{
		memcpy(replay_buf,data,data_len);
	}

	if(!disable_anti_replay)
	{
		data_len-=sizeof(uint32_t)*2;
		if(data_len<0)
		{
			mylog(log_debug,"data_len<=0\n");
			return -2;
		}

		uint64_t seq_high= ntohl(*((uint32_t*)(replay_buf) ) );
		uint32_t seq_low= ntohl(*((uint32_t*)(replay_buf+sizeof(uint32_t)) ) );
		uint64_t recv_seq =(seq_high<<32u )+seq_low;


		if((program_mode==client_mode&&client_current_state==client_ready)
				||(program_mode==server_mode&&server_current_state==server_ready ))
		{
			if(data_len<sizeof(uint32_t)*2+1)
			{
				mylog(log_debug,"no room for session id and oppiste session_id\n");
				return -4;
			}

			uint32_t tmp_oppiste_session_id = ntohl(
					*((uint32_t*) (replay_buf + sizeof(uint32_t) * 2+1)));
			uint32_t tmp_session_id = ntohl(
					*((uint32_t*) (replay_buf + sizeof(uint32_t) * 3+1)));

			if (tmp_oppiste_session_id != oppsite_id
					|| tmp_session_id != my_id) {
				mylog(log_debug,"auth fail and pre send\n");
				return -5;
			}

			mylog(log_debug,"seq=========%u\n", recv_seq);

			if (anti_replay.is_vaild(recv_seq) != 1) {
				mylog(log_info,"dropped replay packet\n");
				return -1;
			}
		}

		mylog(log_trace,"<<<<<%ld,%d,%ld>>>>\n",seq_high,seq_low,recv_seq);


		memcpy(data,replay_buf+sizeof(uint32_t)*2,data_len);
	}
	else
	{
		memcpy(data,replay_buf,data_len);
	}


	return 0;
}
void  INThandler(int sig)
{
     if(enable_log_color)
    	 printf(RESET);
     myexit(0);
}
void handler(int num) {
	int status;
	int pid;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status)) {
			//printf("The child exit with code %d",WEXITSTATUS(status));
		}
	}
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

int init_raw_socket()
{

	raw_send_fd = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);


    if(raw_send_fd == -1) {
    	mylog(log_fatal,"Failed to create raw_send_fd\n");
        //perror("Failed to create raw_send_fd");
        myexit(1);
    }

    if(setsockopt(raw_send_fd, SOL_SOCKET, SO_SNDBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
    {
    	mylog(log_fatal,"SO_SNDBUFFORCE fail\n");
    	myexit(1);
    }
	//raw_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));

	raw_recv_fd= socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));

    if(raw_recv_fd == -1) {
    	mylog(log_fatal,"Failed to create raw_recv_fd\n");
        //perror("");
        myexit(1);
    }

    if(setsockopt(raw_recv_fd, SOL_SOCKET, SO_RCVBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
    {
    	mylog(log_fatal,"SO_RCVBUFFORCE fail\n");
    	myexit(1);
    }

    //IP_HDRINCL to tell the kernel that headers are included in the packet

    int one = 1;
    const int *val = &one;
    if (setsockopt (raw_send_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
    	mylog(log_fatal,"Error setting IP_HDRINCL %d\n",errno);
        //perror("Error setting IP_HDRINCL");
        myexit(2);
    }

    setnonblocking(raw_send_fd); //not really necessary
    setnonblocking(raw_recv_fd);

	return 0;
}
void init_filter(int port)
{
	filter_port=port;
	if(disable_bpf_filter) return;
	//if(raw_mode==mode_icmp) return ;
	//code_tcp[8].k=code_tcp[10].k=port;
	if(raw_mode==mode_faketcp)
	{
		bpf.len = sizeof(code_tcp)/sizeof(code_tcp[0]);
		code_tcp[code_tcp_port_index].k=port;
		bpf.filter = code_tcp;
	}
	else if(raw_mode==mode_udp)
	{
		bpf.len = sizeof(code_udp)/sizeof(code_udp[0]);
		code_udp[code_udp_port_index].k=port;
		bpf.filter = code_udp;
	}
	else if(raw_mode==mode_icmp)
	{
		bpf.len = sizeof(code_icmp)/sizeof(code_icmp[0]);
		bpf.filter = code_icmp;
	}

	int dummy;

	int ret=setsockopt(raw_recv_fd, SOL_SOCKET, SO_DETACH_FILTER, &dummy, sizeof(dummy)); //in case i forgot to remove
	if (ret != 0)
	{
		mylog(log_debug,"error remove fiter\n");
		//perror("filter");
		//exit(-1);
	}
	ret = setsockopt(raw_recv_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (ret != 0)
	{
		mylog(log_fatal,"error set fiter\n");
		//perror("filter");
		myexit(-1);
	}
}
void remove_filter()
{
	filter_port=0;
	int dummy;
	int ret=setsockopt(raw_recv_fd, SOL_SOCKET, SO_DETACH_FILTER, &dummy, sizeof(dummy));
	if (ret != 0)
	{
		mylog(log_debug,"error remove fiter\n");
		//perror("filter");
		//exit(-1);
	}
}

long long get_current_time()
{
	timespec tmp_time;
	clock_gettime(CLOCK_MONOTONIC, &tmp_time);
	return tmp_time.tv_sec*1000+tmp_time.tv_nsec/(1000*1000l);
}

void server_clear_function(uint64_t u64)
{
	int fd=int((u64<<32u)>>32u);
	epoll_event ev;

	ev.events = EPOLLIN;
	ev.data.u64 = u64;

	int ret = epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev);
	if (ret!=0)
	{
		mylog(log_fatal,"fd:%d epoll delete failed!!!!\n",fd);
		myexit(-1);   //this shouldnt happen
	}
	ret= close(fd);

	if (ret!=0)
	{
		mylog(log_fatal,"close fd %d failed !!!!\n",fd);
		myexit(-1);  //this shouldnt happen
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



int send_raw_ip(const packet_info_t &info,const char * payload,int payloadlen)
{
	char send_raw_ip_buf[buf_len];

	struct iphdr *iph = (struct iphdr *) send_raw_ip_buf;
    memset(iph,0,sizeof(iphdr));

	struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    //sin.sin_port = htons(info.dst_port); //dont need this
    sin.sin_addr.s_addr = info.dst_ip;

    iph->ihl = sizeof(iphdr)/4;  //we dont use ip options,so the length is just sizeof(iphdr)
    iph->version = 4;
    iph->tos = 0;

   // iph->id = htonl (ip_id++); //Id of this packet
    // iph->id = 0; //Id of this packet  ,kernel will auto fill this if id is zero
    iph->frag_off = htons(0x4000); //DF set,others are zero
    iph->ttl = 64;
    iph->protocol = info.protocol;
    iph->check = 0; //Set to 0 before calculating checksum
    iph->saddr = info.src_ip;    //Spoof the source ip address
    iph->daddr = info.dst_ip;

    uint16_t ip_tot_len=sizeof (struct iphdr)+payloadlen;
   // iph->tot_len = htons(ip_tot_len);            //this is not necessary ,kernel will always auto fill this  //http://man7.org/linux/man-pages/man7/raw.7.html
    //iph->tot_len = ip_tot_len;
    memcpy(send_raw_ip_buf+sizeof(iphdr) , payload, payloadlen);

    //iph->check = csum ((unsigned short *) send_raw_ip_buf, ip_tot_len); //this is not necessary ,kernel will always auto fill this

    int ret = sendto(raw_send_fd, send_raw_ip_buf, ip_tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin));

    if(ret==-1)
    {
    	mylog(log_debug,"sendto failed\n");
    	return -1;
    }
    return 0;
}

int recv_raw_ip(packet_info_t &info,char * &payload,int &payloadlen)
{
	static char recv_raw_ip_buf[buf_len];

	iphdr *  iph;
	struct sockaddr saddr;
	socklen_t saddr_size;
	saddr_size = sizeof(saddr);

	int recv_len = recvfrom(raw_recv_fd, recv_raw_ip_buf, buf_len, 0 ,&saddr , &saddr_size);

	if(recv_len<0)
	{
		mylog(log_trace,"recv_len %d\n",recv_len);
		return -1;
	}
	if(recv_len<link_level_header_len)
	{
		mylog(log_trace,"length error\n");
	}

	if(link_level_header_len ==14&&(recv_raw_ip_buf[12]!=8||recv_raw_ip_buf[13]!=0))
	{
		mylog(log_trace,"not an ipv4 packet!\n");
		return -1;
	}


	char *ip_begin=recv_raw_ip_buf+link_level_header_len;  //14 is eth net header

	iph = (struct iphdr *) (ip_begin);

	info.src_ip=iph->saddr;
	info.dst_ip=iph->daddr;
	info.protocol=iph->protocol;

	if(local_address_uint32!=0 &&info.dst_ip!=local_address_uint32)
	{
		//printf(" bind adress doenst match, dropped\n");
		return -1;
	}


    if (!(iph->ihl > 0 && iph->ihl <=60)) {
    	mylog(log_trace,"iph ihl error\n");
        return -1;
    }

	int ip_len=ntohs(iph->tot_len);

	if(recv_len-link_level_header_len <ip_len)
	{
		mylog(log_debug,"incomplete packet\n");
		return -1;
	}

    unsigned short iphdrlen =iph->ihl*4;

    uint32_t ip_chk=csum ((unsigned short *) ip_begin, iphdrlen);

    if(ip_chk!=0)
     {
    	mylog(log_debug,"ip header error %d\n",ip_chk);
     	return -1;
     }

    payload=ip_begin+iphdrlen;

    payloadlen=ip_len-iphdrlen;

    if(payloadlen<0)
    {
    	mylog(log_warn,"error payload len\n");
    	return -1;
    }

	return 0;
}


int send_raw_icmp(const packet_info_t &info, const char * payload, int payloadlen)
{
	char send_raw_icmp_buf[buf_len];
	icmphdr *icmph=(struct icmphdr *) (send_raw_icmp_buf);
	memset(icmph,0,sizeof(icmphdr));
	if(program_mode==client_mode)
	{
		icmph->type=8;
	}
	else
	{
		icmph->type=0;
	}
	icmph->code=0;
	icmph->id=htons(g_packet_info_send.src_port);

	icmph->seq=htons(g_packet_info_send.icmp_seq++);

	memcpy(send_raw_icmp_buf+sizeof(icmphdr),payload,payloadlen);

	icmph->check_sum = csum( (unsigned short*) send_raw_icmp_buf, sizeof(icmphdr)+payloadlen);

	if(send_raw_ip(info,send_raw_icmp_buf,sizeof(icmphdr)+payloadlen)!=0)
	{
		return -1;
	}

	return 0;
}

int send_raw_udp(const packet_info_t &info, const char * payload, int payloadlen)
{
	char send_raw_udp_buf[buf_len];

	udphdr *udph=(struct udphdr *) (send_raw_udp_buf
			+ sizeof(struct pseudo_header));

	memset(udph,0,sizeof(udphdr));
	struct pseudo_header *psh = (struct pseudo_header *) (send_raw_udp_buf);

	udph->source = htons(info.src_port);
	udph->dest = htons(info.dst_port);

	int udp_tot_len=payloadlen+sizeof(udphdr);

	if(udp_tot_len>65535)
	{
		mylog(log_debug,"invalid len\n");
		return -1;
	}
	mylog(log_debug,"udp_len:%d %d\n",udp_tot_len,udph->len);
	udph->len=htons(uint16_t(udp_tot_len));

	memcpy(send_raw_udp_buf+sizeof(struct pseudo_header)+sizeof(udphdr),payload,payloadlen);

	psh->source_address = info.src_ip;
	psh->dest_address = info.dst_ip;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_UDP;
	psh->tcp_length = htons(uint16_t(udp_tot_len));

	int csum_size = sizeof(struct pseudo_header) +udp_tot_len  ;

	udph->check = csum( (unsigned short*) send_raw_udp_buf, csum_size);

	if(send_raw_ip(info,send_raw_udp_buf+ sizeof(struct pseudo_header),udp_tot_len)!=0)
	{
		return -1;
	}
	return 0;
}

int send_raw_tcp(const packet_info_t &info,const char * payload, int payloadlen) {  //TODO seq increase

	char send_raw_tcp_buf[buf_len];
	struct tcphdr *tcph = (struct tcphdr *) (send_raw_tcp_buf
			+ sizeof(struct pseudo_header));


	memset(tcph,0,sizeof(tcphdr));

	struct pseudo_header *psh = (struct pseudo_header *) (send_raw_tcp_buf);

	//TCP Header
	tcph->source = htons(info.src_port);
	tcph->dest = htons(info.dst_port);

	tcph->seq = htonl(info.seq);
	tcph->ack_seq = htonl(info.ack_seq);

	tcph->fin = 0;
	tcph->syn = info.syn;
	tcph->rst = 0;
	tcph->psh = info.psh;
	tcph->ack = info.ack;

	if (tcph->syn == 1) {
		tcph->doff = 10;  //tcp header size
		int i = sizeof(pseudo_header)+sizeof(tcphdr);
		send_raw_tcp_buf[i++] = 0x02;  //mss
		send_raw_tcp_buf[i++] = 0x04;
		send_raw_tcp_buf[i++] = 0x05;
		send_raw_tcp_buf[i++] = 0xb4;

		//raw_send_buf[i++]=0x01;
		//raw_send_buf[i++]=0x01;
		send_raw_tcp_buf[i++] = 0x04; //sack ok
		send_raw_tcp_buf[i++] = 0x02; //sack ok

		send_raw_tcp_buf[i++] = 0x08;   //ts
		send_raw_tcp_buf[i++] = 0x0a;

		*(uint32_t*) (&send_raw_tcp_buf[i]) = htonl(
				(uint32_t) get_current_time());

		i += 4;

		*(uint32_t*) (&send_raw_tcp_buf[i]) = htonl(info.ts_ack);
		i += 4;

		send_raw_tcp_buf[i++] = 0x01;
		send_raw_tcp_buf[i++] = 0x03;
		send_raw_tcp_buf[i++] = 0x03;
		send_raw_tcp_buf[i++] = 0x05;
	} else {
		tcph->doff = 8;
		int i = sizeof(pseudo_header)+sizeof(tcphdr);

		send_raw_tcp_buf[i++] = 0x01;
		send_raw_tcp_buf[i++] = 0x01;

		send_raw_tcp_buf[i++] = 0x08;  //ts
		send_raw_tcp_buf[i++] = 0x0a;

		*(uint32_t*) (&send_raw_tcp_buf[i]) = htonl(
				(uint32_t) get_current_time());

		i += 4;

		*(uint32_t*) (&send_raw_tcp_buf[i]) = htonl(info.ts_ack);
		i += 4;
	}

	tcph->urg = 0;
	//tcph->window = htons((uint16_t)(1024));
	tcph->window = htons((uint16_t) (10240 + random() % 100));

	tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;

	char *tcp_data = send_raw_tcp_buf+sizeof(struct pseudo_header) + tcph->doff * 4;

	memcpy(tcp_data, payload, payloadlen);

	psh->source_address = info.src_ip;
	psh->dest_address = info.dst_ip;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_TCP;
	psh->tcp_length = htons(tcph->doff * 4 + payloadlen);

	int csum_size = sizeof(struct pseudo_header) + tcph->doff*4 + payloadlen;

	tcph->check = csum( (unsigned short*) send_raw_tcp_buf, csum_size);

	int tcp_totlen=tcph->doff*4 + payloadlen;

	if(send_raw_ip(info,send_raw_tcp_buf+ sizeof(struct pseudo_header),tcp_totlen)!=0)
	{
		return -1;
	}
	if (g_packet_info_send.syn == 0 && g_packet_info_send.ack == 1
			&& payloadlen != 0) {
		if (seq_mode == 0) {

		} else if (seq_mode == 1) {
			g_packet_info_send.seq += payloadlen;
		} else if (seq_mode == 2) {
			if (random() % 5 == 3)
				g_packet_info_send.seq += payloadlen;
		}
	}

	return 0;
}

int send_raw_tcp_deprecated(const packet_info_t &info,const char * payload,int payloadlen)
{
	static uint16_t ip_id=1;
	char raw_send_buf[buf_len];
	char raw_send_buf2[buf_len];

	//if((prog_mode==client_mode&& payloadlen!=9)  ||(prog_mode==server_mode&& payloadlen!=5 )  )
	mylog(log_trace,"send raw from to %d %d %d %d\n",info.src_ip,info.src_port,info.dst_ip,info.dst_port);

	char *data;

    memset(raw_send_buf,0,payloadlen+100);

    struct iphdr *iph = (struct iphdr *) raw_send_buf;

    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (raw_send_buf + sizeof (struct ip));

    struct sockaddr_in sin;
    struct pseudo_header psh;

    //some address resolution
    sin.sin_family = AF_INET;
    sin.sin_port = htons(info.dst_port);
    sin.sin_addr.s_addr = info.dst_ip;

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;

    iph->id = htonl (ip_id++); //Id of this packet
    iph->frag_off = htons(0x4000); //DF set,others are zero
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; //Set to 0 before calculating checksum
    iph->saddr = info.src_ip;    //Spoof the source ip address
    iph->daddr = info.dst_ip;

    //TCP Header
    tcph->source = htons(info.src_port);
    tcph->dest = htons(info.dst_port);

    tcph->seq =htonl(info.seq);
    tcph->ack_seq = htonl(info.ack_seq);

    tcph->fin=0;
    tcph->syn=info.syn;
    tcph->rst=0;
    tcph->psh=info.psh;
    tcph->ack=info.ack;

    if(tcph->syn==1)
    {
    	tcph->doff = 10;  //tcp header size
    	int i=sizeof (struct iphdr)+20;
    	raw_send_buf[i++]=0x02;//mss
    	raw_send_buf[i++]=0x04;
    	raw_send_buf[i++]=0x05;
    	raw_send_buf[i++]=0xb4;

    	//raw_send_buf[i++]=0x01;
    	//raw_send_buf[i++]=0x01;
    	raw_send_buf[i++]=0x04; //sack ok
    	raw_send_buf[i++]=0x02; //sack ok


    	raw_send_buf[i++]=0x08;   //i=6;
    	raw_send_buf[i++]=0x0a;

    	*(uint32_t*)(& raw_send_buf[i])=htonl((uint32_t)get_current_time());

    	i+=4;

    	*(uint32_t*)(& raw_send_buf[i])=htonl(info.ts_ack);
    	i+=4;

    	raw_send_buf[i++]=0x01;
    	raw_send_buf[i++]=0x03;
    	raw_send_buf[i++]=0x03;
    	raw_send_buf[i++]=0x05;
    }
    else
    {
    	tcph->doff=8;
    	int i=sizeof (struct iphdr)+20;

    	raw_send_buf[i++]=0x01;
    	raw_send_buf[i++]=0x01;

    	raw_send_buf[i++]=0x08;   //i=0;
    	raw_send_buf[i++]=0x0a;

    	*(uint32_t*)(& raw_send_buf[i])=htonl((uint32_t)get_current_time());

    	i+=4;

    	*(uint32_t*)(& raw_send_buf[i])=htonl(info.ts_ack);
    	i+=4;


    }



    tcph->urg=0;
    //tcph->window = htons((uint16_t)(1024));
    tcph->window = htons((uint16_t)(10240+random()%100));


    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;


    //Data part
    data = raw_send_buf + sizeof(struct iphdr) + tcph->doff*4;

    iph->tot_len = sizeof (struct iphdr) + tcph->doff*4 + payloadlen;

    memcpy(data , payload, payloadlen);

    psh.source_address = info.src_ip;
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(tcph->doff*4 + payloadlen );

    int psize = sizeof(struct pseudo_header) + tcph->doff*4 + payloadlen;

     memcpy(raw_send_buf2 , (char*) &psh , sizeof (struct pseudo_header));
     memcpy(raw_send_buf2 + sizeof(struct pseudo_header) , tcph , tcph->doff*4 + payloadlen);

     tcph->check = csum( (unsigned short*) raw_send_buf2, psize);

     //Ip checksum
     iph->check = csum ((unsigned short *) raw_send_buf, iph->tot_len);

     mylog(log_trace,"sent seq  ack_seq len<%u %u %d>\n",g_packet_info_send.seq,g_packet_info_send.ack_seq,payloadlen);

     int ret = sendto(raw_send_fd, raw_send_buf, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin));

     if(g_packet_info_send.syn==0&&g_packet_info_send.ack==1&&payloadlen!=0)
     {
    	 if(seq_mode==0)
    	 {


    	 }
    	 else if(seq_mode==1)
    	 {
    		 g_packet_info_send.seq+=payloadlen;
    	 }
    	 else if(seq_mode==2)
    	 {
    		 if(random()% 5==3 )
    			 g_packet_info_send.seq+=payloadlen;
    	 }
     }
     mylog(log_trace,"<ret:%d>\n",ret);
	 if(ret<0)
     {
	    	mylog(log_fatal,"");
    	 perror("raw send error\n");
    	 //printf("send error\n");
     }
     return 0;
}


int recv_raw_icmp(packet_info_t &info, char *&payload, int &payloadlen)
{
	static char recv_raw_icmp_buf[buf_len];

	char * ip_payload;
	int ip_payloadlen;

	if(recv_raw_ip(info,ip_payload,ip_payloadlen)!=0)
	{
		mylog(log_debug,"recv_raw_ip error\n");
		return -1;
	}
	if(info.protocol!=IPPROTO_ICMP)
	{
		//printf("not udp protocol\n");
		return -1;
	}

	icmphdr *icmph=(struct icmphdr *) (ip_payload);

	info.src_port=info.dst_port=ntohs(icmph->id);


	if(program_mode==client_mode)
	{
		if(icmph->type!=0)
			return -1;
	}
	else
	{
		if(icmph->type!=8)
			return -1;
	}

	if(icmph->code!=0)
		return -1;

	unsigned short check = csum( (unsigned short*) ip_payload, ip_payloadlen);

	if(check!=0)
	{
		mylog(log_debug,"icmp checksum fail %x\n",check);
		return -1;
	}

	payload=ip_payload+sizeof(icmphdr);
	payloadlen=ip_payloadlen-sizeof(icmphdr);
	mylog(log_debug,"get a packet len=%d\n",payloadlen);

    return 0;
}

int recv_raw_udp(packet_info_t &info, char *&payload, int &payloadlen)
{
	static char recv_raw_udp_buf[buf_len];
	char * ip_payload;
	int ip_payloadlen;

	if(recv_raw_ip(info,ip_payload,ip_payloadlen)!=0)
	{
		mylog(log_debug,"recv_raw_ip error\n");
		return -1;
	}
	if(info.protocol!=IPPROTO_UDP)
	{
		//printf("not udp protocol\n");
		return -1;
	}
	if(ip_payloadlen<sizeof(udphdr))
	{
		mylog(log_debug,"too short to hold udpheader\n");
		return -1;
	}
	udphdr *udph=(struct udphdr*)ip_payload;

	if(ntohs(udph->len)!=ip_payloadlen)
	{

		mylog(log_debug,"udp length error %d %d \n",ntohs(udph->len),ip_payloadlen);
		return -1;
	}

    if(udph->dest!=ntohs(uint16_t(filter_port)))
    {
    	//printf("%x %x",tcph->dest,);
    	return -1;
    }

    memcpy(recv_raw_udp_buf+ sizeof(struct pseudo_header) , ip_payload , ip_payloadlen);

    struct pseudo_header *psh=(pseudo_header *)recv_raw_udp_buf ;

    psh->source_address = info.src_ip;
    psh->dest_address = info.dst_ip;
    psh->placeholder = 0;
    psh->protocol = IPPROTO_UDP;
    psh->tcp_length = htons(ip_payloadlen);

    int csum_len=sizeof(struct pseudo_header)+ip_payloadlen;
    uint16_t udp_chk = csum( (unsigned short*) recv_raw_udp_buf, csum_len);

    if(udp_chk!=0)
    {
    	mylog(log_debug,"udp_chk:%x\n",udp_chk);
    	mylog(log_debug,"udp header error\n");
    	return -1;

    }

    char *udp_begin=recv_raw_udp_buf+sizeof(struct pseudo_header);

    info.src_port=ntohs(udph->source);
    info.dst_port=ntohs(udph->dest);

    payloadlen = ip_payloadlen-sizeof(udphdr);

    payload=udp_begin+sizeof(udphdr);

    return 0;
}

int recv_raw_tcp(packet_info_t &info,char * &payload,int &payloadlen)
{
	static char recv_raw_tcp_buf[buf_len];

	char * ip_payload;
	int ip_payloadlen;


	if(recv_raw_ip(info,ip_payload,ip_payloadlen)!=0)
	{
		mylog(log_debug,"recv_raw_ip error\n");
		return -1;
	}

	if(info.protocol!=IPPROTO_TCP)
	{
		//printf("not tcp protocol\n");
		return -1;
	}


	tcphdr * tcph=(struct tcphdr*)ip_payload;

    unsigned short tcphdrlen = tcph->doff*4;

    if (!(tcph->doff > 0 && tcph->doff <=60)) {
    	mylog(log_debug,"tcph error\n");
    	return 0;
    }


    if(tcph->dest!=ntohs(uint16_t(filter_port)))
    {
    	//printf("%x %x",tcph->dest,);
    	return -1;
    }

    memcpy(recv_raw_tcp_buf+ sizeof(struct pseudo_header) , ip_payload , ip_payloadlen);

    struct pseudo_header *psh=(pseudo_header *)recv_raw_tcp_buf ;

    psh->source_address = info.src_ip;
    psh->dest_address = info.dst_ip;
    psh->placeholder = 0;
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(ip_payloadlen);

    int csum_len=sizeof(struct pseudo_header)+ip_payloadlen;
    uint16_t tcp_chk = csum( (unsigned short*) recv_raw_tcp_buf, csum_len);

    if(tcp_chk!=0)
    {
    	mylog(log_debug,"tcp_chk:%x\n",tcp_chk);
    	mylog(log_debug,"tcp header error\n");
    	return -1;

    }

    char *tcp_begin=recv_raw_tcp_buf+sizeof(struct pseudo_header);  //ip packet's data part

    char *tcp_option=recv_raw_tcp_buf+sizeof(struct pseudo_header)+sizeof(tcphdr);

    info.has_ts=0;
    if(tcph->doff==10)
    {
    	if(tcp_option[6]==0x08 &&tcp_option[7]==0x0a)
    	{
    		info.has_ts=1;
    		info.ts=ntohl(*(uint32_t*)(&tcp_option[8]));
    		info.ts_ack=ntohl(*(uint32_t*)(&tcp_option[12]));
    		//g_packet_info_send.ts_ack= ntohl(*(uint32_t*)(&tcp_option[8]));
    	}
    }
    else if(tcph->doff==8)
    {
    	if(tcp_option[3]==0x08 &&tcp_option[4]==0x0a)
    	{
    		info.has_ts=1;
    		info.ts=ntohl(*(uint32_t*)(&tcp_option[0]));
    		info.ts_ack=ntohl(*(uint32_t*)(&tcp_option[4]));
    		//g_packet_info_send.ts_ack= ntohl(*(uint32_t*)(&tcp_option[0]));
    	}
    }
    if(tcph->rst==1)
    {
    	mylog(log_warn,"%%%%%%%%%%%%%rst==1%%%%%%%%%%%%%\n");
    }

    info.ack=tcph->ack;
    info.syn=tcph->syn;
    info.rst=tcph->rst;
    info.src_port=ntohs(tcph->source);
    info.dst_port=ntohs(tcph->dest);

    info.seq=ntohl(tcph->seq);
    info.ack_seq=ntohl(tcph->ack_seq);
    info.psh=tcph->psh;

    if(info.has_ts)
    {
    	g_packet_info_send.ts_ack=info.ts;
    }

    payloadlen = ip_payloadlen-tcphdrlen;

    payload=tcp_begin+tcphdrlen;
    return 0;
}

int recv_raw_tcp_deprecated(packet_info_t &info,char * &payload,int &payloadlen)
{
	static char buf[buf_len];

	char raw_recv_buf[buf_len];
	char raw_recv_buf2[buf_len];
	char raw_recv_buf3[buf_len];

	iphdr *  iph;
	tcphdr * tcph;
	int size;
	struct sockaddr saddr;
	socklen_t saddr_size;
	saddr_size = sizeof(saddr);

	mylog(log_trace,"raw!\n");

	size = recvfrom(raw_recv_fd, buf, buf_len, 0 ,&saddr , &saddr_size);

	if(buf[12]!=8||buf[13]!=0)
	{
		mylog(log_debug,"not an ipv4 packet!\n");
		return -1;
	}

	char *ip_begin=buf+14;

	iph = (struct iphdr *) (ip_begin);


    if (!(iph->ihl > 0 && iph->ihl <=60)) {
    	mylog(log_debug,"iph ihl error");
        return -1;
    }

    if (iph->protocol != IPPROTO_TCP) {
    	mylog(log_debug,"iph protocal != tcp\n");
    	return -1;
    }


	int ip_len=ntohs(iph->tot_len);

    unsigned short iphdrlen =iph->ihl*4;
    tcph=(struct tcphdr*)(ip_begin+ iphdrlen);
    unsigned short tcphdrlen = tcph->doff*4;

    if (!(tcph->doff > 0 && tcph->doff <=60)) {
    	mylog(log_debug,"tcph error");
    	return 0;
    }


    if(tcph->dest!=ntohs(uint16_t(filter_port)))
    {
    	//printf("%x %x",tcph->dest,);
    	return -1;
    }
    /////ip
    uint32_t ip_chk=csum ((unsigned short *) ip_begin, iphdrlen);

    int psize = sizeof(struct pseudo_header) + ip_len-iphdrlen;
    /////ip end


    ///tcp
    struct pseudo_header psh;

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(ip_len-iphdrlen);

    memcpy(raw_recv_buf2 , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(raw_recv_buf2 + sizeof(struct pseudo_header) , ip_begin+ iphdrlen , ip_len-iphdrlen);

    uint16_t tcp_chk = csum( (unsigned short*) raw_recv_buf2, psize);


   if(ip_chk!=0)
    {
	   mylog(log_debug,"ip header error %d\n",ip_chk);
    	return -1;
    }
    if(tcp_chk!=0)
    {
    	mylog(log_debug,"tcp_chk:%x\n",tcp_chk);
    	mylog(log_debug,"tcp header error\n");
    	return -1;

    }
    char *tcp_begin=raw_recv_buf2+sizeof(struct pseudo_header);  //ip packet's data part

    char *tcp_option=raw_recv_buf2+sizeof(struct pseudo_header)+sizeof(tcphdr);

    info.has_ts=0;

    if(tcph->doff==10)
    {
    	if(tcp_option[6]==0x08 &&tcp_option[7]==0x0a)
    	{
    		info.has_ts=1;
    		info.ts=ntohl(*(uint32_t*)(&tcp_option[8]));
    		info.ts_ack=ntohl(*(uint32_t*)(&tcp_option[12]));
    		//g_packet_info_send.ts_ack= ntohl(*(uint32_t*)(&tcp_option[8]));
    	}
    }
    else if(tcph->doff==8)
    {
    	if(tcp_option[3]==0x08 &&tcp_option[4]==0x0a)
    	{
    		info.has_ts=1;
    		info.ts=ntohl(*(uint32_t*)(&tcp_option[0]));
    		info.ts_ack=ntohl(*(uint32_t*)(&tcp_option[4]));
    		//g_packet_info_send.ts_ack= ntohl(*(uint32_t*)(&tcp_option[0]));
    	}
    }

    if(tcph->rst==1)
    {
    	mylog(log_warn,"%%%%%%%%%%rst==1%%%%%%%%%%%%%\n");
    }


    info.ack=tcph->ack;
    info.syn=tcph->syn;
    info.rst=tcph->rst;
    info.src_port=ntohs(tcph->source);
    info.src_ip=iph->saddr;
    info.seq=ntohl(tcph->seq);
    info.ack_seq=ntohl(tcph->ack_seq);
    info.psh=tcph->psh;
    if(info.has_ts)
    {
    	g_packet_info_send.ts_ack=info.ts;
    }
    ////tcp end


    payloadlen = ip_len-tcphdrlen-iphdrlen;

    payload=ip_begin+tcphdrlen+iphdrlen;

    if(payloadlen>0&&payload[0]=='h')
    {
    	mylog(log_debug,"recvd <%u %u %d>\n",ntohl(tcph->seq ),ntohl(tcph->ack_seq), payloadlen);
    }

    if(payloadlen>0&&tcph->syn==0&&tcph->ack==1)
    {
    	//if(seq_increse)
    		g_packet_info_send.ack_seq=ntohl(tcph->seq)+(uint32_t)payloadlen;
    }


    //printf("%d\n",ip_len);

    mylog(log_trace,"<%u,%u,%u,%u,%d>\n",(unsigned int)iphdrlen,(unsigned int)tcphdrlen,(unsigned int)tcph->syn,(unsigned int)tcph->ack,payloadlen);


	return 0;
}

int send_raw(const packet_info_t &info,const char * payload,int payloadlen)
{
	switch(raw_mode)
	{
		case mode_faketcp:return send_raw_tcp(info,payload,payloadlen);
		case mode_udp: return send_raw_udp(info,payload,payloadlen);
		case mode_icmp: return send_raw_icmp(info,payload,payloadlen);
	}
	return -1;
}
int recv_raw(packet_info_t &info,char * &payload,int &payloadlen)
{
	switch(raw_mode)
	{
		case mode_faketcp:return recv_raw_tcp(info,payload,payloadlen);
		case mode_udp: return recv_raw_udp(info,payload,payloadlen);
		case mode_icmp: return recv_raw_icmp(info,payload,payloadlen);
	}
	return -1;
}

int send_bare(const packet_info_t &info,const char* data,int len)
{
	char send_data_buf[buf_len];  //buf for send data and send hb
	char send_data_buf2[buf_len];

	if(len==0) //dont encrpyt zero length packet;
	{
		send_raw(info,data,len);
		return 0;
	}
	//static send_bare[buf_len];
	iv_t iv=get_true_random_number_64();

	memcpy(send_data_buf,&iv,sizeof(iv_t));
	memcpy(send_data_buf+sizeof(iv_t),data,len);

	int new_len=len+sizeof(iv_t);
	if(my_encrypt(send_data_buf,send_data_buf2,new_len,key)!=0)
	{
		return -1;
	}
	send_raw(info,send_data_buf2,new_len);
	return 0;
}

int recv_bare(packet_info_t &info,char* & data,int & len)
{
	static char recv_data_buf[buf_len];
	if(recv_raw(info,data,len)<0)
	{
		//printf("recv_raw_fail in recv bare\n");
		return -1;
	}
	if(len==0) //dont decrpyt zero length packet;
	{
		return 0;
	}

	if(my_decrypt(data,recv_data_buf,len,key)!=0)
	{
		mylog(log_debug,"decrypt_fail in recv bare\n");
		return -1;
	}
	data=recv_data_buf+sizeof(iv_t);
	len-=sizeof(iv_t);
	return 0;
}

int numbers_to_char(id_t id1,id_t id2,id_t id3,char * &data,int len)
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
	if(len<sizeof(id_t)*3) return -1;
	id1=ntohl(  *((id_t*)(data+0)) );
	id2=ntohl(  *((id_t*)(data+sizeof(id_t))) );
	id3=ntohl(  *((id_t*)(data+sizeof(id_t)*2)) );
	return 0;
}


int send_handshake(const packet_info_t &info,id_t id1,id_t id2,id_t id3)
{
	char * data;int len;
	len=sizeof(id_t)*3;
	if(numbers_to_char(id1,id2,id3,data,len)!=0) return -1;
	if(send_bare(info,data,len)!=0) {mylog(log_warn,"send bare fail\n");return -1;}
	return 0;
}
/*
int recv_handshake(packet_info_t &info,id_t &id1,id_t &id2,id_t &id3)
{
	char * data;int len;
	if(recv_bare(info,data,len)!=0) return -1;

	if(char_to_numbers(data,len,id1,id2,id3)!=0) return -1;

	return 0;
}*/

int send_safer(const packet_info_t &info,const char* data,int len)
{
	char send_data_buf[buf_len];  //buf for send data and send hb
	char send_data_buf2[buf_len];

	id_t n_tmp_id=htonl(my_id);

	memcpy(send_data_buf,&n_tmp_id,sizeof(n_tmp_id));

	n_tmp_id=htonl(oppsite_id);

	memcpy(send_data_buf+sizeof(n_tmp_id),&n_tmp_id,sizeof(n_tmp_id));

	anti_replay_seq_t n_seq=hton64(anti_replay_seq++);

	memcpy(send_data_buf+sizeof(n_tmp_id)*2,&n_seq,sizeof(n_seq));


	memcpy(send_data_buf+sizeof(n_tmp_id)*2+sizeof(n_seq),data,len);//data;

	int new_len=len+sizeof(n_seq)+sizeof(n_tmp_id)*2;

	if(my_encrypt(send_data_buf,send_data_buf2,new_len,key2)!=0)
	{
		return -1;
	}

	send_raw(info,send_data_buf2,new_len);

	return 0;
}
int send_data_safer(packet_info_t &info,const char* data,int len,uint32_t conv_num)
{
	char send_data_buf[buf_len];
	send_data_buf[0]='d';
	uint32_t n_conv_num=htonl(conv_num);
	memcpy(send_data_buf+1,&n_conv_num,sizeof(n_conv_num));

	memcpy(send_data_buf+1+sizeof(n_conv_num),data,len);
	int new_len=len+1+sizeof(n_conv_num);
	send_safer(info,send_data_buf,new_len);
	return 0;

}
int recv_safer(packet_info_t &info,char* &data,int &len)
{

	char * recv_data;int recv_len;
	static char recv_data_buf[buf_len];

	if(recv_raw(info,recv_data,recv_len)!=0) return -1;

	//printf("1111111111111111\n");

	if(my_decrypt(recv_data,recv_data_buf,recv_len,key2)!=0)
	{
		//printf("decrypt fail\n");
		return -1;
	}


	//printf("recv _len %d\n ",recv_len);

	//printf("222222222222222\n");


	id_t h_oppiste_id= ntohl (  *((id_t * )(recv_data_buf)) );

	id_t h_my_id= ntohl (  *((id_t * )(recv_data_buf+sizeof(id_t)))    );

	anti_replay_seq_t h_seq= ntoh64 (  *((anti_replay_seq_t * )(recv_data_buf  +sizeof(id_t) *2 ))   );

	if(h_oppiste_id!=oppsite_id||h_my_id!=my_id)
	{
		mylog(log_warn,"id and oppsite_id verification failed %x %x %x %x \n",h_oppiste_id,oppsite_id,h_my_id,my_id);
		return -1;
	}

	if (anti_replay.is_vaild(h_seq) != 1) {
		mylog(log_warn,"dropped replay packet\n");
		return -1;
	}

	//printf("recv _len %d\n ",recv_len);
	data=recv_data_buf+sizeof(anti_replay_seq_t)+sizeof(id_t)*2;
	len=recv_len-(sizeof(anti_replay_seq_t)+sizeof(id_t)*2  );


	if(len<0)
	{
		mylog(log_error,"len <0 ,%d\n",len);
		return -1;
	}

	return 0;
}

/*
int send_bare_deprecated(const packet_info_t &info,const char* data,int len)
{
	char send_data_buf[buf_len];  //buf for send data and send hb
	char send_data_buf2[buf_len];

	int new_len=len;

	memcpy(send_data_buf,data,len);

	if(pre_send_deprecate(send_data_buf,new_len)<0)
	{
		return -1;
	}
	send_raw(info,send_data_buf,new_len);
	return 0;
}

int send_data_deprecated(const packet_info_t &info,const char* data,int len,uint32_t id1,uint32_t id2,uint32_t conv_id)
{
	char send_data_buf[buf_len];  //buf for send data and send hb
	char send_data_buf2[buf_len];

	int new_len=1+sizeof(my_id)*3+len;
	send_data_buf[0]='d';
	uint32_t tmp;
	tmp=htonl(id1);
	memcpy(send_data_buf+1,&tmp,sizeof(my_id));

	tmp=htonl(id2);
	memcpy(send_data_buf+1+sizeof(my_id),&tmp,sizeof(my_id));

	tmp=htonl(conv_id);
	memcpy(send_data_buf+1+sizeof(my_id)*2,&tmp,sizeof(my_id));

	memcpy(send_data_buf+1+sizeof(my_id)*3,data,len);

	if(pre_send_deprecate(send_data_buf,new_len)<0)
	{
		return -1;
	}
	send_raw(info,send_data_buf,new_len);
	return 0;
}

int send_hb_deprecated(const packet_info_t &info,uint32_t id1,uint32_t id2 ,uint32_t id3)
{
	char send_data_buf[buf_len];  //buf for send data and send hb
	char send_data_buf2[buf_len];

	int new_len=1+sizeof(my_id)*3;
	send_data_buf[0]='h';

	uint32_t tmp;
	tmp=htonl(id1);
	memcpy(send_data_buf+1,&tmp,sizeof(my_id));

	tmp=htonl(id2);
	memcpy(send_data_buf+1+sizeof(my_id),&tmp,sizeof(my_id));

	tmp=htonl(id3);
	memcpy(send_data_buf+1+sizeof(my_id)*2,&tmp,sizeof(my_id));

	if(pre_send_deprecate(send_data_buf,new_len)<0)
	{
		return -1;
	}
	send_raw(info,send_data_buf,new_len);

	return 0;
}

int recv_tmp_deprecated(packet_info_t &info,char * &data,int &data_len)
{
	if(recv_raw(g_packet_info_recv,data,data_len)!=0)
	{
		return -1;
	}

    if(data_len!=0)
    {
    	if(pre_recv_deprecated(data,data_len)<0)
    		return -1;
    }
    return 0;
}*/


/*int send_sync()
{
	//g_packet_info.seq=3;
	g_packet_info.ack=0;
	g_packet_info.syn=1;
	//g_packet_info.ack_seq=5;
	g_packet_info.psh=0;
	send_raw(g_packet_info,0,0);
	return 0;
}*/
int try_to_list_and_bind(int port)
{
	 int old_bind_fd=bind_fd;

	 if(raw_mode==mode_faketcp)
	 {
		 bind_fd=socket(AF_INET,SOCK_STREAM,0);
	 }
	 else  if(raw_mode==mode_udp||raw_mode==mode_icmp)
	 {
		 bind_fd=socket(AF_INET,SOCK_DGRAM,0);
	 }
     if(old_bind_fd!=-1)
     {
    	 close(old_bind_fd);
     }

	 struct sockaddr_in temp_bind_addr;
     bzero(&temp_bind_addr, sizeof(temp_bind_addr));

     temp_bind_addr.sin_family = AF_INET;
     temp_bind_addr.sin_port = htons(port);
     temp_bind_addr.sin_addr.s_addr = local_address_uint32;

     if (bind(bind_fd, (struct sockaddr*)&temp_bind_addr, sizeof(temp_bind_addr)) !=0)
     {
    	 mylog(log_debug,"bind fail\n");
    	 return -1;
     }
	 if(raw_mode==mode_faketcp)
	 {

		if (listen(bind_fd, SOMAXCONN) != 0) {
			mylog(log_warn,"listen fail\n");
			return -1;
		}
	 }
     return 0;
}
int client_bind_to_a_new_port()
{
	int raw_send_port=10000+get_true_random_number_nz()%(65535-10000);
	for(int i=0;i<1000;i++)//try 1000 times at max,this should be enough
	{
		if (try_to_list_and_bind(raw_send_port)==0)
		{
			return raw_send_port;
		}
	}
	mylog(log_fatal,"bind port fail\n");
	myexit(-1);
	return -1;////for compiler check
}

int keep_connection_client() //for client
{
	conv_manager.clean_inactive();
	mylog(log_trace,"timer!\n");
	begin:
	if(client_current_state==client_nothing)
	{
		anti_replay.re_init(); //  this is not safe

		if(raw_mode==mode_icmp)
		{
			remove_filter();
		}

		if(source_port==0)
		{
			g_packet_info_send.src_port = client_bind_to_a_new_port();
		}
		else
		{
			g_packet_info_send.src_port=source_port;
		}

		if(raw_mode==mode_icmp)
		{
			g_packet_info_send.dst_port =g_packet_info_send.src_port ;
		}
		mylog(log_info,"using port %d\n", g_packet_info_send.src_port);




		init_filter(g_packet_info_send.src_port);

		if(raw_mode==mode_faketcp)
		{
			client_current_state = client_syn_sent;
			last_state_time = get_current_time();
			mylog(log_info,"state changed from nothing to syn_sent\n");
			retry_counter = RETRY_TIME;

			g_packet_info_send.seq = get_true_random_number_nz();
			g_packet_info_send.ack_seq = 0; //get_true_random_number();
			g_packet_info_send.ts_ack = 0;
			g_packet_info_send.ack = 0;
			g_packet_info_send.syn = 1;
			g_packet_info_send.psh = 0;

			send_bare(g_packet_info_send, 0, 0);   /////////////send
		}
		else if(raw_mode==mode_udp||raw_mode==mode_icmp)
		{
			client_current_state = client_ack_sent;
			last_state_time = get_current_time();
			mylog(log_info,"state changed from nothing to ack_sent\n");
			retry_counter = RETRY_TIME;
			g_packet_info_send.icmp_seq=0;

			send_bare(g_packet_info_send, (char*)"hello", strlen("hello"));/////////////send

		}
	}
	if(client_current_state==client_syn_sent  &&get_current_time()-last_state_time>handshake_timeout)
	{
		if(retry_counter==0)
		{
			client_current_state=client_nothing;
			mylog(log_info,"state back to nothing\n");
			return 0;
			//goto begin;
		}
		else
		{
			retry_counter--;
			mylog(log_info,"retry send sync\n");
			send_bare(g_packet_info_send,0,0); /////////////send
			last_state_time=get_current_time();
		}
	}
	if(client_current_state==client_ack_sent &&get_current_time()-last_state_time>handshake_timeout)
	{
		if(retry_counter==0)
		{
			client_current_state=client_nothing;
			mylog(log_info,"state back to nothing\n");
			return 0;
			//goto begin;
		}
		else
		{
			retry_counter--;
			if(raw_mode==mode_faketcp)
			{
				send_bare(g_packet_info_send,0,0);/////////////send
			}
			else if(raw_mode==mode_udp||raw_mode==mode_icmp)
			{
				send_bare(g_packet_info_send, (char*)"hello", strlen("hello"));/////////////send
			}
			last_state_time=get_current_time();
			mylog(log_info,"retry send ack  counter left:%d\n",retry_counter);
		}
	}

	if(client_current_state==client_handshake_sent&&get_current_time()-last_state_time>handshake_timeout)
	{
		if(retry_counter==0)
		{
			client_current_state=client_nothing;
			mylog(log_info,"state back to nothing\n");
			return 0;
			//goto begin;
		}
		else
		{
			retry_counter--;
			send_handshake(g_packet_info_send,my_id,oppsite_id,const_id);/////////////send
			last_state_time=get_current_time();
			mylog(log_info,"retry send handshake  counter left:%d\n",retry_counter);
			mylog(log_info,"handshake sent <%x,%x>\n",oppsite_id,my_id);

		}


	}

	if(client_current_state==client_ready)
	{
		mylog(log_trace,"time %lld %lld\n",get_current_time(),last_state_time);
		if(get_current_time()-last_hb_recv_time>heartbeat_timeout)
		{
			client_current_state=client_nothing;
			my_id=get_true_random_number_nz();
			mylog(log_info,"state back to nothing\n");
			return 0;
		}

		if(get_current_time()-last_hb_sent_time<heartbeat_interval)
		{
			return 0;
		}

		mylog(log_trace,"heartbeat sent <%x,%x>\n",oppsite_id,my_id);

		send_safer(g_packet_info_send,(char *)"h",1);/////////////send

		last_hb_sent_time=get_current_time();
	}
	return 0;

}

int keep_connection_server()
{
	conv_manager.clean_inactive();
	//begin:
	mylog(log_trace,"timer!\n");
	if(server_current_state==server_nothing)
	{
		if(raw_mode==mode_icmp)
		{
			remove_filter();
		}
		return 0;
	}
	if(server_current_state==server_syn_ack_sent &&get_current_time()-last_state_time>handshake_timeout )
	{
		if(retry_counter==0)
		{
			server_current_state=server_nothing;
			mylog(log_info,"state back to nothing\n");
		}
		else
		{
			retry_counter--;
			send_bare(g_packet_info_send,0,0);    /////////////send
			last_state_time=get_current_time();
			mylog(log_info,"resend syn ack\n");
		}
	}
	if(server_current_state==server_handshake_sent &&get_current_time()-last_state_time>handshake_timeout)
	{
		if(retry_counter==0)
		{
			server_current_state=server_nothing;
			mylog(log_info,"state back to nothing\n");
		}
		else
		{
			retry_counter--;
			send_handshake(g_packet_info_send,my_id,random(),const_id);   /////////////send
			last_state_time=get_current_time();
			mylog(log_info,"handshake sent<%x>\n",my_id);
		}
	}

	if(server_current_state==server_ready)
	{
		if( get_current_time()-last_hb_recv_time>heartbeat_timeout )
		{
			mylog(log_trace,"%lld %lld\n",get_current_time(),last_state_time);
			server_current_state=server_nothing;

			mylog(log_info,"changed server id\n");
			my_id=get_true_random_number_nz();

			mylog(log_info,"changed state to server_nothing\n");
			return 0;
		}

		if(get_current_time()-last_hb_sent_time<heartbeat_interval)
		{
			return 0;
		}

		//printf("heart beat sent\n");
		send_safer(g_packet_info_send,(char *)"h",1);  /////////////send

		last_hb_sent_time=get_current_time();

		mylog(log_trace,"heart beat sent<%x>\n",my_id);
	}

}

int set_timer(int epollfd,int &timer_fd)
{
	int ret;
	epoll_event ev;

	itimerspec its;
	memset(&its,0,sizeof(its));

	if((timer_fd=timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK)) < 0)
	{
		mylog(log_fatal,"timer_fd create error\n");
		myexit(1);
	}
	its.it_interval.tv_nsec=timer_interval*1000ll*1000ll;
	its.it_value.tv_nsec=1; //imidiately
	timerfd_settime(timer_fd,0,&its,0);


	ev.events = EPOLLIN;
	ev.data.u64 = epoll_timer_fd_sn;

	epoll_ctl(epollfd, EPOLL_CTL_ADD, timer_fd, &ev);
	if (ret < 0) {
		mylog(log_fatal,"epoll_ctl return %d\n", ret);
		myexit(-1);
	}
	return 0;
}


int client_on_raw_recv(packet_info_t &info)
{
	char* data;int data_len;


	if(client_current_state==client_syn_sent )
	{


		if(recv_bare(info,data,data_len)!=0)
		{
			return -1;
		}


		if (raw_mode==mode_faketcp&&!(info.syn==1&&info.ack==1&&data_len==0)) return 0;

		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			mylog(log_debug,"unexpected adress %x %x %d %d\n",info.src_ip,g_packet_info_send.dst_ip,info.src_port,g_packet_info_send.dst_port);
			return 0;
		}

		g_packet_info_send.ack_seq=info.seq+1;
		g_packet_info_send.psh=0;
		g_packet_info_send.syn=0;
		g_packet_info_send.ack=1;
		g_packet_info_send.seq+=1;

		mylog(log_info,"sent ack back\n");


		send_raw(g_packet_info_send,0,0);
		client_current_state=client_ack_sent;
		last_state_time=get_current_time();
		retry_counter=RETRY_TIME;

		mylog(log_info,"changed state to client_ack_sent\n");
	}
	if(client_current_state==client_ack_sent )
	{


		if(recv_bare(info,data,data_len)!=0)
		{
			return -1;
		}

		if(raw_mode==mode_faketcp&& (info.syn==1||info.ack!=1 ||data_len==0))
		{
			mylog(log_debug,"unexpected syn ack or other zero lenght packet\n");
			return 0;
		}
		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			mylog(log_debug,"unexpected adress %x %x %d %d\n",info.src_ip,g_packet_info_send.dst_ip,info.src_port,g_packet_info_send.dst_port);
			return 0;
		}

		/*
		if(data_len<hb_length||data[0]!='h')
		{
			printf("not a heartbeat\n");
			return 0;
		}*/


		oppsite_id=  ntohl(* ((uint32_t *)&data[0]));

		mylog(log_info,"handshake received %x\n",oppsite_id);
		mylog(log_info,"changed state to client_handshake_sent\n");
		send_handshake(g_packet_info_send,my_id,oppsite_id,const_id);

		client_current_state=client_handshake_sent;
		last_state_time=get_current_time();
		retry_counter=RETRY_TIME;
	}
	if(client_current_state==client_handshake_sent)
	{


		if(recv_safer(info,data,data_len)!=0)
		{
			return -1;
		}

		if((raw_mode==mode_faketcp&&( info.syn==1||info.ack!=1 ) )||data_len==0  )
		{
			mylog(log_trace,"unexpected syn ack or other zero lenght packet\n");
			return 0;
		}
		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			mylog(log_trace,"unexpected adress\n");
			return 0;
		}
		if(data_len!=1||data[0]!='h')
		{
			mylog(log_trace,"not a heartbeat\n");
			return 0;
		}

		/*
		uint32_t tmp_my_id= ntohl(* ((uint32_t *)&data[1+sizeof(my_id)]));
		if(tmp_my_id!=my_id)
		{
			printf("auth fail\n");
			return 0;
		}

		uint32_t tmp_oppsite_session_id=ntohl(* ((uint32_t *)&data[1]));

		if(tmp_oppsite_session_id!=oppsite_id)
		{
			printf("oppsite id mismatch%x %x,ignore\n",tmp_oppsite_session_id,my_id);
			return 0;
		}*/

		mylog(log_info,"changed state to client_ready\n");
		client_current_state=client_ready;
		last_state_time=get_current_time();
		last_hb_recv_time=get_current_time();
	}

	if(client_current_state==client_ready )
	{


		if(recv_safer(info,data,data_len)!=0)
		{
			return -1;
		}

		if((raw_mode==mode_faketcp&&( info.syn==1||info.ack!=1) )||data_len==0)
		{
			mylog(log_debug,"unexpected syn ack\n");
			return 0;
		}
		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			mylog(log_debug,"unexpected adress\n");
			return 0;
		}

		if(data_len==1&&data[0]=='h')
		{
			mylog(log_debug,"heart beat received\n");
			last_hb_recv_time=get_current_time();
			return 0;
		}
		else if(data_len>=sizeof(uint32_t)+1&&data[0]=='d')
		{
			mylog(log_trace,"received a data from fake tcp,len:%d\n",data_len);

			last_hb_recv_time=get_current_time();

			uint32_t tmp_conv_id= ntohl(* ((uint32_t *)&data[1]));

			if(!conv_manager.is_conv_used(tmp_conv_id))
			{
				mylog(log_info,"unknow conv %d,ignore\n",tmp_conv_id);
				return 0;
			}

			conv_manager.update_active_time(tmp_conv_id);

			uint64_t u64=conv_manager.find_u64_by_conv(tmp_conv_id);


			sockaddr_in tmp_sockaddr;

			tmp_sockaddr.sin_family = AF_INET;
			tmp_sockaddr.sin_addr.s_addr=(u64>>32u);

			tmp_sockaddr.sin_port= htons(uint16_t((u64<<32u)>>32u));


			int ret=sendto(udp_fd,data+1+sizeof(uint32_t),data_len -(1+sizeof(uint32_t)),0,(struct sockaddr *)&tmp_sockaddr,sizeof(tmp_sockaddr));

			if(ret<0)
			{
		    	mylog(log_warn,"sento returned %d\n",ret);
				//perror("ret<0");
			}
			mylog(log_trace,"%s :%d\n",inet_ntoa(tmp_sockaddr.sin_addr),ntohs(tmp_sockaddr.sin_port));
			mylog(log_trace,"%d byte sent\n",ret);
		}
		return 0;
	}
	return 0;
}
int server_on_raw_recv(packet_info_t &info)
{

	char* data;int data_len;



	if(server_current_state==server_nothing)
	{
		if(recv_bare(info,data,data_len)!=0)
		{
			return -1;
		}

		anti_replay.re_init();

		if(raw_mode==mode_icmp)
		{
			g_packet_info_send.src_port = info.src_port;;
		}

		g_packet_info_send.src_ip=info.dst_ip;
		g_packet_info_send.src_port=info.dst_port;

		g_packet_info_send.dst_port = info.src_port;
		g_packet_info_send.dst_ip = info.src_ip;

		if(raw_mode==mode_faketcp)
		{
			if (!(info.syn == 1 && info.ack == 0 && data_len == 0))
				return 0;

			g_packet_info_send.ack_seq = info.seq + 1;

			g_packet_info_send.psh = 0;
			g_packet_info_send.syn = 1;
			g_packet_info_send.ack = 1;

			g_packet_info_send.seq = get_true_random_number_nz(); //not necessary to set

			mylog(log_info,"sent syn ack\n");
			send_bare(g_packet_info_send, 0, 0);  //////////////send

			mylog(log_info,"changed state to server_syn_ack_sent\n");

			server_current_state = server_syn_ack_sent;
			retry_counter = 0;
			last_state_time = get_current_time();
		}
		else if(raw_mode==mode_udp||raw_mode==mode_icmp)
		{

			if(data_len==strlen("hello")&& memcmp((char *)"hello",data,strlen("hello"))!=0)
			{
				//data[6]=0;
				mylog(log_debug,"not a hello packet %d\n",data,data_len);
				return 0;
			}
			else
			{
				mylog(log_info,"got a hello packet\n");
			}

			mylog(log_info,"sent half heart_beat\n");
			//send_raw(g_packet_info_send, 0, 0);
			send_handshake(g_packet_info_send,my_id,random(),const_id);  //////////////send

			mylog(log_info,"changed state to server_heartbeat_sent_sent\n");

			server_current_state = server_handshake_sent;
			retry_counter = 0;
			last_state_time = get_current_time();
		}
	}
	else if(server_current_state==server_syn_ack_sent)
	{
		if(recv_bare(info,data,data_len)!=0)
		{
			return -1;
		}

		if(raw_mode==mode_faketcp&&!( info.syn==0&&info.ack==1 &&data_len==0)) return 0;
		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			mylog(log_debug,"unexpected adress\n");
			return 0;
		}

		g_packet_info_send.syn=0;
		g_packet_info_send.ack=1;
		g_packet_info_send.seq+=1;////////is this right?

		send_handshake(g_packet_info_send,my_id,0,const_id);   //////////////send

		mylog(log_info,"changed state to server_handshake_sent\n");

		server_current_state=server_handshake_sent;
		last_state_time=get_current_time();

		retry_counter=RETRY_TIME;

	}
	else if(server_current_state==server_handshake_sent)//heart beat received
	{
		if(recv_bare(info,data,data_len)!=0)
		{
			return -1;
		}

		if(( raw_mode==mode_faketcp&& (info.syn==1||info.ack!=1)) ||data_len==0)  return 0;

		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			mylog(log_trace,"unexpected adress\n");
			return 0;
		}
		/*
		if(data_len<hb_length||data[0]!='h')
		{
			return 0;
		}*/

		uint32_t tmp_session_id= ntohl(* ((uint32_t *)&data[sizeof(my_id)]));

		uint32_t tmp_oppsite_const_id=ntohl(* ((uint32_t *)&data[sizeof(my_id)*2]));

		if(oppsite_const_id!=0&&tmp_oppsite_const_id!=oppsite_const_id)
		{
			conv_manager.clear();
		}
		oppsite_const_id=tmp_oppsite_const_id;



		if(tmp_session_id!=my_id)
		{
			mylog(log_trace,"auth fail!!\n");
			return 0;
		}

		int tmp_oppsite_session_id=  ntohl(* ((uint32_t *)&data[0]));
		oppsite_id=tmp_oppsite_session_id;


		mylog(log_info,"received heartbeat %x %x\n",oppsite_id,tmp_session_id);

		send_safer(g_packet_info_send,(char *)"h",1);/////////////send

		//send_hb(g_packet_info_send,my_id,oppsite_id,const_id);/////////////////send

		server_current_state=server_ready;
		last_state_time=get_current_time();

		last_hb_recv_time=get_current_time();
		//first_data_packet=1;

		mylog(log_info,"changed state to server_ready\n");

	}
	else if(server_current_state==server_ready)
	{
		if(recv_safer(info,data,data_len)!=0)
		{
			return -1;
		}

		if( (raw_mode==mode_faketcp&&(info.syn==1||info.ack!=1)) ||data_len==0)  return 0;
		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			mylog(log_debug,"unexpected adress\n");
			return 0;
		}

		if(data[0]=='h'&&data_len==1)
		{
			uint32_t tmp= ntohl(* ((uint32_t *)&data[1+sizeof(uint32_t)]));
			mylog(log_debug,"received hb <%x,%x>\n",oppsite_id,tmp);
			last_hb_recv_time=get_current_time();
			return 0;
		}
		else if(data[0]=='d'&&data_len>=sizeof(uint32_t)+1)
		{
			uint32_t tmp_conv_id=ntohl(* ((uint32_t *)&data[1]));

			last_hb_recv_time=get_current_time();

			mylog(log_debug,"<<<<conv:%u>>>>\n",tmp_conv_id);
			if(!conv_manager.is_conv_used(tmp_conv_id))
			{
				struct sockaddr_in remote_addr_in;

				socklen_t slen = sizeof(sockaddr_in);
				memset(&remote_addr_in, 0, sizeof(remote_addr_in));
				remote_addr_in.sin_family = AF_INET;
				remote_addr_in.sin_port = htons(remote_port);
				remote_addr_in.sin_addr.s_addr = remote_address_uint32;

				int new_udp_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
				if(new_udp_fd<0)
				{
					mylog(log_warn,"create udp_fd error\n");
					return -1;
				}
				set_buf_size(new_udp_fd);

				mylog(log_debug,"created new udp_fd %d\n",new_udp_fd);
				int ret = connect(new_udp_fd, (struct sockaddr *) &remote_addr_in, slen);
				if(ret!=0)
				{
					mylog(log_warn,"udp fd connect fail\n");
					close(new_udp_fd);
					return -1;
				}
				struct epoll_event ev;

				uint64_t u64=((u_int64_t(tmp_conv_id))<<32u)+(uint32_t)new_udp_fd;
				mylog(log_trace,"u64: %ld\n",u64);
				ev.events = EPOLLIN;

				ev.data.u64 = u64;

				ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, new_udp_fd, &ev);

				if (ret!= 0) {
					mylog(log_warn,"add udp_fd error\n");
					close(new_udp_fd);
					return -1;
				}

				conv_manager.insert_conv(tmp_conv_id,u64);

				mylog(log_info,"new conv conv_id=%x, assigned fd=%d\n",tmp_conv_id,new_udp_fd);

			}

			uint64_t u64=conv_manager.find_u64_by_conv(tmp_conv_id);

			conv_manager.update_active_time(tmp_conv_id);

			int fd=int((u64<<32u)>>32u);

			mylog(log_debug,"received a data from fake tcp,len:%d\n",data_len);
			int ret=send(fd,data+1+sizeof(uint32_t),data_len -(1+sizeof(uint32_t)),0);

			mylog(log_debug,"%d byte sent  ,fd :%d\n ",ret,fd);
			if(ret<0)
			{
		    	mylog(log_warn,"send returned %d\n",ret);
				//perror("what happened????");
			}


			/*
			if(first_data_packet==0&& tmp_conv_id!=conv_id)  //magic to find out which one is actually larger
				//consider 0xffffffff+1= 0x0 ,in this case 0x0 is "actually" larger
			{
				uint32_t smaller,bigger;
				smaller=min(conv_id,tmp_conv_id);//smaller in normal sense
				bigger=max(conv_id,tmp_conv_id);
				uint32_t distance=min(bigger-smaller,smaller+(0xffffffff-bigger+1));

				if(distance==bigger-smaller)
				{
					if(bigger==conv_id) //received_session_id is acutally bigger
					{
						printf("old_session_id ,ingored1\n");
						return 0;
					}
				}
				else
				{
					if(smaller==conv_id) //received_session_id is acutally bigger
					{
						printf("old_session_id ,ingored2\n");
						return 0;
					}
				}
			}
			first_data_packet=0;

			if(udp_fd==-1||tmp_conv_id!=conv_id)// this is first send or client changed session
			{
				int old_fd=udp_fd;

				struct sockaddr_in remote_addr_in;

				socklen_t slen = sizeof(sockaddr_in);
				memset(&remote_addr_in, 0, sizeof(remote_addr_in));
				remote_addr_in.sin_family = AF_INET;
				remote_addr_in.sin_port = htons(remote_port);
				remote_addr_in.sin_addr.s_addr = inet_addr(remote_address);
				udp_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
				set_udp_buf_size(udp_fd);

				printf("created new udp_fd");
				int ret = connect(udp_fd, (struct sockaddr *) &remote_addr_in, slen);
				if(ret!=0)
				{
					printf("udp fd connect fail\n");
				}
				struct epoll_event ev;

				ev.events = EPOLLIN;
				epoll_udp_fd_sn+=256;
				ev.data.u64 = epoll_udp_fd_sn;

				ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, udp_fd, &ev);

				if (ret!= 0) {
					printf("add udp_fd error\n");
					exit(-1);
				}

				if(old_fd!=-1)
				{
					epoll_ctl(epollfd, EPOLL_CTL_DEL, old_fd, 0);
					close(old_fd);
				}

			}

			if(tmp_conv_id!=conv_id)
			{
				conv_id=tmp_conv_id;
			}
			*/


		}
	}
	return 0;
}
int get_src_adress(uint32_t &ip)
{
	struct sockaddr_in remote_addr_in;

	socklen_t slen = sizeof(sockaddr_in);
	memset(&remote_addr_in, 0, sizeof(remote_addr_in));
	remote_addr_in.sin_family = AF_INET;
	remote_addr_in.sin_port = htons(remote_port);
	remote_addr_in.sin_addr.s_addr = remote_address_uint32;


	int new_udp_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(new_udp_fd<0)
	{
		mylog(log_warn,"create udp_fd error\n");
		return -1;
	}
	set_buf_size(new_udp_fd);

	mylog(log_debug,"created new udp_fd %d\n",new_udp_fd);
	int ret = connect(new_udp_fd, (struct sockaddr *) &remote_addr_in, slen);
	if(ret!=0)
	{
		mylog(log_warn,"udp fd connect fail\n");
		close(new_udp_fd);
		return -1;
	}

	struct sockaddr_in my_addr;
	unsigned int len=sizeof(my_addr);

    if(getsockname(new_udp_fd, (struct sockaddr *) &my_addr, &len)!=0) return -1;

    ip=my_addr.sin_addr.s_addr;

    close(new_udp_fd);

    return 0;
}
int client_event_loop()
{
	char buf[buf_len];

	//printf("?????\n");
	if(source_address_uint32==0)
	{
		mylog(log_info,"get_src_adress called\n");
		if(get_src_adress(source_address_uint32)!=0)
		{
			mylog(log_fatal,"the trick to auto get source ip failed,you should specific an ip by --source-ip\n");
			myexit(-1);
		}
	}
	in_addr tmp;
	tmp.s_addr=source_address_uint32;
	mylog(log_info,"source ip = %s\n",inet_ntoa(tmp));
	//printf("done\n");


	if(try_to_list_and_bind(source_port)!=0)
	{
		mylog(log_fatal,"bind to source_port:%d fail\n ",source_port);
		myexit(-1);
	}
	g_packet_info_send.src_port=source_port;


	g_packet_info_send.src_ip = source_address_uint32;

	int i, j, k;int ret;
	init_raw_socket();
	//my_id=get_true_random_number_nz();
	conv_num=get_true_random_number_nz();

	//init_filter(source_port);
	g_packet_info_send.dst_ip=remote_address_uint32;
	g_packet_info_send.dst_port=remote_port;

	//g_packet_info.src_ip=source_address_uint32;
	//g_packet_info.src_port=source_port;

    udp_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    set_buf_size(udp_fd);

	int yes = 1;
	//setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	struct sockaddr_in local_me;

	socklen_t slen = sizeof(sockaddr_in);
	memset(&local_me, 0, sizeof(local_me));
	local_me.sin_family = AF_INET;
	local_me.sin_port = htons(local_port);
	local_me.sin_addr.s_addr = local_address_uint32;


	if (bind(udp_fd, (struct sockaddr*) &local_me, slen) == -1) {
		mylog(log_fatal,"socket bind error\n");
		//perror("socket bind error");
		myexit(1);
	}
	setnonblocking(udp_fd);
	int epollfd = epoll_create1(0);
	const int max_events = 4096;
	struct epoll_event ev, events[max_events];
	if (epollfd < 0) {
		mylog(log_fatal,"epoll return %d\n", epollfd);
		myexit(-1);
	}

	ev.events = EPOLLIN;
	ev.data.u64 = epoll_udp_fd_sn;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, udp_fd, &ev);
	if (ret!=0) {
		mylog(log_fatal,"add  udp_listen_fd error\n");
		myexit(-1);
	}
	ev.events = EPOLLIN;
	ev.data.u64 = epoll_raw_recv_fd_sn;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
	if (ret!= 0) {
		mylog(log_fatal,"add raw_fd error\n");
		myexit(-1);
	}

	////add_timer for fake_tcp_keep_connection_client

	//sleep(10);

	//memset(&udp_old_addr_in,0,sizeof(sockaddr_in));
	int unbind=1;
	int timer_fd;

	set_timer(epollfd,timer_fd);
	while(1)////////////////////////
	{
		int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
		if (nfds < 0) {  //allow zero
			mylog(log_fatal,"epoll_wait return %d\n", nfds);
			myexit(-1);
		}
		int n;
		for (n = 0; n < nfds; ++n) {
			if (events[n].data.u64 == epoll_raw_recv_fd_sn)
			{
				iphdr *iph;tcphdr *tcph;
				client_on_raw_recv(g_packet_info_recv);
			}
			if(events[n].data.u64 ==epoll_timer_fd_sn)
			{
				uint64_t value;
				read(timer_fd, &value, 8);
				keep_connection_client();
			}
			if (events[n].data.u64 == epoll_udp_fd_sn)
			{

				socklen_t recv_len;
				struct sockaddr_in udp_new_addr_in;
				if ((recv_len = recvfrom(udp_fd, buf, buf_len, 0,
						(struct sockaddr *) &udp_new_addr_in, &slen)) == -1) {
					mylog(log_error,"recv_from error\n");
					//exit(1);
				};

				mylog(log_trace,"Received packet from %s:%d,len: %d\n", inet_ntoa(udp_new_addr_in.sin_addr),
						ntohs(udp_new_addr_in.sin_port),recv_len);

				/*
				if(udp_old_addr_in.sin_addr.s_addr==0&&udp_old_addr_in.sin_port==0)
				{
					memcpy(&udp_old_addr_in,&udp_new_addr_in,sizeof(udp_new_addr_in));
				}
				else if(udp_new_addr_in.sin_addr.s_addr!=udp_old_addr_in.sin_addr.s_addr
						||udp_new_addr_in.sin_port!=udp_old_addr_in.sin_port)
				{
					if(get_current_time()- last_udp_recv_time <udp_timeout)
					{
						printf("new <ip,port> connected in,ignored,bc last connection is still active\n");
						continue;
					}
					else
					{
						printf("new <ip,port> connected in,accpeted\n");
						memcpy(&udp_old_addr_in,&udp_new_addr_in,sizeof(udp_new_addr_in));
						conv_id++;
					}
				}*/

				//last_udp_recv_time=get_current_time();
				uint64_t u64=((uint64_t(udp_new_addr_in.sin_addr.s_addr))<<32u)+ntohs(udp_new_addr_in.sin_port);
				uint32_t conv;

				if(!conv_manager.is_u64_used(u64))
				{
					conv=conv_manager.get_new_conv();
					conv_manager.insert_conv(conv,u64);
					mylog(log_info,"new connection from %s:%d,conv_id=%x\n",inet_ntoa(udp_new_addr_in.sin_addr),ntohs(udp_new_addr_in.sin_port),conv);
				}
				else
				{
					conv=conv_manager.find_conv_by_u64(u64);
				}

				conv_manager.update_active_time(conv);

				if(client_current_state==client_ready)
				{
						send_data_safer(g_packet_info_send,buf,recv_len,conv);
				}
			}
		}
	}
	return 0;
}


int server_event_loop()
{
	char buf[buf_len];

	conv_manager.set_clear_function(server_clear_function);
	int i, j, k;int ret;

	//g_packet_info_send.src_ip=inet_addr(local_address);
	//g_packet_info_send.src_port=local_port;

	 if(raw_mode==mode_faketcp)
	 {
		 bind_fd=socket(AF_INET,SOCK_STREAM,0);
	 }
	 else  if(raw_mode==mode_udp||raw_mode==mode_icmp)
	 {
		 bind_fd=socket(AF_INET,SOCK_DGRAM,0);
	 }

	 struct sockaddr_in temp_bind_addr;
     bzero(&temp_bind_addr, sizeof(temp_bind_addr));

     temp_bind_addr.sin_family = AF_INET;
     temp_bind_addr.sin_port = htons(local_port);
     temp_bind_addr.sin_addr.s_addr = local_address_uint32;

     if (bind(bind_fd, (struct sockaddr*)&temp_bind_addr, sizeof(temp_bind_addr)) !=0)
     {
    	 mylog(log_fatal,"bind fail\n");
    	 myexit(-1);
     }
	 if(raw_mode==mode_faketcp)
	 {

		 if(listen(bind_fd, SOMAXCONN) != 0 )
		 {
			 mylog(log_fatal,"listen fail\n");
			 myexit(-1);
		 }
	 }



	init_raw_socket();
	init_filter(local_port);

	epollfd = epoll_create1(0);
	const int max_events = 4096;

	struct epoll_event ev, events[max_events];
	if (epollfd < 0) {
		mylog(log_fatal,"epoll return %d\n", epollfd);
		myexit(-1);
	}

	ev.events = EPOLLIN;
	ev.data.u64 = epoll_raw_recv_fd_sn;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
	if (ret!= 0) {
		mylog(log_fatal,"add raw_fd error\n");
		myexit(-1);
	}
	int timer_fd;
	set_timer(epollfd,timer_fd);
	while(1)////////////////////////
	{
		int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
		if (nfds < 0) {  //allow zero
			mylog(log_fatal,"epoll_wait return %d\n", nfds);
			myexit(-1);
		}
		int n;
		const int MTU=1440;
		for (n = 0; n < nfds; ++n)
		{
			if ((events[n].data.u64 >>32u) > 0u)
			{
				uint32_t conv_id=events[n].data.u64>>32u;

				int fd=int((events[n].data.u64<<32u)>>32u);

				if(!conv_manager.is_u64_used(events[n].data.u64))
				{
					mylog(log_debug,"conv %x no longer exists\n",conv_id);
					int recv_len=recv(fd,buf,buf_len,0); ///////////TODO ,delete this
					continue;
				}



				int recv_len=recv(fd,buf,buf_len,0);

				mylog(log_debug,"received a packet from udp_fd,len:%d\n",recv_len);

				if(recv_len<0)
				{
					mylog(log_trace,"continue\n");
					//perror("wtf?");
					continue;
					//return 0;
				}

				conv_manager.update_active_time(conv_id);

				if(server_current_state==server_ready)
				{
					send_data_safer(g_packet_info_send,buf,recv_len,conv_id);
					//send_data(g_packet_info_send,buf,recv_len,my_id,oppsite_id,conv_id);
					mylog(log_trace,"send !!\n");
				}
			}
			//printf("%d %d %d %d\n",timer_fd,raw_recv_fd,raw_send_fd,n);
			if (events[n].data.u64 == epoll_timer_fd_sn)
			{
				uint64_t value;
				read(timer_fd, &value, 8);
				keep_connection_server();
			}
			if (events[n].data.u64 == epoll_raw_recv_fd_sn)
			{
				iphdr *iph;tcphdr *tcph;
				server_on_raw_recv(g_packet_info_recv);
			}

		}
	}
	return 0;
}


int get_ip_deprecated()
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);


    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;

    /* I want an IP address attached to "eth0" */
    strncpy(ifr.ifr_name, "eth1", IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    /* Display result */
    printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    return 0;
}
void print_help()
{
	printf("udp-to-raw tunnel v0.1\n");
	printf("\n");
	printf("usage:\n");
	printf("    run as client : ./this_program -c -l adress:port -r adress:port  [options]\n");
	printf("    run as server : ./this_program -s -l adress:port -r adress:port  [options]\n");
	printf("\n");
	printf("common options,these options must be same on both side:\n");
	printf("    --raw-mode      <string>    avaliable values:faketcp,udp,icmp\n");
	printf("    --key           <string>    password to gen symetric key\n");
	printf("    --auth-mode     <string>    avaliable values:aes128cbc,xor,none\n");
	printf("    --cipher-mode   <string>    avaliable values:md5,crc32,sum,none\n");
	printf("\n");
	printf("client options:\n");
	printf("    --source-ip     <ip>        override source-ip for raw socket\n");
	printf("    --source-port   <port>      override source-port for tcp/udp \n");
	printf("\n");
	printf("other options:\n");
	printf("    --log-level     <number>    0:never print log\n");
	printf("                                1:fatal\n");
	printf("                                2:error\n");
	printf("                                3:warn\n");
	printf("                                4:info (default)\n");
	printf("                                5:debug\n");
	printf("                                6:trace\n");
	printf("\n");
	printf("    --disable-color             disable log color\n");
	printf("    --log-position              enable file name,function name,line number in log\n");
	printf("    --disable-bpf               disable the kernel space filter,most time its not necessary\n");
	printf("                                unless you suspect there is a bug\n");
	printf("\n");
	printf("    --sock-buf      <number>    buf size for socket,>=1 and <=10240,unit:kbyte\n");
	printf("    --seqmode       <number>    seq increase mode for faketcp:\n");
	printf("                                0:dont increase\n");
	printf("                                1:increase every packet\n");
	printf("                                2:increase randomly, about every 5 packets (default)\n");
	printf("\n");
	printf("    -h,--help                   print this help message\n");

	//printf("common options,these options must be same on both side\n");
}
void process_arg(int argc, char *argv[])
{
	int i,j,k,opt;
    static struct option long_options[] =
      {
        /* These options set a flag. */
        {"source-ip", required_argument,    0, 1},
        {"source-port", required_argument,    0, 1},
		{"log-level", required_argument,    0, 1},
		{"key", required_argument,    0, 'k'},
		{"auth-mode", required_argument,    0, 1},
		{"cipher-mode", required_argument,    0, 1},
		{"raw-mode", required_argument,    0, 1},
		{"disable-color", no_argument,    0, 1},
		{"log-position", no_argument,    0, 1},
		{"disable-bpf", no_argument,    0, 1},
		{"sock-buf", required_argument,    0, 1},
		{"seq-mode", required_argument,    0, 1},
		{NULL, 0, 0, 0}
      };

    int option_index = 0;
	for (i = 0; i < argc; i++)
	{
		if(strcmp(argv[i],"-h")==0||strcmp(argv[i],"--help")==0)
		{
			print_help();
			myexit(0);
		}
	}
	for (i = 0; i < argc; i++)
	{
		if(strcmp(argv[i],"--log-level")==0)
		{
			if(i<argc -1)
			{
				sscanf(argv[i+1],"%d",&log_level);
				if(0<=log_level&&log_level<log_end)
				{
				}
				else
				{
					log_bare(log_fatal,"invalid log_level\n");
					myexit(-1);
				}
			}
		}
	}

    mylog(log_info,"argc=%d ", argc);

	for (i = 0; i < argc; i++) {
		log_bare(log_info, "%s ", argv[i]);
	}
	log_bare(log_info, "\n");

	if (argc == 1)
	{
		print_help();
		myexit(-1);
	}

	int no_l = 1, no_r = 1;
	while ((opt = getopt_long(argc, argv, "l:r:sch",long_options,&option_index)) != -1) {
		//string opt_key;
		//opt_key+=opt;
		switch (opt) {
		case 'l':
			no_l = 0;
			if (strchr(optarg, ':') != 0) {
				sscanf(optarg, "%[^:]:%d", local_address, &local_port);
			} else {
				strcpy(local_address, "127.0.0.1");
				sscanf(optarg, "%d", &local_port);
			}
			break;
		case 'r':
			no_r = 0;
			if (strchr(optarg, ':') != 0) {
				sscanf(optarg, "%[^:]:%d", remote_address, &remote_port);
			} else {
				strcpy(remote_address, "127.0.0.1");
				sscanf(optarg, "%d", &remote_port);
			}
			break;
		case 's':
			if(program_mode==0)
			{
				program_mode=server_mode;
			}
			else
			{
				mylog(log_fatal,"-s /-c has already been set,-s option conflict\n");
				myexit(-1);
			}
			break;
		case 'c':
			if(program_mode==0)
			{
				program_mode=client_mode;
			}
			else
			{
				mylog(log_fatal,"-s /-c has already been set,-c option conflict\n");
				myexit(-1);
			}
			break;
		case 'h':
			break;

		case 'k':
			mylog(log_debug,"parsing key option\n");
			sscanf(optarg,"%s",key_string);
			break;
		case 1:
			mylog(log_debug,"option_index: %d\n",option_index);
			if(strcmp(long_options[option_index].name,"source-ip")==0)
			{
				mylog(log_debug,"parsing long option :source-ip\n");
				sscanf(optarg, "%s", source_address);
				mylog(log_debug,"source: %s\n",source_address);
			}
			else if(strcmp(long_options[option_index].name,"source-port")==0)
			{
				mylog(log_debug,"parsing long option :source-port\n");
				sscanf(optarg, "%d", &source_port);
				mylog(log_info,"source: %d\n",&source_port);
			}
			else if(strcmp(long_options[option_index].name,"raw-mode")==0)
			{
				for(i=0;i<mode_end;i++)
				{
					if(strcmp(optarg,raw_mode_tostring[i].c_str())==0)
					{
						raw_mode=(raw_mode_t)i;
						break;
					}
				}
				if(i==mode_end)
				{
					mylog(log_fatal,"no such raw_mode %s\n",optarg);
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"auth-mode")==0)
			{
				for(i=0;i<auth_end;i++)
				{
					if(strcmp(optarg,auth_mode_tostring[i].c_str())==0)
					{
						auth_mode=(auth_mode_t)i;
						break;
					}
				}
				if(i==auth_end)
				{
					mylog(log_fatal,"no such auth_mode %s\n",optarg);
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"cipher-mode")==0)
			{
				for(i=0;i<cipher_end;i++)
				{
					if(strcmp(optarg,cipher_mode_tostring[i].c_str())==0)
					{
						cipher_mode=(cipher_mode_t)i;
						break;
					}
				}
				if(i==cipher_end)
				{
					mylog(log_fatal,"no such cipher_mode %s\n",optarg);
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"log-level")==0)
			{
			}
			else if(strcmp(long_options[option_index].name,"disable-color")==0)
			{
				enable_log_color=0;
			}
			else if(strcmp(long_options[option_index].name,"log-position")==0)
			{
				enable_log_position=1;
			}
			else if(strcmp(long_options[option_index].name,"disable-bpf")==0)
			{
				disable_bpf_filter=1;
			}
			else if(strcmp(long_options[option_index].name,"sock-buf")==0)
			{
				int tmp=-1;
				sscanf(optarg,"%d",&tmp);
				if(1<=tmp&&tmp<=10*1024)
				{
					socket_buf_size=tmp*1024;
				}
				else
				{
					mylog(log_fatal,"sock-buf value must be between 1 and 10240 (kbyte) \n");
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"seq-mode")==0)
			{
				sscanf(optarg,"%d",&seq_mode);
				if(1<=seq_mode&&seq_mode<=10*1024)
				{
				}
				else
				{
					mylog(log_fatal,"seq_mode value must be  0,1,or 2 \n");
					myexit(-1);
				}
			}
			else
			{
				mylog(log_warn,"ignored unknown long option ,option_index:%d code:<%x>\n",option_index, optopt);
			}
			break;
		default:
			mylog(log_warn,"ignored unknown option ,code:<%x>\n", optopt);
		}
	}

	if (no_l)
		mylog(log_fatal,"error: -l not found\n");
	if (no_r)
		mylog(log_fatal,"error: -r not found\n");
	if(program_mode==0)
		mylog(log_fatal,"error: -c /-s  hasnt been set\n");
	if (no_l || no_r||program_mode==0)
	{
		print_help();
		myexit(-1);
	}

	 mylog(log_info,"important variables: ", argc);

	 log_bare(log_info,"log_level=%d:%s ",log_level,log_text[log_level]);
	 log_bare(log_info,"raw_mode=%s ",raw_mode_tostring[raw_mode].c_str());
	 log_bare(log_info,"cipher_mode=%s ",cipher_mode_tostring[cipher_mode].c_str());
	 log_bare(log_info,"auth_mode=%s ",auth_mode_tostring[auth_mode].c_str());

	 log_bare(log_info,"key=%s ",key_string);

	 log_bare(log_info,"local_ip=%s ",local_address);
	 log_bare(log_info,"local_port=%d ",local_port);
	 log_bare(log_info,"remote_ip=%s ",remote_address);
	 log_bare(log_info,"remote_port=%d ",remote_port);
	 log_bare(log_info,"source_ip=%s ",source_address);
	 log_bare(log_info,"source_port=%d ",source_port);

	 log_bare(log_info,"socket_buf_size=%d ",socket_buf_size);

	 log_bare(log_info,"\n");
}
int main(int argc, char *argv[])
{
	signal(SIGINT, INThandler);
	signal(SIGCHLD, handler);
	process_arg(argc,argv);

	dup2(1, 2);//redirect stderr to stdout
	srand(time(0));

	if(raw_mode==mode_faketcp)
	{
		g_packet_info_send.protocol=IPPROTO_TCP;
	}
	else if(raw_mode==mode_udp)
	{
		g_packet_info_send.protocol=IPPROTO_UDP;
	}
	else if(raw_mode==mode_icmp)
	{
		g_packet_info_send.protocol=IPPROTO_ICMP;
	}
	init_random_number_fd();
	my_id=get_true_random_number_nz();
	const_id=get_true_random_number_nz();

	mylog(log_info,"myid:%x constid:%x\n",my_id,const_id);

	anti_replay_seq=get_true_random_number_nz();

	g_packet_info_send.ack_seq=get_true_random_number_nz();
	g_packet_info_send.seq=get_true_random_number_nz();

	local_address_uint32=inet_addr(local_address);
	remote_address_uint32=inet_addr(remote_address);
	source_address_uint32=inet_addr(source_address);


	char tmp[1000]="";

	strcat(tmp,key_string);

	strcat(tmp,"key1");



	md5((uint8_t*)tmp,strlen(tmp),(uint8_t*)key);

	tmp[0]=0;

	strcat(tmp,key_string);

	strcat(tmp,"key2");

	md5((uint8_t*)tmp,strlen(tmp),(uint8_t*)key2);


	if(program_mode==client_mode)
	{
		client_event_loop();
	}
	else
	{
		server_event_loop();
	}

	return 0;
}
