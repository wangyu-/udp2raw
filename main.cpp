#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<getopt.h>
#include <unistd.h>
#include<errno.h>

#include <fcntl.h>
//#include"aes.h"

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

using namespace std;

const int mode_tcp=0;
const int mode_udp=1;
const int mode_icmp=2;
int raw_mode=mode_udp;

char local_address[100], remote_address[100],source_address[100];
int local_port = -1, remote_port = -1;
int epollfd ;

uint32_t const_id=0;

uint32_t oppsite_const_id=0;

uint32_t my_id=0;
uint32_t oppsite_id=0;

uint32_t conv_id=0;

uint32_t link_level_header_len=0;

const int handshake_timeout=2000;

const int heartbeat_timeout=10000;
const int udp_timeout=3000;

const int heartbeat_interval=1000;

const int timer_interval=500;

const int RETRY_TIME=3;

//const uint16_t tcp_window=50000;

const int buf_len = 65535+100;

const int server_mode=2;
const int client_mode=1;
int prog_mode=0; //0 unset; 1client 2server


const int disable_encrypt=0;
const int disable_anti_replay=0;

const int disable_bpf_filter=1;



const int debug_mode=0;
int bind_fd;

int first_data_packet=0;

const int seq_mode=2;  //0  dont  increase /1 increase   //increase randomly,about every 5 packet

const uint64_t epoll_timer_fd_sn=1;
const uint64_t epoll_raw_recv_fd_sn=2;
const uint64_t epoll_udp_fd_sn_begin=256;
uint64_t epoll_udp_fd_sn=epoll_udp_fd_sn_begin;  //udp_fd_sn =256,512,768......the lower 8 bit is not used,to avoid confliction


const int server_nothing=0;
const int server_syn_ack_sent=1;
const int server_heartbeat_sent=2;
const int server_ready=3;
int server_current_state=server_nothing;
long long last_hb_recv_time;
long long last_udp_recv_time=0;

int socket_buf_size=1024*1024*4;

int udp_fd=-1;
int raw_recv_fd;
int raw_send_fd;

int filter_port=-1;
const int client_nothing=0;
const int client_syn_sent=1;
const int client_ack_sent=2;
const int client_heartbeat_sent=3;
const int client_ready=4;
int client_current_state=client_nothing;
int retry_counter;

long long last_state_time=0;

long long last_hb_sent_time=0;


char buf[buf_len];
char buf2[buf_len];
char raw_send_buf[buf_len];
char raw_send_buf2[buf_len];
char raw_recv_buf[buf_len];
char raw_recv_buf2[buf_len];
char raw_recv_buf3[buf_len];
char replay_buf[buf_len];
char send_data_buf[buf_len];  //buf for send data and send hb

struct sock_filter code_tcp[] = {
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
sock_fprog bpf;


uint16_t ip_id=1;
//const int MTU=1440;

struct sockaddr_in udp_old_addr_in;

uint64_t anti_replay_seq=0;

uint8_t key[]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,   0,0,0,0};

uint8_t key_me[16];

uint8_t key_oppsite[16];

const int window_size=2000;


int random_number_fd=-1;

const int conv_timeout=60000; //60 second
const int conv_clear_ratio=10;

const int hb_length=1+3*sizeof(uint32_t);

int OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO;
////////==============================variable/function divider=============================================================

void init_random_number_fd()
{
	random_number_fd=open("/dev/urandom",O_RDONLY);
	if(random_number_fd==-1)
	{
		printf("error open /dev/urandom");
		exit(-1);
	}
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
struct anti_replay_t
{
	uint64_t max_packet_received;
	char window[window_size];
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
			if(seq-max_packet_received>=window_size)
			{
				memset(window,0,sizeof(window));
				window[seq%window_size]=1;
			}
			else
			{
				for (int i=max_packet_received+1;i<seq;i++)
					window[i%window_size]=0;
				window[seq%window_size]=1;
			}
			max_packet_received=seq;
			return 1;
		}
		else if(seq<max_packet_received)
		{
			if(max_packet_received-seq>=window_size) return 0||disabled;
			else
			{
				if (window[seq%window_size]==1) return 0||disabled;
				else
				{
					window[seq%window_size]=1;
					return 1;
				}
			}
		}
	}
}anti_replay;


int pre_send(char * data, int &data_len)
{
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
		if(my_encrypt((unsigned char*)replay_buf,(unsigned char*)data,data_len,key_me) <0)
		{
			printf("encrypt fail\n");
			return -1;
		}
	}
	else
	{
		memcpy(data,replay_buf,data_len);
	}
	return 0;
}

int pre_recv(char * data, int &data_len)
{
	//return 0;
	if(data_len<0) return -1;

	if(disable_encrypt&&disable_anti_replay) return 0;

	if(!disable_encrypt)
	{
		if(my_decrypt((uint8_t*)data,(uint8_t*)replay_buf,data_len,key_oppsite) <0)
		{
			printf("decrypt fail\n");
			return -1;
		}
		else
		{
			printf("decrypt succ\n");
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
			printf("data_len<=0\n");
			return -2;
		}

		uint64_t seq_high= ntohl(*((uint32_t*)(replay_buf) ) );
		uint32_t seq_low= ntohl(*((uint32_t*)(replay_buf+sizeof(uint32_t)) ) );
		uint64_t recv_seq =(seq_high<<32u )+seq_low;


		if((prog_mode==client_mode&&client_current_state==client_ready)
				||(prog_mode==server_mode&&server_current_state==server_ready ))
		{
			if(data_len<sizeof(uint32_t)*2+1)
			{
				printf("no room for session id and oppiste session_id");
				return -4;
			}

			uint32_t tmp_oppiste_session_id = ntohl(
					*((uint32_t*) (replay_buf + sizeof(uint32_t) * 2+1)));
			uint32_t tmp_session_id = ntohl(
					*((uint32_t*) (replay_buf + sizeof(uint32_t) * 3+1)));

			if (tmp_oppiste_session_id != oppsite_id
					|| tmp_session_id != my_id) {
				printf("auth fail and pre send\n");
				return -5;
			}

			printf("seq=========%u\n", recv_seq);

			if (anti_replay.is_vaild(recv_seq) != 1) {
				printf("dropped replay packet\n");
				return -1;
			}
		}

		printf("<<<<<%ld,%d,%ld>>>>\n",seq_high,seq_low,recv_seq);


		memcpy(data,replay_buf+sizeof(uint32_t)*2,data_len);
	}
	else
	{
		memcpy(data,replay_buf,data_len);
	}


	return 0;
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
		perror("fcntl(sock,GETFL)");
		exit(1);
	}
	opts = opts | O_NONBLOCK;
	if (fcntl(sock, F_SETFL, opts) < 0) {
		perror("fcntl(sock,SETFL,opts)");
		exit(1);
	}

}
int set_buf_size(int fd)
{
    if(setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
    {
    	printf("SO_SNDBUFFORCE fail\n");
    	exit(1);
    }
    if(setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
    {
    	printf("SO_RCVBUFFORCE fail\n");
    	exit(1);
    }
	return 0;
}

int init_raw_socket()
{

	raw_send_fd = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);


    if(raw_send_fd == -1) {
        perror("Failed to create raw_send_fd");
        exit(1);
    }

    if(setsockopt(raw_send_fd, SOL_SOCKET, SO_SNDBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
    {
    	printf("SO_SNDBUFFORCE fail\n");
    	exit(1);
    }
	//raw_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));

	raw_recv_fd= socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));

    if(setsockopt(raw_recv_fd, SOL_SOCKET, SO_RCVBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
    {
    	printf("SO_RCVBUFFORCE fail\n");
    	exit(1);
    }
	//raw_fd=socket(AF_PACKET , SOCK_RAW , htons(ETH_P_IP));
    // packet_recv_sd = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(raw_recv_fd == -1) {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create raw_recv_fd");
        exit(1);
    }

    //IP_HDRINCL to tell the kernel that headers are included in the packet

    int one = 1;
    const int *val = &one;
    if (setsockopt (raw_send_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(2);
    }

    setnonblocking(raw_send_fd); //not really necessary
    setnonblocking(raw_recv_fd);

	return 0;
}
void init_filter(int port)
{
	filter_port=port;

	if(disable_bpf_filter) return;

	code_tcp[8].k=code_tcp[10].k=port;
	bpf.len = sizeof(code_tcp)/sizeof(code_tcp[0]);
	bpf.filter = code_tcp;
	//printf("<%d>\n",bpf.len);
	int dummy;

	int ret=setsockopt(raw_recv_fd, SOL_SOCKET, SO_DETACH_FILTER, &dummy, sizeof(dummy));
	if (ret != 0)
	{
		printf("error remove fiter\n");
		perror("filter");
		//exit(-1);
	}
	ret = setsockopt(raw_recv_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	//memset(code,0,sizeof(code));
	if (ret != 0)
	{
		printf("error set fiter\n");
		perror("filter");
		exit(-1);
	}
}

long long get_current_time()
{
	timespec tmp_time;
	clock_gettime(CLOCK_MONOTONIC, &tmp_time);
	return tmp_time.tv_sec*1000+tmp_time.tv_nsec/(1000*1000l);
}

void server_clear(uint64_t u64)
{
	int fd=int((u64<<32u)>>32u);
	epoll_event ev;

	ev.events = EPOLLIN;
	ev.data.u64 = u64;

	int ret = epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev);
	if (ret!=0)
	{
		printf("fd:%d epoll delete failed!!!!\n",fd);
	}
	ret= close(fd);
	if (ret!=0)
	{
		printf("close fd %d failed !!!!\n",fd);
	}
}
struct conv_manager_t
{
	map<uint64_t,uint32_t> u64_to_conv;  //conv and u64 are both supposed to be uniq
	map<uint32_t,uint64_t> conv_to_u64;

	map<uint32_t,uint64_t> conv_last_active_time;

	map<uint32_t,uint64_t>::iterator clear_it;

	void (*clear_function)(uint64_t u64) ;


	conv_manager_t()
	{
		clear_it=conv_last_active_time.begin();
		clear_function=0;
	}

	void set_clear_function(void (*a)(uint64_t u64))
	{
		clear_function=a;
	}
	void clear()
	{
		if(clear_function!=0)
		{
			map<uint32_t,uint64_t>::iterator it;
			for(it=conv_last_active_time.begin();it!=conv_last_active_time.end();it++)
			{
				clear_function(it->second);
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
		uint64_t u64=conv_to_u64[conv];
		if(clear_function!=0)
		{
			clear_function(u64);
		}
		conv_to_u64.erase(conv);
		u64_to_conv.erase(u64);
		conv_last_active_time.erase(conv);
		return 0;
	}
	int clean_inactive( )
	{
		map<uint32_t,uint64_t>::iterator old_it;
		map<uint32_t,uint64_t>::iterator it;
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
				printf("inactive conv %u cleared  !!!!!!!!!!!!!!!!!!!!!!!!!\n",it->first);
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


void process_arg(int argc, char *argv[])
{
	int i,j,k,opt;
    static struct option long_options[] =
      {
        /* These options set a flag. */
        {"source-ip", required_argument,    0, 1},
      };
    int option_index = 0;
	printf("argc=%d ", argc);
	for (i = 0; i < argc; i++)
		printf("%s ", argv[i]);
	printf("\n");

	if (argc == 1)
	{
		printf(
				"proc -l [adress:]port -r [adress:]port  [-a passwd] [-b passwd]\n");
		exit(-1);
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
			if(prog_mode==0)
			{
				prog_mode=server_mode;
			}
			else
			{
				printf("-s /-c has already been set,-s option conflict");
				exit(-1);
			}
			break;
		case 'c':
			if(prog_mode==0)
			{
				prog_mode=client_mode;
			}
			else
			{
				printf("-s /-c has already been set,-c option conflict");
				exit(-1);
			}
			break;
		case 'h':
			break;
		case 1:
			//if (strchr(optarg, ':') != 0) {
				sscanf(optarg, "%s", source_address);
				printf("source: %s",source_address);
			//} else {
				//printf("format --source-ip :adress");
				//exit(-1);
			//}
			break;

		default:
			printf("ignore unknown <%s>", optopt);
		}
	}

	if (no_l)
		printf("error: -i not found\n");
	if (no_r)
		printf("error: -o not found\n");
	if(prog_mode==0)
		printf("error: -s /-r  hasnt been set\n");
	if (no_l || no_r||prog_mode==0)
	{
		exit(-1);
	}
}
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

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) {
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

char send_raw_ip_buf[buf_len];

int send_raw_ip(packet_info_t &info,char * payload,int payloadlen)
{
	struct iphdr *iph = (struct iphdr *) send_raw_ip_buf;
    memset(iph,0,sizeof(iphdr));

	struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    //sin.sin_port = htons(info.dst_port); //dont need this
    sin.sin_addr.s_addr = info.dst_ip;

    iph->ihl = sizeof(iphdr)/4;  //we dont use ip options,so the length is just sizeof(iphdr)
    iph->version = 4;
    iph->tos = 0;

    iph->id = htonl (ip_id++); //Id of this packet
    iph->frag_off = htons(0x4000); //DF set,others are zero
    iph->ttl = 64;
    iph->protocol = info.protocol;
    iph->check = 0; //Set to 0 before calculating checksum
    iph->saddr = info.src_ip;    //Spoof the source ip address
    iph->daddr = info.dst_ip;

    iph->tot_len = sizeof (struct iphdr)+payloadlen;

    memcpy(send_raw_ip_buf+sizeof(iphdr) , payload, payloadlen);

    iph->check = csum ((unsigned short *) send_raw_ip_buf, iph->tot_len);

    int ret = sendto(raw_send_fd, send_raw_ip_buf, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin));

    if(ret==-1)
    {
    	printf("sendto failed\n");
    	return -1;
    }
    return 0;
}

char recv_raw_ip_buf[buf_len];
int recv_raw_ip(packet_info_t &info,char * &payload,int &payloadlen)
{
	iphdr *  iph;
	struct sockaddr saddr;
	socklen_t saddr_size;
	saddr_size = sizeof(saddr);

	int recv_len = recvfrom(raw_recv_fd, recv_raw_ip_buf, buf_len, 0 ,&saddr , &saddr_size);

	if(recv_len<0)
	{
		printf("recv_len %d",recv_len);
		return -1;
	}
	if(recv_len<link_level_header_len)
	{
		printf("length error");
	}

	if(link_level_header_len ==14&&(recv_raw_ip_buf[12]!=8||recv_raw_ip_buf[13]!=0))
	{
		printf("not an ipv4 packet!\n");
		return -1;
	}

	char *ip_begin=recv_raw_ip_buf+link_level_header_len;  //14 is eth net header

	iph = (struct iphdr *) (ip_begin);

	info.src_ip=iph->saddr;
	info.dst_ip=iph->daddr;
	info.protocol=iph->protocol;


    if (!(iph->ihl > 0 && iph->ihl <=60)) {
    	if(debug_mode) printf("iph ihl error");
        return -1;
    }

	int ip_len=ntohs(iph->tot_len);

	if(recv_len-link_level_header_len <ip_len)
	{
		printf("incomplete packet\n");
		return -1;
	}

    unsigned short iphdrlen =iph->ihl*4;

    uint32_t ip_chk=csum ((unsigned short *) ip_begin, iphdrlen);

    if(ip_chk!=0)
     {
     	printf("ip header error %d\n",ip_chk);
     	return -1;
     }

    payload=ip_begin+iphdrlen;

    payloadlen=ip_len-iphdrlen;

    if(payloadlen<0)
    {
    	printf("error payload len");
    	return -1;
    }


	return 0;
}


struct icmphdr
{
	uint8_t type;
	uint8_t code;
	uint16_t check_sum;
	uint16_t id;
	uint16_t seq;
};

char send_raw_icmp_buf[buf_len];
int send_raw_icmp(packet_info_t &info, char * payload, int payloadlen)
{
	icmphdr *icmph=(struct icmphdr *) (send_raw_icmp_buf);
	memset(icmph,0,sizeof(icmphdr));
	if(prog_mode==client_mode)
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
char send_raw_udp_buf[buf_len];
int send_raw_udp(packet_info_t &info, char * payload, int payloadlen)
{
	udphdr *udph=(struct udphdr *) (send_raw_udp_buf
			+ sizeof(struct pseudo_header));

	memset(udph,0,sizeof(udphdr));
	struct pseudo_header *psh = (struct pseudo_header *) (send_raw_udp_buf);

	udph->source = htons(info.src_port);
	udph->dest = htons(info.dst_port);

	int udp_tot_len=payloadlen+sizeof(udph);
	if(udp_tot_len>65535)
	{
		printf("invalid len\n");
		return -1;
	}
	udph->len=htons(uint16_t(udp_tot_len));

	memcpy(send_raw_udp_buf+sizeof(struct pseudo_header)+sizeof(udph),payload,payloadlen);

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
char send_raw_tcp_buf[buf_len];
int send_raw_tcp(packet_info_t &info, char * payload, int payloadlen) {  //TODO seq increase

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

		send_raw_tcp_buf[i++] = 0x08;   //i=6;
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

		send_raw_tcp_buf[i++] = 0x08;   //i=0;
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

	return 0;
}
int send_raw_tcp_deprecated(packet_info_t &info,char * payload,int payloadlen)
{
	if((prog_mode==client_mode&& payloadlen!=9)  ||(prog_mode==server_mode&& payloadlen!=5 )  )
		printf("send raw from to %d %d %d %d\n",info.src_ip,info.src_port,info.dst_ip,info.dst_port);

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

     if(prog_mode==client_mode&& payloadlen!=9  ||prog_mode==server_mode&& payloadlen!=5)
     printf("sent seq  ack_seq len<%u %u %d>\n",g_packet_info_send.seq,g_packet_info_send.ack_seq,payloadlen);

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
     if(debug_mode) printf("<ret:%d>\n",ret);
	 if(ret<0)
     {

    	 perror("raw send error");
    	 //printf("send error\n");
     }
     return 0;
}

char recv_raw_icmp_buf[buf_len];
int recv_raw_icmp(packet_info_t &info, char *&payload, int &payloadlen)
{
	char * ip_payload;
	int ip_payloadlen;

	if(recv_raw_ip(info,ip_payload,ip_payloadlen)!=0)
	{
		printf("recv_raw_ip error");
		return -1;
	}
	if(info.protocol!=IPPROTO_ICMP)
	{
		//printf("not udp protocol\n");
		return -1;
	}

	icmphdr *icmph=(struct icmphdr *) (ip_payload);

	info.src_port=info.dst_port=ntohs(icmph->id);


	if(prog_mode==client_mode)
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
		printf("icmp checksum fail %x\n",check);
		return -1;
	}

	payload=ip_payload+sizeof(icmphdr);
	payloadlen=ip_payloadlen-sizeof(icmphdr);
	printf("get a packet len=%d\n",payloadlen);

    return 0;
}
char recv_raw_udp_buf[buf_len];
int recv_raw_udp(packet_info_t &info, char *&payload, int &payloadlen)
{
	char * ip_payload;
	int ip_payloadlen;

	if(recv_raw_ip(info,ip_payload,ip_payloadlen)!=0)
	{
		printf("recv_raw_ip error");
		return -1;
	}
	if(info.protocol!=IPPROTO_UDP)
	{
		//printf("not udp protocol\n");
		return -1;
	}
	if(ip_payloadlen<sizeof(udphdr))
	{
		printf("too short to hold udpheader\n");
		return -1;
	}
	udphdr *udph=(struct udphdr*)ip_payload;

	if(ntohs(udph->len)!=ip_payloadlen)
	{

		printf("udp length error %d %d \n",ntohs(udph->len),ip_payloadlen);
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
    	printf("udp_chk:%x\n",udp_chk);
    	printf("udp header error\n");
    	return -1;

    }

    char *udp_begin=recv_raw_udp_buf+sizeof(struct pseudo_header);

    info.src_port=ntohs(udph->source);
    info.dst_port=ntohs(udph->dest);

    payloadlen = ip_payloadlen-sizeof(udphdr);

    payload=udp_begin+sizeof(udphdr);

    return 0;
}
char recv_raw_tcp_buf[buf_len];
int recv_raw_tcp(packet_info_t &info,char * &payload,int &payloadlen)
{

	char * ip_payload;
	int ip_payloadlen;


	if(recv_raw_ip(info,ip_payload,ip_payloadlen)!=0)
	{
		printf("recv_raw_ip error");
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
    	if(debug_mode) printf("tcph error");
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
    	printf("tcp_chk:%x\n",tcp_chk);
    	printf("tcp header error\n");
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
    	printf("%%%%%%%%%%rst==1%%%%%%%%%%%%%\n");
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
	iphdr *  iph;
	tcphdr * tcph;
	int size;
	struct sockaddr saddr;
	socklen_t saddr_size;
	saddr_size = sizeof(saddr);

	if(debug_mode)printf("raw!\n");

	size = recvfrom(raw_recv_fd, buf, buf_len, 0 ,&saddr , &saddr_size);

	if(buf[12]!=8||buf[13]!=0)
	{
		printf("not an ipv4 packet!\n");
		fflush(stdout);
		return -1;
	}

	char *ip_begin=buf+14;

	iph = (struct iphdr *) (ip_begin);


    if (!(iph->ihl > 0 && iph->ihl <=60)) {
    	if(debug_mode) printf("iph ihl error");
        return -1;
    }

    if (iph->protocol != IPPROTO_TCP) {
    	if(debug_mode)printf("iph protocal != tcp\n");
    	return -1;
    }


	int ip_len=ntohs(iph->tot_len);

    unsigned short iphdrlen =iph->ihl*4;
    tcph=(struct tcphdr*)(ip_begin+ iphdrlen);
    unsigned short tcphdrlen = tcph->doff*4;

    if (!(tcph->doff > 0 && tcph->doff <=60)) {
    	if(debug_mode) printf("tcph error");
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
    	printf("ip header error %d\n",ip_chk);
    	return -1;
    }
    if(tcp_chk!=0)
    {
    	printf("tcp_chk:%x\n",tcp_chk);
    	printf("tcp header error\n");
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
    	printf("%%%%%%%%%%rst==1%%%%%%%%%%%%%\n");
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
    	printf("recvd <%u %u %d>\n",ntohl(tcph->seq ),ntohl(tcph->ack_seq), payloadlen);
    }

    if(payloadlen>0&&tcph->syn==0&&tcph->ack==1)
    {
    	//if(seq_increse)
    		g_packet_info_send.ack_seq=ntohl(tcph->seq)+(uint32_t)payloadlen;
    }


    //printf("%d\n",ip_len);
/*
    for(int i=0;i<size;i++)
    {
    	printf("<%x>",(unsigned char)buf[i]);

    }
	  printf("\n");
	  */

/*
    for(int i=0;i<data_len;i++)
    {
    	printf("<%x>",(unsigned char)data[i]);
    }*/
    if(debug_mode)
    {
		printf("\n");
		printf("<%u,%u,%u,%u,%d>\n",(unsigned int)iphdrlen,(unsigned int)tcphdrlen,(unsigned int)tcph->syn,(unsigned int)tcph->ack,payloadlen);
		//fflush(stdout);
    }


	return 0;
}

int send_raw(packet_info_t &info,char * payload,int payloadlen)
{
	if(raw_mode==mode_tcp) return send_raw_tcp(info,payload,payloadlen);
	else if(raw_mode==mode_udp) return send_raw_udp(info,payload,payloadlen);
	else if(raw_mode==mode_icmp) return send_raw_icmp(info,payload,payloadlen);
}
int recv_raw(packet_info_t &info,char * &payload,int &payloadlen)
{
	if(raw_mode==mode_tcp)  return recv_raw_tcp(info,payload,payloadlen);
	else if(raw_mode==mode_udp) return recv_raw_udp(info,payload,payloadlen);
	else if(raw_mode==mode_icmp) return recv_raw_icmp(info,payload,payloadlen);
}


int send_bare_data(packet_info_t &info,char* data,int len)
{
	int new_len=len;

	memcpy(send_data_buf,data,len);

	if(pre_send(send_data_buf,new_len)<0)
	{
		return -1;
	}
	send_raw(info,send_data_buf,new_len);
	return 0;
}
int send_data(packet_info_t &info,char* data,int len,uint32_t id1,uint32_t id2,uint32_t conv_id)
{
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

	if(pre_send(send_data_buf,new_len)<0)
	{
		return -1;
	}
	send_raw(info,send_data_buf,new_len);
	return 0;
}

int send_hb(packet_info_t &info,uint32_t id1,uint32_t id2 ,uint32_t id3)
{
	int new_len=1+sizeof(my_id)*3;
	send_data_buf[0]='h';

	uint32_t tmp;
	tmp=htonl(id1);
	memcpy(send_data_buf+1,&tmp,sizeof(my_id));

	tmp=htonl(id2);
	memcpy(send_data_buf+1+sizeof(my_id),&tmp,sizeof(my_id));

	tmp=htonl(id3);
	memcpy(send_data_buf+1+sizeof(my_id)*2,&tmp,sizeof(my_id));

	if(pre_send(send_data_buf,new_len)<0)
	{
		return -1;
	}
	send_raw(info,send_data_buf,new_len);

	return 0;
}

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

	 if(raw_mode==mode_tcp)
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
     temp_bind_addr.sin_addr.s_addr = inet_addr(local_address);

     if (bind(bind_fd, (struct sockaddr*)&temp_bind_addr, sizeof(temp_bind_addr)) !=0)
     {
    	 printf("bind fail\n");
    	 return -1;
     }
	 if(raw_mode==mode_tcp)
	 {

		if (listen(bind_fd, SOMAXCONN) != 0) {
			printf("listen fail\n");
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
	printf("bind port fail\n");
	fflush(stdout);
	exit(-1);
	return -1;////for compiler check
}

int keep_connection_client() //for client
{
	conv_manager.clean_inactive();
	if(debug_mode)printf("timer!\n");
	//fflush(stdout);
	begin:
	if(client_current_state==client_nothing)
	{
		anti_replay.re_init(); //  this is not safe

		g_packet_info_send.src_port = client_bind_to_a_new_port();

		if(raw_mode==mode_icmp)
		{
			g_packet_info_send.dst_port =g_packet_info_send.src_port ;
		}
		printf("using port %d\n", g_packet_info_send.src_port);

		g_packet_info_send.src_ip = inet_addr(source_address);


		init_filter(g_packet_info_send.src_port);

		if(raw_mode==mode_tcp)
		{
			client_current_state = client_syn_sent;
			last_state_time = get_current_time();
			printf("state changed from nothing to syn_sent\n");
			retry_counter = RETRY_TIME;

			g_packet_info_send.seq = get_true_random_number_nz();
			g_packet_info_send.ack_seq = 0; //get_true_random_number();
			g_packet_info_send.ts_ack = 0;
			g_packet_info_send.ack = 0;
			g_packet_info_send.syn = 1;
			g_packet_info_send.psh = 0;

			send_raw(g_packet_info_send, 0, 0);
		}
		else if(raw_mode==mode_udp||raw_mode==mode_icmp)
		{
			client_current_state = client_ack_sent;
			last_state_time = get_current_time();
			printf("state changed from nothing to ack_sent\n");
			retry_counter = RETRY_TIME;
			g_packet_info_send.icmp_seq=0;

			send_bare_data(g_packet_info_send, (char*)"hello", strlen("hello"));

		}
	}
	if(client_current_state==client_syn_sent  &&get_current_time()-last_state_time>handshake_timeout)
	{
		if(retry_counter==0)
		{
			client_current_state=client_nothing;
			printf("state back to nothing\n");
			return 0;
			//goto begin;
		}
		else
		{
			retry_counter--;
			printf("retry send sync\n");
			send_raw(g_packet_info_send,0,0);
			last_state_time=get_current_time();
		}
	}
	if(client_current_state==client_ack_sent &&get_current_time()-last_state_time>handshake_timeout)
	{
		if(retry_counter==0)
		{
			client_current_state=client_nothing;
			printf("state back to nothing\n");
			return 0;
			//goto begin;
		}
		else
		{
			retry_counter--;
			if(raw_mode==mode_tcp)
			{
				send_raw(g_packet_info_send,0,0);
			}
			else if(raw_mode==mode_udp||raw_mode==mode_icmp)
			{
				send_bare_data(g_packet_info_send, (char*)"hello", strlen("hello"));
			}
			last_state_time=get_current_time();
			printf("retry send ack  counter left:%d\n",retry_counter);
		}
	}

	if(client_current_state==client_heartbeat_sent&&get_current_time()-last_state_time>handshake_timeout)
	{
		if(retry_counter==0)
		{
			client_current_state=client_nothing;
			printf("state back to nothing\n");
			return 0;
			//goto begin;
		}
		else
		{
			retry_counter--;
			send_hb(g_packet_info_send,my_id,oppsite_id,const_id);
			last_state_time=get_current_time();
			printf("retry send heart_beat  counter left:%d\n",retry_counter);
			printf("heartbeat sent <%x,%x>\n",oppsite_id,my_id);

		}


	}

	if(client_current_state==client_ready)
	{
		if(debug_mode)printf("time %lld %lld\n",get_current_time(),last_state_time);
		if(get_current_time()-last_hb_recv_time>heartbeat_timeout)
		{
			client_current_state=client_nothing;
			my_id=get_true_random_number_nz();
			printf("state back to nothing\n");
			return 0;
		}

		if(get_current_time()-last_hb_sent_time<heartbeat_interval)
		{
			return 0;
		}

		if(debug_mode)printf("heartbeat sent <%x,%x>\n",oppsite_id,my_id);

		send_hb(g_packet_info_send,my_id,oppsite_id,const_id);
		last_hb_sent_time=get_current_time();
	}

}

int keep_connection_server()
{
	conv_manager.clean_inactive();
	//begin:
	if(debug_mode)	printf("timer!\n");
	if(server_current_state==server_nothing)
	{
		return 0;
	}
	if(server_current_state==server_syn_ack_sent &&get_current_time()-last_state_time>handshake_timeout )
	{
		if(retry_counter==0)
		{
			server_current_state=server_nothing;
			printf("state back to nothing\n");
		}
		else
		{
			retry_counter--;
			send_raw(g_packet_info_send,0,0);
			last_state_time=get_current_time();
			printf("resend syn ack\n");
		}
	}
	if(server_current_state==server_heartbeat_sent &&get_current_time()-last_state_time>handshake_timeout)
	{
		if(retry_counter==0)
		{
			server_current_state=server_nothing;
			printf("state back to nothing\n");
		}
		else
		{
			retry_counter--;
			send_hb(g_packet_info_send,my_id,random(),const_id);
			last_state_time=get_current_time();
			printf("half heart beat sent<%x>\n",my_id);
		}
	}

	if(server_current_state==server_ready)
	{
		if( get_current_time()-last_hb_recv_time>heartbeat_timeout )
		{
			printf("%lld %lld",get_current_time(),last_state_time);
			server_current_state=server_nothing;

			printf("changed session id\n");
			my_id=get_true_random_number_nz();

			printf("state back to nothing\n");
			printf("changed state to server_nothing111\n");
			return 0;
		}

		if(get_current_time()-last_hb_sent_time<heartbeat_interval)
		{
			return 0;
		}

		send_hb(g_packet_info_send,my_id,oppsite_id,const_id);
		last_hb_sent_time=get_current_time();

		if(debug_mode) printf("heart beat sent<%x>\n",my_id);
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
		printf("timer_fd create error");
		exit(1);
	}
	its.it_interval.tv_nsec=timer_interval*1000ll*1000ll;
	its.it_value.tv_nsec=1; //imidiately
	timerfd_settime(timer_fd,0,&its,0);


	ev.events = EPOLLIN;
	ev.data.u64 = epoll_timer_fd_sn;

	epoll_ctl(epollfd, EPOLL_CTL_ADD, timer_fd, &ev);
	if (ret < 0) {
		printf("epoll_ctl return %d\n", ret);
		exit(-1);
	}
}

int client_on_raw_recv(packet_info_t &info,char * data,int data_len)
{
	if(client_current_state==client_syn_sent )
	{
		if (raw_mode==mode_tcp&&!(info.syn==1&&info.ack==1&&data_len==0)) return 0;

		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}

		g_packet_info_send.ack_seq=info.seq+1;
		g_packet_info_send.psh=0;
		g_packet_info_send.syn=0;
		g_packet_info_send.ack=1;
		g_packet_info_send.seq+=1;

		printf("sent ack back\n");


		send_raw(g_packet_info_send,0,0);
		client_current_state=client_ack_sent;
		last_state_time=get_current_time();
		retry_counter=RETRY_TIME;

		printf("changed state to client_ack_sent\n");
	}
	if(client_current_state==client_ack_sent )
	{
		if(raw_mode==mode_tcp&& (info.syn==1||info.ack!=1 ||data_len==0))
		{
			printf("unexpected syn ack or other zero lenght packet\n");
			return 0;
		}
		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}

		if(data_len<hb_length||data[0]!='h')
		{
			printf("not a heartbeat\n");
			return 0;
		}


		oppsite_id=  ntohl(* ((uint32_t *)&data[1]));

		printf("====first hb received %x\n==",oppsite_id);
		printf("changed state to client_heartbeat_sent\n");
		send_hb(g_packet_info_send,my_id,oppsite_id,const_id);

		client_current_state=client_heartbeat_sent;
		last_state_time=get_current_time();
		retry_counter=RETRY_TIME;
	}
	if(client_current_state==client_heartbeat_sent)
	{
		if((raw_mode==mode_tcp&&( info.syn==1||info.ack!=1 ) )||data_len==0  )
		{
			printf("unexpected syn ack or other zero lenght packet\n");
			return 0;
		}
		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}
		if(data_len<hb_length||data[0]!='h')
		{
			printf("not a heartbeat\n");
			return 0;
		}
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
		}

		printf("changed state to client_ready\n");
		client_current_state=client_ready;
		last_state_time=get_current_time();
		last_hb_recv_time=get_current_time();
	}

	if(client_current_state==client_ready )
	{
		if((raw_mode==mode_tcp&&( info.syn==1||info.ack!=1) )||data_len==0)
		{
			printf("unexpected syn ack");
			return 0;
		}
		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}

		if(data_len>=hb_length&&data[0]=='h')
		{
			if(debug_mode)printf("heart beat received\n");
			last_hb_recv_time=get_current_time();
			return 0;
		}
		else if(data_len>=sizeof(my_id)*3+1&&data[0]=='d')
		{
			printf("received a data from fake tcp,len:%d\n",data_len);
			uint32_t tmp_session_id= ntohl(* ((uint32_t *)&data[1+sizeof(my_id)]));

			if(tmp_session_id!=my_id)
			{
				printf("client session id mismatch%x %x,ignore\n",tmp_session_id,my_id);
				return 0;
			}

			uint32_t tmp_oppsite_session_id=ntohl(* ((uint32_t *)&data[1]));
			if(tmp_oppsite_session_id!=oppsite_id)
			{
				printf("server session id mismatch%x %x,ignore\n",tmp_oppsite_session_id,my_id);
				return 0;
			}

			last_hb_recv_time=get_current_time();

			uint32_t tmp_conv_id= ntohl(* ((uint32_t *)&data[1+sizeof(my_id)*2]));
			/*
			if(tmp_conv_id!=conv_id)
			{
				printf("conv id mismatch%x %x,ignore\n",tmp_oppsite_session_id,my_id);
				return 0;
			}*/

			if(!conv_manager.is_conv_used(tmp_conv_id))
			{
				printf("unknow conv %d,ignore\n",tmp_conv_id);
				return 0;
			}

			conv_manager.update_active_time(tmp_conv_id);

			uint64_t u64=conv_manager.find_u64_by_conv(tmp_conv_id);

			sockaddr_in tmp_sockaddr;
			memset(&tmp_sockaddr,0,sizeof(tmp_sockaddr));

			tmp_sockaddr.sin_family = AF_INET;
			tmp_sockaddr.sin_addr.s_addr=(u64>>32u);

			tmp_sockaddr.sin_port= htons(uint16_t((u64<<32u)>>32u));


			int ret=sendto(udp_fd,data+1+sizeof(my_id)*3,data_len -(1+sizeof(my_id)*3),0,(struct sockaddr *)&tmp_sockaddr,sizeof(tmp_sockaddr));

			if(ret<0)perror("ret<0");
			printf("%s :%d\n",inet_ntoa(tmp_sockaddr.sin_addr),ntohs(tmp_sockaddr.sin_port));
			printf("%d byte sent!!!!!!!!!!!!!!!!!!\n",ret);
		}
		return 0;
	}
}
int server_on_raw_recv(packet_info_t &info,char * data,int data_len)
{
	if(server_current_state==server_nothing)
	{
		anti_replay.re_init();

		if(raw_mode==mode_icmp)
		{
			g_packet_info_send.src_port = info.src_port;;
		}

		g_packet_info_send.dst_port = info.src_port;
		g_packet_info_send.dst_ip = info.src_ip;

		if(raw_mode==mode_tcp)
		{
			if (!(info.syn == 1 && info.ack == 0 && data_len == 0))
				return 0;

			g_packet_info_send.ack_seq = info.seq + 1;

			g_packet_info_send.psh = 0;
			g_packet_info_send.syn = 1;
			g_packet_info_send.ack = 1;

			g_packet_info_send.seq = get_true_random_number_nz(); //not necessary to set

			printf("sent syn ack\n");
			send_raw(g_packet_info_send, 0, 0);

			printf("changed state to server_syn_ack_sent\n");

			server_current_state = server_syn_ack_sent;
			retry_counter = RETRY_TIME;
			last_state_time = get_current_time();
		}
		else if(raw_mode==mode_udp||raw_mode==mode_icmp)
		{

			if(data_len==strlen("hello")&& memcmp((char *)"hello",data,strlen("hello"))!=0)
			{
				//data[6]=0;
				printf("not a hello packet %d\n",data,data_len);
				return 0;
			}
			else
			{
				printf("got a hello packet\n");
			}

			printf("sent half heart_beat\n");
			//send_raw(g_packet_info_send, 0, 0);
			send_hb(g_packet_info_send,my_id,random(),const_id);

			printf("changed state to server_heartbeat_sent_sent\n");

			server_current_state = server_heartbeat_sent;
			retry_counter = RETRY_TIME;
			last_state_time = get_current_time();
		}
	}
	else if(server_current_state==server_syn_ack_sent)
	{
		if(raw_mode==mode_tcp&&!( info.syn==0&&info.ack==1 &&data_len==0)) return 0;
		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}

		g_packet_info_send.syn=0;
		g_packet_info_send.ack=1;
		g_packet_info_send.seq+=1;////////is this right?

		send_hb(g_packet_info_send,my_id,0,const_id);   // send a hb immidately

		printf("changed state to server_heartbeat_sent\n");

		server_current_state=server_heartbeat_sent;
		last_state_time=get_current_time();

		retry_counter=RETRY_TIME;

	}
	else if(server_current_state==server_heartbeat_sent)//heart beat received
	{
		if(( raw_mode==mode_tcp&& (info.syn==1||info.ack!=1)) ||data_len==0)  return 0;

		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}
		if(data_len<hb_length||data[0]!='h')
		{
			return 0;
		}

		uint32_t tmp_session_id= ntohl(* ((uint32_t *)&data[1+sizeof(my_id)]));

		uint32_t tmp_oppsite_const_id=ntohl(* ((uint32_t *)&data[1+sizeof(my_id)*2]));

		if(oppsite_const_id!=0&&tmp_oppsite_const_id!=oppsite_const_id)
		{
			conv_manager.clear();
		}
		oppsite_const_id=tmp_oppsite_const_id;


		printf("received hb %x %x\n",oppsite_id,tmp_session_id);

		if(tmp_session_id!=my_id)
		{
			printf("auth fail!!\n");
			return 0;
		}

		int tmp_oppsite_session_id=  ntohl(* ((uint32_t *)&data[1]));
		oppsite_id=tmp_oppsite_session_id;

		send_hb(g_packet_info_send,my_id,oppsite_id,const_id);

		server_current_state=server_ready;
		last_state_time=get_current_time();

		last_hb_recv_time=get_current_time();
		//first_data_packet=1;

		printf("changed state to server_ready\n");

	}
	else if(server_current_state==server_ready)
	{
		if( (raw_mode==mode_tcp&&(info.syn==1||info.ack!=1)) ||data_len==0)  return 0;
		if(info.src_ip!=g_packet_info_send.dst_ip||info.src_port!=g_packet_info_send.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}

		if(data[0]=='h'&&data_len>=hb_length)
		{
			uint32_t tmp= ntohl(* ((uint32_t *)&data[1+sizeof(uint32_t)]));
			if(debug_mode)printf("received hb <%x,%x>\n",oppsite_id,tmp);
			last_hb_recv_time=get_current_time();
			return 0;
		}
		else if(data[0]=='d'&&data_len>=sizeof(my_id)*3+1)
		{
			uint32_t tmp_oppsite_session_id=ntohl(* ((uint32_t *)&data[1]));
			uint32_t tmp_session_id=ntohl(* ((uint32_t *)&data[1+sizeof(my_id)]));
			uint32_t tmp_conv_id=ntohl(* ((uint32_t *)&data[1+sizeof(my_id)*2]));


			if(tmp_session_id!=my_id)
			{
				printf("my id mismatch,ignore\n");
				return 0;
			}

			if(tmp_oppsite_session_id!=oppsite_id)
			{
				printf("oppsite id mismatch,ignore\n");
				return 0;
			}
			last_hb_recv_time=get_current_time();

			printf("<<<<conv:%u>>>>\n",tmp_conv_id);
			if(!conv_manager.is_conv_used(tmp_conv_id))
			{
				struct sockaddr_in remote_addr_in;

				socklen_t slen = sizeof(sockaddr_in);
				memset(&remote_addr_in, 0, sizeof(remote_addr_in));
				remote_addr_in.sin_family = AF_INET;
				remote_addr_in.sin_port = htons(remote_port);
				remote_addr_in.sin_addr.s_addr = inet_addr(remote_address);

				int new_udp_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
				if(new_udp_fd<0)
				{
					printf("create udp_fd error");
					return -1;
				}
				set_buf_size(new_udp_fd);

				printf("created new udp_fd %d\n",new_udp_fd);
				int ret = connect(new_udp_fd, (struct sockaddr *) &remote_addr_in, slen);
				if(ret!=0)
				{
					printf("udp fd connect fail\n");
					close(new_udp_fd);
					return -1;
				}
				struct epoll_event ev;

				uint64_t u64=((u_int64_t(tmp_conv_id))<<32u)+(uint32_t)new_udp_fd;
				printf("u64: %ld\n",u64);
				ev.events = EPOLLIN;

				ev.data.u64 = u64;

				ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, new_udp_fd, &ev);

				if (ret!= 0) {
					printf("add udp_fd error\n");
					close(new_udp_fd);
					return -1;
				}

				conv_manager.insert_conv(tmp_conv_id,u64);

			}

			uint64_t u64=conv_manager.find_u64_by_conv(tmp_conv_id);

			conv_manager.update_active_time(tmp_conv_id);

			int fd=int((u64<<32u)>>32u);

			printf("received a data from fake tcp,len:%d\n",data_len);
			int ret=send(fd,data+1+sizeof(my_id)*3,data_len -(1+sizeof(my_id)*3),0);

			printf("%d byte sent  ,fd :%d\n ",ret,fd);
			if(ret<0)
			{
				perror("what happened????");
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
}

int client_event_loop()
{
	int i, j, k;int ret;
	init_raw_socket();
	my_id=get_true_random_number_nz();
	conv_id=get_true_random_number_nz();

	//init_filter(source_port);
	g_packet_info_send.dst_ip=inet_addr(remote_address);
	g_packet_info_send.dst_port=remote_port;

	//g_packet_info.src_ip=inet_addr(source_address);
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
	local_me.sin_addr.s_addr = inet_addr(local_address);


	if (bind(udp_fd, (struct sockaddr*) &local_me, slen) == -1) {
		perror("socket bind error");
		exit(1);
	}
	setnonblocking(udp_fd);
	int epollfd = epoll_create1(0);
	const int max_events = 4096;
	struct epoll_event ev, events[max_events];
	if (epollfd < 0) {
		printf("epoll return %d\n", epollfd);
		exit(-1);
	}

	ev.events = EPOLLIN;
	ev.data.u64 = epoll_udp_fd_sn;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, udp_fd, &ev);
	if (ret!=0) {
		printf("add  udp_listen_fd error\n");
		exit(-1);
	}
	ev.events = EPOLLIN;
	ev.data.u64 = epoll_raw_recv_fd_sn;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
	if (ret!= 0) {
		printf("add raw_fd error\n");
		exit(-1);
	}

	////add_timer for fake_tcp_keep_connection_client

	//sleep(10);

	memset(&udp_old_addr_in,0,sizeof(sockaddr_in));
	int unbind=1;
	int timer_fd;

	set_timer(epollfd,timer_fd);
	while(1)////////////////////////
	{
		int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
		if (nfds < 0) {  //allow zero
			printf("epoll_wait return %d\n", nfds);
			exit(-1);
		}
		int n;
		for (n = 0; n < nfds; ++n) {
			if (events[n].data.u64 == epoll_raw_recv_fd_sn)
			{
				iphdr *iph;tcphdr *tcph;char* data;int data_len;
				if(recv_raw(g_packet_info_recv,data,data_len)!=0)
				{
					continue;
				}

			    int new_len=data_len;
			    memcpy(raw_recv_buf3,data,new_len); //for safety,copy to a new buffer,will remove later
			    if(data_len!=0)
			    {
			    	if(pre_recv(raw_recv_buf3,new_len)<0)
			    		continue;
			    }
				client_on_raw_recv(g_packet_info_recv,raw_recv_buf3,new_len);
			}
			if(events[n].data.u64 ==epoll_timer_fd_sn)
			{
				//printf("timer!\n");
				//fflush(stdout);
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
					printf("recv_from error");
					exit(1);
				};

				printf("Received packet from %s:%d,len: %d\n", inet_ntoa(udp_new_addr_in.sin_addr),
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
					printf("new connection!!!!!!!!!!!\n");
					conv=conv_manager.get_new_conv();
					conv_manager.insert_conv(conv,u64);
				}
				else
				{
					conv=conv_manager.find_conv_by_u64(u64);
				}

				conv_manager.update_active_time(conv);

				if(client_current_state==client_ready)
				{
						send_data(g_packet_info_send,buf,recv_len,my_id,oppsite_id,conv);
				}
			}
		}
	}
	return 0;
}

int server_event_loop()
{
	conv_manager.set_clear_function(server_clear);
	int i, j, k;int ret;

	g_packet_info_send.src_ip=inet_addr(local_address);
	g_packet_info_send.src_port=local_port;

	 if(raw_mode==mode_tcp)
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
     temp_bind_addr.sin_addr.s_addr = inet_addr(local_address);

     if (bind(bind_fd, (struct sockaddr*)&temp_bind_addr, sizeof(temp_bind_addr)) !=0)
     {
    	 printf("bind fail\n");
    	 exit(-1);
     }
	 if(raw_mode==mode_tcp)
	 {

		 if(listen(bind_fd, SOMAXCONN) != 0 )
		 {
			 printf("listen fail\n");
			 exit(-1);
		 }
	 }



	init_raw_socket();
	init_filter(local_port);

	epollfd = epoll_create1(0);
	const int max_events = 4096;

	struct epoll_event ev, events[max_events];
	if (epollfd < 0) {
		printf("epoll return %d\n", epollfd);
		exit(-1);
	}

	ev.events = EPOLLIN;
	ev.data.u64 = epoll_raw_recv_fd_sn;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
	if (ret!= 0) {
		printf("add raw_fd error\n");
		exit(-1);
	}
	int timer_fd;
	set_timer(epollfd,timer_fd);
	while(1)////////////////////////
	{
		int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
		if (nfds < 0) {  //allow zero
			printf("epoll_wait return %d\n", nfds);
			exit(-1);
		}
		int n;
		const int MTU=1440;
		for (n = 0; n < nfds; ++n)
		{
			if ((events[n].data.u64 >>32u) > 0u)
			{
				uint32_t conv_id=events[n].data.u64>>32u;

				if(!conv_manager.is_u64_used(events[n].data.u64))
				{
					printf("conv no longer exists");
					continue;
				}

				int fd=int((events[n].data.u64<<32u)>>32u);

				int recv_len=recv(fd,buf,buf_len,0);

				printf("received a packet from udp_fd,len:%d\n",recv_len);

				if(recv_len<0)
				{
					printf("continue\n");
					perror("wtf?");
					continue;
					//return 0;
				}

				conv_manager.update_active_time(conv_id);

				if(server_current_state==server_ready)
				{
					send_data(g_packet_info_send,buf,recv_len,my_id,oppsite_id,conv_id);
					printf("send !!!!!!!!!!!!!!!!!!");
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
				iphdr *iph;tcphdr *tcph;char* data;int data_len;
				if(recv_raw(g_packet_info_recv,data,data_len)!=0)
				{
					continue;
				}

			    int new_len=data_len;
			    memcpy(raw_recv_buf3,data,new_len);
			    if(data_len!=0)
			    {
			    	//if(raw_mode==mode_tcp || ((raw_mode==mode_udp||raw_mode==mode_icmp) &&server_current_state!=server_nothing ))
			    	//{
			    	if(pre_recv(raw_recv_buf3,new_len)<0)
			    		continue;
			    	//}
			    }

				server_on_raw_recv(g_packet_info_recv,raw_recv_buf3,new_len);
			}

		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	srand(time(0));

	if(raw_mode==mode_tcp)
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
	const_id=get_true_random_number_nz();

	anti_replay_seq=get_true_random_number_nz();

	g_packet_info_send.ack_seq=get_true_random_number_nz();
	g_packet_info_send.seq=get_true_random_number_nz();
	int i, j, k;

	signal(SIGCHLD, handler);
	process_arg(argc,argv);

	if(prog_mode==client_mode)
	{
		for(int i=0;i<16;i++)
		{
			key_me[i]=key[i];
			key_oppsite[i]=key[i]+1;
		}
		client_event_loop();
	}
	else
	{
		for(int i=0;i<16;i++)
		{
			key_me[i]=key[i]+1;
			key_oppsite[i]=key[i];
		}
		server_event_loop();
	}

	return 0;
}
