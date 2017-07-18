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
#include <encryption.h>
#include <inttypes.h>

using namespace std;

char local_address[100], remote_address[100],source_address[100];
int local_port = -1, remote_port = -1;
int epollfd ;

uint32_t session_id=0;
uint32_t oppsite_session_id=0;

const int handshake_timeout=1000;
const int heartbeat_timeout=10000;
const int udp_timeout=2000;

const int heartbeat_interval=1000;

const int timer_interval=50;

//const uint16_t tcp_window=50000;


const int buf_len = 65535+100;

const int server_mode=2;
const int client_mode=1;
int prog_mode=0; //0 unset; 1client 2server
const int RETRY_TIME=3;

const int debug_mode=0;
int bind_fd;

const int seq_mode=2;  //0  dont  increase /1 increase   //increase randomly,about every 10 packet

const uint64_t epoll_timer_fd_sn=1;
const uint64_t epoll_raw_recv_fd_sn=2;
uint64_t epoll_udp_fd_sn=256;  //udp_fd_sn =256,512,768......the lower 8 bit is not used,to avoid confliction


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


char buf[buf_len];
char buf2[buf_len];
char raw_send_buf[buf_len];
char raw_send_buf2[buf_len];
char raw_recv_buf[buf_len];
char raw_recv_buf2[buf_len];
char raw_recv_buf3[buf_len];
char replay_buf[buf_len];
char send_data_buf[buf_len];  //buf for send data and send hb

struct sock_filter code[] = {
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


const int client_nothing=0;
const int client_syn_sent=1;
const int client_ack_sent=2;
const int client_ready=3;
int client_current_state=client_nothing;
int retry_counter;

long long last_state_time=0;

long long last_hb_sent_time=0;

uint16_t ip_id=1;
//const int MTU=1440;

struct sockaddr_in udp_old_addr_in;

uint64_t seq=0;
uint8_t key[]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,   0,0,0,0};



int pre_send(char * data, int &data_len)
{
	//return 0;
	if(data_len<0) return -3;

	seq++;
	uint32_t seq_high= htonl(seq>>32u);

	uint32_t seq_low= htonl((seq<<32u)>>32u);

	memcpy(replay_buf,&seq_high,sizeof(uint32_t));
	memcpy(replay_buf+sizeof(uint32_t),&seq_low,sizeof(uint32_t));

	memcpy(replay_buf+sizeof(uint32_t)*2,data,data_len);

	data_len+=sizeof(uint32_t)*2;

	//memcpy(data,replay_buf,data_len);

	if(my_encrypt((unsigned char*)replay_buf,(unsigned char*)data,data_len,key) <0)
	{
		printf("encrypt fail\n");
		return -1;
	}
	return 0;
}

int pre_recv(char * data, int &data_len)
{
	//return 0;
	if(data_len<0) return -1;
	//if(data_len<8+16) return -3;

	if(my_decrypt((uint8_t*)data,(uint8_t*)replay_buf,data_len,key) <0)
	{
		printf("decrypt fail\n");
		return -1;
	}

	data_len-=sizeof(uint32_t)*2;
	if(data_len<0)
	{
		printf("data_len<=0\n");
		return -2;
	}

	uint64_t seq_high= ntohl(*((uint32_t*)(replay_buf) ) );
	uint32_t seq_low= ntohl(*((uint32_t*)(replay_buf+sizeof(uint32_t)) ) );


	uint64_t recv_seq =(seq_high<<32u )+seq_low;

	printf("<<<<<%ld,%d,%ld>>>>\n",seq_high,seq_low,recv_seq);


	memcpy(data,replay_buf+sizeof(uint32_t)*2,data_len);


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
int set_udp_buf_size(int fd)
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

	raw_recv_fd= socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));

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
	return 0;
}

long long get_current_time()
{
	timespec tmp_time;
	clock_gettime(CLOCK_MONOTONIC, &tmp_time);
	return tmp_time.tv_sec*1000+tmp_time.tv_nsec/(1000*1000ll);
}
void init_filter(int port)
{
	code[8].k=code[10].k=port;
	bpf.len = sizeof(code)/sizeof(code[0]);
	bpf.filter = code;
	//printf("<%d>\n",bpf.len);
	int dummy;

	int ret=setsockopt(raw_recv_fd, SOL_SOCKET, SO_DETACH_FILTER, &dummy, sizeof(int));
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
	//ip_part:
	uint32_t src_ip;
	uint16_t src_port;
	uint32_t dst_ip;
	uint16_t dst_port;

	//tcp_part:
	bool syn,ack,psh;
	uint32_t seq,ack_seq;

	uint32_t ts,ts_ack;


}g_packet_info;

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

int send_raw(packet_info_t &info,char * payload,int payloadlen)
{
	if(prog_mode==client_mode&& payloadlen!=9  ||prog_mode==server_mode&& payloadlen!=5)
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
     printf("sent seq  ack_seq len<%u %u %d>\n",g_packet_info.seq,g_packet_info.ack_seq,payloadlen);

     int ret = sendto(raw_send_fd, raw_send_buf, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin));

     if(g_packet_info.syn==0&&g_packet_info.ack==1&&payloadlen!=0)
     {
    	 if(seq_mode==0)
    	 {


    	 }
    	 else if(seq_mode==1)
    	 {
    		 g_packet_info.seq+=payloadlen;
    	 }
    	 else if(seq_mode==2)
    	 {
    		 if(random()% 20==5 )
    			 g_packet_info.seq+=payloadlen;
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



int send_data(packet_info_t &info,char* data,int len,uint32_t id1,uint32_t id2 )
{
	int new_len=1+sizeof(session_id)*2+len;
	send_data_buf[0]='d';
	uint32_t tmp;
	tmp=htonl(id1);
	memcpy(send_data_buf+1,&tmp,sizeof(session_id));

	tmp=htonl(id2);
	memcpy(send_data_buf+1+sizeof(session_id),&tmp,sizeof(session_id));

	memcpy(send_data_buf+1+sizeof(session_id)*2,data,len);

	if(pre_send(send_data_buf,new_len)<0)
	{
		return -1;
	}
	send_raw(info,send_data_buf,new_len);
	return 0;
}

int send_hb(packet_info_t &info,uint32_t id1,uint32_t id2 )
{
	int new_len=1+sizeof(session_id)*2;
	send_data_buf[0]='h';

	uint32_t tmp;
	tmp=htonl(id1);
	memcpy(send_data_buf+1,&tmp,sizeof(session_id));

	tmp=htonl(id2);
	memcpy(send_data_buf+1+sizeof(session_id),&tmp,sizeof(session_id));

	if(pre_send(send_data_buf,new_len)<0)
	{
		return -1;
	}

	send_raw(info,send_data_buf,new_len);

	return 0;
}

int send_sync()
{
	//g_packet_info.seq=3;
	g_packet_info.ack=0;
	g_packet_info.syn=1;
	//g_packet_info.ack_seq=5;
	g_packet_info.psh=0;
	send_raw(g_packet_info,0,0);
	return 0;
}

uint32_t get_true_random_number()
{
	uint32_t ret;
	int fd=open("/dev/urandom",O_RDONLY);
	read(fd,&ret,sizeof(ret));
	return htonl(ret);
}

int try_to_list_and_bind(int port)
{
	 int old_bind_fd=bind_fd;
	 bind_fd=socket(AF_INET,SOCK_STREAM,0);
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
     if(listen(bind_fd, SOMAXCONN) != 0 )
     {
    	 printf("listen fail\n");
    	 return -1;
     }
     return 0;
}
int client_bind_to_a_new_port()
{
	int raw_send_port=10000+get_true_random_number()%(65535-10000);
	for(int i=0;i<1000;i++)
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
int fake_tcp_keep_connection_client() //for client
{
	if(debug_mode)printf("timer!\n");
	//fflush(stdout);
	begin:
	if(client_current_state==client_nothing)
	{

		client_current_state=client_syn_sent;
		last_state_time=get_current_time();
		printf("state changed from nothing to syn_sent\n");
		retry_counter=5;


		g_packet_info.src_port=client_bind_to_a_new_port();
		printf("using port %d\n",g_packet_info.src_port);

		g_packet_info.src_ip=inet_addr(source_address);

		init_filter(g_packet_info.src_port);

		g_packet_info.seq=get_true_random_number();
		g_packet_info.ack_seq=0;//get_true_random_number();

		g_packet_info.ts_ack=0;
		send_sync(/*sync*/);//send sync
	}
	if(client_current_state==client_syn_sent  &&get_current_time()-last_state_time>handshake_timeout)
	{
		if(retry_counter==0)
		{
			client_current_state=client_nothing;
			printf("state back to nothing\n");
			goto begin;
		}
		else
		{
			retry_counter--;
			printf("retry send sync\n");
			send_sync(/*sync*/);//send sync again
			last_state_time=get_current_time();
		}
	}
	if(client_current_state==client_ack_sent &&get_current_time()-last_state_time>handshake_timeout)
	{
		printf("!!!!!\n");
		fflush(stdout);
		if(retry_counter==0)
		{
			client_current_state=client_nothing;
			printf("state back to nothing\n");
			goto begin;
		}
		else
		{
			retry_counter--;
			send_raw(g_packet_info,0,0);
			last_state_time=get_current_time();
			printf("retry send ack  counter left:%d\n",retry_counter);
			fflush(stdout);
		}
	}

	if(client_current_state==client_ready)
	{
		if(debug_mode)printf("time %lld %lld\n",get_current_time(),last_state_time);
		if(get_current_time()-last_hb_recv_time>heartbeat_timeout)
		{
			client_current_state=client_nothing;
			printf("state back to nothing\n");
			return 0;
		}

		if(get_current_time()-last_hb_sent_time<heartbeat_interval)
		{
			return 0;
		}

		g_packet_info.syn=0;
		g_packet_info.ack=1;

		if(debug_mode)printf("heartbeat sent <%x,%x>\n",oppsite_session_id,session_id);

		/*
		buf[0]='h';
		uint32_t tmp;
		tmp=htonl(oppsite_session_id);
		memcpy(buf+1+sizeof(session_id),&tmp,sizeof(session_id));

		tmp=htonl(session_id);
		memcpy(buf+1,&tmp,sizeof(session_id));

		send_raw(g_packet_info,buf,sizeof(session_id)*2+1);*/
		send_hb(g_packet_info,session_id,oppsite_session_id);
		last_hb_sent_time=get_current_time();
		//last_time=get_current_time();
	}

}

int fake_tcp_keep_connection_server()
{
	//begin:
	if(debug_mode)	printf("timerxxxx!\n");
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
			//send_raw(g_packet_info,0,0);
		}
		else
		{
			retry_counter--;
			send_raw(g_packet_info,0,0);
			last_state_time=get_current_time();
			printf("resend syn ack\n");
		}
		//send_raw(/*syn ack*/);
	}
	if(server_current_state==server_heartbeat_sent||server_current_state==server_ready)
	{
		if( (server_current_state==server_heartbeat_sent&&get_current_time()-last_hb_recv_time>handshake_timeout )
		||  ( server_current_state==server_ready&&get_current_time()-last_hb_recv_time>heartbeat_timeout )
		)
		{
			printf("%lld %lld",get_current_time(),last_state_time);
			server_current_state=server_nothing;

			if(server_current_state==server_ready)
			{
				printf("changed session id\n");
				session_id=get_true_random_number();
			}
			printf("state back to nothing\n");
			printf("changed state to server_nothing111\n");
			return 0;
		}

		if(get_current_time()-last_hb_sent_time<heartbeat_interval)
		{
			return 0;
		}


		g_packet_info.syn=0;
		g_packet_info.ack=1;
		//g_packet_info.psh=1;

		/*
		buf[0]='h';
		uint32_t tmp;

		tmp=htonl(session_id);


		memcpy(buf+1,&tmp,sizeof(session_id));
		memset(buf+1+sizeof(session_id),0,sizeof(session_id));

		send_raw(g_packet_info,buf,sizeof(session_id)*2+1);
		*/
		send_hb(g_packet_info,session_id,0);

		last_hb_sent_time=get_current_time();

		//last_time=get_current_time();
		if(debug_mode) printf("heart beat sent<%x>\n",session_id);
		fflush(stdout);
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

int client_raw_recv(iphdr * iph,tcphdr *tcph,char * data,int data_len)
{

	if(client_current_state==client_syn_sent )
	{
		if (!(tcph->syn==1&&tcph->ack==1&&data_len==0)) return 0;
		if(iph->saddr!=g_packet_info.dst_ip||ntohs(tcph->source)!=g_packet_info.dst_port)
		{
			printf("unexpected adress %d %d  %d %d\n",iph->saddr,g_packet_info.dst_ip,ntohl(tcph->source),g_packet_info.dst_port);
			return 0;
		}

		g_packet_info.ack_seq=ntohl(tcph->seq)+1;
		g_packet_info.psh=0;
		g_packet_info.syn=0;
		g_packet_info.ack=1;
		g_packet_info.seq+=1;

		printf("sent ack back\n");


		send_raw(g_packet_info,0,0);
		client_current_state=client_ack_sent;
		printf("changed state to client_ack_sent\n");
		last_state_time=get_current_time();
		retry_counter=RETRY_TIME;
	}
	if(client_current_state==client_ack_sent )
	{
		if( tcph->syn==1||tcph->ack!=1 ||data_len==0)
		{
			printf("unexpected syn ack or other zero lenght packet\n");
			return 0;
		}
		if(data_len!=sizeof(session_id)*2+1||data[0]!='h')
		{
			return 0;
		}
		if(iph->saddr!=g_packet_info.dst_ip||ntohs(tcph->source)!=g_packet_info.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}

		oppsite_session_id=  ntohl(* ((uint32_t *)&data[1]));

		printf("====first hb received %x\n==",oppsite_session_id);

		client_current_state=client_ready;
		printf("changed state to client_ready\n");


		send_hb(g_packet_info,session_id,oppsite_session_id);
		/*
		buf[0]='h';

		uint32_t tmp;

		tmp=htonl(session_id);
		memcpy(buf+1,&tmp,sizeof(session_id));


		tmp=htonl(oppsite_session_id);
		memcpy(buf+1+sizeof(session_id),&tmp,sizeof(session_id));

		send_raw(g_packet_info,buf,sizeof(session_id)*2+1);*/
		//send_raw(g_packet_info,"hb",strlen("hb"));
	}
	if(client_current_state==client_ready )
	{
		if( tcph->syn==1||tcph->ack!=1 ||data_len==0)
		{
			printf("unexpected syn ack");
			return 0;
		}
		if(iph->saddr!=g_packet_info.dst_ip||ntohs(tcph->source)!=g_packet_info.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}

		if(data_len==sizeof(session_id)*2+1&&data[0]=='h')
		{
			if(debug_mode)printf("heart beat received\n");
			last_hb_recv_time=get_current_time();
			return 0;
		}
		else if(data_len>=sizeof(session_id)*2+1&&data[0]=='d')
		{
			printf("received a data from fake tcp,len:%d\n",data_len);
			uint32_t tmp_session_id= ntohl(* ((uint32_t *)&data[1+sizeof(session_id)]));

			if(tmp_session_id!=session_id)
			{
				printf("client session id mismatch%x %x,ignore\n",tmp_session_id,session_id);
				return 0;
			}

			uint32_t tmp_oppsite_session_id=ntohl(* ((uint32_t *)&data[1]));
			if(tmp_oppsite_session_id!=oppsite_session_id)
			{
				printf("server session id mismatch%x %x,ignore\n",tmp_oppsite_session_id,session_id);
				return 0;
			}

			last_hb_recv_time=get_current_time();
			int ret=sendto(udp_fd,data+1+sizeof(session_id)*2,data_len -(1+sizeof(session_id)*2),0,(struct sockaddr *)&udp_old_addr_in,sizeof(udp_old_addr_in));
			if(ret<0)perror("ret<0");
			printf("%d byte sent\n",ret);
		}
		return 0;
	}
}
int server_raw_recv(iphdr * iph,tcphdr *tcph,char * data,int data_len)
{
	if(server_current_state==server_nothing)
	{
		if(!( tcph->syn==1&&tcph->ack==0 &&data_len==0)) return 0;

		g_packet_info.dst_port=ntohs(tcph->source);
		g_packet_info.dst_ip=iph->saddr;

		g_packet_info.ack_seq=ntohl(tcph->seq)+1;
		g_packet_info.psh=0;
		g_packet_info.syn=1;
		g_packet_info.ack=1;


		g_packet_info.seq=get_true_random_number();//not necessary to set


		printf("sent syn ack\n");
		fflush(stdout);
		send_raw(g_packet_info,0,0);
		server_current_state=server_syn_ack_sent;
		printf("changed state to server_syn_ack_sent\n");
		retry_counter=RETRY_TIME;
		last_state_time=get_current_time();
	}
	else if(server_current_state==server_syn_ack_sent)
	{
		if(!( tcph->syn==0&&tcph->ack==1 &&data_len==0)) return 0;
		if(iph->saddr!=g_packet_info.dst_ip||ntohs(tcph->source)!=g_packet_info.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}

		server_current_state=server_heartbeat_sent;
		g_packet_info.syn=0;
		g_packet_info.ack=1;
		g_packet_info.seq+=1;////////is this right?

		//send_raw(g_packet_info,"hb",strlen("hb"));
		printf("changed state to server_heartbeat_sent\n");

		last_hb_recv_time=get_current_time(); //this ack is counted as hearbeat

		last_state_time=get_current_time();

	}
	else if(server_current_state==server_heartbeat_sent)//heart beat received
	{
		if( tcph->syn==1||tcph->ack!=1 ||data_len==0)  return 0;
		if(iph->saddr!=g_packet_info.dst_ip||ntohs(tcph->source)!=g_packet_info.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}
		if(data_len!=sizeof(session_id)*2+1||data[0]!='h')
		{
			return 0;
		}

		int tmp_oppsite_session_id=  ntohl(* ((uint32_t *)&data[1]));
		if(tmp_oppsite_session_id!=oppsite_session_id)
		{
			struct epoll_event ev;


			if(udp_fd!=-1)
			{
				int ret = epoll_ctl(epollfd, EPOLL_CTL_DEL, udp_fd, 0);
				close(udp_fd);
				udp_fd=-1;
			}
			oppsite_session_id=tmp_oppsite_session_id;
		}

		uint32_t tmp_session_id= ntohl(* ((uint32_t *)&data[1+sizeof(session_id)]));

		printf("received hb %x %x\n",oppsite_session_id,tmp_session_id);

		if(tmp_session_id!=session_id)
		{
			printf("auth fail!!\n");
			return 0;
		}

		//session_id=get_true_random_number();

		server_current_state=server_ready;
		last_state_time=get_current_time();
		last_hb_recv_time=get_current_time();
		printf("changed state to server_ready\n");

	}
	else if(server_current_state==server_ready)
	{
		if( tcph->syn==1||tcph->ack!=1 ||data_len==0)  return 0;
		if(iph->saddr!=g_packet_info.dst_ip||ntohs(tcph->source)!=g_packet_info.dst_port)
		{
			printf("unexpected adress\n");
			return 0;
		}

		if(data[0]=='h'&&data_len==sizeof(session_id)*2+1)
		{
			uint32_t tmp= ntohl(* ((uint32_t *)&data[1+sizeof(uint32_t)]));
			if(debug_mode)printf("received hb <%x,%x>\n",oppsite_session_id,tmp);
			last_hb_recv_time=get_current_time();
		}
		else if(data[0]=='d'&&data_len>=sizeof(session_id)*2+1)
		{
			uint32_t tmp_oppsite_session_id=ntohl(* ((uint32_t *)&data[1]));
			uint32_t tmp_session_id=ntohl(* ((uint32_t *)&data[1+sizeof(session_id)]));

			if(tmp_session_id!=session_id)
			{
				printf("server session id mismatch,ignore\n");
				return 0;
			}

			if(tmp_oppsite_session_id!=oppsite_session_id)  //magic to find out which one is actually larger
				//consider 0xffffffff+1= 0x0 ,in this case 0x0 is "actually" larger

			{
				uint32_t smaller,bigger;
				smaller=min(oppsite_session_id,tmp_oppsite_session_id);//smaller in normal sense
				bigger=max(oppsite_session_id,tmp_oppsite_session_id);
				uint32_t distance=min(bigger-smaller,smaller+(0xffffffff-bigger+1));

				if(distance==bigger-smaller)
				{
					if(bigger==oppsite_session_id) //received_session_id is acutally bigger
					{
						printf("old_session_id ,ingored1\n");
						return 0;
					}
				}
				else
				{
					if(smaller==oppsite_session_id) //received_session_id is acutally bigger
					{
						printf("old_session_id ,ingored2\n");
						return 0;
					}
				}
			}


			if(udp_fd==-1||tmp_oppsite_session_id!=oppsite_session_id)// this is first send or client changed session
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

			if(tmp_oppsite_session_id!=oppsite_session_id)
			{
				oppsite_session_id=tmp_oppsite_session_id;
				printf("created new udp_fd");
			}
			printf("received a data from fake tcp,len:%d\n",data_len);
			last_hb_recv_time=get_current_time();
			int ret=send(udp_fd,data+1+sizeof(session_id)*2,data_len -(1+sizeof(session_id)*2),0);
			printf("%d byte sent\n",ret);
		}
	}
}
int on_raw_recv()
{
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
		return 0;
	}

	char *ip_begin=buf+14;

	struct iphdr *iph = (struct iphdr *) (ip_begin);


    if (!(iph->ihl > 0 && iph->ihl <=60)) {
    	if(debug_mode) printf("iph ihl error");
        return 0;
    }

    if (iph->protocol != IPPROTO_TCP) {
    	if(debug_mode)printf("iph protocal != tcp\n");
    	return 0;
    }


	int ip_len=ntohs(iph->tot_len);

    unsigned short iphdrlen =iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(ip_begin+ iphdrlen);
    unsigned short tcphdrlen = tcph->doff*4;

    if (!(tcph->doff > 0 && tcph->doff <=60)) {
    	if(debug_mode) printf("tcph error");
    	return 0;
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
    	return 0;
    }
    if(tcp_chk!=0)
    {
    	printf("tcp_chk:%x\n",tcp_chk);
    	printf("tcp header error\n");
    	return 0;

    }
    char *tcp_begin=raw_recv_buf2+sizeof(struct pseudo_header);  //data

    char *tcp_option=raw_recv_buf2+sizeof(struct pseudo_header)+sizeof(tcphdr);

    if(tcph->doff==10)
    {
    	if(tcp_option[6]==0x08 &&tcp_option[7]==0x0a)
    	{
    		g_packet_info.ts_ack= ntohl(*(uint32_t*)(&tcp_option[8]));
    	}
    }
    if(tcph->doff==8)
    {
    	if(tcp_option[3]==0x08 &&tcp_option[4]==0x0a)
    	{
    		g_packet_info.ts_ack= ntohl(*(uint32_t*)(&tcp_option[0]));
    	}
    }

    if(tcph->rst==1)
    {
    	printf("%%%%%%%%%%rst==1%%%%%%%%%%%%%\n");
    }
    ////tcp end





   // char pseudo_tcp_buffer[MTU];

    int data_len = ip_len-tcphdrlen-iphdrlen;

    char *data=ip_begin+tcphdrlen+iphdrlen;

    if(data_len>0&&data[0]=='h')
    {
    	printf("recvd <%u %u %d>\n",ntohl(tcph->seq ),ntohl(tcph->ack_seq), data_len);
    }

    if(data_len>0&&tcph->syn==0&&tcph->ack==1)
    {
    	//if(seq_increse)
    		g_packet_info.ack_seq=ntohl(tcph->seq)+(uint32_t)data_len;
    }


    //printf("%d\n",ip_len);
    /*
    for(int i=0;i<size;i++)
    {
    	printf("<%x>",(unsigned char)buf[i]);

    }
	  printf("\n");

    for(int i=0;i<data_len;i++)
    {
    	printf("<%x>",(unsigned char)data[i]);
    }*/
    if(debug_mode)
    {
		printf("\n");
		printf("<%u,%u,%u,%u,%d>\n",(unsigned int)iphdrlen,(unsigned int)tcphdrlen,(unsigned int)tcph->syn,(unsigned int)tcph->ack,data_len);
		//fflush(stdout);
    }

    int new_len=data_len;
    memcpy(raw_recv_buf3,data,new_len);
    if(data_len!=0)
    {
    	if(pre_recv(raw_recv_buf3,new_len)<0)
    		return -1;
    }
	if(prog_mode==server_mode)
	{
		server_raw_recv(iph,tcph,raw_recv_buf3,new_len);
	}
	else
	{
		client_raw_recv(iph,tcph,raw_recv_buf3,new_len);
	}
	return 0;
}
int client()
{
	int i, j, k;int ret;
	init_raw_socket();
	session_id=get_true_random_number();

	//init_filter(source_port);
	g_packet_info.dst_ip=inet_addr(remote_address);
	g_packet_info.dst_port=remote_port;

	//g_packet_info.src_ip=inet_addr(source_address);
	//g_packet_info.src_port=source_port;

    udp_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    set_udp_buf_size(udp_fd);

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
				on_raw_recv();
				/*if(is_sync_ack)
				{

				}
				else if(is heart_beat)
				{

				}
				else if(is_data)
				{
					sendto();
				}*/
			}
			if(events[n].data.u64 ==epoll_timer_fd_sn)
			{
				//printf("timer!\n");
				//fflush(stdout);
				uint64_t value;
				read(timer_fd, &value, 8);
				fake_tcp_keep_connection_client();
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
						session_id=session_id+1;
					}
				}

				last_udp_recv_time=get_current_time();
				if(client_current_state=client_ready)
				{
					send_data(g_packet_info,buf,recv_len,session_id,oppsite_session_id);
				}
				////send_data_raw(buf,recv_len);
			}
		}
	}
	return 0;
}

int server()
{
	int i, j, k;int ret;

	g_packet_info.src_ip=inet_addr(local_address);
	g_packet_info.src_port=local_port;

	bind_fd=socket(AF_INET,SOCK_STREAM,0);

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
     if(listen(bind_fd, SOMAXCONN) != 0 )
     {
    	 printf("listen fail\n");
    	 exit(-1);
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
			if (events[n].data.u64 == epoll_udp_fd_sn)
			{
				int recv_len=recv(udp_fd,buf,buf_len,0);
				printf("received a packet from udp_fd,len:%d\n",recv_len);
				perror("wtf?");
				if(recv_len<0)
				{
					printf("continue\n");
					continue;
					//return 0;
				}
				send_data(g_packet_info,buf,recv_len,session_id,oppsite_session_id);
			}
			//printf("%d %d %d %d\n",timer_fd,raw_recv_fd,raw_send_fd,n);
			if (events[n].data.u64 == epoll_timer_fd_sn)
			{
				uint64_t value;
				read(timer_fd, &value, 8);
				fake_tcp_keep_connection_server();
			}
			if (events[n].data.u64 == epoll_raw_recv_fd_sn)
			{
				on_raw_recv();
			}

		}
	}
	return 0;
}
int main(int argc, char *argv[])
{

	g_packet_info.ack_seq=get_true_random_number();
	g_packet_info.seq=get_true_random_number();
	int i, j, k;

	signal(SIGCHLD, handler);
	process_arg(argc,argv);

	if(prog_mode==client_mode)
	{
		client();
	}
	else
	{
		server();
	}

	return 0;
}
