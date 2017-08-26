/*
 * network.cpp
 *
 *  Created on: Jul 29, 2017
 *      Author: wangyu
 */
#include "common.h"
#include "network.h"
#include "log.h"

int raw_recv_fd=-1;
int raw_send_fd=-1;
u32_t link_level_header_len=0;//set it to 14 if SOCK_RAW is used in socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));

int seq_mode=1;

int filter_port=-1;

int disable_bpf_filter=0;  //for test only,most time no need to disable this

u32_t bind_address_uint32=0;

int lower_level=0;
int lower_level_manual=0;
int ifindex=-1;
char if_name[100]="";

unsigned short g_ip_id_counter=0;

unsigned char dest_hw_addr[sizeof(sockaddr_ll::sll_addr)]=
    {0xff,0xff,0xff,0xff,0xff,0xff,0,0};
//{0x00,0x23,0x45,0x67,0x89,0xb9};

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
//{ 0x5, 0, 0, 0x00000001 },//0    //jump to 2,dirty hack from tcpdump -d's output
//{ 0x5, 0, 0, 0x00000000 },//1
{ 0x30, 0, 0, 0x00000009 },//2
{ 0x15, 0, 6, 0x00000006 },//3
{ 0x28, 0, 0, 0x00000006 },//4
{ 0x45, 4, 0, 0x00001fff },//5
{ 0xb1, 0, 0, 0x00000000 },//6
{ 0x48, 0, 0, 0x00000002 },//7
{ 0x15, 0, 1, 0x0000fffe },//8   //modify this fffe to the port you listen on
{ 0x6, 0, 0, 0x0000ffff },//9
{ 0x6, 0, 0, 0x00000000 },//10
};
int code_tcp_port_index=6;

struct sock_filter code_udp[] = {
//{ 0x5, 0, 0, 0x00000001 },
//{ 0x5, 0, 0, 0x00000000 },
{ 0x30, 0, 0, 0x00000009 },
{ 0x15, 0, 6, 0x00000011 },
{ 0x28, 0, 0, 0x00000006 },
{ 0x45, 4, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x00000000 },
{ 0x48, 0, 0, 0x00000002 },
{ 0x15, 0, 1, 0x0000fffe },    //modify this fffe to the port you listen on
{ 0x6, 0, 0, 0x0000ffff },
{ 0x6, 0, 0, 0x00000000 },
};
int code_udp_port_index=6;
struct sock_filter code_icmp[] = {
//{ 0x5, 0, 0, 0x00000001 },
//{ 0x5, 0, 0, 0x00000000 },
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

packet_info_t::packet_info_t()
{
	src_port=0;
	dst_port=0;
	if (raw_mode == mode_faketcp)
	{
		protocol = IPPROTO_TCP;
		ack_seq = get_true_random_number();
		seq = get_true_random_number();
		has_ts=0;
		ts_ack=0;
		syn=0;
		ack=1;

		//mylog(log_info,"<cons ,ts_ack= %u>\n",ts_ack);
	}
	else if (raw_mode == mode_udp)
	{
		protocol = IPPROTO_UDP;
	}
	else if (raw_mode == mode_icmp)
	{
		protocol = IPPROTO_ICMP;
		icmp_seq=0;
	}

}


int init_raw_socket()
{

	g_ip_id_counter=get_true_random_number()%65535;
	if(lower_level==0)
	{
		raw_send_fd = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);

	    if(raw_send_fd == -1) {
	    	mylog(log_fatal,"Failed to create raw_send_fd\n");
	        //perror("Failed to create raw_send_fd");
	        myexit(1);
	    }

	    int one = 1;
	    const int *val = &one;
	    if (setsockopt (raw_send_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
	    	mylog(log_fatal,"Error setting IP_HDRINCL %d\n",errno);
	        //perror("Error setting IP_HDRINCL");
	        myexit(2);
	    }


	}
	else
	{
		raw_send_fd = socket(PF_PACKET , SOCK_DGRAM , htons(ETH_P_IP));

	    if(raw_send_fd == -1) {
	    	mylog(log_fatal,"Failed to create raw_send_fd\n");
	        //perror("Failed to create raw_send_fd");
	        myexit(1);
	    }
		//init_ifindex(if_name);

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



    setnonblocking(raw_send_fd); //not really necessary
    setnonblocking(raw_recv_fd);

	return 0;
}
void init_filter(int port)
{
	sock_fprog bpf;
	if(raw_mode==mode_faketcp||raw_mode==mode_udp)
	{
		filter_port=port;
	}
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
int init_ifindex(const char * if_name,int &index)
{
	struct ifreq ifr;
	size_t if_name_len=strlen(if_name);
	if (if_name_len<sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name,if_name,if_name_len);
		ifr.ifr_name[if_name_len]=0;
	} else {
		mylog(log_fatal,"interface name is too long\n");
		myexit(-1);
	}
	if (ioctl(raw_send_fd,SIOCGIFINDEX,&ifr)==-1) {

		mylog(log_fatal,"SIOCGIFINDEX fail ,%s\n",strerror(errno));
		myexit(-1);
	}
	index=ifr.ifr_ifindex;
	mylog(log_info,"ifname:%s  ifindex:%d\n",if_name,index);
	return 0;
}
bool interface_has_arp(const char * interface) {
    struct ifreq ifr;
   // int sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
    int sock=raw_send_fd;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, interface);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            //perror("SIOCGIFFLAGS");
    		mylog(log_fatal,"ioctl(sock, SIOCGIFFLAGS, &ifr) failed for interface %s,errno %s\n",interface,strerror(errno));
            myexit(-1);
    }
    //close(sock);
    return !(ifr.ifr_flags & IFF_NOARP);
}
struct route_info_t
{
	string if_name;
	u32_t dest;
	u32_t mask;
	u32_t gw;
	u32_t flag;

};
int dest_idx=1;
int gw_idx=2;
int if_idx=0;
int mask_idx=7;
int flag_idx=3;
vector<int> find_route_entry(const vector<route_info_t> &route_info_vec,u32_t ip)
{
	vector<int> res;
	for(u32_t i=0;i<=32;i++)
	{
		u32_t mask=0xffffffff;
		//mask >>=i;
		//if(i==32) mask=0;  //why 0xffffffff>>32  equals 0xffffffff??

		mask <<=i;
		if(i==32) mask=0;
		log_bare(log_debug,"(mask:%x)",mask);
		for(u32_t j=0;j<route_info_vec.size();j++)
		{
			const route_info_t & info=route_info_vec[j];
			if(info.mask!=mask)
				continue;
			log_bare(log_debug,"<<%d,%d>>",i,j);
			if((info.dest&mask)==(ip&mask))
			{
				log_bare(log_debug,"found!");
				res.push_back(j);
			}
		}
		if(res.size()!=0)
		{
			return res;
		}
	}
	return res;
}
int find_direct_dest(const vector<route_info_t> &route_info_vec,u32_t ip,u32_t &dest_ip,string &if_name)
{
	vector<int> res;
	for(int i=0;i<1000;i++)
	{
		res=find_route_entry(route_info_vec,ip);
		log_bare(log_debug,"<entry:%u>",(u32_t)res.size());
		if(res.size()==0)
		{
			mylog(log_error,"cant find route entry\n");
			return -1;
		}
		if(res.size()>1)
		{
			mylog(log_error,"found duplicated entries\n");
			return -1;
		}
		if((route_info_vec[res[0]].flag&2)==0)
		{
			dest_ip=ip;
			if_name=route_info_vec[res[0]].if_name;
			return 0;
		}
		else
		{
			ip=route_info_vec[res[0]].gw;
		}
	}
	mylog(log_error,"dead loop in find_direct_dest\n");
	return -1;
}
struct arp_info_t
{
	u32_t ip;
	string hw;
	string if_name;
};
int arp_ip_idx=0;
int arp_hw_idx=3;
int arp_if_idx=5;


int find_arp(const vector<arp_info_t> &arp_info_vec,u32_t ip,string if_name,string &hw)
{
	int pos=-1;
	int count=0;
	for(u32_t i=0;i<arp_info_vec.size();i++)
	{
		const arp_info_t & info=arp_info_vec[i];
		if(info.if_name!=if_name) continue;
		if(info.ip==ip)
		{
			count++;
			pos=i;
		}
	}
	if(count==0)
	{
		//mylog(log_warn,"cant find arp entry for %s %s,using 00:00:00:00:00:00\n",my_ntoa(ip),if_name.c_str());
		//hw="00:00:00:00:00:00";
		mylog(log_error,"cant find arp entry for %s %s\n",my_ntoa(ip),if_name.c_str());
		return -1;
	}
	if(count>1)
	{
		mylog(log_error,"find multiple arp entry for %s %s\n",my_ntoa(ip),if_name.c_str());
		return -1;
	}
	hw=arp_info_vec[pos].hw;
	return 0;
}
int find_lower_level_info(u32_t ip,u32_t &dest_ip,string &if_name,string &hw)
{
	ip=htonl(ip);
	if(ip==htonl(inet_addr("127.0.0.1")))
	{
		dest_ip=ntohl(ip);
		if_name="lo";
		hw="00:00:00:00:00:00";
		return 0;
	}

	string route_file;
	if(read_file("/proc/net/route",route_file)!=0) return -1;
	string arp_file;
	if(read_file("/proc/net/arp",arp_file)!=0) return -1;

	log_bare(log_debug,"/proc/net/route:<<%s>>\n",route_file.c_str());
	log_bare(log_debug,"/proc/net/arp:<<%s>>\n",route_file.c_str());

	auto route_vec2=string_to_vec2(route_file.c_str());
	vector<route_info_t> route_info_vec;
	for(u32_t i=1;i<route_vec2.size();i++)
	{
		log_bare(log_debug,"<size:%u>",(u32_t)route_vec2[i].size());
		if(route_vec2[i].size()!=11)
		{
			mylog(log_error,"route coloum %d !=11 \n",int(route_vec2[i].size()));
			return -1;
		}
		route_info_t tmp;
		tmp.if_name=route_vec2[i][if_idx];
		if(hex_to_u32_with_endian(route_vec2[i][dest_idx],tmp.dest)!=0) return -1;
		if(hex_to_u32_with_endian(route_vec2[i][gw_idx],tmp.gw)!=0) return -1;
		if(hex_to_u32_with_endian(route_vec2[i][mask_idx],tmp.mask)!=0) return -1;
		if(hex_to_u32(route_vec2[i][flag_idx],tmp.flag)!=0)return -1;
		route_info_vec.push_back(tmp);
		for(u32_t j=0;j<route_vec2[i].size();j++)
		{
			log_bare(log_debug,"<%s>",route_vec2[i][j].c_str());
		}
		log_bare(log_debug,"%s dest:%x mask:%x gw:%x flag:%x",tmp.if_name.c_str(),tmp.dest,tmp.mask,tmp.gw,tmp.flag);
		log_bare(log_debug,"\n");
	}

	if(find_direct_dest(route_info_vec,ip,dest_ip,if_name)!=0)
	{
		mylog(log_error,"find_direct_dest failed for ip %s\n",my_ntoa(ntohl(ip)));
		return -1;
	}


	log_bare(log_debug,"========\n");
	auto arp_vec2=string_to_vec2(arp_file.c_str());
	vector<arp_info_t> arp_info_vec;
	for(u32_t i=1;i<arp_vec2.size();i++)
	{
		log_bare(log_debug,"<<arp_vec2[i].size(): %d>>",(int)arp_vec2[i].size());

		for(u32_t j=0;j<arp_vec2[i].size();j++)
		{
			log_bare(log_debug,"<%s>",arp_vec2[i][j].c_str());
		}
		if(arp_vec2[i].size()!=6)
		{
			mylog(log_error,"arp coloum %d !=11 \n",int(arp_vec2[i].size()));
			return -1;
		}
		arp_info_t tmp;
		tmp.if_name=arp_vec2[i][arp_if_idx];
		tmp.hw=arp_vec2[i][arp_hw_idx];
		tmp.ip=htonl(inet_addr(arp_vec2[i][arp_ip_idx].c_str()));
		arp_info_vec.push_back(tmp);
		log_bare(log_debug,"\n");
	}
	if(!interface_has_arp(if_name.c_str()))
	{
		mylog(log_info,"%s is a noarp interface,using 00:00:00:00:00:00\n",if_name.c_str());
		hw="00:00:00:00:00:00";
	}
	else if(find_arp(arp_info_vec,dest_ip,if_name,hw)!=0)
	{
		mylog(log_error,"find_arp failed for dest_ip %s ,if_name %s\n",my_ntoa(ntohl(ip)),if_name.c_str());
		return -1;
	}
	//printf("%s\n",hw.c_str());

	dest_ip=ntohl(dest_ip);
	return 0;
}


int send_raw_ip(raw_info_t &raw_info,const char * payload,int payloadlen)
{
	const packet_info_t &send_info=raw_info.send_info;
	const packet_info_t &recv_info=raw_info.recv_info;
	char send_raw_ip_buf[buf_len];

	struct iphdr *iph = (struct iphdr *) send_raw_ip_buf;
    memset(iph,0,sizeof(iphdr));

    iph->ihl = sizeof(iphdr)/4;  //we dont use ip options,so the length is just sizeof(iphdr)
    iph->version = 4;
    iph->tos = 0;

    if(lower_level)
    {
    	//iph->id=0;
    	iph->id = htons (g_ip_id_counter++); //Id of this packet
    }
    else
    	iph->id = htons (g_ip_id_counter++); //Id of this packet
    	//iph->id = 0; //Id of this packet  ,kernel will auto fill this if id is zero  ,or really?????// todo //seems like there is a problem

    iph->frag_off = htons(0x4000); //DF set,others are zero
   // iph->frag_off = htons(0x0000); //DF set,others are zero
    iph->ttl = 64;
    iph->protocol = send_info.protocol;
    iph->check = 0; //Set to 0 before calculating checksum
    iph->saddr = send_info.src_ip;    //Spoof the source ip address
    iph->daddr = send_info.dst_ip;

    uint16_t ip_tot_len=sizeof (struct iphdr)+payloadlen;
    if(lower_level)iph->tot_len = htons(ip_tot_len);            //this is not necessary ,kernel will always auto fill this  //http://man7.org/linux/man-pages/man7/raw.7.html
    else
    	iph->tot_len = 0;

    memcpy(send_raw_ip_buf+sizeof(iphdr) , payload, payloadlen);

    if(lower_level) iph->check =
    		csum ((unsigned short *) send_raw_ip_buf, iph->ihl*4); //this is not necessary ,kernel will always auto fill this
    else
    	iph->check=0;

    int ret;
    if(lower_level==0)
    {
		struct sockaddr_in sin={0};
		sin.sin_family = AF_INET;
		//sin.sin_port = htons(info.dst_port); //dont need this
		sin.sin_addr.s_addr = send_info.dst_ip;
		ret = sendto(raw_send_fd, send_raw_ip_buf, ip_tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin));

    }
    else
    {

    	struct sockaddr_ll addr={0};  //={0} not necessary
    	memcpy(&addr,&send_info.addr_ll,sizeof(addr));

    	ret = sendto(raw_send_fd, send_raw_ip_buf, ip_tot_len ,  0, (struct sockaddr *) &addr, sizeof (addr));
    }
    if(ret==-1)
    {

    	mylog(log_trace,"sendto failed\n");
    	//perror("why?");
    	return -1;
    }
    else
    {
    	//mylog(log_info,"sendto succ\n");
    }
    return 0;
}
int peek_raw(packet_info_t &peek_info)
{	static char peek_raw_buf[buf_len];
	char *ip_begin=peek_raw_buf+link_level_header_len;
	struct sockaddr saddr={0};
	socklen_t saddr_size=sizeof(saddr);
	int recv_len = recvfrom(raw_recv_fd, peek_raw_buf,max_data_len, MSG_PEEK ,&saddr , &saddr_size);//change max_data_len to something smaller,we only need header here
	iphdr * iph = (struct iphdr *) (ip_begin);
	//mylog(log_info,"recv_len %d\n",recv_len);
	if(recv_len<int(sizeof(iphdr)))
	{
		mylog(log_trace,"failed here %d %d\n",recv_len,int(sizeof(iphdr)));
		mylog(log_trace,"%s\n ",strerror(errno));
		return -1;
	}
	peek_info.src_ip=iph->saddr;
    unsigned short iphdrlen =iph->ihl*4;
    char *payload=ip_begin+iphdrlen;

	//mylog(log_info,"protocol %d\n",iph->protocol);
    switch(raw_mode)
    {
    	case mode_faketcp:
    	{
    		if(iph->protocol!=IPPROTO_TCP)
    		{
    			mylog(log_trace,"failed here");
    			return -1;
    		}
    		struct tcphdr *tcph=(tcphdr *)payload;
    		if(recv_len<int( iphdrlen+sizeof(tcphdr) ))
    		{
    			mylog(log_trace,"failed here");
    			return -1;
    		}
    		peek_info.src_port=ntohs(tcph->source);
    		peek_info.syn=tcph->syn;
			break;
    	}
    	case mode_udp:
    	{
    		if(iph->protocol!=IPPROTO_UDP) return -1;
    		struct udphdr *udph=(udphdr *)payload;
    		if(recv_len<int(iphdrlen+sizeof(udphdr)))
    			return -1;
    		peek_info.src_port=ntohs(udph->source);
			break;
    	}
    	case mode_icmp:
    	{
    		if(iph->protocol!=IPPROTO_ICMP) return -1;
    		struct icmphdr *icmph=(icmphdr *)payload;
    		if(recv_len<int( iphdrlen+sizeof(icmphdr) ))
    			return -1;
    		peek_info.src_port=ntohs(icmph->id);
			break;
    	}
    	default:return -1;
    }
    return 0;
}
int recv_raw_ip(raw_info_t &raw_info,char * &payload,int &payloadlen)
{
	const packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;

	static char recv_raw_ip_buf[buf_len];

	iphdr *  iph;
	struct sockaddr_ll saddr={0};
	socklen_t saddr_size = sizeof(saddr);
	int flag=0;
	int recv_len = recvfrom(raw_recv_fd, recv_raw_ip_buf, max_data_len, flag ,(sockaddr*)&saddr , &saddr_size);

	if(recv_len<0)
	{
		mylog(log_trace,"recv_len %d\n",recv_len);
		return -1;
	}
	if(recv_len<int(link_level_header_len))
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

	recv_info.src_ip=iph->saddr;
	recv_info.dst_ip=iph->daddr;
	recv_info.protocol=iph->protocol;

	if(lower_level)
	{
		memcpy(&recv_info.addr_ll,&saddr,sizeof(recv_info.addr_ll));
	}


	if(bind_address_uint32!=0 &&recv_info.dst_ip!=bind_address_uint32)
	{
		mylog(log_trace,"bind adress doenst match, dropped\n");
		//printf(" bind adress doenst match, dropped\n");
		return -1;
	}


    if (!(iph->ihl > 0 && iph->ihl <=60)) {
    	mylog(log_trace,"iph ihl error\n");
        return -1;
    }

	int ip_len=ntohs(iph->tot_len);

	if(recv_len-int(link_level_header_len) <ip_len)
	{
		mylog(log_debug,"incomplete packet\n");
		return -1;
	}

    unsigned short iphdrlen =iph->ihl*4;

    u32_t ip_chk=csum ((unsigned short *) ip_begin, iphdrlen);

    if(ip_chk!=0)
     {
    	mylog(log_debug,"ip header error %x\n",ip_chk);
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


int send_raw_icmp(raw_info_t &raw_info, const char * payload, int payloadlen)
{
	const packet_info_t &send_info=raw_info.send_info;
	const packet_info_t &recv_info=raw_info.recv_info;

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
	icmph->id=htons(send_info.src_port);


	icmph->seq=htons(send_info.icmp_seq);   /////////////modify

	memcpy(send_raw_icmp_buf+sizeof(icmphdr),payload,payloadlen);

	icmph->check_sum = csum( (unsigned short*) send_raw_icmp_buf, sizeof(icmphdr)+payloadlen);

	if(send_raw_ip(raw_info,send_raw_icmp_buf,sizeof(icmphdr)+payloadlen)!=0)
	{
		return -1;
	}

	/*if(program_mode==client_mode)
	{
		send_info.icmp_seq++;
	}*/

	return 0;
}

int send_raw_udp(raw_info_t &raw_info, const char * payload, int payloadlen)
{
	const packet_info_t &send_info=raw_info.send_info;
	const packet_info_t &recv_info=raw_info.recv_info;

	char send_raw_udp_buf[buf_len];

	udphdr *udph=(struct udphdr *) (send_raw_udp_buf
			+ sizeof(struct pseudo_header));

	memset(udph,0,sizeof(udphdr));
	struct pseudo_header *psh = (struct pseudo_header *) (send_raw_udp_buf);

	udph->source = htons(send_info.src_port);
	udph->dest = htons(send_info.dst_port);

	int udp_tot_len=payloadlen+sizeof(udphdr);

	if(udp_tot_len>65535)
	{
		mylog(log_debug,"invalid len\n");
		return -1;
	}
	mylog(log_trace,"udp_len:%d %d\n",udp_tot_len,udph->len);
	udph->len=htons(uint16_t(udp_tot_len));

	memcpy(send_raw_udp_buf+sizeof(struct pseudo_header)+sizeof(udphdr),payload,payloadlen);

	psh->source_address = send_info.src_ip;
	psh->dest_address = send_info.dst_ip;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_UDP;
	psh->tcp_length = htons(uint16_t(udp_tot_len));

	int csum_size = sizeof(struct pseudo_header) +udp_tot_len  ;

	udph->check = csum( (unsigned short*) send_raw_udp_buf, csum_size);

	if(send_raw_ip(raw_info,send_raw_udp_buf+ sizeof(struct pseudo_header),udp_tot_len)!=0)
	{
		return -1;
	}
	return 0;
}

int send_raw_tcp(raw_info_t &raw_info,const char * payload, int payloadlen) {  	//TODO seq increase


	const packet_info_t &send_info=raw_info.send_info;
	const packet_info_t &recv_info=raw_info.recv_info;

	//mylog(log_debug,"syn %d\n",send_info.syn);

	char send_raw_tcp_buf0[buf_len];
	char *send_raw_tcp_buf=send_raw_tcp_buf0;

	struct tcphdr *tcph = (struct tcphdr *) (send_raw_tcp_buf
			+ sizeof(struct pseudo_header));


	memset(tcph,0,sizeof(tcphdr));

	struct pseudo_header *psh = (struct pseudo_header *) (send_raw_tcp_buf);

	//TCP Header
	tcph->source = htons(send_info.src_port);
	tcph->dest = htons(send_info.dst_port);

	tcph->seq = htonl(send_info.seq);
	tcph->ack_seq = htonl(send_info.ack_seq);

	tcph->fin = 0;
	tcph->syn = send_info.syn;
	tcph->rst = 0;
	tcph->psh = send_info.psh;
	tcph->ack = send_info.ack;

	if (tcph->syn == 1) {
		tcph->doff = 10;  //tcp header size
		int i = sizeof(pseudo_header)+sizeof(tcphdr);
		send_raw_tcp_buf[i++] = 0x02;  //mss
		send_raw_tcp_buf[i++] = 0x04;
		send_raw_tcp_buf[i++] = 0x05;
		send_raw_tcp_buf[i++] = (char)0xb4;

		//raw_send_buf[i++]=0x01;
		//raw_send_buf[i++]=0x01;
		send_raw_tcp_buf[i++] = 0x04; //sack ok
		send_raw_tcp_buf[i++] = 0x02; //sack ok

		send_raw_tcp_buf[i++] = 0x08;   //ts   i=6
		send_raw_tcp_buf[i++] = 0x0a;   //i=7

		*(u32_t*) (&send_raw_tcp_buf[i]) = htonl(
				(u32_t) get_current_time());

		i += 4;

		//mylog(log_info,"[syn]<send_info.ts_ack= %u>\n",send_info.ts_ack);

		*(u32_t*) (&send_raw_tcp_buf[i]) = htonl(send_info.ts_ack);
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

		send_raw_tcp_buf[i++] = 0x08;  //ts   //i=2
		send_raw_tcp_buf[i++] = 0x0a; 		  //i=3;

		*(u32_t*) (&send_raw_tcp_buf[i]) = htonl(
				(u32_t) get_current_time());

		i += 4;

		//mylog(log_info,"<send_info.ts_ack= %u>\n",send_info.ts_ack);

		*(u32_t*) (&send_raw_tcp_buf[i]) = htonl(send_info.ts_ack);
		i += 4;
	}

	tcph->urg = 0;
	//tcph->window = htons((uint16_t)(1024));
	tcph->window = htons((uint16_t) (10240 + random() % 100));

	tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;

	char *tcp_data = send_raw_tcp_buf+sizeof(struct pseudo_header) + tcph->doff * 4;

	memcpy(tcp_data, payload, payloadlen);

	psh->source_address = send_info.src_ip;
	psh->dest_address = send_info.dst_ip;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_TCP;
	psh->tcp_length = htons(tcph->doff * 4 + payloadlen);

	int csum_size = sizeof(struct pseudo_header) + tcph->doff*4 + payloadlen;

	tcph->check = csum( (unsigned short*) send_raw_tcp_buf, csum_size);

	int tcp_totlen=tcph->doff*4 + payloadlen;

	if(send_raw_ip(raw_info,send_raw_tcp_buf+ sizeof(struct pseudo_header),tcp_totlen)!=0)
	{
		return -1;
	}


	raw_info.last_send_len=payloadlen;
	return 0;
}
/*
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
*/

int recv_raw_icmp(raw_info_t &raw_info, char *&payload, int &payloadlen)
{
	const packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;
	static char recv_raw_icmp_buf[buf_len];

	char * ip_payload;
	int ip_payloadlen;

	if(recv_raw_ip(raw_info,ip_payload,ip_payloadlen)!=0)
	{
		mylog(log_debug,"recv_raw_ip error\n");
		return -1;
	}
	if(recv_info.protocol!=IPPROTO_ICMP)
	{
		//printf("not udp protocol\n");
		return -1;
	}


	icmphdr *icmph=(struct icmphdr *) (ip_payload);

	if(ntohs(icmph->id)!=send_info.src_port)
	{
		mylog(log_debug,"icmp id mis-match,ignored\n");
		return -1;
	}

	recv_info.src_port=recv_info.dst_port=ntohs(icmph->id);
	recv_info.icmp_seq=ntohs(icmph->seq);


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
	//mylog(log_info,"program_mode=%d\n",program_mode);
/*
	if(program_mode==server_mode)
	{
		send_info.icmp_seq=ntohs(icmph->seq);
		//mylog(log_info,"send_info.seq=%d\n",send_info.seq);
	}*/

	payload=ip_payload+sizeof(icmphdr);
	payloadlen=ip_payloadlen-sizeof(icmphdr);
	mylog(log_trace,"get a packet len=%d\n",payloadlen);

    return 0;
}

int recv_raw_udp(raw_info_t &raw_info, char *&payload, int &payloadlen)
{
	const packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;
	static char recv_raw_udp_buf[buf_len];
	char * ip_payload;
	int ip_payloadlen;

	if(recv_raw_ip(raw_info,ip_payload,ip_payloadlen)!=0)
	{
		mylog(log_debug,"recv_raw_ip error\n");
		return -1;
	}
	if(recv_info.protocol!=IPPROTO_UDP)
	{
		//printf("not udp protocol\n");
		return -1;
	}
	if(ip_payloadlen<int( sizeof(udphdr) ))
	{
		mylog(log_debug,"too short to hold udpheader\n");
		return -1;
	}
	udphdr *udph=(struct udphdr*)ip_payload;

	if(int(ntohs(udph->len))!=ip_payloadlen)
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

    psh->source_address = recv_info.src_ip;
    psh->dest_address = recv_info.dst_ip;
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

    recv_info.src_port=ntohs(udph->source);
    recv_info.dst_port=ntohs(udph->dest);

    payloadlen = ip_payloadlen-sizeof(udphdr);

    payload=udp_begin+sizeof(udphdr);

    return 0;
}

int recv_raw_tcp(raw_info_t &raw_info,char * &payload,int &payloadlen)
{
	const packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;

	static char recv_raw_tcp_buf[buf_len];

	char * ip_payload;
	int ip_payloadlen;


	if(recv_raw_ip(raw_info,ip_payload,ip_payloadlen)!=0)
	{
		mylog(log_debug,"recv_raw_ip error\n");
		return -1;
	}

	if(recv_info.protocol!=IPPROTO_TCP)
	{
		//printf("not tcp protocol\n");
		return -1;
	}


	tcphdr * tcph=(struct tcphdr*)ip_payload;

    unsigned short tcphdrlen = tcph->doff*4;

    if (!(tcphdrlen > 0 && tcphdrlen <=60)) {
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

    psh->source_address = recv_info.src_ip;
    psh->dest_address = recv_info.dst_ip;
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

    recv_info.has_ts=0;
    recv_info.ts=0;
    if(tcph->doff==10)
    {
    	if(tcp_option[6]==0x08 &&tcp_option[7]==0x0a)
    	{
    		recv_info.has_ts=1;
    		recv_info.ts=ntohl(*(u32_t*)(&tcp_option[8]));
    		recv_info.ts_ack=ntohl(*(u32_t*)(&tcp_option[12]));
    		//g_packet_info_send.ts_ack= ntohl(*(uint32_t*)(&tcp_option[8]));
    	}
    	else
    	{
    	//	mylog(log_info,"\n");
    	}
    }
    else if(tcph->doff==8)
    {
    	if(tcp_option[2]==0x08 &&tcp_option[3]==0x0a)
    	{
    		recv_info.has_ts=1;
    		recv_info.ts=ntohl(*(u32_t*)(&tcp_option[4]));
    		recv_info.ts_ack=ntohl(*(u32_t*)(&tcp_option[8]));
    		//g_packet_info_send.ts_ack= ntohl(*(uint32_t*)(&tcp_option[0]));
    	}
    	else
    	{
    		//mylog(log_info,"!!!\n");
    	}
    }
    else
    {
    	//mylog(log_info,"tcph->doff= %u\n",tcph->doff);
    }


    recv_info.ack=tcph->ack;
    recv_info.syn=tcph->syn;
    recv_info.rst=tcph->rst;
    recv_info.src_port=ntohs(tcph->source);
    recv_info.dst_port=ntohs(tcph->dest);

    recv_info.seq=ntohl(tcph->seq);
    recv_info.ack_seq=ntohl(tcph->ack_seq);
    recv_info.psh=tcph->psh;

    if(tcph->rst==1)
    {
    	mylog(log_error,"[%s,%d]rst==1\n",my_ntoa(recv_info.src_ip),recv_info.src_port);
    }

   /* if(recv_info.has_ts)
    {
    	send_info.ts_ack=recv_info.ts;   //////////////////////////////////////////////modify
    }*/

    payloadlen = ip_payloadlen-tcphdrlen;

    payload=tcp_begin+tcphdrlen;

	/*if (recv_info.syn == 0 && recv_info.ack == 1&& payloadlen != 0)   //only modify   send_info when the packet is not part of handshake
	{
		send_info.ack_seq=recv_info.seq;
	}*/
    raw_info.last_recv_len=payloadlen;
    return 0;
}
/*
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

	size = recvfrom(raw_recv_fd, buf, max_data_len, 0 ,&saddr , &saddr_size);

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
}*/
int send_raw0(raw_info_t &raw_info,const char * payload,int payloadlen)
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;
	mylog(log_trace,"send_raw : from %x %d  to %x %d\n",send_info.src_ip,send_info.src_port,send_info.dst_ip,send_info.dst_port);
	switch(raw_mode)
	{
		case mode_faketcp:return send_raw_tcp(raw_info,payload,payloadlen);
		case mode_udp: return send_raw_udp(raw_info,payload,payloadlen);
		case mode_icmp: return send_raw_icmp(raw_info,payload,payloadlen);
		default:return -1;
	}

}
int recv_raw0(raw_info_t &raw_info,char * &payload,int &payloadlen)
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;
	switch(raw_mode)
	{
		case mode_faketcp:return recv_raw_tcp(raw_info,payload,payloadlen);
		case mode_udp: return recv_raw_udp(raw_info,payload,payloadlen);
		case mode_icmp: return recv_raw_icmp(raw_info,payload,payloadlen);
		default:	return -1;
	}

}

int after_send_raw0(raw_info_t &raw_info)
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;

	if(raw_mode==mode_faketcp)
	{
		if (send_info.syn == 0 && send_info.ack == 1&& raw_info.last_send_len != 0)   //only modify   send_info when the packet is not part of handshake
		{
			if (seq_mode == 0)
			{

			} else if (seq_mode == 1)
			{
				send_info.seq += raw_info.last_send_len;    //////////////////modify
			} else if (seq_mode == 2)
			{
				if (random() % 5 == 3)
					send_info.seq += raw_info.last_send_len; //////////////////modify
			}
		}
	}
	if(raw_mode==mode_icmp)
	{
		if(program_mode==client_mode)
		{
			send_info.icmp_seq++;
		}
	}
	return 0;
}
int after_recv_raw0(raw_info_t &raw_info)
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;

	if(raw_mode==mode_faketcp)
	{
		if(recv_info.has_ts)
			send_info.ts_ack=recv_info.ts;
		if (recv_info.syn == 0 && recv_info.ack == 1 && raw_info.last_recv_len != 0) //only modify   send_info when the packet is not part of handshake
		{
			if(larger_than_u32(recv_info.seq+raw_info.last_recv_len,send_info.ack_seq))
				send_info.ack_seq = recv_info.seq+raw_info.last_recv_len;//TODO only update if its larger
		}
	}
	if(raw_mode==mode_icmp)
	{
		if(program_mode==server_mode)
		{
			if(larger_than_u16(recv_info.icmp_seq,send_info.icmp_seq))
				send_info.icmp_seq = recv_info.icmp_seq;  //TODO only update if its larger
		}
	}
	return 0;
}

/*
int send_raw(raw_info_t &raw_info,const char * payload,int payloadlen)
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;
	int ret=send_raw0(raw_info,payload,payloadlen);
	if(ret<0) return ret;
	else
	{
		after_send_raw0(raw_info);
		return ret;
	}
}

int recv_raw(raw_info_t &raw_info,char *& payload,int & payloadlen)
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;
	int ret=recv_raw0(raw_info,payload,payloadlen);
	if(ret<0) return ret;
	else
	{
		after_recv_raw0(raw_info);
		return ret;
	}
}*/

