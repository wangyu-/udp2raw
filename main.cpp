#include "common.h"
#include "network.h"
#include "log.h"
#include "lib/md5.h"

char local_ip[100]="0.0.0.0", remote_ip[100]="255.255.255.255",source_ip[100]="0.0.0.0";
u32_t local_ip_uint32,remote_ip_uint32,source_ip_uint32;

int force_source_ip=0;
int source_port=0,local_port = -1, remote_port = -1;

id_t const_id=0;


const int disable_conv_clear=0;
const int disable_conn_clear=0;


enum server_current_state_t {server_idle=0,server_handshake1,server_ready};
enum client_current_state_t {client_idle=0,client_tcp_handshake,client_handshake1,client_handshake2,client_ready};
union current_state_t
{
	server_current_state_t server_current_state;
	client_current_state_t client_current_state;
};

int udp_fd=-1;  //for client only
int bind_fd=-1; //bind only,never send or recv
int epollfd=-1;
int timer_fd=-1;
int fail_time_counter=0;
int epoll_trigger_counter=0;
int debug_flag=0;


int simple_rule=0;
int keep_rule=0;
int auto_add_iptables_rule=0;
int generate_iptables_rule=0;
int generate_iptables_rule_add=0;

int debug_resend=0;
int disable_anti_replay=0;
char key_string[1000]= "secret key";
char key[16];//,key2[16];

int mtu_warn=1375;

//uint64_t current_time_rough=0;


int VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV;
////////==============================variable divider=============================================================

struct anti_replay_t
{
	u64_t max_packet_received;
	char window[anti_replay_window_size];
	anti_replay_seq_t anti_replay_seq;
	anti_replay_seq_t get_new_seq_for_send()
	{
		return anti_replay_seq++;
	}
	anti_replay_t()
	{
		max_packet_received=0;
		anti_replay_seq=get_true_random_number_64()/10;//random first seq
		//memset(window,0,sizeof(window)); //not necessary
	}
	void re_init()
	{
		max_packet_received=0;
		//memset(window,0,sizeof(window));
	}

	int is_vaild(u64_t seq)
	{
		if(disable_anti_replay) return 1;
		//if(disabled) return 0;

		if(seq==max_packet_received) return 0;
		else if(seq>max_packet_received)
		{
			if(seq-max_packet_received>=anti_replay_window_size)
			{
				memset(window,0,sizeof(window));
				window[seq%anti_replay_window_size]=1;
			}
			else
			{
				for (u64_t i=max_packet_received+1;i<seq;i++)
					window[i%anti_replay_window_size]=0;
				window[seq%anti_replay_window_size]=1;
			}
			max_packet_received=seq;
			return 1;
		}
		else if(seq<max_packet_received)
		{
			if(max_packet_received-seq>=anti_replay_window_size) return 0;
			else
			{
				if (window[seq%anti_replay_window_size]==1) return 0;
				else
				{
					window[seq%anti_replay_window_size]=1;
					return 1;
				}
			}
		}


		return 0; //for complier check
	}
};//anti_replay;

void server_clear_function(u64_t u64);
struct conv_manager_t  //TODO change map to unordered map
{
	//typedef hash_map map;
	unordered_map<u64_t,u32_t> u64_to_conv;  //conv and u64 are both supposed to be uniq
	unordered_map<u32_t,u64_t> conv_to_u64;

	unordered_map<u32_t,u64_t> conv_last_active_time;

	unordered_map<u32_t,u64_t>::iterator clear_it;

	unordered_map<u32_t,u64_t>::iterator it;
	unordered_map<u32_t,u64_t>::iterator old_it;

	//void (*clear_function)(uint64_t u64) ;

	long long last_clear_time;

	conv_manager_t()
	{
		clear_it=conv_last_active_time.begin();
		long long last_clear_time=0;
		//clear_function=0;
	}
	~conv_manager_t()
	{
		clear();
	}
	int get_size()
	{
		return conv_to_u64.size();
	}
	void reserve()
	{
		u64_to_conv.reserve(10007);
		conv_to_u64.reserve(10007);
		conv_last_active_time.reserve(10007);
	}
	void clear()
	{
		if(disable_conv_clear) return ;

		if(program_mode==server_mode)
		{
			for(it=conv_to_u64.begin();it!=conv_to_u64.end();it++)
			{
				//int fd=int((it->second<<32u)>>32u);
				server_clear_function(  it->second);
			}
		}
		u64_to_conv.clear();
		conv_to_u64.clear();
		conv_last_active_time.clear();

		clear_it=conv_last_active_time.begin();

	}
	u32_t get_new_conv()
	{
		u32_t conv=get_true_random_number_nz();
		while(conv_to_u64.find(conv)!=conv_to_u64.end())
		{
			conv=get_true_random_number_nz();
		}
		return conv;
	}
	int is_conv_used(u32_t conv)
	{
		return conv_to_u64.find(conv)!=conv_to_u64.end();
	}
	int is_u64_used(u64_t u64)
	{
		return u64_to_conv.find(u64)!=u64_to_conv.end();
	}
	u32_t find_conv_by_u64(u64_t u64)
	{
		return u64_to_conv[u64];
	}
	u64_t find_u64_by_conv(u32_t conv)
	{
		return conv_to_u64[conv];
	}
	int update_active_time(u32_t conv)
	{
		return conv_last_active_time[conv]=get_current_time();
	}
	int insert_conv(u32_t conv,u64_t u64)
	{
		u64_to_conv[u64]=conv;
		conv_to_u64[conv]=u64;
		conv_last_active_time[conv]=get_current_time();
		return 0;
	}
	int erase_conv(u32_t conv)
	{
		if(disable_conv_clear) return 0;
		u64_t u64=conv_to_u64[conv];
		if(program_mode==server_mode)
		{
			server_clear_function(u64);
		}
		conv_to_u64.erase(conv);
		u64_to_conv.erase(u64);
		conv_last_active_time.erase(conv);
		return 0;
	}
	int clear_inactive(char * ip_port=0)
	{
		if(get_current_time()-last_clear_time>conv_clear_interval)
		{
			last_clear_time=get_current_time();
			return clear_inactive0(ip_port);
		}
		return 0;
	}
	int clear_inactive0(char * ip_port)
	{
		if(disable_conv_clear) return 0;


		//map<uint32_t,uint64_t>::iterator it;
		int cnt=0;
		it=clear_it;
		int size=conv_last_active_time.size();
		int num_to_clean=size/conv_clear_ratio+conv_clear_min;   //clear 1/10 each time,to avoid latency glitch

		num_to_clean=min(num_to_clean,size);

		u64_t current_time=get_current_time();
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
				//mylog(log_info,"inactive conv %u cleared \n",it->first);
				old_it=it;
				it++;
				u32_t conv= old_it->first;
				erase_conv(old_it->first);
				if(ip_port==0)
				{
					mylog(log_info,"conv %x cleared\n",conv);
				}
				else
				{
					mylog(log_info,"[%s]conv %x cleared\n",ip_port,conv);
				}
			}
			else
			{
				it++;
			}
			cnt++;
		}
		return 0;
	}
};//g_conv_manager;
struct blob_t
{
	conv_manager_t conv_manager;
	anti_replay_t anti_replay;
};
struct conn_info_t
{
	current_state_t state;

	raw_info_t raw_info;
	u64_t last_state_time;
	u64_t last_hb_sent_time;  //client re-use this for retry
	u64_t last_hb_recv_time;
	//long long last_resent_time;

	id_t my_id;
	id_t oppsite_id;


	int timer_fd;
	id_t oppsite_const_id;

	blob_t *blob;

	uint8_t my_roller;
	uint8_t oppsite_roller;
	u64_t last_oppsite_roller_time;

/*
	const uint32_t &ip=raw_info.recv_info.src_ip;
	const uint16_t &port=raw_info.recv_info.src_port;

*/
	 void recover(const conn_info_t &conn_info)
	 {
			raw_info=conn_info.raw_info;
			last_state_time=conn_info.last_state_time;
			last_hb_recv_time=conn_info.last_hb_recv_time;
			last_hb_sent_time=conn_info.last_hb_sent_time;
			my_id=conn_info.my_id;
			oppsite_id=conn_info.oppsite_id;
			blob->anti_replay.re_init();

			my_roller=0;//no need to set,but for easier debug,set it to zero
			oppsite_roller=0;//same as above
			last_oppsite_roller_time=0;
	 }

	void re_init()
	{
		//send_packet_info.protocol=g_packet_info_send.protocol;
		if(program_mode==server_mode)
			state.server_current_state=server_idle;
		else
			state.client_current_state=client_idle;
		last_state_time=0;
		oppsite_const_id=0;

		timer_fd=0;

		my_roller=0;
		oppsite_roller=0;
		last_oppsite_roller_time=0;
	}
	conn_info_t()
	{
		blob=0;
		re_init();
	}
	void prepare()
	{
		blob=new blob_t;

	}
	conn_info_t(const conn_info_t&b)
	{
		//mylog(log_error,"called!!!!!!!!!!!!!\n");
		*this=b;
		if(blob!=0)
		{
			blob=new blob_t(*b.blob);
		}
	}
	conn_info_t& operator=(const conn_info_t& b)
	  {
		mylog(log_fatal,"not allowed\n");
		myexit(-1);
	    return *this;
	  }
	~conn_info_t();
};//g_conn_info;

struct conn_manager_t
{

 u32_t ready_num;

 unordered_map<int,conn_info_t *> udp_fd_mp;  //a bit dirty to used pointer,but can void unordered_map search
 unordered_map<int,conn_info_t *> timer_fd_mp;//we can use pointer here since unordered_map.rehash() uses shallow copy

 unordered_map<id_t,conn_info_t *> const_id_mp;

 unordered_map<u64_t,conn_info_t*> mp; //put it at end so that it de-consturcts first

 unordered_map<u64_t,conn_info_t*>::iterator clear_it;

 long long last_clear_time;

 conn_manager_t()
 {
	 ready_num=0;
	 mp.reserve(10007);
	 clear_it=mp.begin();
	 timer_fd_mp.reserve(10007);
	 const_id_mp.reserve(10007);
	 udp_fd_mp.reserve(100007);
	 last_clear_time=0;
	 //current_ready_ip=0;
	// current_ready_port=0;
 }
 int exist(u32_t ip,uint16_t port)
 {
	 u64_t u64=0;
	 u64=ip;
	 u64<<=32u;
	 u64|=port;
	 if(mp.find(u64)!=mp.end())
	 {
		 return 1;
	 }
	 return 0;
 }
 /*
 int insert(uint32_t ip,uint16_t port)
 {
	 uint64_t u64=0;
	 u64=ip;
	 u64<<=32u;
	 u64|=port;
	 mp[u64];
	 return 0;
 }*/
 conn_info_t *& find_insert_p(u32_t ip,uint16_t port)  //be aware,the adress may change after rehash
 {
	 u64_t u64=0;
	 u64=ip;
	 u64<<=32u;
	 u64|=port;
	 unordered_map<u64_t,conn_info_t*>::iterator it=mp.find(u64);
	 if(it==mp.end())
	 {
		 mp[u64]=new conn_info_t;
	 }
	 return mp[u64];
 }
 conn_info_t & find_insert(u32_t ip,uint16_t port)  //be aware,the adress may change after rehash
 {
	 u64_t u64=0;
	 u64=ip;
	 u64<<=32u;
	 u64|=port;
	 unordered_map<u64_t,conn_info_t*>::iterator it=mp.find(u64);
	 if(it==mp.end())
	 {
		 mp[u64]=new conn_info_t;
	 }
	 return *mp[u64];
 }
 int erase(unordered_map<u64_t,conn_info_t*>::iterator erase_it)
 {
		if(erase_it->second->state.server_current_state==server_ready)
		{
			ready_num--;
			assert(i32_t(ready_num)!=-1);
			assert(erase_it->second!=0);
			assert(erase_it->second->timer_fd !=0);
			assert(erase_it->second->oppsite_const_id!=0);
			assert(const_id_mp.find(erase_it->second->oppsite_const_id)!=const_id_mp.end());
			assert(timer_fd_mp.find(erase_it->second->timer_fd)!=timer_fd_mp.end());

			const_id_mp.erase(erase_it->second->oppsite_const_id);
			timer_fd_mp.erase(erase_it->second->timer_fd);
			close(erase_it->second->timer_fd);// close will auto delte it from epoll
			delete(erase_it->second);
			mp.erase(erase_it->first);
		}
		else
		{
			assert(erase_it->second->blob==0);
			assert(erase_it->second->timer_fd ==0);
			assert(erase_it->second->oppsite_const_id==0);
			delete(erase_it->second);
			mp.erase(erase_it->first);
		}
		return 0;
 }
int clear_inactive()
{
	if(get_current_time()-last_clear_time>conn_clear_interval)
	{
		last_clear_time=get_current_time();
		return clear_inactive0();
	}
	return 0;
}
int clear_inactive0()
{
	 unordered_map<u64_t,conn_info_t*>::iterator it;
	 unordered_map<u64_t,conn_info_t*>::iterator old_it;

	if(disable_conn_clear) return 0;

	//map<uint32_t,uint64_t>::iterator it;
	int cnt=0;
	it=clear_it;
	int size=mp.size();
	int num_to_clean=size/conn_clear_ratio+conn_clear_min;   //clear 1/10 each time,to avoid latency glitch

	mylog(log_trace,"mp.size() %d\n", size);

	num_to_clean=min(num_to_clean,(int)mp.size());
	u64_t current_time=get_current_time();

	for(;;)
	{
		if(cnt>=num_to_clean) break;
		if(mp.begin()==mp.end()) break;

		if(it==mp.end())
		{
			it=mp.begin();
		}

		if(it->second->state.server_current_state==server_ready &&current_time - it->second->last_hb_recv_time  <=server_conn_timeout)
		{
				it++;
		}
		else if(it->second->state.server_current_state!=server_ready&& current_time - it->second->last_state_time  <=server_handshake_timeout )
		{
			it++;
		}
		else if(it->second->blob!=0&&it->second->blob->conv_manager.get_size() >0)
		{
			assert(it->second->state.server_current_state==server_ready);
			it++;
		}
		else
		{
			mylog(log_info,"[%s:%d]inactive conn cleared \n",my_ntoa(it->second->raw_info.recv_info.src_ip),it->second->raw_info.recv_info.src_port);
			old_it=it;
			it++;
			erase(old_it);
		}
		cnt++;
	}
	return 0;
}

}conn_manager;

conn_info_t::~conn_info_t()
{
	if(program_mode==server_mode)
	{
		if(state.server_current_state==server_ready)
		{
			assert(blob!=0);
			assert(oppsite_const_id!=0);
			//assert(conn_manager.const_id_mp.find(oppsite_const_id)!=conn_manager.const_id_mp.end()); // conn_manager 's deconstuction function  erases it
		}
		else
		{
			assert(blob==0);
			assert(oppsite_const_id==0);
		}
	}
	//if(oppsite_const_id!=0)     //do this at conn_manager 's deconstuction function
		//conn_manager.const_id_mp.erase(oppsite_const_id);
	if(blob!=0)
		delete blob;

	//send_packet_info.protocol=g_packet_info_send.protocol;
}

int TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT;
////////==========================type divider=======================================================

int server_on_raw_recv_pre_ready(conn_info_t &conn_info,char * ip_port,u32_t tmp_oppsite_const_id);
int server_on_raw_recv_ready(conn_info_t &conn_info,char * ip_port,char type,char *data,int data_len);
int server_on_raw_recv_handshake1(conn_info_t &conn_info,char * ip_port,char * data, int data_len);

int DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD;
////////////////=======================declear divider=============================

void server_clear_function(u64_t u64)
{
	int fd=int(u64);
	int ret;
	assert(fd!=0);
	/*
	epoll_event ev;

	ev.events = EPOLLIN;
	ev.data.u64 = u64;

	ret = epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev);
	if (ret!=0)
	{
		mylog(log_fatal,"fd:%d epoll delete failed!!!!\n",fd);
		myexit(-1);   //this shouldnt happen
	}*/                //no need
	ret= close(fd);  //closed fd should be auto removed from epoll

	if (ret!=0)
	{
		mylog(log_fatal,"close fd %d failed !!!!\n",fd);
		myexit(-1);  //this shouldnt happen
	}
	//mylog(log_fatal,"size:%d !!!!\n",conn_manager.udp_fd_mp.size());
	assert(conn_manager.udp_fd_mp.find(fd)!=conn_manager.udp_fd_mp.end());
	conn_manager.udp_fd_mp.erase(fd);
}




int send_bare(raw_info_t &raw_info,const char* data,int len)
{
	if(len<0)
	{
		mylog(log_debug,"input_len <0\n");
		return -1;
	}
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;

	char send_data_buf[buf_len];  //buf for send data and send hb
	char send_data_buf2[buf_len];


	//static send_bare[buf_len];
	iv_t iv=get_true_random_number_64();
	padding_t padding=get_true_random_number_64();

	memcpy(send_data_buf,&iv,sizeof(iv));
	memcpy(send_data_buf+sizeof(iv),&padding,sizeof(padding));

	send_data_buf[sizeof(iv)+sizeof(padding)]='b';
	memcpy(send_data_buf+sizeof(iv)+sizeof(padding)+1,data,len);
	int new_len=len+sizeof(iv)+sizeof(padding)+1;

	if(my_encrypt(send_data_buf,send_data_buf2,new_len,key)!=0)
	{
		return -1;
	}
	send_raw0(raw_info,send_data_buf2,new_len);
	return 0;
}
int parse_bare(const char *input,int input_len,char* & data,int & len)  //allow overlap
{
	static char recv_data_buf[buf_len];

	if(input_len<0)
	{
		mylog(log_debug,"input_len <0\n");
		return -1;
	}
	if(my_decrypt(input,recv_data_buf,input_len,key)!=0)
	{
		mylog(log_debug,"decrypt_fail in recv bare\n");
		return -1;
	}
	if(recv_data_buf[sizeof(iv_t)+sizeof(padding_t)]!='b')
	{
		mylog(log_debug,"not a bare packet\n");
		return -1;
	}
	len=input_len;
	data=recv_data_buf+sizeof(iv_t)+sizeof(padding_t)+1;
	len-=sizeof(iv_t)+sizeof(padding_t)+1;
	if(len<0)
	{
		mylog(log_debug,"len <0\n");
		return -1;
	}
	return 0;
}
int recv_bare(raw_info_t &raw_info,char* & data,int & len)
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;

	if(recv_raw0(raw_info,data,len)<0)
	{
		//printf("recv_raw_fail in recv bare\n");
		return -1;
	}
	if ((raw_mode == mode_faketcp && (recv_info.syn == 1 || recv_info.ack != 1)))
	{
		mylog(log_debug,"unexpect packet type recv_info.syn=%d recv_info.ack=%d \n",recv_info.syn,recv_info.ack);
		return -1;
	}
	return parse_bare(data,len,data,len);
}

int send_handshake(raw_info_t &raw_info,id_t id1,id_t id2,id_t id3)
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;

	char * data;int len;
	//len=sizeof(id_t)*3;
	if(numbers_to_char(id1,id2,id3,data,len)!=0) return -1;
	if(send_bare(raw_info,data,len)!=0) {mylog(log_warn,"send bare fail\n");return -1;}
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

int send_safer(conn_info_t &conn_info,char type,const char* data,int len)
{

	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;

	if(type!='h'&&type!='d')
	{
		mylog(log_warn,"first byte is not h or d  ,%x\n",type);
		return -1;
	}



	char send_data_buf[buf_len];  //buf for send data and send hb
	char send_data_buf2[buf_len];



	id_t n_tmp_id=htonl(conn_info.my_id);

	memcpy(send_data_buf,&n_tmp_id,sizeof(n_tmp_id));

	n_tmp_id=htonl(conn_info.oppsite_id);

	memcpy(send_data_buf+sizeof(n_tmp_id),&n_tmp_id,sizeof(n_tmp_id));

	anti_replay_seq_t n_seq=hton64(conn_info.blob->anti_replay.get_new_seq_for_send());

	memcpy(send_data_buf+sizeof(n_tmp_id)*2,&n_seq,sizeof(n_seq));


	send_data_buf[sizeof(n_tmp_id)*2+sizeof(n_seq)]=type;
	send_data_buf[sizeof(n_tmp_id)*2+sizeof(n_seq)+1]=conn_info.my_roller;

	memcpy(send_data_buf+2+sizeof(n_tmp_id)*2+sizeof(n_seq),data,len);//data;

	int new_len=len+sizeof(n_seq)+sizeof(n_tmp_id)*2+2;

	if(my_encrypt(send_data_buf,send_data_buf2,new_len,key)!=0)
	{
		return -1;
	}

	if(send_raw0(conn_info.raw_info,send_data_buf2,new_len)!=0) return -1;

	if(after_send_raw0(conn_info.raw_info)!=0) return -1;

	return 0;
}
int send_data_safer(conn_info_t &conn_info,const char* data,int len,u32_t conv_num)
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;

	char send_data_buf[buf_len];
	//send_data_buf[0]='d';
	u32_t n_conv_num=htonl(conv_num);
	memcpy(send_data_buf,&n_conv_num,sizeof(n_conv_num));

	memcpy(send_data_buf+sizeof(n_conv_num),data,len);
	int new_len=len+sizeof(n_conv_num);
	send_safer(conn_info,'d',send_data_buf,new_len);
	return 0;

}
int parse_safer(conn_info_t &conn_info,const char * input,int input_len,char &type,char* &data,int &len)//allow overlap
{
	 static char recv_data_buf0[buf_len];

	 char *recv_data_buf=recv_data_buf0; //fix strict alias warning
	if(my_decrypt(input,recv_data_buf,input_len,key)!=0)
	{
		//printf("decrypt fail\n");
		return -1;
	}



	//char *a=recv_data_buf;
	id_t h_oppiste_id= ntohl (  *((id_t * )(recv_data_buf)) );

	id_t h_my_id= ntohl (  *((id_t * )(recv_data_buf+sizeof(id_t)))    );

	anti_replay_seq_t h_seq= ntoh64 (  *((anti_replay_seq_t * )(recv_data_buf  +sizeof(id_t) *2 ))   );

	if(h_oppiste_id!=conn_info.oppsite_id||h_my_id!=conn_info.my_id)
	{
		mylog(log_debug,"id and oppsite_id verification failed %x %x %x %x \n",h_oppiste_id,conn_info.oppsite_id,h_my_id,conn_info.my_id);
		return -1;
	}

	if (conn_info.blob->anti_replay.is_vaild(h_seq) != 1) {
		mylog(log_debug,"dropped replay packet\n");
		return -1;
	}

	//printf("recv _len %d\n ",recv_len);
	data=recv_data_buf+sizeof(anti_replay_seq_t)+sizeof(id_t)*2;
	len=input_len-(sizeof(anti_replay_seq_t)+sizeof(id_t)*2  );


	if(data[0]!='h'&&data[0]!='d')
	{
		mylog(log_debug,"first byte is not h or d  ,%x\n",data[0]);
		return -1;
	}

	uint8_t roller=data[1];


	type=data[0];
	data+=2;
	len-=2;

	if(len<0)
	{
		mylog(log_debug,"len <0 ,%d\n",len);
		return -1;
	}

	if(roller!=conn_info.oppsite_roller)
	{
		conn_info.oppsite_roller=roller;
		conn_info.last_oppsite_roller_time=get_current_time();
	}
	conn_info.my_roller++;//increase on a successful recv


	if(after_recv_raw0(conn_info.raw_info)!=0) return -1;

	return 0;
}
int recv_safer(conn_info_t &conn_info,char &type,char* &data,int &len)
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;

	char * recv_data;int recv_len;
	static char recv_data_buf[buf_len];

	if(recv_raw0(conn_info.raw_info,recv_data,recv_len)!=0) return -1;

	return parse_safer(conn_info,recv_data,recv_len,type,data,len);
}

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

	 struct sockaddr_in temp_bind_addr={0};
     //bzero(&temp_bind_addr, sizeof(temp_bind_addr));

     temp_bind_addr.sin_family = AF_INET;
     temp_bind_addr.sin_port = htons(port);
     temp_bind_addr.sin_addr.s_addr = local_ip_uint32;

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
	int raw_send_port=10000+get_true_random_number()%(65535-10000);
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
	its.it_interval.tv_sec=(timer_interval/1000);
	its.it_interval.tv_nsec=(timer_interval%1000)*1000ll*1000ll;
	its.it_value.tv_nsec=1; //imidiately
	timerfd_settime(timer_fd,0,&its,0);


	ev.events = EPOLLIN;
	ev.data.u64 = timer_fd;

	ret=epoll_ctl(epollfd, EPOLL_CTL_ADD, timer_fd, &ev);
	if (ret < 0) {
		mylog(log_fatal,"epoll_ctl return %d\n", ret);
		myexit(-1);
	}
	return 0;
}


int set_timer_server(int epollfd,int &timer_fd)
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
	its.it_interval.tv_sec=(timer_interval/1000);
	its.it_interval.tv_nsec=(timer_interval%1000)*1000ll*1000ll;
	its.it_value.tv_nsec=1; //imidiately
	timerfd_settime(timer_fd,0,&its,0);


	ev.events = EPOLLIN;
	ev.data.u64 = pack_u64(2,timer_fd);

	ret=epoll_ctl(epollfd, EPOLL_CTL_ADD, timer_fd, &ev);
	if (ret < 0) {
		mylog(log_fatal,"epoll_ctl return %d\n", ret);
		myexit(-1);
	}
	return 0;
}
int get_src_adress(u32_t &ip);
int client_on_timer(conn_info_t &conn_info) //for client
{
	//keep_iptables_rule();
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;
	conn_info.blob->conv_manager.clear_inactive();
	mylog(log_trace,"timer!\n");

	mylog(log_trace,"roller my %d,oppsite %d,%lld\n",int(conn_info.my_roller),int(conn_info.oppsite_roller),conn_info.last_oppsite_roller_time);

	mylog(log_trace,"<client_on_timer,send_info.ts_ack= %u>\n",send_info.ts_ack);




	if(conn_info.state.client_current_state==client_idle)
	{
		fail_time_counter++;
		if(max_fail_time>0&&fail_time_counter>max_fail_time)
		{
			mylog(log_fatal,"max_fail_time exceed\n");
			myexit(-1);
		}

		conn_info.blob->anti_replay.re_init();
		conn_info.my_id = get_true_random_number_nz(); ///todo no need to do this everytime

		u32_t new_ip=0;
		if(!force_source_ip&&get_src_adress(new_ip)==0)
		{
			if(new_ip!=source_ip_uint32)
			{
				mylog(log_info,"source ip changed from %s to ",my_ntoa(source_ip_uint32));
				log_bare(log_info,"%s\n",my_ntoa(new_ip));
				source_ip_uint32=new_ip;
				send_info.src_ip=new_ip;
			}
		}

		if (source_port == 0)
		{
			send_info.src_port = client_bind_to_a_new_port();
		}
		else
		{
			send_info.src_port = source_port;
		}

		if (raw_mode == mode_icmp)
		{
			send_info.dst_port = send_info.src_port;
		}

		mylog(log_info, "using port %d\n", send_info.src_port);
		init_filter(send_info.src_port);

		if(raw_mode==mode_icmp||raw_mode==mode_udp)
		{
			conn_info.state.client_current_state=client_handshake1;

			mylog(log_info,"state changed from client_idle to client_pre_handshake\n");
		}
		if(raw_mode==mode_faketcp)
		{
			conn_info.state.client_current_state=client_tcp_handshake;
			mylog(log_info,"state changed from client_idle to client_tcp_handshake\n");

		}
		conn_info.last_state_time=get_current_time();
		conn_info.last_hb_sent_time=0;
		//dont return;
	}
	if(conn_info.state.client_current_state==client_tcp_handshake)  //send and resend syn
	{
		assert(raw_mode==mode_faketcp);
		if (get_current_time() - conn_info.last_state_time > client_handshake_timeout)
		{
			conn_info.state.client_current_state = client_idle;
			mylog(log_info, "state back to client_idle from client_tcp_handshake\n");
			return 0;

		}
		else if (get_current_time() - conn_info.last_hb_sent_time > client_retry_interval)
		{

			if (raw_mode == mode_faketcp)
			{
				if (conn_info.last_hb_sent_time == 0)
				{
					send_info.psh = 0;
					send_info.syn = 1;
					send_info.ack = 0;
					send_info.ts_ack =0;
					send_info.seq=get_true_random_number();
					send_info.ack_seq=get_true_random_number();
				}
			}

			send_raw0(raw_info, 0, 0);

			conn_info.last_hb_sent_time = get_current_time();
			mylog(log_info, "(re)sent tcp syn\n");
			return 0;
		}
		else
		{
			return 0;
		}
		return 0;
	}
	else if(conn_info.state.client_current_state==client_handshake1)//send and resend handshake1
	{
		if(get_current_time()-conn_info.last_state_time>client_handshake_timeout)
		{
			conn_info.state.client_current_state=client_idle;
			mylog(log_info,"state back to client_idle from client_handshake1\n");
			return 0;

		}
		else if(get_current_time()-conn_info.last_hb_sent_time>client_retry_interval)
		{

			if(raw_mode==mode_faketcp)
			{
				if(conn_info.last_hb_sent_time==0)
				{
					send_info.seq++;
					send_info.ack_seq=recv_info.seq+1;
					send_info.ts_ack=recv_info.ts;
					raw_info.reserved_seq=send_info.seq;
				}
				send_info.seq=raw_info.reserved_seq;
				send_info.psh = 0;
				send_info.syn = 0;
				send_info.ack = 1;
				send_raw0(raw_info, 0, 0);

				send_handshake(raw_info,conn_info.my_id,0,const_id);

				send_info.seq+=raw_info.last_send_len;
			}
			else
			{

				send_handshake(raw_info,conn_info.my_id,0,const_id);
				if(raw_mode==mode_icmp)
					send_info.icmp_seq++;
			}

			conn_info.last_hb_sent_time=get_current_time();
			mylog(log_info,"(re)sent handshake1\n");
			return 0;
		}
		else
		{
			return 0;
		}
		return 0;
	}
	else if(conn_info.state.client_current_state==client_handshake2)
	{
		if(get_current_time()-conn_info.last_state_time>client_handshake_timeout)
		{
			conn_info.state.client_current_state=client_idle;
			mylog(log_info,"state back to client_idle from client_handshake2\n");
			return 0;
		}
		else if(get_current_time()-conn_info.last_hb_sent_time>client_retry_interval)
		{
			if(raw_mode==mode_faketcp)
			{
				if(conn_info.last_hb_sent_time==0)
				{
					send_info.ack_seq=recv_info.seq+raw_info.last_recv_len;
					send_info.ts_ack=recv_info.ts;
					raw_info.reserved_seq=send_info.seq;
				}
				send_info.seq=raw_info.reserved_seq;
				send_handshake(raw_info,conn_info.my_id,conn_info.oppsite_id,const_id);
				send_info.seq+=raw_info.last_send_len;

			}
			else
			{

				send_handshake(raw_info,conn_info.my_id,conn_info.oppsite_id,const_id);
				if(raw_mode==mode_icmp)
					send_info.icmp_seq++;
			}
			conn_info.last_hb_sent_time=get_current_time();
			mylog(log_info,"(re)sent handshake2\n");
			return 0;

		}
		else
		{
			return 0;
		}
		return 0;
	}
	else if(conn_info.state.client_current_state==client_ready)
	{
		fail_time_counter=0;
		mylog(log_trace,"time %llu,%llu\n",get_current_time(),conn_info.last_state_time);

		if(get_current_time()-conn_info.last_hb_recv_time>client_conn_timeout)
		{
			conn_info.state.client_current_state=client_idle;
			conn_info.my_id=get_true_random_number_nz();
			mylog(log_info,"state back to client_idle from  client_ready bc of server-->client direction timeout\n");
			return 0;
		}

		if(get_current_time()-conn_info.last_hb_sent_time<heartbeat_interval)
		{
			return 0;
		}

		if(get_current_time()- conn_info.last_oppsite_roller_time>client_conn_uplink_timeout)
		{
			conn_info.state.client_current_state=client_idle;
			conn_info.my_id=get_true_random_number_nz();
			mylog(log_info,"state back to client_idle from  client_ready bc of client-->server direction timeout\n");
		}

		mylog(log_debug,"heartbeat sent <%x,%x>\n",conn_info.oppsite_id,conn_info.my_id);

		send_safer(conn_info,'h',"",0);/////////////send

		conn_info.last_hb_sent_time=get_current_time();
		return 0;
	}
	else
	{
		mylog(log_fatal,"unknown state,this shouldnt happen.\n");
		myexit(-1);
	}
	return 0;
}
int server_on_timer_multi(conn_info_t &conn_info,char * ip_port)
{
	//keep_iptables_rule();
	mylog(log_trace,"server timer!\n");
	raw_info_t &raw_info=conn_info.raw_info;

	assert(conn_info.state.server_current_state==server_ready);


	if(conn_info.state.server_current_state==server_ready)
	{
		conn_info.blob->conv_manager.clear_inactive(ip_port);
		/*
		if( get_current_time()-conn_info.last_hb_recv_time>heartbeat_timeout )
		{
			mylog(log_trace,"%lld %lld\n",get_current_time(),conn_info.last_state_time);
			conn_info.server_current_state=server_nothing;

			//conn_manager.current_ready_ip=0;
			//conn_manager.current_ready_port=0;

			mylog(log_info,"changed state to server_nothing\n");
			return 0;
		}*/  //dont need to do this at server,conn_manger will clear expired connections

		if(get_current_time()-conn_info.last_hb_sent_time<heartbeat_interval)
		{
			return 0;
		}

		send_safer(conn_info,'h',"",0);  /////////////send

		conn_info.last_hb_sent_time=get_current_time();

		mylog(log_debug,"heart beat sent<%x,%x>\n",conn_info.my_id,conn_info.oppsite_id);
	}
	else
	{
		mylog(log_fatal,"this shouldnt happen!\n");
		myexit(-1);
	}
	return 0;

}
int client_on_raw_recv(conn_info_t &conn_info)
{
	char* data;int data_len;
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;

	raw_info_t &raw_info=conn_info.raw_info;

	mylog(log_trace,"<client_on_raw_recv,send_info.ts_ack= %u>\n",send_info.ts_ack);

	if(conn_info.state.client_current_state==client_idle )
	{
		recv(raw_recv_fd, 0,0, 0  );
	}
	else if(conn_info.state.client_current_state==client_tcp_handshake)//received syn ack
	{
		assert(raw_mode==mode_faketcp);
		if(recv_raw0(raw_info,data,data_len)<0)
		{
			return -1;
		}
		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_debug,"unexpected adress %x %x %d %d\n",recv_info.src_ip,send_info.dst_ip,recv_info.src_port,send_info.dst_port);
			return -1;
		}
		if(data_len==0&&raw_info.recv_info.syn==1&&raw_info.recv_info.ack==1)
		{
			if(recv_info.ack_seq!=send_info.seq+1)
			{
				mylog(log_debug,"seq ack_seq mis match\n");
							return -1;
			}

			conn_info.state.client_current_state = client_handshake1;
			mylog(log_info,"state changed from client_tcp_handshake to client_handshake1\n");
			conn_info.last_state_time = get_current_time();
			conn_info.last_hb_sent_time=0;
			client_on_timer(conn_info);
			return 0;
		}
		else
		{
			mylog(log_debug,"unexpected packet type,expected:syn ack\n");
			return -1;
		}
	}
	else if(conn_info.state.client_current_state==client_handshake1)//recevied respond of handshake1
	{
		if(recv_bare(raw_info,data,data_len)!=0)
		{
			mylog(log_debug,"recv_bare failed!\n");
			return -1;
		}
		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_debug,"unexpected adress %x %x %d %d\n",recv_info.src_ip,send_info.dst_ip,recv_info.src_port,send_info.dst_port);
			return -1;
		}
		if(data_len<int( 3*sizeof(id_t)))
		{
			mylog(log_debug,"too short to be a handshake\n");
			return -1;
		}
		id_t tmp_oppsite_id=  ntohl(* ((u32_t *)&data[0]));
		id_t tmp_my_id=ntohl(* ((u32_t *)&data[sizeof(id_t)]));
		id_t tmp_oppsite_const_id=ntohl(* ((u32_t *)&data[sizeof(id_t)*2]));

		if(tmp_my_id!=conn_info.my_id)
		{
			mylog(log_debug,"tmp_my_id doesnt match\n");
			return -1;
		}


		if(raw_mode==mode_faketcp)
		{
			if(recv_info.ack_seq!=send_info.seq)
			{
				mylog(log_debug,"seq ack_seq mis match\n");
							return -1;
			}
			if(recv_info.seq!=send_info.ack_seq)
			{
				mylog(log_debug,"seq ack_seq mis match\n");
							return -1;
			}
		}
		conn_info.oppsite_id=tmp_oppsite_id;

		mylog(log_info,"changed state from to client_handshake1 to client_handshake2,my_id is %x,oppsite id is %x\n",conn_info.my_id,conn_info.oppsite_id);

		//send_handshake(raw_info,conn_info.my_id,conn_info.oppsite_id,const_id);  //////////////send
		conn_info.state.client_current_state = client_handshake2;
		conn_info.last_state_time = get_current_time();
		conn_info.last_hb_sent_time=0;
		client_on_timer(conn_info);

		return 0;
	}
	else if(conn_info.state.client_current_state==client_handshake2||conn_info.state.client_current_state==client_ready)//received heartbeat or data
	{
		char type;
		if(recv_safer(conn_info,type,data,data_len)!=0)
		{
			mylog(log_debug,"recv_safer failed!\n");
			return -1;
		}
		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_warn,"unexpected adress %x %x %d %d,this shouldnt happen.\n",recv_info.src_ip,send_info.dst_ip,recv_info.src_port,send_info.dst_port);
			return -1;
		}
		if(conn_info.state.client_current_state==client_handshake2)
		{
			mylog(log_info,"changed state from to client_handshake2 to client_ready\n");
			conn_info.state.client_current_state=client_ready;
			conn_info.last_hb_sent_time=0;
			conn_info.last_hb_recv_time=get_current_time();
			conn_info.last_oppsite_roller_time=conn_info.last_hb_recv_time;
			client_on_timer(conn_info);
		}
		if(data_len==0&&type=='h')
		{
			mylog(log_debug,"[hb]heart beat received\n");
			conn_info.last_hb_recv_time=get_current_time();
			return 0;
		}
		else if(data_len>= int( sizeof(u32_t))&&type=='d')
		{
			mylog(log_trace,"received a data from fake tcp,len:%d\n",data_len);

			conn_info.last_hb_recv_time=get_current_time();

			u32_t tmp_conv_id= ntohl(* ((u32_t *)&data[0]));

			if(!conn_info.blob->conv_manager.is_conv_used(tmp_conv_id))
			{
				mylog(log_info,"unknow conv %d,ignore\n",tmp_conv_id);
				return 0;
			}

			conn_info.blob->conv_manager.update_active_time(tmp_conv_id);

			u64_t u64=conn_info.blob->conv_manager.find_u64_by_conv(tmp_conv_id);


			sockaddr_in tmp_sockaddr={0};

			tmp_sockaddr.sin_family = AF_INET;
			tmp_sockaddr.sin_addr.s_addr=(u64>>32u);

			tmp_sockaddr.sin_port= htons(uint16_t((u64<<32u)>>32u));


			int ret=sendto(udp_fd,data+sizeof(u32_t),data_len -(sizeof(u32_t)),0,(struct sockaddr *)&tmp_sockaddr,sizeof(tmp_sockaddr));

			if(ret<0)
			{
		    	mylog(log_warn,"sento returned %d\n",ret);
				//perror("ret<0");
			}
			mylog(log_trace,"%s :%d\n",inet_ntoa(tmp_sockaddr.sin_addr),ntohs(tmp_sockaddr.sin_port));
			mylog(log_trace,"%d byte sent\n",ret);
		}
		else
		{
			mylog(log_warn,"unknown packet,this shouldnt happen.\n");
						return -1;
		}

		return 0;
	}
	else
	{
		mylog(log_fatal,"unknown state,this shouldnt happen.\n");
		myexit(-1);
	}
	return 0;
}
int handle_lower_level(raw_info_t &raw_info)
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;

	if(lower_level_manual)
	{
		memset(&send_info.addr_ll,0,sizeof(send_info.addr_ll));
		send_info.addr_ll.sll_family=AF_PACKET;
		send_info.addr_ll.sll_ifindex=ifindex;
		send_info.addr_ll.sll_halen=ETHER_ADDR_LEN;
		send_info.addr_ll.sll_protocol=htons(ETH_P_IP);
		memcpy(&send_info.addr_ll.sll_addr,dest_hw_addr,ETHER_ADDR_LEN);
		 mylog(log_debug,"[manual]lower level info %x %x\n ",send_info.addr_ll.sll_halen,send_info.addr_ll.sll_protocol);
	}
	else
	{
	memset(&send_info.addr_ll,0,sizeof(send_info.addr_ll));
	send_info.addr_ll.sll_family=recv_info.addr_ll.sll_family;
	send_info.addr_ll.sll_ifindex=recv_info.addr_ll.sll_ifindex;
	send_info.addr_ll.sll_protocol=recv_info.addr_ll.sll_protocol;
	send_info.addr_ll.sll_halen=recv_info.addr_ll.sll_halen;
	memcpy(send_info.addr_ll.sll_addr,recv_info.addr_ll.sll_addr,sizeof(send_info.addr_ll.sll_addr));
	//other bytes should be kept zero.

	  mylog(log_debug,"[auto]lower level info %x %x\n ",send_info.addr_ll.sll_halen,send_info.addr_ll.sll_protocol);
	}
	return 0;
}
int server_on_raw_recv_multi()
{
	char dummy_buf[buf_len];
	packet_info_t peek_info;
	if(peek_raw(peek_info)<0)
	{
		recv(raw_recv_fd, 0,0, 0  );//
		//struct sockaddr saddr;
		//socklen_t saddr_size=sizeof(saddr);
		///recvfrom(raw_recv_fd, 0,0, 0 ,&saddr , &saddr_size);//
		mylog(log_trace,"peek_raw failed\n");
		return -1;
	}else
	{
		mylog(log_trace,"peek_raw success\n");
	}
	u32_t ip=peek_info.src_ip;uint16_t port=peek_info.src_port;

	char ip_port[40];
	sprintf(ip_port,"%s:%d",my_ntoa(ip),port);
	mylog(log_trace,"[%s]peek_raw\n",ip_port);
	int data_len; char *data;

	if(raw_mode==mode_faketcp&&peek_info.syn==1)
	{
		if(!conn_manager.exist(ip,port)||conn_manager.find_insert(ip,port).state.server_current_state!=server_ready)
		{//reply any syn ,before state become ready

			raw_info_t tmp_raw_info;
			if(recv_raw0(tmp_raw_info,data,data_len)<0)
			{
				return 0;
			}
			raw_info_t &raw_info=tmp_raw_info;
			packet_info_t &send_info=raw_info.send_info;
			packet_info_t &recv_info=raw_info.recv_info;

			send_info.src_ip=recv_info.dst_ip;
			send_info.src_port=recv_info.dst_port;

			send_info.dst_port = recv_info.src_port;
			send_info.dst_ip = recv_info.src_ip;

			if(lower_level)
			{
				handle_lower_level(raw_info);
			}

			if(data_len==0&&raw_info.recv_info.syn==1&&raw_info.recv_info.ack==0)
			{
				send_info.ack_seq = recv_info.seq + 1;

				send_info.psh = 0;
				send_info.syn = 1;
				send_info.ack = 1;
				send_info.ts_ack=recv_info.ts;

				mylog(log_info,"[%s]received syn,sent syn ack back\n",ip_port);
				send_raw0(raw_info, 0, 0);
				return 0;
			}
		}
		return 0;
	}
	if(!conn_manager.exist(ip,port))
	{
		if(conn_manager.mp.size()>=max_handshake_conn_num)
		{
			mylog(log_info,"[%s]reached max_handshake_conn_num,ignored new handshake\n",ip_port);
			recv(raw_recv_fd, 0,0, 0  );//
			return 0;
		}

		raw_info_t tmp_raw_info;


		if(raw_mode==mode_icmp)
		{
			tmp_raw_info.send_info.dst_port=tmp_raw_info.send_info.src_port=port;
		}
		if(recv_bare(tmp_raw_info,data,data_len)<0)
		{
			return 0;
		}
		if(data_len<int( 3*sizeof(id_t)))
		{
			mylog(log_debug,"[%s]too short to be a handshake\n",ip_port);
			return -1;
		}

		id_t zero=ntohl(* ((u32_t *)&data[sizeof(id_t)]));
		if(zero!=0)
		{
			mylog(log_debug,"[%s]not a invalid initial handshake\n",ip_port);
			return -1;
		}

		mylog(log_info,"[%s]got packet from a new ip\n",ip_port);

		conn_info_t &conn_info=conn_manager.find_insert(ip,port);
		conn_info.raw_info=tmp_raw_info;

		packet_info_t &send_info=conn_info.raw_info.send_info;
		packet_info_t &recv_info=conn_info.raw_info.recv_info;
		raw_info_t &raw_info=conn_info.raw_info;

		send_info.src_ip=recv_info.dst_ip;
		send_info.src_port=recv_info.dst_port;

		send_info.dst_port = recv_info.src_port;
		send_info.dst_ip = recv_info.src_ip;

		if(lower_level)
		{
			handle_lower_level(raw_info);
		}

		//id_t tmp_oppsite_id=  ntohl(* ((u32_t *)&data[0]));
		//mylog(log_info,"[%s]handshake1 received %x\n",ip_port,tmp_oppsite_id);

		conn_info.my_id=get_true_random_number_nz();


		mylog(log_info,"[%s]created new conn,state: server_handshake1,my_id is %x\n",ip_port,conn_info.my_id);

		conn_info.state.server_current_state = server_handshake1;
		conn_info.last_state_time = get_current_time();

		server_on_raw_recv_handshake1(conn_info,ip_port,data,data_len);
		return 0;
	}


	conn_info_t & conn_info=conn_manager.find_insert(ip,port);//insert if not exist
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;

	if(conn_info.state.server_current_state==server_handshake1)
	{
		if(recv_bare(raw_info,data,data_len)!=0)
		{
			return -1;
		}
		server_on_raw_recv_handshake1(conn_info,ip_port,data,data_len);
	}
	if(conn_info.state.server_current_state==server_ready)
	{
		char type;
		//mylog(log_info,"before recv_safer\n");
		if (recv_safer(conn_info,type, data, data_len) != 0) {
			return -1;
		}
		//mylog(log_info,"after recv_safer\n");
		return server_on_raw_recv_ready(conn_info,ip_port,type,data,data_len);
	}
	return 0;
}

/*
int server_on_raw_recv_handshake1(conn_info_t &conn_info,id_t tmp_oppsite_id )
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;



	return 0;
}*/
int server_on_raw_recv_handshake1(conn_info_t &conn_info,char * ip_port,char * data, int data_len)
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;

	//u32_t ip=conn_info.raw_info.recv_info.src_ip;
	//uint16_t port=conn_info.raw_info.recv_info.src_port;

	//char ip_port[40];
	//sprintf(ip_port,"%s:%d",my_ntoa(ip),port);

	if(data_len<int( 3*sizeof(id_t)))
	{
		mylog(log_debug,"[%s] data_len=%d too short to be a handshake\n",ip_port,data_len);
		return -1;
	}
	id_t tmp_oppsite_id=  ntohl(* ((u32_t *)&data[0]));
	id_t tmp_my_id=ntohl(* ((u32_t *)&data[sizeof(id_t)]));

	if(tmp_my_id==0)  //received  init handshake again
	{
		if(raw_mode==mode_faketcp)
		{
			send_info.seq=recv_info.ack_seq;
			send_info.ack_seq=recv_info.seq+raw_info.last_recv_len;
			send_info.ts_ack=recv_info.ts;
		}
		if(raw_mode==mode_icmp)
		{
			send_info.icmp_seq=recv_info.icmp_seq;
		}
		send_handshake(raw_info,conn_info.my_id,tmp_oppsite_id,const_id);  //////////////send

		mylog(log_info,"[%s]changed state to server_handshake1,my_id is %x\n",ip_port,conn_info.my_id);
	}
	else if(tmp_my_id==conn_info.my_id)
	{
		conn_info.oppsite_id=tmp_oppsite_id;
		id_t tmp_oppsite_const_id=ntohl(* ((u32_t *)&data[sizeof(id_t)*2]));

		if(raw_mode==mode_faketcp)
		{
			send_info.seq=recv_info.ack_seq;
			send_info.ack_seq=recv_info.seq+raw_info.last_recv_len;
			send_info.ts_ack=recv_info.ts;
		}

		if(raw_mode==mode_icmp)
		{
			send_info.icmp_seq=recv_info.icmp_seq;
		}

		server_on_raw_recv_pre_ready(conn_info,ip_port,tmp_oppsite_const_id);

	}
	else
	{
		mylog(log_debug,"[%s]invalid my_id %x,my_id is %x\n",ip_port,tmp_my_id,conn_info.my_id);
	}
	return 0;
}
int server_on_raw_recv_ready(conn_info_t &conn_info,char * ip_port,char type,char *data,int data_len)
{

	raw_info_t &raw_info = conn_info.raw_info;
	packet_info_t &send_info = conn_info.raw_info.send_info;
	packet_info_t &recv_info = conn_info.raw_info.recv_info;
	//char ip_port[40];

	//sprintf(ip_port,"%s:%d",my_ntoa(recv_info.src_ip),recv_info.src_port);


/*
	if (recv_info.src_ip != send_info.dst_ip
			|| recv_info.src_port != send_info.dst_port) {
		mylog(log_debug, "unexpected adress\n");
		return 0;
	}*/

	if (type == 'h' && data_len == 0) {
		//u32_t tmp = ntohl(*((u32_t *) &data[sizeof(u32_t)]));
		mylog(log_debug,"[%s][hb]received hb \n",ip_port);
		conn_info.last_hb_recv_time = get_current_time();
		return 0;
	} else if (type== 'd' && data_len >=int( sizeof(u32_t) ))
	{

		u32_t tmp_conv_id = ntohl(*((u32_t *) &data[0]));

		conn_info.last_hb_recv_time = get_current_time();

		mylog(log_trace, "conv:%u\n", tmp_conv_id);
		if (!conn_info.blob->conv_manager.is_conv_used(tmp_conv_id)) {
			if (conn_info.blob->conv_manager.get_size() >= max_conv_num) {
				mylog(log_warn,
						"[%s]ignored new conv %x connect bc max_conv_num exceed\n",ip_port,
						tmp_conv_id);
				return 0;
			}
			struct sockaddr_in remote_addr_in={0};

			socklen_t slen = sizeof(sockaddr_in);
			//memset(&remote_addr_in, 0, sizeof(remote_addr_in));
			remote_addr_in.sin_family = AF_INET;
			remote_addr_in.sin_port = htons(remote_port);
			remote_addr_in.sin_addr.s_addr = remote_ip_uint32;

			int new_udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (new_udp_fd < 0) {
				mylog(log_warn, "[%s]create udp_fd error\n",ip_port);
				return -1;
			}
			setnonblocking(new_udp_fd);
			set_buf_size(new_udp_fd);

			mylog(log_debug, "[%s]created new udp_fd %d\n",ip_port, new_udp_fd);
			int ret = connect(new_udp_fd, (struct sockaddr *) &remote_addr_in,
					slen);
			if (ret != 0) {
				mylog(log_warn, "udp fd connect fail\n");
				close(new_udp_fd);
				return -1;
			}
			struct epoll_event ev;

			u64_t u64 = (u32_t(new_udp_fd))+(1llu<<32u);
			mylog(log_trace, "[%s]u64: %lld\n",ip_port, u64);
			ev.events = EPOLLIN;

			ev.data.u64 = u64;

			ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, new_udp_fd, &ev);

			if (ret != 0) {
				mylog(log_warn, "[%s]add udp_fd error\n",ip_port);
				close(new_udp_fd);
				return -1;
			}

			conn_info.blob->conv_manager.insert_conv(tmp_conv_id, new_udp_fd);
			assert(conn_manager.udp_fd_mp.find(new_udp_fd)==conn_manager.udp_fd_mp.end());

			conn_manager.udp_fd_mp[new_udp_fd] = &conn_info;

			//pack_u64(conn_info.raw_info.recv_info.src_ip,conn_info.raw_info.recv_info.src_port);

			mylog(log_info, "[%s]new conv conv_id=%x, assigned fd=%d\n",ip_port,
					tmp_conv_id, new_udp_fd);



		}

		u64_t u64 = conn_info.blob->conv_manager.find_u64_by_conv(tmp_conv_id);

		conn_info.blob->conv_manager.update_active_time(tmp_conv_id);

		int fd = int((u64 << 32u) >> 32u);

		mylog(log_trace, "[%s]received a data from fake tcp,len:%d\n",ip_port, data_len);
		int ret = send(fd, data + sizeof(u32_t),
				data_len - ( sizeof(u32_t)), 0);

		mylog(log_trace, "[%s]%d byte sent  ,fd :%d\n ",ip_port, ret, fd);
		if (ret < 0) {
			mylog(log_warn, "send returned %d\n", ret);
			//perror("what happened????");
		}
		return 0;
	}
	return 0;
}

int server_on_raw_recv_pre_ready(conn_info_t &conn_info,char * ip_port,u32_t tmp_oppsite_const_id)
{
	//u32_t ip;uint16_t port;
	//ip=conn_info.raw_info.recv_info.src_ip;
	//port=conn_info.raw_info.recv_info.src_port;
	//char ip_port[40];
	//sprintf(ip_port,"%s:%d",my_ntoa(ip),port);

	mylog(log_info,"[%s]received handshake oppsite_id:%x  my_id:%x\n",ip_port,conn_info.oppsite_id,conn_info.my_id);

	mylog(log_info,"[%s]oppsite const_id:%x \n",ip_port,tmp_oppsite_const_id);
	if(conn_manager.const_id_mp.find(tmp_oppsite_const_id)==conn_manager.const_id_mp.end())
	{
		//conn_manager.const_id_mp=

		if(conn_manager.ready_num>=max_ready_conn_num)
		{
			mylog(log_info,"[%s]max_ready_conn_num,cant turn to ready\n",ip_port);
			conn_info.state.server_current_state =server_idle;
			return 0;
		}

		conn_info.prepare();
		conn_info.state.server_current_state = server_ready;
		conn_info.oppsite_const_id=tmp_oppsite_const_id;
		conn_manager.ready_num++;
		conn_manager.const_id_mp[tmp_oppsite_const_id]=&conn_info;


		//conn_info.last_state_time=get_current_time(); //dont change this!!!!!!!!!!!!!!!!!!!!!!!!!

		//conn_manager.current_ready_ip=ip;
		//conn_manager.current_ready_port=port;

		//my_id=conn_info.my_id;
		//oppsite_id=conn_info.oppsite_id;

		conn_info.last_hb_recv_time = get_current_time();
		conn_info.last_hb_sent_time = conn_info.last_hb_recv_time;//=get_current_time()

		send_safer(conn_info, 'h',"", 0);		/////////////send

		mylog(log_info, "[%s]changed state to server_ready\n",ip_port);
		conn_info.blob->anti_replay.re_init();

		//g_conn_info=conn_info;
		int new_timer_fd;
		set_timer_server(epollfd, new_timer_fd);
		conn_info.timer_fd=new_timer_fd;
		assert(conn_manager.timer_fd_mp.find(new_timer_fd)==conn_manager.timer_fd_mp.end());
		conn_manager.timer_fd_mp[new_timer_fd] = &conn_info;//pack_u64(ip,port);


		//timer_fd_mp[new_timer_fd]
		/*
		 if(oppsite_const_id!=0&&tmp_oppsite_const_id!=oppsite_const_id)  //TODO MOVE TO READY
		 {
		 mylog(log_info,"cleared all conv bc of const id doesnt match\n");
		 conv_manager.clear();
		 }*/
		//oppsite_const_id=tmp_oppsite_const_id;
	}
	else
	{

		conn_info_t &ori_conn_info=*conn_manager.const_id_mp[tmp_oppsite_const_id];

		if(ori_conn_info.state.server_current_state==server_ready)
		{
			if(conn_info.last_state_time<ori_conn_info.last_state_time)
			{
				 mylog(log_info,"[%s]conn_info.last_state_time<ori_conn_info.last_state_time. ignored new handshake\n",ip_port);
				 conn_info.state.server_current_state=server_idle;
				 conn_info.oppsite_const_id=0;
				 return 0;
			}
			if(!conn_manager.exist(ori_conn_info.raw_info.recv_info.src_ip,ori_conn_info.raw_info.recv_info.src_port))//TODO remove this
			{
				mylog(log_fatal,"[%s]this shouldnt happen\n",ip_port);
				myexit(-1);
			}
			if(!conn_manager.exist(conn_info.raw_info.recv_info.src_ip,conn_info.raw_info.recv_info.src_port))//TODO remove this
			{
				mylog(log_fatal,"[%s]this shouldnt happen2\n",ip_port);
				myexit(-1);
			}
			conn_info_t *&p_ori=conn_manager.find_insert_p(ori_conn_info.raw_info.recv_info.src_ip,ori_conn_info.raw_info.recv_info.src_port);
			conn_info_t *&p=conn_manager.find_insert_p(conn_info.raw_info.recv_info.src_ip,conn_info.raw_info.recv_info.src_port);
			conn_info_t *tmp=p;
			p=p_ori;
			p_ori=tmp;


			mylog(log_info,"[%s]grabbed a connection\n",ip_port);


			//ori_conn_info.state.server_current_state=server_ready;
			ori_conn_info.recover(conn_info);

			send_safer(ori_conn_info, 'h',"", 0);
			//ori_conn_info.blob->anti_replay.re_init();



			conn_info.state.server_current_state=server_idle;
			conn_info.oppsite_const_id=0;

		}
		else
		{
			mylog(log_fatal,"[%s]this should never happen\n",ip_port);
			myexit(-1);
		}
		return 0;
	}
	return 0;
}

int get_src_adress(u32_t &ip)
{
	struct sockaddr_in remote_addr_in={0};

	socklen_t slen = sizeof(sockaddr_in);
	//memset(&remote_addr_in, 0, sizeof(remote_addr_in));
	remote_addr_in.sin_family = AF_INET;
	remote_addr_in.sin_port = htons(remote_port);
	remote_addr_in.sin_addr.s_addr = remote_ip_uint32;


	int new_udp_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(new_udp_fd<0)
	{
		mylog(log_warn,"create udp_fd error\n");
		return -1;
	}
	//set_buf_size(new_udp_fd);

	mylog(log_debug,"created new udp_fd %d\n",new_udp_fd);
	int ret = connect(new_udp_fd, (struct sockaddr *) &remote_addr_in, slen);
	if(ret!=0)
	{
		mylog(log_warn,"udp fd connect fail\n");
		close(new_udp_fd);
		return -1;
	}

	struct sockaddr_in my_addr={0};
	socklen_t len=sizeof(my_addr);

    if(getsockname(new_udp_fd, (struct sockaddr *) &my_addr, &len)!=0) return -1;

    ip=my_addr.sin_addr.s_addr;

    close(new_udp_fd);

    return 0;
}

int client_event_loop()
{


	char buf[buf_len];

	conn_info_t conn_info;
	conn_info.my_id=get_true_random_number_nz();

	conn_info.prepare();
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;


	if(lower_level)
	{
		if(lower_level_manual)
		{
			//init_ifindex(if_name);
			memset(&send_info.addr_ll, 0, sizeof(send_info.addr_ll));
			send_info.addr_ll.sll_family = AF_PACKET;
			send_info.addr_ll.sll_ifindex = ifindex;
			send_info.addr_ll.sll_halen = ETHER_ADDR_LEN;
			send_info.addr_ll.sll_protocol = htons(ETH_P_IP);
			memcpy(&send_info.addr_ll.sll_addr, dest_hw_addr, ETHER_ADDR_LEN);
			mylog(log_info,"we are running at lower-level (manual) mode\n");
		}
		else
		{
			mylog(log_fatal,"--lower-level auto for client hasnt been implemented\n");
			myexit(-1);
		}

	}
	//printf("?????\n");
	if(source_ip_uint32==0)
	{
		mylog(log_info,"get_src_adress called\n");
		if(get_src_adress(source_ip_uint32)!=0)
		{
			mylog(log_fatal,"the trick to auto get source ip failed,you should specific an ip by --source-ip\n");
			myexit(-1);
		}
	}
	in_addr tmp;
	tmp.s_addr=source_ip_uint32;
	mylog(log_info,"source ip = %s\n",inet_ntoa(tmp));
	//printf("done\n");


	if(try_to_list_and_bind(source_port)!=0)
	{
		mylog(log_fatal,"bind to source_port:%d fail\n ",source_port);
		myexit(-1);
	}
	send_info.src_port=source_port;
	send_info.src_ip = source_ip_uint32;

	int i, j, k;int ret;


	//init_filter(source_port);
	send_info.dst_ip=remote_ip_uint32;
	send_info.dst_port=remote_port;

	//g_packet_info.src_ip=source_address_uint32;
	//g_packet_info.src_port=source_port;

    udp_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    set_buf_size(udp_fd);

	int yes = 1;
	//setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	struct sockaddr_in local_me={0};

	socklen_t slen = sizeof(sockaddr_in);
	//memset(&local_me, 0, sizeof(local_me));
	local_me.sin_family = AF_INET;
	local_me.sin_port = htons(local_port);
	local_me.sin_addr.s_addr = local_ip_uint32;


	if (bind(udp_fd, (struct sockaddr*) &local_me, slen) == -1) {
		mylog(log_fatal,"socket bind error\n");
		//perror("socket bind error");
		myexit(1);
	}
	setnonblocking(udp_fd);
	epollfd = epoll_create1(0);

	const int max_events = 4096;
	struct epoll_event ev, events[max_events];
	if (epollfd < 0) {
		mylog(log_fatal,"epoll return %d\n", epollfd);
		myexit(-1);
	}

	ev.events = EPOLLIN;
	ev.data.u64 = udp_fd;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, udp_fd, &ev);
	if (ret!=0) {
		mylog(log_fatal,"add  udp_listen_fd error\n");
		myexit(-1);
	}
	ev.events = EPOLLIN;
	ev.data.u64 = raw_recv_fd;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
	if (ret!= 0) {
		mylog(log_fatal,"add raw_fd error\n");
		myexit(-1);
	}

	////add_timer for fake_tcp_keep_connection_client

	//sleep(10);

	//memset(&udp_old_addr_in,0,sizeof(sockaddr_in));
	int unbind=1;


	set_timer(epollfd,timer_fd);

	mylog(log_debug,"send_raw : from %x %d  to %x %d\n",send_info.src_ip,send_info.src_port,send_info.dst_ip,send_info.dst_port);
	while(1)////////////////////////
	{
		if(about_to_exit) myexit(0);
		epoll_trigger_counter++;
		int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
		if (nfds < 0) {  //allow zero
			if(errno==EINTR  )
			{
				mylog(log_info,"epoll interrupted by signal\n");
				myexit(0);
			}
			else
			{
				mylog(log_fatal,"epoll_wait return %d\n", nfds);
				myexit(-1);
			}
		}
		int idx;
		for (idx = 0; idx < nfds; ++idx) {
			if (events[idx].data.u64 == (u64_t)raw_recv_fd)
			{
				iphdr *iph;tcphdr *tcph;
				client_on_raw_recv(conn_info);
			}
			else if(events[idx].data.u64 ==(u64_t)timer_fd)
			{
				u64_t value;
				read(timer_fd, &value, 8);
				client_on_timer(conn_info);

				mylog(log_trace,"epoll_trigger_counter:  %d \n",epoll_trigger_counter);
				epoll_trigger_counter=0;
			}
			else if (events[idx].data.u64 == (u64_t)udp_fd)
			{

				int recv_len;
				struct sockaddr_in udp_new_addr_in={0};
				socklen_t udp_new_addr_len = sizeof(sockaddr_in);
				if ((recv_len = recvfrom(udp_fd, buf, max_data_len, 0,
						(struct sockaddr *) &udp_new_addr_in, &udp_new_addr_len)) == -1) {
					mylog(log_error,"recv_from error,this shouldnt happen at client\n");
					myexit(1);
				};

				if(recv_len>=mtu_warn)
				{
					mylog(log_warn,"huge packet,data len=%d (>=%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ",recv_len,mtu_warn);
				}
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
				u64_t u64=((u64_t(udp_new_addr_in.sin_addr.s_addr))<<32u)+ntohs(udp_new_addr_in.sin_port);
				u32_t conv;

				if(!conn_info.blob->conv_manager.is_u64_used(u64))
				{
					if(conn_info.blob->conv_manager.get_size() >=max_conv_num)
					{
						mylog(log_warn,"ignored new udp connect bc max_conv_num exceed\n");
						continue;
					}
					conv=conn_info.blob->conv_manager.get_new_conv();
					conn_info.blob->conv_manager.insert_conv(conv,u64);
					mylog(log_info,"new packet from %s:%d,conv_id=%x\n",inet_ntoa(udp_new_addr_in.sin_addr),ntohs(udp_new_addr_in.sin_port),conv);
				}
				else
				{
					conv=conn_info.blob->conv_manager.find_conv_by_u64(u64);
				}

				conn_info.blob->conv_manager.update_active_time(conv);

				if(conn_info.state.client_current_state==client_ready)
				{
					/*
					char buf2[6000];
					int ret1=send_raw(conn_info.raw_info,buf2,40);
					int ret2=send_raw(conn_info.raw_info,buf2,500);
					int ret3=send_raw(conn_info.raw_info,buf2,1000);
					int ret4=send_raw(conn_info.raw_info,buf2,2000);
					mylog(log_warn,"ret= %d %d %d %d\n",ret1,ret2,ret3,ret4);*/

					send_data_safer(conn_info,buf,recv_len,conv);
				}
			}
			else
			{
				mylog(log_fatal,"unknown fd,this should never happen\n");
				myexit(-1);
			}
		}
	}
	return 0;
}

int server_event_loop()
{
	char buf[buf_len];

	int i, j, k;int ret;

	bind_address_uint32=local_ip_uint32;//only server has bind adress,client sets it to zero


	 if(raw_mode==mode_faketcp)
	 {
		 bind_fd=socket(AF_INET,SOCK_STREAM,0);
	 }
	 else  if(raw_mode==mode_udp||raw_mode==mode_icmp)//bind an adress to avoid collision,for icmp,there is no port,just bind a udp port
	 {
		 bind_fd=socket(AF_INET,SOCK_DGRAM,0);
	 }

	 struct sockaddr_in temp_bind_addr={0};
    // bzero(&temp_bind_addr, sizeof(temp_bind_addr));

     temp_bind_addr.sin_family = AF_INET;
     temp_bind_addr.sin_port = htons(local_port);
     temp_bind_addr.sin_addr.s_addr = local_ip_uint32;

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



	//init_raw_socket();
	init_filter(local_port);//bpf filter

	epollfd = epoll_create1(0);
	const int max_events = 4096;

	struct epoll_event ev, events[max_events];
	if (epollfd < 0) {
		mylog(log_fatal,"epoll return %d\n", epollfd);
		myexit(-1);
	}

	ev.events = EPOLLIN;
	ev.data.u64 = raw_recv_fd;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
	if (ret!= 0) {
		mylog(log_fatal,"add raw_fd error\n");
		myexit(-1);
	}
	int timer_fd;

	set_timer(epollfd,timer_fd);

	u64_t begin_time=0;
	u64_t end_time=0;

	mylog(log_info,"now listening at %s:%d\n",my_ntoa(local_ip_uint32),local_port);
	while(1)////////////////////////
	{

		if(about_to_exit) myexit(0);

		int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
		if (nfds < 0) {  //allow zero
			if(errno==EINTR  )
			{
				mylog(log_info,"epoll interrupted by signal\n");
				myexit(0);
			}
			else
			{
				mylog(log_fatal,"epoll_wait return %d\n", nfds);
				myexit(-1);
			}
		}
		int idx;
		for (idx = 0; idx < nfds; ++idx)
		{
			//mylog(log_debug,"ndfs:  %d \n",nfds);
			epoll_trigger_counter++;
			//printf("%d %d %d %d\n",timer_fd,raw_recv_fd,raw_send_fd,n);
			if ((events[idx].data.u64 ) == (u64_t)timer_fd)
			{
				if(debug_flag)begin_time=get_current_time();
				conn_manager.clear_inactive();
				u64_t dummy;
				read(timer_fd, &dummy, 8);
				//current_time_rough=get_current_time();
				if(debug_flag)
				{
					end_time=get_current_time();
					mylog(log_debug,"timer_fd,%llu,%llu,%llu\n",begin_time,end_time,end_time-begin_time);
				}

				mylog(log_trace,"epoll_trigger_counter:  %d \n",epoll_trigger_counter);
				epoll_trigger_counter=0;

			}
			else if (events[idx].data.u64 == (u64_t)raw_recv_fd)
			{
				if(debug_flag)begin_time=get_current_time();
				server_on_raw_recv_multi();
				if(debug_flag)
				{
					end_time=get_current_time();
					mylog(log_debug,"raw_recv_fd,%llu,%llu,%llu  \n",begin_time,end_time,end_time-begin_time);
				}
			}
			else if ((events[idx].data.u64 >>32u) == 2u)
			{
				if(debug_flag)begin_time=get_current_time();
				int fd=get_u64_l(events[idx].data.u64);
				u64_t dummy;
				read(fd, &dummy, 8);

				if(conn_manager.timer_fd_mp.find(fd)==conn_manager.timer_fd_mp.end()) //this can happen,when fd is a just closed fd
				{
					mylog(log_info,"timer_fd no longer exits\n");
					continue;
				}
				conn_info_t* p_conn_info=conn_manager.timer_fd_mp[fd];
				u32_t ip=p_conn_info->raw_info.recv_info.src_ip;
				u32_t port=p_conn_info->raw_info.recv_info.src_port;
				assert(conn_manager.exist(ip,port));//TODO remove this for peformance

				assert(p_conn_info->state.server_current_state == server_ready); //TODO remove this for peformance

				//conn_info_t &conn_info=conn_manager.find(ip,port);
				char ip_port[40];

				sprintf(ip_port,"%s:%d",my_ntoa(ip),port);

				server_on_timer_multi(*p_conn_info,ip_port);

				if(debug_flag)
				{
					end_time=get_current_time();
					mylog(log_debug,"(events[idx].data.u64 >>32u) == 2u ,%llu,%llu,%llu  \n",begin_time,end_time,end_time-begin_time);
				}
			}
			else if ((events[idx].data.u64 >>32u) == 1u)
			{
				//uint32_t conv_id=events[n].data.u64>>32u;

				if(debug_flag)begin_time=get_current_time();

				int fd=int((events[idx].data.u64<<32u)>>32u);

				if(conn_manager.udp_fd_mp.find(fd)==conn_manager.udp_fd_mp.end()) //this can happen,when fd is a just closed fd
				{
					mylog(log_debug,"fd no longer exists in udp_fd_mp,udp fd %d\n",fd);
					recv(fd,0,0,0);
					continue;
				}
				conn_info_t* p_conn_info=conn_manager.udp_fd_mp[fd];

				u32_t ip=p_conn_info->raw_info.recv_info.src_ip;
				u32_t port=p_conn_info->raw_info.recv_info.src_port;
				if(!conn_manager.exist(ip,port))//TODO remove this for peformance
				{
					mylog(log_fatal,"ip port no longer exits 2!!!this shouldnt happen\n");
					myexit(-1);
				}

				if(p_conn_info->state.server_current_state!=server_ready)//TODO remove this for peformance
				{
					mylog(log_fatal,"p_conn_info->state.server_current_state!=server_ready!!!this shouldnt happen\n");
					myexit(-1);
				}

				conn_info_t &conn_info=*p_conn_info;

				if(!conn_info.blob->conv_manager.is_u64_used(fd))
				{
					mylog(log_debug,"conv no longer exists,udp fd %d\n",fd);
					int recv_len=recv(fd,0,0,0); ///////////TODO ,delete this
					continue;
				}

				u32_t conv_id=conn_info.blob->conv_manager.find_conv_by_u64(fd);

				int recv_len=recv(fd,buf,max_data_len,0);

				mylog(log_trace,"received a packet from udp_fd,len:%d\n",recv_len);

				if(recv_len<0)
				{
					mylog(log_debug,"udp fd,recv_len<0 continue,%s\n",strerror(errno));

					continue;
				}

				if(recv_len>=mtu_warn)
				{
					mylog(log_warn,"huge packet,data len=%d (>=%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ",recv_len,mtu_warn);
				}

				//conn_info.conv_manager->update_active_time(conv_id);  server dosnt update from upd side,only update from raw side.  (client updates at both side)

				if(conn_info.state.server_current_state==server_ready)
				{
					send_data_safer(conn_info,buf,recv_len,conv_id);
					//send_data(g_packet_info_send,buf,recv_len,my_id,oppsite_id,conv_id);
					mylog(log_trace,"send_data_safer ,sent !!\n");
				}

				if(debug_flag)
				{
					end_time=get_current_time();
				    mylog(log_debug,"(events[idx].data.u64 >>32u) == 1u,%lld,%lld,%lld  \n",begin_time,end_time,end_time-begin_time);
				}
			}
			else
			{
				mylog(log_fatal,"unknown fd,this should never happen\n");
				myexit(-1);
			}

		}
	}
	return 0;
}
//char lower_level_arg[1000];
int process_lower_level_arg()
{
	lower_level=1;
	if(strcmp(optarg,"auto")==0)
	{
		if(program_mode==server_mode)
			return 0;
		else
		{
			mylog(log_fatal,"--lower-level auto hasnt be implement at client side,specify it manually\n");
			myexit(-1);
		}
	}

	lower_level_manual=1;
	if (strchr(optarg, '#') == 0) {
		mylog(log_fatal,
				"lower-level parameter invaild,check help page for format\n");
		myexit(-1);
	}
	lower_level = 1;
	u32_t hw[6];
	memset(hw, 0, sizeof(hw));
	sscanf(optarg, "%[^#]#%x:%x:%x:%x:%x:%x", if_name, &hw[0], &hw[1], &hw[2],
			&hw[3], &hw[4], &hw[5]);

	mylog(log_warn,
			"make sure this is correct:   if_name=<%s>  dest_mac_adress=<%02x:%02x:%02x:%02x:%02x:%02x>  \n",
			if_name, hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
	for (int i = 0; i < 6; i++) {
		dest_hw_addr[i] = uint8_t(hw[i]);
	}
	return 0;
}
void print_help()
{
	printf("udp2raw-tunnel\n");
	printf("version: %s %s\n",__DATE__,__TIME__);
	printf("repository: https://github.com/wangyu-/udp2raw-tunnel\n");
	printf("\n");
	printf("usage:\n");
	printf("    run as client : ./this_program -c -l local_listen_ip:local_port -r server_ip:server_port  [options]\n");
	printf("    run as server : ./this_program -s -l server_listen_ip:server_port -r remote_ip:remote_port  [options]\n");
	printf("\n");
	printf("common options,these options must be same on both side:\n");
	printf("    --raw-mode            <string>        avaliable values:faketcp(default),udp,icmp\n");
	printf("    -k,--key              <string>        password to gen symetric key,default:\"secret key\"\n");
	printf("    --cipher-mode         <string>        avaliable values:aes128cbc(default),xor,none\n");
	printf("    --auth-mode           <string>        avaliable values:md5(default),crc32,simple,none\n");
	printf("    -a,--auto-rule                        auto add (and delete) iptables rule\n");
	printf("    -g,--gen-rule                         generate iptables rule then exit,overrides -a\n");
	printf("    --disable-anti-replay                 disable anti-replay,not suggested\n");

	//printf("\n");
	printf("client options:\n");
	printf("    --source-ip           <ip>            force source-ip for raw socket\n");
	printf("    --source-port         <port>          force source-port for raw socket,tcp/udp only\n");
	printf("                                          this option disables port changing while re-connecting\n");
//	printf("                                          \n");
	printf("other options:\n");
	printf("    --log-level           <number>        0:never    1:fatal   2:error   3:warn \n");
	printf("                                          4:info (default)     5:debug   6:trace\n");
//	printf("\n");
	printf("    --log-position                        enable file name,function name,line number in log\n");
	printf("    --disable-color                       disable log color\n");
	printf("    --disable-bpf                         disable the kernel space filter,most time its not necessary\n");
	printf("                                          unless you suspect there is a bug\n");
//	printf("\n");
	printf("    --sock-buf            <number>        buf size for socket,>=10 and <=10240,unit:kbyte,default:1024\n");
	printf("    --seqmode             <number>        seq increase mode for faketcp:\n");
	printf("                                          0:dont increase\n");
	printf("                                          1:increase every packet(default)\n");
	printf("                                          2:increase randomly, about every 3 packets\n");
//	printf("\n");
	printf("    --lower-level         <string>        send packet at OSI level 2, format:'if_name#dest_mac_adress'\n");
	printf("                                          ie:'eth0#00:23:45:67:89:b9'.Beta.\n");
	printf("    --gen-add                             generate iptables rule and add it for you,then exit.overrides -g\n");
	printf("    --keep_rule                           monitor iptables and auto re-add if necessary.Implys -a\n");
	printf("    --clear                               clear any iptables rules added by this program.overrides everything\n");
	printf("    -h,--help                             print this help message\n");

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
		{"disable-anti-replay", no_argument,    0, 1},
		{"auto-rule", no_argument,    0, 'a'},
		{"gen-rule", no_argument,    0, 'g'},
		{"gen-add", no_argument,    0, 1},
		{"debug", no_argument,    0, 1},
		{"clear", no_argument,    0, 1},
		{"simple-rule", no_argument,    0, 1},
		{"keep-rule", no_argument,    0, 1},
		{"lower-level", required_argument,    0, 1},
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
	if (argc == 1)
	{
		print_help();
		myexit(-1);
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
		if(strcmp(argv[i],"--disable-color")==0)
		{
			enable_log_color=0;
		}
	}

    mylog(log_info,"argc=%d ", argc);

	for (i = 0; i < argc; i++) {
		log_bare(log_info, "%s ", argv[i]);
	}
	log_bare(log_info, "\n");



	int no_l = 1, no_r = 1;
	while ((opt = getopt_long(argc, argv, "l:r:schk:ag",long_options,&option_index)) != -1) {
		//string opt_key;
		//opt_key+=opt;
		switch (opt) {
		case 'l':
			no_l = 0;
			if (strchr(optarg, ':') != 0) {
				sscanf(optarg, "%[^:]:%d", local_ip, &local_port);
				if(local_port==22)
				{
					mylog(log_fatal,"port 22 not allowed\n");
					myexit(-1);
				}
			} else {
				mylog(log_fatal,"invalid parameter for -l ,%s,should be ip:port\n",optarg);
				myexit(-1);

			}
			break;
		case 'r':
			no_r = 0;
			if (strchr(optarg, ':') != 0) {
				sscanf(optarg, "%[^:]:%d", remote_ip, &remote_port);
				if(remote_port==22)
				{
					mylog(log_fatal,"port 22 not allowed\n");
					myexit(-1);
				}
			} else {
				mylog(log_fatal,"invalid parameter for -r ,%s,should be ip:port\n",optarg);
				myexit(-1);
			}
			break;
		case 's':
			if(program_mode==0)
			{
				program_mode=server_mode;
			}
			else
			{
				mylog(log_fatal,"-s /-c has already been set,conflict\n");
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
				mylog(log_fatal,"-s /-c has already been set,conflict\n");
				myexit(-1);
			}
			break;
		case 'h':
			break;
		case 'a':
			auto_add_iptables_rule=1;
			break;
		case 'g':
			generate_iptables_rule=1;
			break;
		case 'k':
			mylog(log_debug,"parsing key option\n");
			sscanf(optarg,"%s",key_string);
			break;
		case 1:
			mylog(log_debug,"option_index: %d\n",option_index);
			if(strcmp(long_options[option_index].name,"clear")==0)
			{
				char *output;
				//int ret =system("iptables-save |grep udp2raw_dWRwMnJhdw|sed -n 's/^-A/iptables -D/p'|sh");
				int ret =run_command("iptables -S|sed -n '/udp2rawDwrW/p'|sed -n 's/^-A/iptables -D/p'|sh",output);

				int ret2 =run_command("iptables -S|sed -n '/udp2rawDwrW/p'|sed -n 's/^-N/iptables -X/p'|sh",output);
				//system("iptables-save |grep udp2raw_dWRwMnJhdw|sed 's/^-A/iptables -D/'|sh");
				//system("iptables-save|grep -v udp2raw_dWRwMnJhdw|iptables-restore");
				mylog(log_info,"tried to clear all iptables rule created previously,return value %d %d\n",ret,ret2);
				myexit(-1);
			}
			else if(strcmp(long_options[option_index].name,"source-ip")==0)
			{
				mylog(log_debug,"parsing long option :source-ip\n");
				sscanf(optarg, "%s", source_ip);
				mylog(log_debug,"source: %s\n",source_ip);
				force_source_ip=1;
			}
			else if(strcmp(long_options[option_index].name,"source-port")==0)
			{
				mylog(log_debug,"parsing long option :source-port\n");
				sscanf(optarg, "%d", &source_port);
				mylog(log_info,"source: %d\n",source_port);
			}
			else if(strcmp(long_options[option_index].name,"raw-mode")==0)
			{
				for(i=0;i<mode_end;i++)
				{
					if(strcmp(optarg,raw_mode_tostring[i])==0)
					{
						//printf("%d i\n",i);
						//printf("%s",raw_mode_tostring[i]);
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
					if(strcmp(optarg,auth_mode_tostring[i])==0)
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
					if(strcmp(optarg,cipher_mode_tostring[i])==0)
					{
						cipher_mode=(cipher_mode_t)i;
						break;
					}
				}
				if(i==cipher_end)
				{

					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"log-level")==0)
			{
			}
			else if(strcmp(long_options[option_index].name,"lower-level")==0)
			{
				process_lower_level_arg();
				//lower_level=1;
				//strcpy(lower_level_arg,optarg);
			}
			else if(strcmp(long_options[option_index].name,"simple-rule")==0)
			{
				simple_rule=1;
			}
			else if(strcmp(long_options[option_index].name,"keep-rule")==0)
			{
				keep_rule=1;
			}
			else if(strcmp(long_options[option_index].name,"gen-add")==0)
			{
				generate_iptables_rule_add=1;
			}
			else if(strcmp(long_options[option_index].name,"disable-color")==0)
			{
				//enable_log_color=0;
			}
			else if(strcmp(long_options[option_index].name,"debug")==0)
			{
				debug_flag=1;
				//enable_log_color=0;
			}
			else if(strcmp(long_options[option_index].name,"debug-resend")==0)
			{
				//debug_resend=1;
				//enable_log_color=0;
			}
			else if(strcmp(long_options[option_index].name,"log-position")==0)
			{
				enable_log_position=1;
			}
			else if(strcmp(long_options[option_index].name,"disable-bpf")==0)
			{
				disable_bpf_filter=1;
			}
			else if(strcmp(long_options[option_index].name,"disable-anti-replay")==0)
			{
				disable_anti_replay=1;
			}
			else if(strcmp(long_options[option_index].name,"sock-buf")==0)
			{
				int tmp=-1;
				sscanf(optarg,"%d",&tmp);
				if(10<=tmp&&tmp<=10*1024)
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
				if(0<=seq_mode&&seq_mode<=2)
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
			mylog(log_fatal,"unknown option ,code:<%c>,<%x>\n",optopt, optopt);
			myexit(-1);
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
	//if(lower_level)
		//process_lower_level_arg();

	 mylog(log_info,"important variables: ");

	 log_bare(log_info,"log_level=%d:%s ",log_level,log_text[log_level]);
	 log_bare(log_info,"raw_mode=%s ",raw_mode_tostring[raw_mode]);
	 log_bare(log_info,"cipher_mode=%s ",cipher_mode_tostring[cipher_mode]);
	 log_bare(log_info,"auth_mode=%s ",auth_mode_tostring[auth_mode]);

	 log_bare(log_info,"key=%s ",key_string);

	 log_bare(log_info,"local_ip=%s ",local_ip);
	 log_bare(log_info,"local_port=%d ",local_port);
	 log_bare(log_info,"remote_ip=%s ",remote_ip);
	 log_bare(log_info,"remote_port=%d ",remote_port);
	 log_bare(log_info,"source_ip=%s ",source_ip);
	 log_bare(log_info,"source_port=%d ",source_port);

	 log_bare(log_info,"socket_buf_size=%d ",socket_buf_size);

	 log_bare(log_info,"\n");
}

void *run_keep(void *none)
{

	while(1)
	{
		sleep(10);
		keep_iptables_rule();
		if(about_to_exit)   //just incase it runs forever if there is some bug,not necessary
		{
			sleep(10);
			keep_thread_running=0; //not thread safe ,but wont cause problem
			break;
		}
	}
	return NULL;

}
void iptables_rule()
{
	if(auto_add_iptables_rule&&generate_iptables_rule)
	{
		mylog(log_warn," -g overrides -a\n");
		auto_add_iptables_rule=0;
		//myexit(-1);
	}
	if(generate_iptables_rule_add&&generate_iptables_rule)
	{
		mylog(log_warn," --gen-add overrides -g\n");
		generate_iptables_rule=0;
		//myexit(-1);
	}

	if(keep_rule&&auto_add_iptables_rule==0)
	{
		auto_add_iptables_rule=1;
		mylog(log_warn," --keep_rule implys -a\n");
		generate_iptables_rule=0;
		//myexit(-1);
	}
	char tmp_pattern[200];
	string pattern="";

	if(program_mode==client_mode)
	{
		if(raw_mode==mode_faketcp)
		{
			sprintf(tmp_pattern,"-s %s/32 -p tcp -m tcp --sport %d",remote_ip,remote_port);
		}
		if(raw_mode==mode_udp)
		{
			sprintf(tmp_pattern,"-s %s/32 -p udp -m udp --sport %d",remote_ip,remote_port);
		}
		if(raw_mode==mode_icmp)
		{
			sprintf(tmp_pattern,"-s %s/32 -p icmp",remote_ip);
		}
		pattern=tmp_pattern;
	}
	if(program_mode==server_mode)
	{

		if(raw_mode==mode_faketcp)
		{
			sprintf(tmp_pattern,"-p tcp -m tcp --dport %d",local_port);
		}
		if(raw_mode==mode_udp)
		{
			sprintf(tmp_pattern,"-p udp -m udp --dport %d",local_port);
		}
		if(raw_mode==mode_icmp)
		{
			if(local_ip_uint32==0)
			{
				sprintf(tmp_pattern,"-p icmp");
			}
			else
			{
				sprintf(tmp_pattern,"-d %s/32 -p icmp",local_ip);
			}
		}
		pattern=tmp_pattern;
	}
/*
	if(!simple_rule)
	{
		pattern += " -m comment --comment udp2rawDwrW_";

		char const_id_str[100];
		sprintf(const_id_str, "%x_", const_id);

		pattern += const_id_str;

		time_t timer;
		char buffer[26];
		struct tm* tm_info;

		time(&timer);
		tm_info = localtime(&timer);

		strftime(buffer, 26, "%Y-%m-%d-%H:%M:%S", tm_info);

		pattern += buffer;


	}*/

	if(auto_add_iptables_rule)
	{
		iptables_rule_init(pattern.c_str(),const_id,keep_rule);
		if(keep_rule)
		{
			if(pthread_create(&keep_thread, NULL, run_keep, 0)) {

				mylog(log_fatal, "Error creating thread\n");
				myexit(-1);
			}
			keep_thread_running=1;
		}
	}
	if(generate_iptables_rule)
	{
		string rule="iptables -I ";
		rule+=pattern;
		rule+=" -j DROP";

		printf("generated iptables rule:\n");
		printf("%s\n",rule.c_str());
		myexit(0);
	}
	if(generate_iptables_rule_add)
	{
		iptables_gen_add(pattern.c_str(),const_id);
		myexit(0);
	}


}
/*
int test()
{

	 int fd;
	 struct ifreq ifr;

	 fd = socket(AF_INET, SOCK_DGRAM, 0);

	 ifr.ifr_addr.sa_family = AF_INET;

	 strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);

	 ioctl(fd, SIOCGIFADDR, &ifr);

	 close(fd);

	 printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	 return 0;
}*/
int main(int argc, char *argv[])
{
	printf("%s\n",my_ntoa(0x00ffffff));
	//auto a=string_to_vec("a b c d ");
	//printf("%d\n",(int)a.size());
	//printf("%d %d %d %d",larger_than_u32(1,2),larger_than_u32(2,1),larger_than_u32(0xeeaaeebb,2),larger_than_u32(2,0xeeaaeebb));
	//assert(0==1);
	dup2(1, 2);//redirect stderr to stdout
	signal(SIGINT, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGKILL, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGQUIT, signal_handler);

	process_arg(argc,argv);

	if(geteuid() != 0)
	{
		mylog(log_error,"root check failed,make sure you run this program with root,we can try to continue,but it will likely fail\n");
	}

	local_ip_uint32=inet_addr(local_ip);
	remote_ip_uint32=inet_addr(remote_ip);
	source_ip_uint32=inet_addr(source_ip);


	//current_time_rough=get_current_time();

	init_random_number_fd();
	srand(get_true_random_number_nz());
	const_id=get_true_random_number_nz();

	mylog(log_info,"const_id:%x\n",const_id);

	char tmp[1000]="";

	strcat(tmp,key_string);

	strcat(tmp,"key1");

	md5((uint8_t*)tmp,strlen(tmp),(uint8_t*)key);

	/*
	tmp[0]=0;

	strcat(tmp,key_string);

	strcat(tmp,"key2");

	md5((uint8_t*)tmp,strlen(tmp),(uint8_t*)key2);*/

	iptables_rule();
	init_raw_socket();
	if(lower_level_manual)
	{
		init_ifindex(if_name);
	}

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
