#include "common.h"
#include "network.h"
#include "log.h"
#include "md5.h"

char local_address[100]="0.0.0.0", remote_address[100]="255.255.255.255",source_address[100]="0.0.0.0";
uint32_t local_address_uint32,remote_address_uint32,source_address_uint32;
int source_port=0,local_port = -1, remote_port = -1;

id_t const_id=0;


const int disable_conv_clear=0;
const int disable_conn_clear=0;


enum server_current_state_t {server_nothing=0,server_syn_ack_sent,server_handshake_sent,server_ready};
enum client_current_state_t {client_nothing=0,client_syn_sent,client_ack_sent,client_handshake_sent,client_ready};
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

char key_string[1000]= "secret key";
char key[16],key2[16];

uint64_t current_time_rough=0;


int VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV;
////////==============================variable divider=============================================================

struct anti_replay_t
{
	uint64_t max_packet_received;
	char window[anti_replay_window_size];
	char disabled;
	anti_replay_seq_t anti_replay_seq;
	anti_replay_seq_t get_new_seq_for_send()
	{
		return anti_replay_seq++;
	}
	anti_replay_t()
	{
		disabled=0;
		max_packet_received=0;
		anti_replay_seq=get_true_random_number();
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
				for (uint32_t i=max_packet_received+1;i<seq;i++)
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
};//anti_replay;

void server_clear_function(uint64_t u64);
struct conv_manager_t  //TODO change map to unordered map
{
	//typedef hash_map map;
	unordered_map<uint64_t,uint32_t> u64_to_conv;  //conv and u64 are both supposed to be uniq
	unordered_map<uint32_t,uint64_t> conv_to_u64;

	unordered_map<uint32_t,uint64_t> conv_last_active_time;

	unordered_map<uint32_t,uint64_t>::iterator clear_it;

	unordered_map<uint32_t,uint64_t>::iterator it;
	unordered_map<uint32_t,uint64_t>::iterator old_it;

	//void (*clear_function)(uint64_t u64) ;


	conv_manager_t()
	{
		clear_it=conv_last_active_time.begin();
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
	uint32_t get_new_conv()
	{
		uint32_t conv=get_true_random_number_nz();
		while(conv_to_u64.find(conv)!=conv_to_u64.end())
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
		return conv_last_active_time[conv]=current_time_rough;
	}
	int insert_conv(uint32_t conv,uint64_t u64)
	{
		u64_to_conv[u64]=conv;
		conv_to_u64[conv]=u64;
		conv_last_active_time[conv]=current_time_rough;
		return 0;
	}
	int erase_conv(uint32_t conv)
	{
		if(disable_conv_clear) return 0;
		uint64_t u64=conv_to_u64[conv];
		if(program_mode==server_mode)
		{
			server_clear_function(u64);
		}
		conv_to_u64.erase(conv);
		u64_to_conv.erase(u64);
		conv_last_active_time.erase(conv);
		mylog(log_info,"conv %x cleared\n",conv);
		return 0;
	}
	int clear_inactive()
	{
		if(disable_conv_clear) return 0;


		//map<uint32_t,uint64_t>::iterator it;
		int cnt=0;
		it=clear_it;
		int size=conv_last_active_time.size();
		int num_to_clean=size/conv_clear_ratio+conv_clear_min;   //clear 1/10 each time,to avoid latency glitch

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
				//mylog(log_info,"inactive conv %u cleared \n",it->first);
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
};//g_conv_manager;

struct conn_info_t
{
	current_state_t state;

	raw_info_t raw_info;
	long long last_state_time;
	long long last_hb_sent_time;  //client re-use this for retry
	long long last_hb_recv_time;
	id_t my_id;
	id_t oppsite_id;

	conv_manager_t *conv_manager;
	anti_replay_t *anti_replay;
	int timer_fd;
	id_t oppsite_const_id;
	conn_info_t()
	{
		//send_packet_info.protocol=g_packet_info_send.protocol;
		if(program_mode==server_mode)
			state.server_current_state=server_nothing;
		else
			state.client_current_state=client_nothing;
		last_state_time=0;
		oppsite_const_id=0;
		conv_manager=0;
		anti_replay=0;
		timer_fd=0;
	}
	void prepare()
	{
		conv_manager=new conv_manager_t;
		anti_replay=new anti_replay_t;
	}
	conn_info_t(const conn_info_t&b)
	{
		//mylog(log_error,"called!!!!!!!!!!!!!\n");
		*this=b;
		if(conv_manager!=0)
		{
			conv_manager=new conv_manager_t(*b.conv_manager);
		}
		if(anti_replay!=0)
		{
			anti_replay=new anti_replay_t(*b.anti_replay);
		}
	}
	conn_info_t& operator=(const conn_info_t& b)
	  {
		mylog(log_fatal,"not allowed\n");
		exit(-1);
	    return *this;
	  }
	~conn_info_t();
};//g_conn_info;

struct conn_manager_t
{

 uint32_t ready_num;

 unordered_map<int,conn_info_t *> udp_fd_mp;  //a bit dirty to used pointer,but can void unordered_map search
 unordered_map<int,conn_info_t *> timer_fd_mp;//we can use pointer here since unordered_map.rehash() uses shallow copy

 unordered_map<id_t,conn_info_t *> const_id_mp;

 unordered_map<uint64_t,conn_info_t*> mp; //put it at end so that it de-consturcts first

 unordered_map<uint64_t,conn_info_t*>::iterator clear_it;

 conn_manager_t()
 {
	 ready_num=0;
	 mp.reserve(10007);
	 clear_it=mp.begin();
	 timer_fd_mp.reserve(10007);
	 const_id_mp.reserve(10007);
	 udp_fd_mp.reserve(100007);
	 //current_ready_ip=0;
	// current_ready_port=0;
 }
 int exist(uint32_t ip,uint16_t port)
 {
	 uint64_t u64=0;
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
 conn_info_t *& find_insert_p(uint32_t ip,uint16_t port)  //be aware,the adress may change after rehash
 {
	 uint64_t u64=0;
	 u64=ip;
	 u64<<=32u;
	 u64|=port;
	 unordered_map<uint64_t,conn_info_t*>::iterator it=mp.find(u64);
	 if(it==mp.end())
	 {
		 mp[u64]=new conn_info_t;
	 }
	 return mp[u64];
 }
 conn_info_t & find_insert(uint32_t ip,uint16_t port)  //be aware,the adress may change after rehash
 {
	 uint64_t u64=0;
	 u64=ip;
	 u64<<=32u;
	 u64|=port;
	 unordered_map<uint64_t,conn_info_t*>::iterator it=mp.find(u64);
	 if(it==mp.end())
	 {
		 mp[u64]=new conn_info_t;
	 }
	 return *mp[u64];
 }
 int erase(unordered_map<uint64_t,conn_info_t*>::iterator erase_it)
 {
		if(erase_it->second->state.server_current_state==server_ready)
		{
			ready_num--;
			assert(int32_t(ready_num)!=-1);
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
			assert(erase_it->second->anti_replay==0);
			assert(erase_it->second->conv_manager==0);
			assert(erase_it->second->timer_fd ==0);
			assert(erase_it->second->oppsite_const_id==0);
		}
		return 0;
 }
int clear_inactive()
{
	 unordered_map<uint64_t,conn_info_t*>::iterator it;
	 unordered_map<uint64_t,conn_info_t*>::iterator old_it;

	if(disable_conn_clear) return 0;

	//map<uint32_t,uint64_t>::iterator it;
	int cnt=0;
	it=clear_it;
	int size=mp.size();
	int num_to_clean=size/conn_clear_ratio+conn_clear_min;   //clear 1/10 each time,to avoid latency glitch

	uint64_t current_time=get_current_time();
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
		else if(it->second->conv_manager!=0&&it->second->conv_manager->get_size() >0)
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
			assert(conv_manager!=0);
			assert(anti_replay!=0);
			assert(oppsite_const_id!=0);
			//assert(conn_manager.const_id_mp.find(oppsite_const_id)!=conn_manager.const_id_mp.end()); // conn_manager 's deconstuction function  erases it
		}
		else
		{
			assert(conv_manager==0);
			assert(anti_replay==0);
			assert(oppsite_const_id==0);
		}
	}
	//if(oppsite_const_id!=0)     //do this at conn_manager 's deconstuction function
		//conn_manager.const_id_mp.erase(oppsite_const_id);
	if(conv_manager!=0)
		delete conv_manager;
	if(anti_replay!=0)
		delete anti_replay;

	//send_packet_info.protocol=g_packet_info_send.protocol;
}

int TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT;
////////==========================type divider=======================================================


/*
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
}*/


void server_clear_function(uint64_t u64)
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
		exit(-1);  //this shouldnt happen
	}
	//mylog(log_fatal,"size:%d !!!!\n",conn_manager.udp_fd_mp.size());
	assert(conn_manager.udp_fd_mp.find(fd)!=conn_manager.udp_fd_mp.end());
	conn_manager.udp_fd_mp.erase(fd);
}




int send_bare(raw_info_t &raw_info,const char* data,int len)
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;

	char send_data_buf[buf_len];  //buf for send data and send hb
	char send_data_buf2[buf_len];

	if(len==0) //dont encrpyt zero length packet;
	{
		send_raw(raw_info,data,len);
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
	send_raw(raw_info,send_data_buf2,new_len);
	return 0;
}
int parse_bare(const char *input,int input_len,char* & data,int & len)  //allow overlap
{
	static char recv_data_buf[buf_len];
	if(len==0) //dont decrpyt zero length packet;
	{
		return 0;
	}

	if(my_decrypt(input,recv_data_buf,input_len,key)!=0)
	{
		mylog(log_debug,"decrypt_fail in recv bare\n");
		return -1;
	}
	len=input_len;
	data=recv_data_buf+sizeof(iv_t);
	len-=sizeof(iv_t);
	return 0;
}
int recv_bare(raw_info_t &raw_info,char* & data,int & len)
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;

	if(recv_raw(raw_info,data,len)<0)
	{
		//printf("recv_raw_fail in recv bare\n");
		return -1;
	}
	parse_bare(data,len,data,len);
	return 0;
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

int send_safer(conn_info_t &conn_info,const char* data,int len)
{

	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;


	char send_data_buf[buf_len];  //buf for send data and send hb
	char send_data_buf2[buf_len];

	id_t n_tmp_id=htonl(conn_info.my_id);

	memcpy(send_data_buf,&n_tmp_id,sizeof(n_tmp_id));

	n_tmp_id=htonl(conn_info.oppsite_id);

	memcpy(send_data_buf+sizeof(n_tmp_id),&n_tmp_id,sizeof(n_tmp_id));

	anti_replay_seq_t n_seq=hton64(conn_info.anti_replay->get_new_seq_for_send());

	memcpy(send_data_buf+sizeof(n_tmp_id)*2,&n_seq,sizeof(n_seq));


	memcpy(send_data_buf+sizeof(n_tmp_id)*2+sizeof(n_seq),data,len);//data;

	int new_len=len+sizeof(n_seq)+sizeof(n_tmp_id)*2;

	if(my_encrypt(send_data_buf,send_data_buf2,new_len,key2)!=0)
	{
		return -1;
	}

	send_raw(conn_info.raw_info,send_data_buf2,new_len);

	return 0;
}
int send_data_safer(conn_info_t &conn_info,const char* data,int len,uint32_t conv_num)
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;

	char send_data_buf[buf_len];
	send_data_buf[0]='d';
	uint32_t n_conv_num=htonl(conv_num);
	memcpy(send_data_buf+1,&n_conv_num,sizeof(n_conv_num));

	memcpy(send_data_buf+1+sizeof(n_conv_num),data,len);
	int new_len=len+1+sizeof(n_conv_num);
	send_safer(conn_info,send_data_buf,new_len);
	return 0;

}
int parse_safer(conn_info_t &conn_info,const char * input,int input_len,char* &data,int &len)//allow overlap
{
	 static char recv_data_buf0[buf_len];

	 char *recv_data_buf=recv_data_buf0; //fix strict alias warning
	if(my_decrypt(input,recv_data_buf,input_len,key2)!=0)
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
		mylog(log_warn,"id and oppsite_id verification failed %x %x %x %x \n",h_oppiste_id,conn_info.oppsite_id,h_my_id,conn_info.my_id);
		return -1;
	}

	if (conn_info.anti_replay->is_vaild(h_seq) != 1) {
		mylog(log_warn,"dropped replay packet\n");
		return -1;
	}

	//printf("recv _len %d\n ",recv_len);
	data=recv_data_buf+sizeof(anti_replay_seq_t)+sizeof(id_t)*2;
	len=input_len-(sizeof(anti_replay_seq_t)+sizeof(id_t)*2  );


	if(len<0)
	{
		mylog(log_error,"len <0 ,%d\n",len);
		return -1;
	}

	return 0;
}
int recv_safer(conn_info_t &conn_info,char* &data,int &len)
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;

	char * recv_data;int recv_len;
	static char recv_data_buf[buf_len];

	if(recv_raw(conn_info.raw_info,recv_data,recv_len)!=0) return -1;

	return parse_safer(conn_info,recv_data,recv_len,data,len);
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
	int raw_send_port=10000+get_true_random_number()%(65535-10000);
	for(int i=0;i<1000;i++)//try 1000 times at max,this should be enough
	{
		if (try_to_list_and_bind(raw_send_port)==0)
		{
			return raw_send_port;
		}
	}
	mylog(log_fatal,"bind port fail\n");
	exit(-1);
	return -1;////for compiler check
}

int keep_connection_client(conn_info_t &conn_info) //for client
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;
	current_time_rough=get_current_time();
	conn_info.conv_manager->clear_inactive();
	mylog(log_trace,"timer!\n");
	//begin:

	if(conn_info.state.client_current_state==client_nothing)
	{
		fail_time_counter++;
		if(fail_time_counter>max_fail_time)
		{
			mylog(log_fatal,"max_fail_time exceed");
			exit(-1);
		}

		conn_info.anti_replay->re_init(); //  this is not safe

		if(raw_mode==mode_icmp)
		{
			remove_filter();
		}

		if(source_port==0)
		{
			send_info.src_port = client_bind_to_a_new_port();
		}
		else
		{
			send_info.src_port=source_port;
		}

		if(raw_mode==mode_icmp)
		{
			send_info.dst_port =send_info.src_port ;
		}
		mylog(log_info,"using port %d\n", send_info.src_port);


		init_filter(send_info.src_port);

		if(raw_mode==mode_faketcp)
		{
			conn_info.state.client_current_state = client_syn_sent;
			conn_info.last_state_time = get_current_time();
			mylog(log_info,"state changed from nothing to syn_sent %d\n",conn_info.state.client_current_state);
			conn_info.last_hb_sent_time=conn_info.last_state_time;

			send_info.seq = get_true_random_number();
			send_info.ack_seq = get_true_random_number();
			send_info.ts_ack = 0;
			send_info.ack = 0;
			send_info.syn = 1;
			send_info.psh = 0;

			send_bare(raw_info, 0, 0);   /////////////send
		}
		else if(raw_mode==mode_udp||raw_mode==mode_icmp)
		{
			conn_info.state.client_current_state = client_ack_sent;
			conn_info.last_state_time = get_current_time();
			mylog(log_info,"state changed from nothing to ack_sent\n");
			conn_info.last_hb_sent_time=conn_info.last_state_time;

			send_info.icmp_seq=0;

			send_bare(raw_info, (char*)"hello", strlen("hello"));/////////////send

		}
		return 0;
	}
	if(conn_info.state.client_current_state==client_syn_sent  )
	{
		if(get_current_time()-conn_info.last_state_time>client_handshake_timeout)
		{
			conn_info.state.client_current_state=client_nothing;
			mylog(log_info,"state back to nothing\n");
			return 0;
		}
		else if(get_current_time()-conn_info.last_hb_sent_time>client_retry_interval)
		{
			mylog(log_info,"retry send sync\n");
			send_bare(raw_info,0,0); /////////////send
			conn_info.last_hb_sent_time=get_current_time();
		}
	}
	if(conn_info.state.client_current_state==client_ack_sent)
	{
		if(get_current_time()-conn_info.last_state_time>client_handshake_timeout)
		{
			conn_info.state.client_current_state=client_nothing;
			mylog(log_info,"state back to nothing\n");
			return 0;

		}
		else if(get_current_time()-conn_info.last_hb_sent_time>client_retry_interval)
		{
			if(raw_mode==mode_faketcp)
			{
				send_bare(raw_info,0,0);/////////////send
			}
			else if(raw_mode==mode_udp||raw_mode==mode_icmp)
			{
				send_bare(raw_info, (char*)"hello", strlen("hello"));/////////////send
			}
			conn_info.last_hb_sent_time=get_current_time();
			mylog(log_info,"retry send ack \n");
		}
	}
	if(conn_info.state.client_current_state==client_handshake_sent)
	{
		if(get_current_time()-conn_info.last_state_time>client_handshake_timeout)
		{
			conn_info.state.client_current_state=client_nothing;
			mylog(log_info,"state back to nothing\n");
			return 0;
		}
		else
		{
			send_handshake(raw_info,conn_info.my_id,conn_info.oppsite_id,const_id);/////////////send
			conn_info.last_hb_sent_time=get_current_time();
			mylog(log_info,"retry handshake sent <%x,%x>\n",conn_info.oppsite_id,conn_info.my_id);

		}


	}

	if(conn_info.state.client_current_state==client_ready)
	{
		mylog(log_trace,"time %lld %lld\n",get_current_time(),conn_info.last_state_time);
		if(get_current_time()-conn_info.last_hb_recv_time>client_conn_timeout)
		{
			conn_info.state.client_current_state=client_nothing;
			conn_info.my_id=get_true_random_number_nz();
			mylog(log_info,"state back to nothing\n");
			return 0;
		}

		if(get_current_time()-conn_info.last_hb_sent_time<heartbeat_interval)
		{
			return 0;
		}

		mylog(log_trace,"heartbeat sent <%x,%x>\n",conn_info.oppsite_id,conn_info.my_id);

		send_safer(conn_info,(char *)"h",1);/////////////send

		conn_info.last_hb_sent_time=get_current_time();
	}
	return 0;

}
int keep_connection_server_multi(conn_info_t &conn_info)
{
	mylog(log_trace,"server timer!\n");
	raw_info_t &raw_info=conn_info.raw_info;

	assert(conn_info.state.server_current_state==server_ready);

	if(conn_info.state.server_current_state==server_ready)
	{
		conn_info.conv_manager->clear_inactive();
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

		send_safer(conn_info,(char *)"h",1);  /////////////send

		conn_info.last_hb_sent_time=get_current_time();

		mylog(log_trace,"heart beat sent<%x,%x>\n",conn_info.my_id,conn_info.oppsite_id);
	}
	else
	{
		mylog(log_fatal,"this shouldnt happen!\n");
		exit(-1);
	}
	return 0;

}
/*
int keep_connection_server()
{
	current_time_rough=get_current_time();
	conv_manager.clean_inactive();
	//begin:
	mylog(log_trace,"timer!\n");
	if(server_current_state==server_nothing)
	{
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
*/
int set_timer(int epollfd,int &timer_fd)
{
	int ret;
	epoll_event ev;

	itimerspec its;
	memset(&its,0,sizeof(its));

	if((timer_fd=timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK)) < 0)
	{
		mylog(log_fatal,"timer_fd create error\n");
		exit(1);
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
		exit(-1);
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
		exit(1);
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
		exit(-1);
	}
	return 0;
}

int client_on_raw_recv(conn_info_t &conn_info)
{
	char* data;int data_len;
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;

	raw_info_t &raw_info=conn_info.raw_info;


	if(conn_info.state.client_current_state==client_nothing )
	{
		recv_raw(raw_info,data,data_len);//todo change it to something else faster
	}
	if(conn_info.state.client_current_state==client_syn_sent )
	{

		if(recv_bare(raw_info,data,data_len)!=0)
		{
			mylog(log_debug,"recv_bare failed!\n");
			return -1;
		}

		if (raw_mode==mode_faketcp&&!(recv_info.syn==1&&recv_info.ack==1&&data_len==0))
		{
			mylog(log_debug,"%d %d %d \n",recv_info.syn,recv_info.ack,data_len);
		}

		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_debug,"unexpected adress %x %x %d %d\n",recv_info.src_ip,send_info.dst_ip,recv_info.src_port,send_info.dst_port);
			return 0;
		}

		send_info.ack_seq=recv_info.seq+1;
		send_info.psh=0;
		send_info.syn=0;
		send_info.ack=1;
		send_info.seq+=1;

		mylog(log_info,"sent ack back\n");


		send_raw(raw_info,0,0);
		conn_info.state.client_current_state=client_ack_sent;
		conn_info.last_state_time=get_current_time();
		conn_info.last_hb_sent_time=conn_info.last_state_time;

		mylog(log_info,"changed state to client_ack_sent\n");
	}
	if(conn_info.state.client_current_state==client_ack_sent )
	{

		if(recv_bare(raw_info,data,data_len)!=0)
		{
			mylog(log_debug,"recv_bare failed!\n");
			return -1;
		}

		if(raw_mode==mode_faketcp&& (recv_info.syn==1||recv_info.ack!=1 ||data_len==0))
		{
			mylog(log_debug,"unexpected syn ack or other zero lenght packet\n");
			return 0;
		}
		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_debug,"unexpected adress %x %x %d %d\n",recv_info.src_ip,send_info.dst_ip,recv_info.src_port,send_info.dst_port);
			return 0;
		}

		/*
		if(data_len<hb_length||data[0]!='h')
		{
			printf("not a heartbeat\n");
			return 0;
		}*/


		conn_info.oppsite_id=  ntohl(* ((uint32_t *)&data[0]));

		mylog(log_info,"handshake received %x\n",conn_info.oppsite_id);
		mylog(log_info,"changed state to client_handshake_sent\n");
		send_handshake(raw_info,conn_info.my_id,conn_info.oppsite_id,const_id);

		mylog(log_info,"<<handshake sent %x %d>>\n",conn_info.my_id,conn_info.oppsite_id);

		conn_info.state.client_current_state=client_handshake_sent;
		conn_info.last_state_time=get_current_time();
		conn_info.last_hb_sent_time=conn_info.last_state_time;
	}
	if(conn_info.state.client_current_state==client_handshake_sent)
	{


		if(recv_safer(conn_info,data,data_len)!=0)
		{
			return -1;
		}

		if((raw_mode==mode_faketcp&&( recv_info.syn==1||recv_info.ack!=1 ) )||data_len==0  )
		{
			mylog(log_trace,"unexpected syn ack or other zero lenght packet\n");
			return 0;
		}
		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
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
		conn_info.state.client_current_state=client_ready;
		fail_time_counter=0;
		conn_info.last_state_time=get_current_time();
		conn_info.last_hb_recv_time=get_current_time();
	}

	if(conn_info.state.client_current_state==client_ready )
	{


		if(recv_safer(conn_info,data,data_len)!=0)
		{
			return -1;
		}

		if((raw_mode==mode_faketcp&&( recv_info.syn==1||recv_info.ack!=1) )||data_len==0)
		{
			mylog(log_debug,"unexpected syn ack\n");
			return 0;
		}
		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_debug,"unexpected adress\n");
			return 0;
		}

		if(data_len==1&&data[0]=='h')
		{
			mylog(log_debug,"[hb]heart beat received\n");
			conn_info.last_hb_recv_time=current_time_rough;
			return 0;
		}
		else if(data_len>= int( sizeof(uint32_t)+1 )&&data[0]=='d')
		{
			mylog(log_trace,"received a data from fake tcp,len:%d\n",data_len);

			conn_info.last_hb_recv_time=current_time_rough;

			uint32_t tmp_conv_id= ntohl(* ((uint32_t *)&data[1]));

			if(!conn_info.conv_manager->is_conv_used(tmp_conv_id))
			{
				mylog(log_info,"unknow conv %d,ignore\n",tmp_conv_id);
				return 0;
			}

			conn_info.conv_manager->update_active_time(tmp_conv_id);

			uint64_t u64=conn_info.conv_manager->find_u64_by_conv(tmp_conv_id);


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
int server_on_raw_ready(conn_info_t &conn_info)
{
	int data_len; char *data;

	raw_info_t &raw_info = conn_info.raw_info;
	packet_info_t &send_info = conn_info.raw_info.send_info;
	packet_info_t &recv_info = conn_info.raw_info.recv_info;
	char ip_port[40];

	sprintf(ip_port,"%s:%d",my_ntoa(recv_info.src_ip),recv_info.src_port);
	if (recv_safer(conn_info, data, data_len) != 0) {
		return -1;
	}

	if ((raw_mode == mode_faketcp && (recv_info.syn == 1 || recv_info.ack != 1))|| data_len == 0)
	{
		//recv(raw_recv_fd, 0,0, 0  );//
		return 0;
	}

	if (recv_info.src_ip != send_info.dst_ip
			|| recv_info.src_port != send_info.dst_port) {
		mylog(log_debug, "unexpected adress\n");
		return 0;
	}

	if (data[0] == 'h' && data_len == 1) {
		uint32_t tmp = ntohl(*((uint32_t *) &data[1 + sizeof(uint32_t)]));
		mylog(log_debug,"[%s][hb]received hb \n",ip_port);
		conn_info.last_hb_recv_time = current_time_rough;
		return 0;
	} else if (data[0] == 'd' && data_len >=int( sizeof(uint32_t) + 1)) {
		uint32_t tmp_conv_id = ntohl(*((uint32_t *) &data[1]));

		conn_info.last_hb_recv_time = current_time_rough;

		mylog(log_trace, "conv:%u\n", tmp_conv_id);
		if (!conn_info.conv_manager->is_conv_used(tmp_conv_id)) {
			if (conn_info.conv_manager->get_size() >= max_conv_num) {
				mylog(log_warn,
						"ignored new conv %x connect bc max_conv_num exceed\n",
						tmp_conv_id);
				return 0;
			}
			struct sockaddr_in remote_addr_in;

			socklen_t slen = sizeof(sockaddr_in);
			memset(&remote_addr_in, 0, sizeof(remote_addr_in));
			remote_addr_in.sin_family = AF_INET;
			remote_addr_in.sin_port = htons(remote_port);
			remote_addr_in.sin_addr.s_addr = remote_address_uint32;

			int new_udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (new_udp_fd < 0) {
				mylog(log_warn, "create udp_fd error\n");
				return -1;
			}
			setnonblocking(new_udp_fd);
			set_buf_size(new_udp_fd);

			mylog(log_debug, "created new udp_fd %d\n", new_udp_fd);
			int ret = connect(new_udp_fd, (struct sockaddr *) &remote_addr_in,
					slen);
			if (ret != 0) {
				mylog(log_warn, "udp fd connect fail\n");
				close(new_udp_fd);
				return -1;
			}
			struct epoll_event ev;

			uint64_t u64 = (uint32_t(new_udp_fd))+(1llu<<32u);
			mylog(log_trace, "u64: %ld\n", u64);
			ev.events = EPOLLIN;

			ev.data.u64 = u64;

			ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, new_udp_fd, &ev);

			if (ret != 0) {
				mylog(log_warn, "add udp_fd error\n");
				close(new_udp_fd);
				return -1;
			}

			conn_info.conv_manager->insert_conv(tmp_conv_id, new_udp_fd);
			conn_manager.udp_fd_mp[new_udp_fd] = &conn_info;

			//pack_u64(conn_info.raw_info.recv_info.src_ip,conn_info.raw_info.recv_info.src_port);

			mylog(log_info, "new conv conv_id=%x, assigned fd=%d\n",
					tmp_conv_id, new_udp_fd);



		}

		uint64_t u64 = conn_info.conv_manager->find_u64_by_conv(tmp_conv_id);

		conn_info.conv_manager->update_active_time(tmp_conv_id);

		int fd = int((u64 << 32u) >> 32u);

		mylog(log_trace, "received a data from fake tcp,len:%d\n", data_len);
		int ret = send(fd, data + 1 + sizeof(uint32_t),
				data_len - (1 + sizeof(uint32_t)), 0);

		mylog(log_trace, "%d byte sent  ,fd :%d\n ", ret, fd);
		if (ret < 0) {
			mylog(log_warn, "send returned %d\n", ret);
			//perror("what happened????");
		}
		return 0;
	}
	return 0;
}
int server_on_raw_pre_ready(conn_info_t &conn_info,char * data,int data_len)
{
	uint32_t ip;uint16_t port;
	ip=conn_info.raw_info.send_info.src_ip;
	port=conn_info.raw_info.send_info.src_ip;
	char ip_port[40];
	sprintf(ip_port,"%s:%d",my_ntoa(ip),port);


	//mylog(log_debug,"!!!\n");
	if(data_len<int(sizeof(id_t)*3))
	{
		mylog(log_debug,"too short to be a handshake\n");
		return 0;
	}
	uint32_t tmp_session_id= ntohl(* ((uint32_t *)&data[sizeof(id_t)]));
	uint32_t tmp_oppsite_const_id=ntohl(* ((uint32_t *)&data[sizeof(id_t)*2]));

	/*
	if(oppsite_const_id!=0&&tmp_oppsite_const_id!=oppsite_const_id)  //TODO MOVE TO READY
	{
		conv_manager.clear();
	}
	oppsite_const_id=tmp_oppsite_const_id;*/

	if(tmp_session_id!=conn_info.my_id)
	{
		mylog(log_debug,"[%s]%x %x auth fail!!\n",tmp_session_id,conn_info.my_id,ip_port);
		return 0;
	}

	int tmp_oppsite_session_id=  ntohl(* ((uint32_t *)&data[0]));
	conn_info.oppsite_id=tmp_oppsite_session_id;

	mylog(log_info,"[%s]received handshake %x %x\n",ip_port,conn_info.oppsite_id,conn_info.my_id);

	if(conn_manager.const_id_mp.find(tmp_oppsite_const_id)==conn_manager.const_id_mp.end())
	{
		//conn_manager.const_id_mp=

		if(conn_manager.ready_num>=max_ready_conn_num)
		{
			mylog(log_info,"[%s]max_ready_conn_num,cant turn to ready\n",ip_port);
			conn_info.state.server_current_state =server_nothing;
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

		send_safer(conn_info, (char *) "h", 1);		/////////////send

		mylog(log_info, "[%s]changed state to server_ready\n",ip_port);
		conn_info.anti_replay->re_init();

		//g_conn_info=conn_info;
		int new_timer_fd;
		set_timer_server(epollfd, new_timer_fd);
		conn_info.timer_fd=new_timer_fd;
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
				 conn_info.state.server_current_state=server_nothing;
				 conn_info.oppsite_const_id=0;
				 return 0;
			}
			if(!conn_manager.exist(ori_conn_info.raw_info.recv_info.src_ip,ori_conn_info.raw_info.recv_info.src_port))//TODO remove this
			{
				mylog(log_fatal,"[%s]this shouldnt happen\n",ip_port);
				exit(-1);
			}
			if(!conn_manager.exist(conn_info.raw_info.recv_info.src_ip,conn_info.raw_info.recv_info.src_port))//TODO remove this
			{
				mylog(log_fatal,"[%s]this shouldnt happen2\n",ip_port);
				exit(-1);
			}
			conn_info_t *&p_ori=conn_manager.find_insert_p(ori_conn_info.raw_info.recv_info.src_ip,ori_conn_info.raw_info.recv_info.src_port);
			conn_info_t *&p=conn_manager.find_insert_p(conn_info.raw_info.recv_info.src_ip,conn_info.raw_info.recv_info.src_port);
			conn_info_t *tmp=p;
			p=p_ori;
			p_ori=tmp;


			mylog(log_info,"[%s]grabbed a connection\n",ip_port);


			//ori_conn_info.state.server_current_state=server_ready;
			ori_conn_info.raw_info=conn_info.raw_info;
			ori_conn_info.last_state_time=conn_info.last_state_time;
			ori_conn_info.last_hb_recv_time=conn_info.last_hb_recv_time;
			ori_conn_info.last_hb_sent_time=conn_info.last_hb_sent_time;
			ori_conn_info.my_id=conn_info.my_id;
			ori_conn_info.oppsite_id=conn_info.oppsite_id;
			send_safer(ori_conn_info, (char *) "h", 1);
			ori_conn_info.anti_replay->re_init();



			conn_info.state.server_current_state=server_nothing;
			conn_info.oppsite_const_id=0;

		}
		else
		{
			mylog(log_fatal,"[%s]this should never happen\n",ip_port);
			exit(-1);
		}
		return 0;
	}
	return 0;
}
int server_on_raw_recv_multi()
{
	char dummy_buf[buf_len];
	uint32_t ip;uint16_t port;
	if(peek_raw(ip,port)<0)
	{
		recv(raw_recv_fd, 0,0, 0  );//
		//struct sockaddr saddr;
		//socklen_t saddr_size;
		///recvfrom(raw_recv_fd, 0,0, 0 ,&saddr , &saddr_size);//
		mylog(log_trace,"peek_raw failed\n");
		return -1;
	}
	mylog(log_trace,"peek_raw %s %d\n",my_ntoa(ip),port);
	char ip_port[40];
	sprintf(ip_port,"%s:%d",my_ntoa(ip),port);
	/*if(ip==conn_manager.current_ready_ip&&port==conn_manager.current_ready_port)
	{
		return server_on_raw_ready();
	}*/

	int data_len; char *data;
	if(!conn_manager.exist(ip,port))
	{
		raw_info_t tmp_raw_info;

		if(recv_bare(tmp_raw_info,data,data_len)<0)
		{
			return 0;
		}
		if(raw_mode==mode_faketcp)
		{
			if (tmp_raw_info.recv_info.syn != 1 || tmp_raw_info.recv_info.ack != 0 || data_len != 0)
				return 0;

		}
		else if(raw_mode==mode_udp||raw_mode==mode_icmp)
		{

			if(data_len!=strlen("hello")|| memcmp((char *)"hello",data,strlen("hello"))!=0)
			{
				//data[6]=0;
				mylog(log_debug,"[%s]not a hello packet %d\n",ip_port,data,data_len);
				return 0;
			}
		}
		conn_info_t &conn_info=conn_manager.find_insert(ip,port);
		conn_info.raw_info=tmp_raw_info;
		packet_info_t &send_info=conn_info.raw_info.send_info;
		packet_info_t &recv_info=conn_info.raw_info.recv_info;
		raw_info_t &raw_info=conn_info.raw_info;

		send_info.src_ip=recv_info.dst_ip;
		send_info.src_port=recv_info.dst_port;

		send_info.dst_port = recv_info.src_port;
		send_info.dst_ip = recv_info.src_ip;

		mylog(log_info,"[%s]send_info.src_port  %d,%d\n",ip_port,send_info.src_port,send_info.dst_port);

		if(raw_mode==mode_faketcp) /////////////////////////here is server nothing
		{
			send_info.ack_seq = recv_info.seq + 1;

			send_info.psh = 0;
			send_info.syn = 1;
			send_info.ack = 1;

			send_info.seq = get_true_random_number(); //not necessary to set

			send_info.first_seq=send_info.seq;   //correct seq and ack_seq are import for create nat pipe.
			send_info.first_ack_seq=send_info.ack_seq;//if someone attack you with fake data,those two value may be changed

			mylog(log_info,"[%s]sent syn ack\n",ip_port);
			send_bare(raw_info, 0, 0);  //////////////send

			mylog(log_info,"[%s]changed state to server_syn_ack_sent\n",ip_port);
			conn_info.state.server_current_state = server_syn_ack_sent;
			conn_info.last_state_time = get_current_time();
		}
		else if(raw_mode==mode_udp||raw_mode==mode_icmp)
		{
			mylog(log_info,"[%s]got a hello packet\n",ip_port);

			mylog(log_info,"[%s]sent handshake\n",ip_port);

			conn_info.my_id=get_true_random_number_nz();
			send_handshake(raw_info,conn_info.my_id,get_true_random_number_nz(),const_id);  //////////////send

			mylog(log_info,"[%s]changed state to server_heartbeat_sent_sent\n",ip_port);

			conn_info.state.server_current_state = server_handshake_sent;
			conn_info.last_state_time = get_current_time();
		}
		return 0;
	}
/////////////////////////////////////////////////////////////////////////////////////////////////////
	if(conn_manager.mp.size()>=max_handshake_conn_num)
	{
		mylog(log_info,"[%s]reached max_handshake_conn_num,ignored new handshake\n",ip_port);
		recv(raw_recv_fd, 0,0, 0  );//
		return 0;
	}

	conn_info_t & conn_info=conn_manager.find_insert(ip,port);//insert if not exist
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;

	if(conn_info.state.server_current_state==server_ready)
	{
		return server_on_raw_ready(conn_info);
	}

/////////////////////////////////////////////////////////////////////////////////////////////////
	if(recv_bare(conn_info.raw_info,data,data_len)<0)
		return -1;

	if(conn_info.state.server_current_state==server_syn_ack_sent)
	{
		assert(raw_mode!=mode_udp&&raw_mode!=mode_icmp);
		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_debug,"[%s]unexpected adress\n",ip_port);
			return 0;
		}
		if(raw_mode==mode_faketcp)
		{
			if( recv_info.syn==0&&recv_info.ack==1 &&data_len==0)   //received ack as expect
			{

				send_info.syn=0;
				send_info.ack=1;
				send_info.seq+=1;////////is this right?

				conn_info.my_id=get_true_random_number_nz();
				send_handshake(raw_info,conn_info.my_id,0,const_id);   //////////////send

				mylog(log_info,"[%s]changed state to server_handshake_sent\n",ip_port);

				conn_info.state.server_current_state=server_handshake_sent;
				conn_info.last_state_time=get_current_time();
			}
			else if(recv_info.syn == 1 && recv_info.ack == 0 && data_len == 0)  //received syn again,server will re-send syn ack
			{
				send_info.seq=send_info.first_seq;   //used saved seq and ack_seq
				send_info.ack_seq=send_info.first_ack_seq;

				send_info.psh = 0;
				send_info.syn = 1;
				send_info.ack = 1;

				mylog(log_info,"[%s]re-sent syn ack\n",ip_port);
				send_bare(raw_info, 0, 0);  //////////////send
			}
		}
	}
	else if(conn_info.state.server_current_state==server_handshake_sent)
	{
		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_trace,"[%s]unexpected adress\n",ip_port);
			return 0;
		}

		if(raw_mode==mode_faketcp)
		{
			if(recv_info.syn==0&&recv_info.ack==1 &&data_len!=0 )   //received heandshake_response as expected
			{
				server_on_raw_pre_ready(conn_info,data,data_len);
				return 0;

			}
			else if( recv_info.syn==0&&recv_info.ack==1 &&data_len==0) //received ack again,re-send handshake
			{
				send_info.syn=0;
				send_info.ack=1;

				conn_info.my_id=get_true_random_number_nz();
				mylog(log_info,"[%s]re-sent handshake\n",ip_port);
				send_handshake(raw_info,conn_info.my_id,0,const_id);
			}
			else
			{
				mylog(log_debug,"[%s]enexpected packet type\n",ip_port);
				return 0;
			}
		}
		else if(raw_mode==mode_udp||raw_mode==mode_icmp)
		{
			if(data_len!=strlen("hello")||memcmp((char *)"hello",data,strlen("hello"))!=0)
				////received heandshake_response as expected,likely,since its not a hello packet.lets check it in server_on_raw_pre_ready
			{
				server_on_raw_pre_ready(conn_info,data,data_len);
			}
			else
			{
				mylog(log_info,"[%s]got a hello packet again n",ip_port);
				mylog(log_info,"[%s]re-sent handshake\n",ip_port);
				send_handshake(raw_info,conn_info.my_id,get_true_random_number_nz(),const_id);  //////////////send
				return 0;
			}
		}




	}
	return 0;

}

/*
int server_on_raw_recv()
{
	raw_info_t &raw_info=g_conn_info.raw_info;

	packet_info_t &send_info=g_conn_info.raw_info.send_info;
	packet_info_t &recv_info=g_conn_info.raw_info.recv_info;

	char* data;int data_len;

	//packet_info_t send_info;
	if(g_conn_info.server_current_state==server_nothing)
	{
		if(recv_bare(raw_info,data,data_len)!=0)
		{
			return -1;
		}

		anti_replay.re_init();

		if(raw_mode==mode_icmp)
		{
			send_info.src_port = recv_info.src_port;;
		}

		send_info.src_ip=recv_info.dst_ip;
		send_info.src_port=recv_info.dst_port;

		send_info.dst_port = recv_info.src_port;
		send_info.dst_ip = recv_info.src_ip;

		if(raw_mode==mode_faketcp)
		{
			if (!(recv_info.syn == 1 && recv_info.ack == 0 && data_len == 0))
				return 0;

			send_info.ack_seq = recv_info.seq + 1;

			send_info.psh = 0;
			send_info.syn = 1;
			send_info.ack = 1;

			send_info.seq = get_true_random_number_nz(); //not necessary to set

			mylog(log_info,"sent syn ack\n");
			send_bare(raw_info, 0, 0);  //////////////send

			mylog(log_info,"changed state to server_syn_ack_sent\n");

			g_conn_info.server_current_state = server_syn_ack_sent;
			g_conn_info.retry_counter = 0;
			g_conn_info.last_state_time = get_current_time();
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
			send_handshake(raw_info,my_id,random(),const_id);  //////////////send

			mylog(log_info,"changed state to server_heartbeat_sent_sent\n");

			g_conn_info.server_current_state = server_handshake_sent;
			g_conn_info.retry_counter = 0;
			g_conn_info.last_state_time = get_current_time();
		}
	}
	else if(g_conn_info.server_current_state==server_syn_ack_sent)
	{
		if(recv_bare(raw_info,data,data_len)!=0)
		{
			return -1;
		}

		if(raw_mode==mode_faketcp&&!( recv_info.syn==0&&recv_info.ack==1 &&data_len==0)) return 0;
		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_debug,"unexpected adress\n");
			return 0;
		}

		send_info.syn=0;
		send_info.ack=1;
		send_info.seq+=1;////////is this right?

		send_handshake(raw_info,my_id,0,const_id);   //////////////send

		mylog(log_info,"changed state to server_handshake_sent\n");

		g_conn_info.server_current_state=server_handshake_sent;
		g_conn_info.last_state_time=get_current_time();

		g_conn_info.retry_counter=RETRY_TIME;
	}
	else if(g_conn_info.server_current_state==server_handshake_sent)//heart beat received
	{
		if(recv_bare(raw_info,data,data_len)!=0)
		{
			return -1;
		}

		if(( raw_mode==mode_faketcp&& (recv_info.syn==1||recv_info.ack!=1)) ||data_len==0)  return 0;

		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_trace,"unexpected adress\n");
			return 0;
		}

		//if(data_len<hb_length||data[0]!='h')
		//{
		//	return 0;
		//}

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

		send_safer(raw_info,(char *)"h",1);/////////////send

		//send_hb(g_packet_info_send,my_id,oppsite_id,const_id);/////////////////send

		g_conn_info.server_current_state=server_ready;
		g_conn_info.last_state_time=get_current_time();

		g_conn_info.last_hb_recv_time=get_current_time();
		//first_data_packet=1;

		mylog(log_info,"changed state to server_ready\n");

	}
	else if(g_conn_info.server_current_state==server_ready)
	{
		if(recv_safer(raw_info,data,data_len)!=0)
		{
			return -1;
		}

		if( (raw_mode==mode_faketcp&&(recv_info.syn==1||recv_info.ack!=1)) ||data_len==0)  return 0;
		if(recv_info.src_ip!=send_info.dst_ip||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_debug,"unexpected adress\n");
			return 0;
		}

		if(data[0]=='h'&&data_len==1)
		{
			uint32_t tmp= ntohl(* ((uint32_t *)&data[1+sizeof(uint32_t)]));
			mylog(log_debug,"received hb <%x,%x>\n",oppsite_id,tmp);
			g_conn_info.last_hb_recv_time=current_time_rough;
			return 0;
		}
		else if(data[0]=='d'&&data_len>=sizeof(uint32_t)+1)
		{
			uint32_t tmp_conv_id=ntohl(* ((uint32_t *)&data[1]));

			g_conn_info.last_hb_recv_time=current_time_rough;

			mylog(log_debug,"<<<<conv:%u>>>>\n",tmp_conv_id);
			if(!conv_manager.is_conv_used(tmp_conv_id))
			{
				if(conv_manager.get_size() >=max_conv_num)
				{
					mylog(log_warn,"ignored new conv %x connect bc max_conv_num exceed\n",tmp_conv_id);
					return 0;
				}
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


		}
	}
	return 0;
}*/
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

	conn_info_t conn_info;
	conn_info.my_id=get_true_random_number_nz();

	conn_info.prepare();
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;

	//printf("?????\n");
	if(source_address_uint32==0)
	{
		mylog(log_info,"get_src_adress called\n");
		if(get_src_adress(source_address_uint32)!=0)
		{
			mylog(log_fatal,"the trick to auto get source ip failed,you should specific an ip by --source-ip\n");
			exit(-1);
		}
	}
	in_addr tmp;
	tmp.s_addr=source_address_uint32;
	mylog(log_info,"source ip = %s\n",inet_ntoa(tmp));
	//printf("done\n");


	if(try_to_list_and_bind(source_port)!=0)
	{
		mylog(log_fatal,"bind to source_port:%d fail\n ",source_port);
		exit(-1);
	}
	send_info.src_port=source_port;
	send_info.src_ip = source_address_uint32;

	int i, j, k;int ret;
	init_raw_socket();

	//init_filter(source_port);
	send_info.dst_ip=remote_address_uint32;
	send_info.dst_port=remote_port;

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
		exit(1);
	}
	setnonblocking(udp_fd);
	epollfd = epoll_create1(0);

	const int max_events = 4096;
	struct epoll_event ev, events[max_events];
	if (epollfd < 0) {
		mylog(log_fatal,"epoll return %d\n", epollfd);
		exit(-1);
	}

	ev.events = EPOLLIN;
	ev.data.u64 = udp_fd;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, udp_fd, &ev);
	if (ret!=0) {
		mylog(log_fatal,"add  udp_listen_fd error\n");
		exit(-1);
	}
	ev.events = EPOLLIN;
	ev.data.u64 = raw_recv_fd;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
	if (ret!= 0) {
		mylog(log_fatal,"add raw_fd error\n");
		exit(-1);
	}

	////add_timer for fake_tcp_keep_connection_client

	//sleep(10);

	//memset(&udp_old_addr_in,0,sizeof(sockaddr_in));
	int unbind=1;


	set_timer(epollfd,timer_fd);

	mylog(log_debug,"send_raw : from %x %d  to %x %d\n",send_info.src_ip,send_info.src_port,send_info.dst_ip,send_info.dst_port);
	while(1)////////////////////////
	{
		epoll_trigger_counter++;
		int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
		if (nfds < 0) {  //allow zero
			mylog(log_fatal,"epoll_wait return %d\n", nfds);
			exit(-1);
		}
		int idx;
		for (idx = 0; idx < nfds; ++idx) {
			if (events[idx].data.u64 == (uint64_t)raw_recv_fd)
			{
				iphdr *iph;tcphdr *tcph;
				client_on_raw_recv(conn_info);
			}
			else if(events[idx].data.u64 ==(uint64_t)timer_fd)
			{
				uint64_t value;
				read(timer_fd, &value, 8);
				keep_connection_client(conn_info);

				mylog(log_debug,"epoll_trigger_counter:  %d \n",epoll_trigger_counter);
				epoll_trigger_counter=0;
			}
			else if (events[idx].data.u64 == (uint64_t)udp_fd)
			{

				int recv_len;
				struct sockaddr_in udp_new_addr_in;
				if ((recv_len = recvfrom(udp_fd, buf, buf_len, 0,
						(struct sockaddr *) &udp_new_addr_in, &slen)) == -1) {
					mylog(log_error,"recv_from error,this shouldnt happen at client\n");
					exit(1);
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

				if(!conn_info.conv_manager->is_u64_used(u64))
				{
					if(conn_info.conv_manager->get_size() >=max_conv_num)
					{
						mylog(log_warn,"ignored new udp connect bc max_conv_num exceed\n");
						continue;
					}
					conv=conn_info.conv_manager->get_new_conv();
					conn_info.conv_manager->insert_conv(conv,u64);
					mylog(log_info,"new connection from %s:%d,conv_id=%x\n",inet_ntoa(udp_new_addr_in.sin_addr),ntohs(udp_new_addr_in.sin_port),conv);
				}
				else
				{
					conv=conn_info.conv_manager->find_conv_by_u64(u64);
				}

				conn_info.conv_manager->update_active_time(conv);

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
				exit(-1);
			}
		}
	}
	return 0;
}

int server_event_loop()
{
	char buf[buf_len];

	int i, j, k;int ret;

	bind_address_uint32=local_address_uint32;//only server has bind adress,client sets it to zero


	 if(raw_mode==mode_faketcp)
	 {
		 bind_fd=socket(AF_INET,SOCK_STREAM,0);
	 }
	 else  if(raw_mode==mode_udp||raw_mode==mode_icmp)//bind an adress to avoid collision,for icmp,there is no port,just bind a udp port
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
    	 exit(-1);
     }

	 if(raw_mode==mode_faketcp)
	 {

		 if(listen(bind_fd, SOMAXCONN) != 0 )
		 {
			 mylog(log_fatal,"listen fail\n");
			 exit(-1);
		 }
	 }



	init_raw_socket();
	init_filter(local_port);//bpf filter

	epollfd = epoll_create1(0);
	const int max_events = 4096;

	struct epoll_event ev, events[max_events];
	if (epollfd < 0) {
		mylog(log_fatal,"epoll return %d\n", epollfd);
		exit(-1);
	}

	ev.events = EPOLLIN;
	ev.data.u64 = raw_recv_fd;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
	if (ret!= 0) {
		mylog(log_fatal,"add raw_fd error\n");
		exit(-1);
	}
	int timer_fd;

	set_timer(epollfd,timer_fd);

	while(1)////////////////////////
	{

		int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
		if (nfds < 0) {  //allow zero
			mylog(log_fatal,"epoll_wait return %d\n", nfds);
			exit(-1);
		}
		int idx;
		for (idx = 0; idx < nfds; ++idx)
		{
			//mylog(log_debug,"ndfs:  %d \n",nfds);
			epoll_trigger_counter++;
			//printf("%d %d %d %d\n",timer_fd,raw_recv_fd,raw_send_fd,n);
			if ((events[idx].data.u64 ) == (uint64_t)timer_fd)
			{
				uint64_t dummy;
				read(timer_fd, &dummy, 8);
				current_time_rough=get_current_time();

				long int begin=get_current_time();
				conn_manager.clear_inactive();
				long int end=get_current_time()-begin;

				if(end>1)mylog(log_debug,"%lld,conn_manager.clear_inactive();,%lld  \n",begin,end);

				mylog(log_debug,"epoll_trigger_counter:  %d \n",epoll_trigger_counter);
				epoll_trigger_counter=0;

			}
			else if (events[idx].data.u64 == (uint64_t)raw_recv_fd)
			{
				long int begin=get_current_time();
				server_on_raw_recv_multi();
				long int end=get_current_time()-begin;
				if(end>1)mylog(log_debug,"%lld,server_on_raw_recv_multi(),%lld  \n",begin,end);
			}
			else if ((events[idx].data.u64 >>32u) == 2u)
			{
				long int begin=get_current_time();
				int fd=get_u64_l(events[idx].data.u64);
				uint64_t dummy;
				read(fd, &dummy, 8);

				if(conn_manager.timer_fd_mp.find(fd)==conn_manager.timer_fd_mp.end()) //this can happen,when fd is a just closed fd
				{
					mylog(log_info,"timer_fd no longer exits\n");
					continue;
				}
				conn_info_t* p_conn_info=conn_manager.timer_fd_mp[fd];
				uint32_t ip=p_conn_info->raw_info.recv_info.src_ip;
				uint32_t port=p_conn_info->raw_info.recv_info.src_port;
				if(!conn_manager.exist(ip,port))//TODO remove this for peformance
				{
					mylog(log_fatal,"ip port no longer exits 1!!!this shouldnt happen\n");
					exit(-1);
				}
				if (p_conn_info->state.server_current_state != server_ready) //TODO remove this for peformance
				{
					mylog(log_fatal,"p_conn_info->state.server_current_state!=server_ready!!!this shouldnt happen\n");
					exit(-1);
				}
				//conn_info_t &conn_info=conn_manager.find(ip,port);
				keep_connection_server_multi(*p_conn_info);

				long int end=get_current_time()-begin;
				if(end>1)mylog(log_debug,"%lld,keep_connection_server_multi,%lld  \n",begin,end);
			}
			else if ((events[idx].data.u64 >>32u) == 1u)
			{
				//uint32_t conv_id=events[n].data.u64>>32u;

				long int begin=get_current_time();

				int fd=int((events[idx].data.u64<<32u)>>32u);

				if(conn_manager.udp_fd_mp.find(fd)==conn_manager.udp_fd_mp.end()) //this can happen,when fd is a just closed fd
				{
					mylog(log_debug,"fd no longer exists in udp_fd_mp,udp fd %d\n",fd);
					recv(fd,0,0,0);
					continue;
				}
				conn_info_t* p_conn_info=conn_manager.udp_fd_mp[fd];

				uint32_t ip=p_conn_info->raw_info.recv_info.src_ip;
				uint32_t port=p_conn_info->raw_info.recv_info.src_port;
				if(!conn_manager.exist(ip,port))//TODO remove this for peformance
				{
					mylog(log_fatal,"ip port no longer exits 2!!!this shouldnt happen\n", nfds);
					exit(-1);
				}

				if(p_conn_info->state.server_current_state!=server_ready)//TODO remove this for peformance
				{
					mylog(log_fatal,"p_conn_info->state.server_current_state!=server_ready!!!this shouldnt happen\n", nfds);
					exit(-1);
				}

				conn_info_t &conn_info=*p_conn_info;

				if(!conn_info.conv_manager->is_u64_used(fd))
				{
					mylog(log_debug,"conv no longer exists,udp fd %d\n",fd);
					int recv_len=recv(fd,0,0,0); ///////////TODO ,delete this
					continue;
				}

				uint32_t conv_id=conn_info.conv_manager->find_conv_by_u64(fd);

				int recv_len=recv(fd,buf,buf_len,0);

				mylog(log_trace,"received a packet from udp_fd,len:%d\n",recv_len);

				if(recv_len<0)
				{
					mylog(log_debug,"udp fd,recv_len<0 continue\n");
					continue;
				}

				//conn_info.conv_manager->update_active_time(conv_id);  server dosnt update from upd side,only update from raw side.  (client updates at both side)

				if(conn_info.state.server_current_state==server_ready)
				{
					send_data_safer(conn_info,buf,recv_len,conv_id);
					//send_data(g_packet_info_send,buf,recv_len,my_id,oppsite_id,conv_id);
					mylog(log_trace,"send_data_safer ,sent !!\n");
				}

				long int end=get_current_time()-begin;
				if(end>1) mylog(log_debug,"%lld,send_data_safer,%lld  \n",begin,end);
			}
			else
			{
				mylog(log_fatal,"unknown fd,this should never happen\n");
				exit(-1);
			}

		}
	}
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
			exit(0);
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
					exit(-1);
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

	if (argc == 1)
	{
		print_help();
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
			if(program_mode==0)
			{
				program_mode=server_mode;
			}
			else
			{
				mylog(log_fatal,"-s /-c has already been set,-s option conflict\n");
				exit(-1);
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
				exit(-1);
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
					exit(-1);
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
					exit(-1);
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
					mylog(log_fatal,"no such cipher_mode %s\n",optarg);
					exit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"log-level")==0)
			{
			}
			else if(strcmp(long_options[option_index].name,"disable-color")==0)
			{
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
					exit(-1);
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
					exit(-1);
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
		exit(-1);
	}

	 mylog(log_info,"important variables: ", argc);

	 log_bare(log_info,"log_level=%d:%s ",log_level,log_text[log_level]);
	 log_bare(log_info,"raw_mode=%s ",raw_mode_tostring[raw_mode]);
	 log_bare(log_info,"cipher_mode=%s ",cipher_mode_tostring[cipher_mode]);
	 log_bare(log_info,"auth_mode=%s ",auth_mode_tostring[auth_mode]);

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
void iptables_warn()
{
	if(program_mode==client_mode)
	{
		if(raw_mode==mode_faketcp)
		{
			mylog(log_warn,"make sure you have run once:  iptables -A INPUT -s %s/32 -p tcp -m tcp --sport %d -j DROP\n",remote_address,remote_port);
		}
		if(raw_mode==mode_udp)
		{
			mylog(log_warn,"make sure you have run once:  iptables -A INPUT -s %s/32 -p udp -m udp --sport %d -j DROP\n",remote_address,remote_port);
		}
		if(raw_mode==mode_icmp)
		{
			mylog(log_warn,"make sure you have run once:  iptables -A INPUT -s %s/32 -p icmp -j DROP\n",remote_address);
		}
	}
	if(program_mode==server_mode)
	{
		if(raw_mode==mode_faketcp)
		{
			mylog(log_warn,"make sure you have run once:  iptables -A INPUT -p tcp -m tcp --dport %d -j DROP\n",local_port);
		}
		if(raw_mode==mode_udp)
		{
			mylog(log_warn,"make sure you have run once:  iptables -A INPUT -p udp -m udp --udp %d -j DROP\n",local_port);
		}
		if(raw_mode==mode_icmp)
		{
			if(local_address_uint32==0)
			{
				mylog(log_warn,"make sure you have run once:  iptables -A INPUT -p icmp -j DROP\n");
			}
			else
			{
				mylog(log_warn,"make sure you have run once:  iptables -A INPUT -d %s/32 -p icmp -j DROP\n",local_address);
			}
		}
	}
}
int main(int argc, char *argv[])
{
	//assert(0==1);
	dup2(1, 2);//redirect stderr to stdout
	signal(SIGINT, INThandler);
	process_arg(argc,argv);

	iptables_warn();

	current_time_rough=get_current_time();

	init_random_number_fd();
	srand(get_true_random_number_nz());
	const_id=get_true_random_number_nz();

	mylog(log_info,"const_id:%x\n",const_id);

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
