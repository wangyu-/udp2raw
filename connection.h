/*
 * connection.h
 *
 *  Created on: Sep 23, 2017
 *      Author: root
 */

#ifndef CONNECTION_H_
#define CONNECTION_H_

extern int disable_anti_replay;

#include "connection.h"
#include "common.h"
#include "log.h"
#include "network.h"
#include "misc.h"



struct anti_replay_t  //its for anti replay attack,similar to openvpn/ipsec 's anti replay window
{
	u64_t max_packet_received;
	char window[anti_replay_window_size];
	anti_replay_seq_t anti_replay_seq;
	anti_replay_seq_t get_new_seq_for_send();
	anti_replay_t();
	void re_init();

	int is_vaild(u64_t seq);
};//anti_replay;


struct conv_manager_t  // manage the udp connections
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

	conv_manager_t();
	~conv_manager_t();
	int get_size();
	void reserve();
	void clear();
	u32_t get_new_conv();
	int is_conv_used(u32_t conv);
	int is_u64_used(u64_t u64);
	u32_t find_conv_by_u64(u64_t u64);
	u64_t find_u64_by_conv(u32_t conv);
	int update_active_time(u32_t conv);
	int insert_conv(u32_t conv,u64_t u64);
	int erase_conv(u32_t conv);
	int clear_inactive(char * ip_port=0);
	int clear_inactive0(char * ip_port);
};//g_conv_manager;

struct blob_t  //used in conn_info_t.  conv_manager_t and anti_replay_t are costly data structures ,we dont allocate them until its necessary
{
	conv_manager_t conv_manager;
	anti_replay_t anti_replay;
};
struct conn_info_t     //stores info for a raw connection.for client ,there is only one connection,for server there can be thousand of connection since server can
//handle multiple clients
{
	current_state_t state;

	raw_info_t raw_info;
	u64_t last_state_time;
	u64_t last_hb_sent_time;  //client re-use this for retry
	u64_t last_hb_recv_time;
	//long long last_resent_time;

	id_t my_id;
	id_t oppsite_id;


	fd64_t timer_fd64;

	id_t oppsite_const_id;

	blob_t *blob;

	uint8_t my_roller;
	uint8_t oppsite_roller;
	u64_t last_oppsite_roller_time;

//	ip_port_t ip_port;

/*
	const uint32_t &ip=raw_info.recv_info.src_ip;
	const uint16_t &port=raw_info.recv_info.src_port;

*/
	 void recover(const conn_info_t &conn_info);
	void re_init();
	conn_info_t();
	void prepare();
	conn_info_t(const conn_info_t&b);
	conn_info_t& operator=(const conn_info_t& b);
	~conn_info_t();
};//g_conn_info;

struct conn_manager_t  //manager for connections. for client,we dont need conn_manager since there is only one connection.for server we use one conn_manager for all connections
{

 u32_t ready_num;

 //unordered_map<int,conn_info_t *> udp_fd_mp;  //a bit dirty to used pointer,but can void unordered_map search
 //unordered_map<int,conn_info_t *> timer_fd_mp;//we can use pointer here since unordered_map.rehash() uses shallow copy

 unordered_map<id_t,conn_info_t *> const_id_mp;

 unordered_map<u64_t,conn_info_t*> mp; //put it at end so that it de-consturcts first

 unordered_map<u64_t,conn_info_t*>::iterator clear_it;

 long long last_clear_time;

 conn_manager_t();
 int exist(u32_t ip,uint16_t port);
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
 conn_info_t *& find_insert_p(u32_t ip,uint16_t port);  //be aware,the adress may change after rehash
 conn_info_t & find_insert(u32_t ip,uint16_t port) ; //be aware,the adress may change after rehash

 int erase(unordered_map<u64_t,conn_info_t*>::iterator erase_it);
int clear_inactive();
int clear_inactive0();

};

extern conn_manager_t conn_manager;

void server_clear_function(u64_t u64);

int send_bare(raw_info_t &raw_info,const char* data,int len);//send function with encryption but no anti replay,this is used when client and server verifys each other
//you have to design the protocol carefully, so that you wont be affect by relay attack
//int reserved_parse_bare(const char *input,int input_len,char* & data,int & len); // a sub function used in recv_bare
int recv_bare(raw_info_t &raw_info,char* & data,int & len);//recv function with encryption but no anti replay,this is used when client and server verifys each other
//you have to design the protocol carefully, so that you wont be affect by relay attack
int send_handshake(raw_info_t &raw_info,id_t id1,id_t id2,id_t id3);// a warp for send_bare for sending handshake(this is not tcp handshake) easily
int send_safer(conn_info_t &conn_info,char type,const char* data,int len);  //safer transfer function with anti-replay,when mutually verification is done.
int send_data_safer(conn_info_t &conn_info,const char* data,int len,u32_t conv_num);//a wrap for  send_safer for transfer data.
//int reserved_parse_safer(conn_info_t &conn_info,const char * input,int input_len,char &type,char* &data,int &len);//subfunction for recv_safer,allow overlap
int recv_safer(conn_info_t &conn_info,char &type,char* &data,int &len);///safer transfer function with anti-replay,when mutually verification is done.
#endif /* CONNECTION_H_ */
