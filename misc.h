/*
 * misc.h
 *
 *  Created on: Sep 23, 2017
 *      Author: root
 */

#ifndef MISC_H_
#define MISC_H_


#include "common.h"
#include "log.h"
#include "network.h"

extern int hb_mode;
extern int hb_len;
extern int mtu_warn;

extern int max_rst_allowed;
extern int max_rst_to_show;


const u32_t max_handshake_conn_num=10000;
const u32_t max_ready_conn_num=1000;
const u32_t anti_replay_window_size=4000;
const int max_conv_num=10000;

const u32_t client_handshake_timeout=5000;//unit ms
const u32_t client_retry_interval=1000;//ms

const u32_t server_handshake_timeout=client_handshake_timeout+5000;// this should be longer than clients. client retry initially ,server retry passtively

const int conv_clear_ratio=30;  //conv grabage collecter check 1/30 of all conv one time
const int conn_clear_ratio=50;
const int conv_clear_min=1;
const int conn_clear_min=1;

const u32_t conv_clear_interval=1000;//ms
const u32_t conn_clear_interval=1000;//ms


const i32_t max_fail_time=0;//disable

const u32_t heartbeat_interval=600;//ms

const u32_t timer_interval=400;//ms. this should be smaller than heartbeat_interval and retry interval;

const uint32_t conv_timeout=180000; //ms. 120 second
//const u32_t conv_timeout=30000; //for test

const u32_t client_conn_timeout=10000;//ms.
const u32_t client_conn_uplink_timeout=client_conn_timeout+2000;//ms

const uint32_t server_conn_timeout=conv_timeout+60000;//ms. this should be 60s+ longer than conv_timeout,so that conv_manager can destruct convs gradually,to avoid latency glicth
//const u32_t server_conn_timeout=conv_timeout+10000;//for test

const u32_t iptables_rule_keep_interval=20;//unit: second;

enum server_current_state_t {server_idle=0,server_handshake1,server_ready};  //server state machine
enum client_current_state_t {client_idle=0,client_tcp_handshake,client_handshake1,client_handshake2,client_ready};//client state machine

enum raw_mode_t{mode_faketcp=0,mode_udp,mode_icmp,mode_end};
enum program_mode_t {unset_mode=0,client_mode,server_mode};

union current_state_t
{
	server_current_state_t server_current_state;
	client_current_state_t client_current_state;
};

extern char local_ip[100], remote_ip[100],source_ip[100];//local_ip is for -l option,remote_ip for -r option,source for --source-ip
extern u32_t local_ip_uint32,remote_ip_uint32,source_ip_uint32;//convert from last line.
extern int local_port , remote_port,source_port;//similiar to local_ip  remote_ip,buf for port.source_port=0 indicates --source-port is not enabled

extern int force_source_ip; //if --source-ip is enabled

extern id_t const_id;//an id used for connection recovery,its generated randomly,it never change since its generated

extern int udp_fd;  //for client only. client use this fd to listen and handle udp connection
extern int bind_fd; //bind only,never send or recv.  its just a dummy fd for bind,so that other program wont occupy the same port
extern int epollfd; //fd for epoll
extern int timer_fd;   //the general timer fd for client and server.for server this is not the only timer find,every connection has a timer fd.
extern int fail_time_counter;//determine if the max_fail_time is reached
extern int epoll_trigger_counter;//for debug only
extern int debug_flag;//for debug only


extern int simple_rule;  //deprecated.
extern int keep_rule; //whether to monitor the iptables rule periodly,re-add if losted
extern int auto_add_iptables_rule;//if -a is set
extern int generate_iptables_rule;//if -g is set
extern int generate_iptables_rule_add;// if --gen-add is set
extern int retry_on_error;
const  int retry_on_error_interval=10;

extern int debug_resend; // debug only

extern char key_string[1000];// -k option
extern char fifo_file[1000];


extern raw_mode_t raw_mode;

extern program_mode_t program_mode;
extern unordered_map<int, const char*> raw_mode_tostring ;

extern int about_to_exit;

extern int socket_buf_size;
extern int force_socket_buf;

extern pthread_t keep_thread;
extern int keep_thread_running;


int process_lower_level_arg();
void print_help();
void iptables_rule();
void pre_process_arg(int argc, char *argv[]);//mainly for load conf file;
int unit_test();
int set_timer(int epollfd,int &timer_fd);
int set_timer_server(int epollfd,int &timer_fd,fd64_t &fd64);
int handle_lower_level(raw_info_t &raw_info);

int add_iptables_rule(const char *);

int clear_iptables_rule();

int iptables_gen_add(const char * s,u32_t const_id);
int iptables_rule_init(const char * s,u32_t const_id,int keep);
int keep_iptables_rule();



void  signal_handler(int sig);

#endif /* MISC_H_ */
