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
#include <sys/epoll.h>
#include <sys/wait.h>
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
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <sys/time.h>
#include <time.h>
#include <sys/timerfd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <assert.h>
#include <linux/if_packet.h>
#include <byteswap.h>
#include <pthread.h>

#include<unordered_map>
#include<vector>
#include<string>
using  namespace std;


typedef unsigned long long u64_t;   //this works on most platform,avoid using the PRId64
typedef long long i64_t;

typedef unsigned int u32_t;
typedef int i32_t;


const int max_data_len=1600;
const int buf_len=max_data_len+400;
const u32_t max_handshake_conn_num=10000;
const u32_t max_ready_conn_num=1000;
const u32_t anti_replay_window_size=4000;
const int max_conv_num=10000;

const u32_t client_handshake_timeout=5000;//unit ms
const u32_t client_retry_interval=1000;//ms

const u32_t server_handshake_timeout=client_handshake_timeout+5000;// this should be longer than clients. client retry initially ,server retry passtively

const int conv_clear_ratio=10;  //conv grabage collecter check 1/10 of all conv one time
const int conn_clear_ratio=30;
const int conv_clear_min=1;
const int conn_clear_min=1;

const u32_t conv_clear_interval=3000;//ms
const u32_t conn_clear_interval=3000;//ms


const i32_t max_fail_time=0;//disable

const u32_t heartbeat_interval=1000;//ms

const u32_t timer_interval=400;//ms. this should be smaller than heartbeat_interval and retry interval;

const uint32_t conv_timeout=120000; //ms. 120 second
//const u32_t conv_timeout=30000; //for test

const u32_t client_conn_timeout=15000;//ms.
const u32_t client_conn_uplink_timeout=client_conn_timeout+2000;//ms

const uint32_t server_conn_timeout=conv_timeout+60000;//ms. this should be 60s+ longer than conv_timeout,so that conv_manager can destruct convs gradually,to avoid latency glicth
//const u32_t server_conn_timeout=conv_timeout+10000;//for test

const u32_t iptables_rule_keep_interval=15;//unit: second;

extern int about_to_exit;
extern pthread_t keep_thread;
extern int keep_thread_running;

enum raw_mode_t{mode_faketcp=0,mode_udp,mode_icmp,mode_end};
extern raw_mode_t raw_mode;
enum program_mode_t {unset_mode=0,client_mode,server_mode};
extern program_mode_t program_mode;
extern unordered_map<int, const char*> raw_mode_tostring ;
extern int socket_buf_size;
extern int force_socket_buf;

typedef u32_t id_t;

typedef u64_t iv_t;

typedef u64_t padding_t;

typedef u64_t anti_replay_seq_t;

u64_t get_current_time();
u64_t pack_u64(u32_t a,u32_t b);

u32_t get_u64_h(u64_t a);

u32_t get_u64_l(u64_t a);

char * my_ntoa(u32_t ip);

void myexit(int a);
void init_random_number_fd();
u64_t get_true_random_number_64();
u32_t get_true_random_number();
u32_t get_true_random_number_nz();
u64_t ntoh64(u64_t a);
u64_t hton64(u64_t a);
bool larger_than_u16(uint16_t a,uint16_t b);
bool larger_than_u32(u32_t a,u32_t b);
void setnonblocking(int sock);
int set_buf_size(int fd);

unsigned short csum(const unsigned short *ptr,int nbytes);

void  signal_handler(int sig);
int numbers_to_char(id_t id1,id_t id2,id_t id3,char * &data,int &len);
int char_to_numbers(const char * data,int len,id_t &id1,id_t &id2,id_t &id3);

void myexit(int a);

int add_iptables_rule(const char *);

int clear_iptables_rule();

int iptables_gen_add(const char * s,u32_t const_id);
int iptables_rule_init(const char * s,u32_t const_id,int keep);
int keep_iptables_rule();

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

#endif /* COMMON_H_ */
