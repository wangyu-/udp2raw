/*
 * common.h
 *
 *  Created on: Jul 29, 2017
 *      Author: wangyu
 */

#ifndef COMMON_H_
#define COMMON_H_


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
#include <assert.h>

#include <unordered_map>

using  namespace std;

const int max_data_len=65535;
const int buf_len=max_data_len+200;
const uint32_t max_handshake_conn_num=10000;
const uint32_t max_ready_conn_num=1000;
const uint32_t anti_replay_window_size=1000;
const int max_conv_num=10000;

const uint32_t client_handshake_timeout=3000;
const uint32_t server_handshake_timeout=10000;// this should be much longer than clients. client retry initially ,server retry passtively

const int conv_clear_ratio=10;  //conv grabage collecter check 1/10 of all conv one time
const int conn_clear_ratio=10;
const int conv_clear_min=5;
const int conn_clear_min=1;


const uint32_t heartbeat_interval=1000;

const uint32_t timer_interval=400;//this should be smaller than heartbeat_interval

const int RETRY_TIME=3;

//const uint32_t conv_timeout=120000; //120 second
const uint32_t conv_timeout=20000; //for test

const uint32_t client_conn_timeout=10000;

//const uint32_t server_conn_timeout=conv_timeout+60000;//this should be 60s+ longer than conv_timeout,so that conv_manager can destruct convs gradually,to avoid latency glicth
const uint32_t server_conn_timeout=conv_timeout+10000;//for test



enum raw_mode_t{mode_faketcp=1,mode_udp,mode_icmp,mode_end};
extern raw_mode_t raw_mode;
enum program_mode_t {unset_mode=0,client_mode,server_mode};
extern program_mode_t program_mode;
extern map<int, string> raw_mode_tostring ;
extern int socket_buf_size;

typedef uint32_t id_t;

typedef uint64_t iv_t;

typedef uint64_t anti_replay_seq_t;

uint64_t get_current_time();
uint64_t pack_u64(uint32_t a,uint32_t b);

uint32_t get_u64_h(uint64_t a);

uint32_t get_u64_l(uint64_t a);

char * my_ntoa(uint32_t ip);

void myexit(int a);
void init_random_number_fd();
uint64_t get_true_random_number_64();
uint32_t get_true_random_number();
uint32_t get_true_random_number_nz();
uint64_t ntoh64(uint64_t a);
uint64_t hton64(uint64_t a);

void setnonblocking(int sock);
int set_buf_size(int fd);

unsigned short csum(const unsigned short *ptr,int nbytes);

void  INThandler(int sig);
int numbers_to_char(id_t id1,id_t id2,id_t id3,char * &data,int &len);
int char_to_numbers(const char * data,int len,id_t &id1,id_t &id2,id_t &id3);


#endif /* COMMON_H_ */
