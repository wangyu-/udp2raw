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

extern int debug_resend; // debug only

extern char key_string[1000];// -k option

int process_lower_level_arg();
void print_help();
void iptables_rule();
void pre_process_arg(int argc, char *argv[]);//mainly for load conf file;
int unit_test();
int set_timer(int epollfd,int &timer_fd);
int set_timer_server(int epollfd,int &timer_fd);
int handle_lower_level(raw_info_t &raw_info);

#endif /* MISC_H_ */
