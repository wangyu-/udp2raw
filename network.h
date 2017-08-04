/*
 * network.h
 *
 *  Created on: Jul 29, 2017
 *      Author: wangyu
 */

#ifndef NETWORK_H_
#define NETWORK_H_

extern int raw_recv_fd;
extern int raw_send_fd;
extern int seq_mode;
extern int filter_port;
extern u32_t bind_address_uint32;
extern int disable_bpf_filter;

struct icmphdr
{
	uint8_t type;
	uint8_t code;
	uint16_t check_sum;
	uint16_t id;
	uint16_t seq;
};

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

struct packet_info_t  //todo change this to union
{
	uint8_t protocol;
	//ip_part:
	u32_t src_ip;
	uint16_t src_port;

	u32_t dst_ip;
	uint16_t dst_port;

	//tcp_part:
	bool syn,ack,psh,rst;

	u32_t seq,ack_seq;


	u32_t ts,ts_ack;


	uint16_t icmp_seq;

	bool has_ts;
	packet_info_t();
};

struct raw_info_t
{
	packet_info_t send_info;
	packet_info_t recv_info;

	int last_send_len;
	int last_recv_len;

	u32_t reserved_seq;
	//uint32_t first_seq,first_ack_seq;

};//g_raw_info;


int init_raw_socket();

void init_filter(int port);

void remove_filter();


int send_raw_ip(raw_info_t &raw_info,const char * payload,int payloadlen);

int peek_raw(packet_info_t &peek_info);

int recv_raw_ip(raw_info_t &raw_info,char * &payload,int &payloadlen);

int send_raw_icmp(raw_info_t &raw_info, const char * payload, int payloadlen);

int send_raw_udp(raw_info_t &raw_info, const char * payload, int payloadlen);

int send_raw_tcp(raw_info_t &raw_info,const char * payload, int payloadlen);

int recv_raw_icmp(raw_info_t &raw_info, char *&payload, int &payloadlen);

int recv_raw_udp(raw_info_t &raw_info, char *&payload, int &payloadlen);

int recv_raw_tcp(raw_info_t &raw_info,char * &payload,int &payloadlen);

//int send_raw(raw_info_t &raw_info,const char * payload,int payloadlen);

//int recv_raw(raw_info_t &raw_info,char * &payload,int &payloadlen);

int send_raw0(raw_info_t &raw_info,const char * payload,int payloadlen);

int recv_raw0(raw_info_t &raw_info,char * &payload,int &payloadlen);

int after_send_raw0(raw_info_t &raw_info);

int after_recv_raw0(raw_info_t &raw_info);


#endif /* NETWORK_H_ */
