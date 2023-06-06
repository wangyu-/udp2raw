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

const int disable_conv_clear = 0;  // a udp connection in the multiplexer is called conversation in this program,conv for short.

struct anti_replay_t  // its for anti replay attack,similar to openvpn/ipsec 's anti replay window
{
    u64_t max_packet_received;
    char window[anti_replay_window_size];
    anti_replay_seq_t anti_replay_seq;
    anti_replay_seq_t get_new_seq_for_send();
    anti_replay_t();
    void re_init();

    int is_vaild(u64_t seq);
};  // anti_replay;

void server_clear_function(u64_t u64);

#include <type_traits>

template <class T>
struct conv_manager_t  // manage the udp connections
{
    // typedef hash_map map;
    unordered_map<T, u32_t> data_to_conv;  // conv and u64 are both supposed to be uniq
    unordered_map<u32_t, T> conv_to_data;

    lru_collector_t<u32_t> lru;
    // unordered_map<u32_t,u64_t> conv_last_active_time;

    // unordered_map<u32_t,u64_t>::iterator clear_it;

    void (*additional_clear_function)(T data) = 0;

    long long last_clear_time;

    conv_manager_t() {
        // clear_it=conv_last_active_time.begin();
        long long last_clear_time = 0;
        additional_clear_function = 0;
    }
    ~conv_manager_t() {
        clear();
    }
    int get_size() {
        return conv_to_data.size();
    }
    void reserve() {
        data_to_conv.reserve(10007);
        conv_to_data.reserve(10007);
        // conv_last_active_time.reserve(10007);

        lru.mp.reserve(10007);
    }
    void clear() {
        if (disable_conv_clear) return;

        if (additional_clear_function != 0) {
            for (auto it = conv_to_data.begin(); it != conv_to_data.end(); it++) {
                // int fd=int((it->second<<32u)>>32u);
                additional_clear_function(it->second);
            }
        }
        data_to_conv.clear();
        conv_to_data.clear();

        lru.clear();
        // conv_last_active_time.clear();

        // clear_it=conv_last_active_time.begin();
    }
    u32_t get_new_conv() {
        u32_t conv = get_true_random_number_nz();
        while (conv_to_data.find(conv) != conv_to_data.end()) {
            conv = get_true_random_number_nz();
        }
        return conv;
    }
    int is_conv_used(u32_t conv) {
        return conv_to_data.find(conv) != conv_to_data.end();
    }
    int is_data_used(T data) {
        return data_to_conv.find(data) != data_to_conv.end();
    }
    u32_t find_conv_by_data(T data) {
        return data_to_conv[data];
    }
    T find_data_by_conv(u32_t conv) {
        return conv_to_data[conv];
    }
    int update_active_time(u32_t conv) {
        // return conv_last_active_time[conv]=get_current_time();
        lru.update(conv);
        return 0;
    }
    int insert_conv(u32_t conv, T data) {
        data_to_conv[data] = conv;
        conv_to_data[conv] = data;
        // conv_last_active_time[conv]=get_current_time();
        lru.new_key(conv);
        return 0;
    }
    int erase_conv(u32_t conv) {
        if (disable_conv_clear) return 0;
        T data = conv_to_data[conv];
        if (additional_clear_function != 0) {
            additional_clear_function(data);
        }
        conv_to_data.erase(conv);
        data_to_conv.erase(data);
        // conv_last_active_time.erase(conv);
        lru.erase(conv);
        return 0;
    }
    int clear_inactive(char *info = 0) {
        if (get_current_time() - last_clear_time > conv_clear_interval) {
            last_clear_time = get_current_time();
            return clear_inactive0(info);
        }
        return 0;
    }
    int clear_inactive0(char *info) {
        if (disable_conv_clear) return 0;

        unordered_map<u32_t, u64_t>::iterator it;
        unordered_map<u32_t, u64_t>::iterator old_it;

        // map<uint32_t,uint64_t>::iterator it;
        int cnt = 0;
        // it=clear_it;
        int size = lru.size();
        int num_to_clean = size / conv_clear_ratio + conv_clear_min;  // clear 1/10 each time,to avoid latency glitch

        num_to_clean = min(num_to_clean, size);

        my_time_t current_time = get_current_time();
        for (;;) {
            if (cnt >= num_to_clean) break;
            if (lru.empty()) break;

            u32_t conv;
            my_time_t ts = lru.peek_back(conv);

            if (current_time - ts < conv_timeout) break;

            erase_conv(conv);
            if (info == 0) {
                mylog(log_info, "conv %x cleared\n", conv);
            } else {
                mylog(log_info, "[%s]conv %x cleared\n", info, conv);
            }
            cnt++;
        }
        return 0;
    }

    /*
conv_manager_t();
~conv_manager_t();
int get_size();
void reserve();
void clear();
u32_t get_new_conv();
int is_conv_used(u32_t conv);
int is_u64_used(T u64);
u32_t find_conv_by_u64(T u64);
T find_u64_by_conv(u32_t conv);
int update_active_time(u32_t conv);
int insert_conv(u32_t conv,T u64);
int erase_conv(u32_t conv);
int clear_inactive(char * ip_port=0);
int clear_inactive0(char * ip_port);*/
};  // g_conv_manager;

struct blob_t : not_copy_able_t  // used in conn_info_t.
{
    union tmp_union_t  // conv_manager_t is here to avoid copying when a connection is recovered
    {
        conv_manager_t<address_t> c;
        conv_manager_t<u64_t> s;
        // avoid templates here and there, avoid pointer and type cast
        tmp_union_t() {
            if (program_mode == client_mode) {
                new (&c) conv_manager_t<address_t>();
            } else {
                assert(program_mode == server_mode);
                new (&s) conv_manager_t<u64_t>();
            }
        }
        ~tmp_union_t() {
            if (program_mode == client_mode) {
                c.~conv_manager_t<address_t>();
            } else {
                assert(program_mode == server_mode);
                s.~conv_manager_t<u64_t>();
            }
        }
    } conv_manager;

    anti_replay_t anti_replay;  // anti_replay_t is here bc its huge,its allocation is delayed.
};
struct conn_info_t  // stores info for a raw connection.for client ,there is only one connection,for server there can be thousand of connection since server can
// handle multiple clients
{
    current_state_t state;

    raw_info_t raw_info;
    u64_t last_state_time;
    u64_t last_hb_sent_time;  // client re-use this for retry
    u64_t last_hb_recv_time;
    // long long last_resent_time;

    my_id_t my_id;
    my_id_t oppsite_id;

    fd64_t timer_fd64;
    fd64_t udp_fd64;

    my_id_t oppsite_const_id;

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
    conn_info_t(const conn_info_t &b);
    conn_info_t &operator=(const conn_info_t &b);
    ~conn_info_t();
};  // g_conn_info;

struct conn_manager_t  // manager for connections. for client,we dont need conn_manager since there is only one connection.for server we use one conn_manager for all connections
{
    u32_t ready_num;

    // unordered_map<int,conn_info_t *> udp_fd_mp;  //a bit dirty to used pointer,but can void unordered_map search
    // unordered_map<int,conn_info_t *> timer_fd_mp;//we can use pointer here since unordered_map.rehash() uses shallow copy

    unordered_map<my_id_t, conn_info_t *> const_id_mp;

    unordered_map<address_t, conn_info_t *> mp;  // put it at end so that it de-consturcts first

    // lru_collector_t<address_t> lru;

    unordered_map<address_t, conn_info_t *>::iterator clear_it;

    long long last_clear_time;

    conn_manager_t();
    int exist(address_t addr);
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
    conn_info_t *&find_insert_p(address_t addr);  // be aware,the adress may change after rehash //not true?
    conn_info_t &find_insert(address_t addr);     // be aware,the adress may change after rehash

    int erase(unordered_map<address_t, conn_info_t *>::iterator erase_it);
    int clear_inactive();
    int clear_inactive0();
};

extern conn_manager_t conn_manager;

void server_clear_function(u64_t u64);

int send_bare(raw_info_t &raw_info, const char *data, int len);  // send function with encryption but no anti replay,this is used when client and server verifys each other
// you have to design the protocol carefully, so that you wont be affect by relay attack
// int reserved_parse_bare(const char *input,int input_len,char* & data,int & len); // a sub function used in recv_bare
int recv_bare(raw_info_t &raw_info, char *&data, int &len);  // recv function with encryption but no anti replay,this is used when client and server verifys each other
// you have to design the protocol carefully, so that you wont be affect by relay attack
int send_handshake(raw_info_t &raw_info, my_id_t id1, my_id_t id2, my_id_t id3);         // a warp for send_bare for sending handshake(this is not tcp handshake) easily
int send_safer(conn_info_t &conn_info, char type, const char *data, int len);            // safer transfer function with anti-replay,when mutually verification is done.
int send_data_safer(conn_info_t &conn_info, const char *data, int len, u32_t conv_num);  // a wrap for  send_safer for transfer data.
// int reserved_parse_safer(conn_info_t &conn_info,const char * input,int input_len,char &type,char* &data,int &len);//subfunction for recv_safer,allow overlap

// int recv_safer(conn_info_t &conn_info,char &type,char* &data,int &len);///safer transfer function with anti-replay,when mutually verification is done.

int recv_safer_multi(conn_info_t &conn_info, vector<char> &type_arr, vector<string> &data_arr);  // new api for handle gro
#endif                                                                                           /* CONNECTION_H_ */
