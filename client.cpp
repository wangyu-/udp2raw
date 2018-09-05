#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "log.h"
#include "lib/md5.h"
#include "encrypt.h"
#include "fd_manager.h"


int client_on_timer(conn_info_t &conn_info) //for client. called when a timer is ready in epoll
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;
	conn_info.blob->conv_manager.c.clear_inactive();
	mylog(log_trace,"timer!\n");

	mylog(log_trace,"roller my %d,oppsite %d,%lld\n",int(conn_info.my_roller),int(conn_info.oppsite_roller),conn_info.last_oppsite_roller_time);

	mylog(log_trace,"<client_on_timer,send_info.ts_ack= %u>\n",send_info.ts_ack);

	if(raw_info.disabled)
	{
		conn_info.state.client_current_state=client_idle;
		conn_info.my_id=get_true_random_number_nz();

		mylog(log_info,"state back to client_idle\n");
	}

	if(conn_info.state.client_current_state==client_idle)
	{
		raw_info.rst_received=0;
		raw_info.disabled=0;

		fail_time_counter++;
		if(max_fail_time>0&&fail_time_counter>max_fail_time)
		{
			mylog(log_fatal,"max_fail_time exceed\n");
			myexit(-1);
		}

		conn_info.blob->anti_replay.re_init();
		conn_info.my_id = get_true_random_number_nz(); ///todo no need to do this everytime



		address_t tmp_addr;
		//u32_t new_ip=0;
		if(!force_source_ip)
		{
			if(get_src_adress2(tmp_addr,remote_addr)!=0)
			{
				mylog(log_warn,"get_src_adress() failed\n");
				return -1;
			}
			//source_addr=new_addr;
			//source_addr.set_port(0);

			mylog(log_info,"source_addr is now %s\n",tmp_addr.get_ip());

			/*
			if(new_ip!=source_ip_uint32)
			{
				mylog(log_info,"source ip changed from %s to ",my_ntoa(source_ip_uint32));
				log_bare(log_info,"%s\n",my_ntoa(new_ip));
				source_ip_uint32=new_ip;
				send_info.src_ip=new_ip;
			}*/

		}
		else
		{
			tmp_addr=source_addr;
		}

		send_info.new_src_ip.from_address_t(tmp_addr);

		if (force_source_port == 0)
		{
			send_info.src_port = client_bind_to_a_new_port2(bind_fd,tmp_addr);
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
			if(use_tcp_dummy_socket)
			{
				setnonblocking(bind_fd);
				int ret=connect(bind_fd,(struct sockaddr *)&remote_addr.inner,remote_addr.get_len());
				mylog(log_info,"ret=%d,errno=%s,%d %s\n",ret,get_sock_error(),bind_fd,remote_addr.get_str());
				conn_info.state.client_current_state=client_tcp_handshake_dummy;
				mylog(log_info,"state changed from client_idle to client_tcp_handshake_dummy\n");
			}
			else
			{

				conn_info.state.client_current_state=client_tcp_handshake;
				mylog(log_info,"state changed from client_idle to client_tcp_handshake\n");
			}

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
	else if(conn_info.state.client_current_state==client_tcp_handshake_dummy)
	{
		assert(raw_mode==mode_faketcp);
		if (get_current_time() - conn_info.last_state_time > client_handshake_timeout)
		{
			conn_info.state.client_current_state = client_idle;
			mylog(log_info, "state back to client_idle from client_tcp_handshake_dummy\n");
			return 0;

		}
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
					raw_info.reserved_send_seq=send_info.seq;
				}
				send_info.seq=raw_info.reserved_send_seq;
				send_info.psh = 0;
				send_info.syn = 0;
				send_info.ack = 1;

				if(!use_tcp_dummy_socket)
					send_raw0(raw_info, 0, 0);

				send_handshake(raw_info,conn_info.my_id,0,const_id);

				send_info.seq+=raw_info.send_info.data_len;
			}
			else
			{

				send_handshake(raw_info,conn_info.my_id,0,const_id);
				if(raw_mode==mode_icmp)
					send_info.my_icmp_seq++;
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
					send_info.ack_seq=recv_info.seq+raw_info.recv_info.data_len;
					send_info.ts_ack=recv_info.ts;
					raw_info.reserved_send_seq=send_info.seq;
				}
				send_info.seq=raw_info.reserved_send_seq;
				send_handshake(raw_info,conn_info.my_id,conn_info.oppsite_id,const_id);
				send_info.seq+=raw_info.send_info.data_len;

			}
			else
			{

				send_handshake(raw_info,conn_info.my_id,conn_info.oppsite_id,const_id);
				if(raw_mode==mode_icmp)
					send_info.my_icmp_seq++;
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

		if(get_current_time()- conn_info.last_oppsite_roller_time>client_conn_uplink_timeout)
		{
			conn_info.state.client_current_state=client_idle;
			conn_info.my_id=get_true_random_number_nz();
			mylog(log_info,"state back to client_idle from  client_ready bc of client-->server direction timeout\n");
		}


		if(get_current_time()-conn_info.last_hb_sent_time<heartbeat_interval)
		{
			return 0;
		}



		mylog(log_debug,"heartbeat sent <%x,%x>\n",conn_info.oppsite_id,conn_info.my_id);

		if(hb_mode==0)
			send_safer(conn_info,'h',hb_buf,0);/////////////send
		else
			send_safer(conn_info,'h',hb_buf,hb_len);
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
int client_on_raw_recv(conn_info_t &conn_info) //called when raw fd received a packet.
{
	char* data;int data_len;
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;

	raw_info_t &raw_info=conn_info.raw_info;

	mylog(log_trace,"<client_on_raw_recv,send_info.ts_ack= %u>\n",send_info.ts_ack);
	if(pre_recv_raw_packet()<0) return -1;

	if(conn_info.state.client_current_state==client_idle )
	{
		discard_raw_packet();
		//recv(raw_recv_fd, 0,0, 0  );
	}
	else if(conn_info.state.client_current_state==client_tcp_handshake||conn_info.state.client_current_state==client_tcp_handshake_dummy)//received syn ack
	{
		assert(raw_mode==mode_faketcp);
		if(recv_raw0(raw_info,data,data_len)<0)
		{
			return -1;
		}
		if(!recv_info.new_src_ip.equal(send_info.new_dst_ip)||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_debug,"unexpected adress %s %s %d %d\n",recv_info.new_src_ip.get_str1(),send_info.new_dst_ip.get_str2(),recv_info.src_port,send_info.dst_port);
			return -1;
		}
		if(data_len==0&&raw_info.recv_info.syn==1&&raw_info.recv_info.ack==1)
		{
			if(conn_info.state.client_current_state==client_tcp_handshake)
			{
				if(recv_info.ack_seq!=send_info.seq+1)
				{
					mylog(log_debug,"seq ack_seq mis match\n");
								return -1;
				}
				mylog(log_info,"state changed from client_tcp_handshake to client_handshake1\n");
			}
			else
			{
				send_info.seq=recv_info.ack_seq-1;
				mylog(log_info,"state changed from client_tcp_dummy to client_handshake1\n");
				//send_info.ack_seq=recv_info.seq+1;
			}
			conn_info.state.client_current_state = client_handshake1;

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
		if(!recv_info.new_src_ip.equal(send_info.new_dst_ip)||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_debug,"unexpected adress %s %s %d %d\n",recv_info.new_src_ip.get_str1(),send_info.new_dst_ip.get_str2(),recv_info.src_port,send_info.dst_port);
			return -1;
		}
		if(data_len<int( 3*sizeof(my_id_t)))
		{
			mylog(log_debug,"too short to be a handshake\n");
			return -1;
		}
		my_id_t tmp_oppsite_id;
		memcpy(&tmp_oppsite_id,&data[0],sizeof(tmp_oppsite_id));
		tmp_oppsite_id=ntohl(tmp_oppsite_id);

		my_id_t tmp_my_id;
		memcpy(&tmp_my_id,&data[sizeof(my_id_t)],sizeof(tmp_my_id));
		tmp_my_id=ntohl(tmp_my_id);

		my_id_t tmp_oppsite_const_id;
		memcpy(&tmp_oppsite_const_id,&data[sizeof(my_id_t)*2],sizeof(tmp_oppsite_const_id));
		tmp_oppsite_const_id=ntohl(tmp_oppsite_const_id);

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
		if(!recv_info.new_src_ip.equal(send_info.new_dst_ip)||recv_info.src_port!=send_info.dst_port)
		{
			mylog(log_warn,"unexpected adress %s %s %d %d,this shouldnt happen.\n",recv_info.new_src_ip.get_str1(),send_info.new_dst_ip.get_str2(),recv_info.src_port,send_info.dst_port);
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
		if(data_len>=0&&type=='h')
		{
			mylog(log_debug,"[hb]heart beat received,oppsite_roller=%d\n",int(conn_info.oppsite_roller));
			conn_info.last_hb_recv_time=get_current_time();
			return 0;
		}
		else if(data_len>= int( sizeof(u32_t))&&type=='d')
		{
			mylog(log_trace,"received a data from fake tcp,len:%d\n",data_len);

			if(hb_mode==0)
				conn_info.last_hb_recv_time=get_current_time();

			u32_t tmp_conv_id;
			memcpy(&tmp_conv_id,&data[0],sizeof(tmp_conv_id));
			tmp_conv_id=ntohl(tmp_conv_id);

			if(!conn_info.blob->conv_manager.c.is_conv_used(tmp_conv_id))
			{
				mylog(log_info,"unknow conv %d,ignore\n",tmp_conv_id);
				return 0;
			}

			conn_info.blob->conv_manager.c.update_active_time(tmp_conv_id);

			//u64_t u64=conn_info.blob->conv_manager.c.find_data_by_conv(tmp_conv_id);
			address_t tmp_addr=conn_info.blob->conv_manager.c.find_data_by_conv(tmp_conv_id);

			//sockaddr_in tmp_sockaddr={0};

			//tmp_sockaddr.sin_family = AF_INET;
			//tmp_sockaddr.sin_addr.s_addr=(u64>>32u);

			//tmp_sockaddr.sin_port= htons(uint16_t((u64<<32u)>>32u));


			int ret=sendto(udp_fd,data+sizeof(u32_t),data_len -(sizeof(u32_t)),0,(struct sockaddr *)&tmp_addr.inner,tmp_addr.get_len());

			if(ret<0)
			{
		    	mylog(log_warn,"sento returned %d,%s,%02x,%s\n",ret,get_sock_error(),int(tmp_addr.get_type()),tmp_addr.get_str());
				//perror("ret<0");
			}
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
int client_on_udp_recv(conn_info_t &conn_info)
{
	int recv_len;
	char buf[buf_len];
	address_t::storage_t udp_new_addr_in={0};
	socklen_t udp_new_addr_len = sizeof(address_t::storage_t);
	if ((recv_len = recvfrom(udp_fd, buf, max_data_len+1, 0,
			(struct sockaddr *) &udp_new_addr_in, &udp_new_addr_len)) == -1) {
		mylog(log_debug,"recv_from error,%s\n",get_sock_error());
		return -1;
		//myexit(1);
	};

	if(recv_len==max_data_len+1)
	{
		mylog(log_warn,"huge packet, data_len > %d,dropped\n",max_data_len);
		return -1;
	}

	if(recv_len>=mtu_warn)
	{
		mylog(log_warn,"huge packet,data len=%d (>=%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ",recv_len,mtu_warn);
	}

	address_t tmp_addr;
	tmp_addr.from_sockaddr((sockaddr *)&udp_new_addr_in,udp_new_addr_len);
	u32_t conv;

	if(!conn_info.blob->conv_manager.c.is_data_used(tmp_addr))
	{
		if(conn_info.blob->conv_manager.c.get_size() >=max_conv_num)
		{
			mylog(log_warn,"ignored new udp connect bc max_conv_num exceed\n");
			return -1;
		}
		conv=conn_info.blob->conv_manager.c.get_new_conv();
		conn_info.blob->conv_manager.c.insert_conv(conv,tmp_addr);
		mylog(log_info,"new packet from %s,conv_id=%x\n",tmp_addr.get_str(),conv);
	}
	else
	{
		conv=conn_info.blob->conv_manager.c.find_conv_by_data(tmp_addr);
	}

	conn_info.blob->conv_manager.c.update_active_time(conv);

	if(conn_info.state.client_current_state==client_ready)
	{
		send_data_safer(conn_info,buf,recv_len,conv);
	}
	return 0;
}
void udp_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	conn_info_t & conn_info= *((conn_info_t*)watcher->data);
	client_on_udp_recv(conn_info);
}
void raw_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	//assert(0==1);
	conn_info_t & conn_info= *((conn_info_t*)watcher->data);
	client_on_raw_recv(conn_info);
}
void clear_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	conn_info_t & conn_info= *((conn_info_t*)watcher->data);
	client_on_timer(conn_info);
}
void fifo_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	conn_info_t & conn_info= *((conn_info_t*)watcher->data);

	char buf[buf_len];
	int fifo_fd=watcher->fd;

	int len=read (fifo_fd, buf, sizeof (buf));
	if(len<0)
	{
		mylog(log_warn,"fifo read failed len=%d,errno=%s\n",len,get_sock_error());
		return;
	}
	buf[len]=0;
	while(len>=1&&buf[len-1]=='\n')
		buf[len-1]=0;
	mylog(log_info,"got data from fifo,len=%d,s=[%s]\n",len,buf);
	if(strcmp(buf,"reconnect")==0)
	{
		mylog(log_info,"received command: reconnect\n");
		conn_info.state.client_current_state=client_idle;
		conn_info.my_id=get_true_random_number_nz();
	}
	else
	{
		mylog(log_info,"unknown command\n");
	}

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
			int index;
			init_ifindex(if_name,raw_send_fd,index);
			//init_ifindex(if_name);
			memset(&send_info.addr_ll, 0, sizeof(send_info.addr_ll));
			send_info.addr_ll.sll_family = AF_PACKET;
			send_info.addr_ll.sll_ifindex =index;
			send_info.addr_ll.sll_halen = ETHER_ADDR_LEN;
			send_info.addr_ll.sll_protocol = htons(ETH_P_IP);
			memcpy(&send_info.addr_ll.sll_addr, dest_hw_addr, ETHER_ADDR_LEN);
			mylog(log_info,"we are running at lower-level (manual) mode\n");
		}
		else
		{
			u32_t dest_ip;
			string if_name_string;
			string hw_string;
			assert(remote_addr.get_type()==AF_INET);

			if(retry_on_error==0)
			{
				if(find_lower_level_info(remote_addr.inner.ipv4.sin_addr.s_addr,dest_ip,if_name_string,hw_string)!=0)
				{
					mylog(log_fatal,"auto detect lower-level info failed for %s,specific it manually\n",remote_addr.get_ip());
					myexit(-1);
				}
			}
			else
			{
				int ok=0;
				while(!ok)
				{
					if(find_lower_level_info(remote_addr.inner.ipv4.sin_addr.s_addr,dest_ip,if_name_string,hw_string)!=0)
					{
						mylog(log_warn,"auto detect lower-level info failed for %s,retry in %d seconds\n",remote_addr.get_ip(),retry_on_error_interval);
						sleep(retry_on_error_interval);
					}
					else
					{
						ok=1;
					}

				}
			}
			mylog(log_info,"we are running at lower-level (auto) mode,%s %s %s\n",my_ntoa(dest_ip),if_name_string.c_str(),hw_string.c_str());

			u32_t hw[6];
			memset(hw, 0, sizeof(hw));
			sscanf(hw_string.c_str(), "%x:%x:%x:%x:%x:%x",&hw[0], &hw[1], &hw[2],
					&hw[3], &hw[4], &hw[5]);

			mylog(log_warn,
					"make sure this is correct:   if_name=<%s>  dest_mac_adress=<%02x:%02x:%02x:%02x:%02x:%02x>  \n",
					if_name_string.c_str(), hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
			for (int i = 0; i < 6; i++) {
				dest_hw_addr[i] = uint8_t(hw[i]);
			}

			//mylog(log_fatal,"--lower-level auto for client hasnt been implemented\n");
			int index;
			init_ifindex(if_name_string.c_str(),raw_send_fd,index);

			memset(&send_info.addr_ll, 0, sizeof(send_info.addr_ll));
			send_info.addr_ll.sll_family = AF_PACKET;
			send_info.addr_ll.sll_ifindex = index;
			send_info.addr_ll.sll_halen = ETHER_ADDR_LEN;
			send_info.addr_ll.sll_protocol = htons(ETH_P_IP);
			memcpy(&send_info.addr_ll.sll_addr, dest_hw_addr, ETHER_ADDR_LEN);
			//mylog(log_info,"we are running at lower-level (manual) mode\n");
		}

	}

	send_info.src_port=0;
	memset(&send_info.new_src_ip,0,sizeof(send_info.new_src_ip));

	int i, j, k;int ret;


	send_info.new_dst_ip.from_address_t(remote_addr);
	send_info.dst_port=remote_addr.get_port();


    udp_fd=socket(local_addr.get_type(), SOCK_DGRAM, IPPROTO_UDP);
    set_buf_size(udp_fd,socket_buf_size);


	if (::bind(udp_fd, (struct sockaddr*) &local_addr.inner, local_addr.get_len()) == -1) {
		mylog(log_fatal,"socket bind error\n");
		//perror("socket bind error");
		myexit(1);
	}
	setnonblocking(udp_fd);

	//epollfd = epoll_create1(0);

	//const int max_events = 4096;
	//struct epoll_event ev, events[max_events];
	//if (epollfd < 0) {
	//	mylog(log_fatal,"epoll return %d\n", epollfd);
	//	myexit(-1);
	//}

	struct ev_loop * loop= ev_default_loop(0);
	assert(loop != NULL);

	//ev.events = EPOLLIN;
	//ev.data.u64 = udp_fd;
	//ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, udp_fd, &ev);
	//if (ret!=0) {
	//	mylog(log_fatal,"add  udp_listen_fd error\n");
	//	myexit(-1);
	//}


	struct ev_io udp_accept_watcher;

	udp_accept_watcher.data=&conn_info;
    ev_io_init(&udp_accept_watcher, udp_accept_cb, udp_fd, EV_READ);
    ev_io_start(loop, &udp_accept_watcher);


	//ev.events = EPOLLIN;
	//ev.data.u64 = raw_recv_fd;

	//ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
	//if (ret!= 0) {
	//	mylog(log_fatal,"add raw_fd error\n");
	//	myexit(-1);
	//}

	struct ev_io raw_recv_watcher;

	raw_recv_watcher.data=&conn_info;
    ev_io_init(&raw_recv_watcher, raw_recv_cb, raw_recv_fd, EV_READ);
    ev_io_start(loop, &raw_recv_watcher);

	//set_timer(epollfd,timer_fd);
	struct ev_timer clear_timer;

	clear_timer.data=&conn_info;
	ev_timer_init(&clear_timer, clear_timer_cb, 0, timer_interval/1000.0);
	ev_timer_start(loop, &clear_timer);

	mylog(log_debug,"send_raw : from %s %d  to %s %d\n",send_info.new_src_ip.get_str1(),send_info.src_port,send_info.new_dst_ip.get_str2(),send_info.dst_port);

	int fifo_fd=-1;

	struct ev_io fifo_watcher;
	fifo_watcher.data=&conn_info;

	if(fifo_file[0]!=0)
	{
		fifo_fd=create_fifo(fifo_file);

	    ev_io_init(&fifo_watcher, fifo_cb, fifo_fd, EV_READ);
	    ev_io_start(loop, &fifo_watcher);

		mylog(log_info,"fifo_file=%s\n",fifo_file);
	}

	ev_run(loop, 0);
	return 0;
}
