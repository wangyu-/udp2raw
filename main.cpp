#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "log.h"
#include "lib/md5.h"
#include "encrypt.h"
#include "fd_manager.h"


char hb_buf[buf_len];

int on_epoll_recv_event=0;  //TODO, just a flag to help detect epoll infinite shoot


u32_t detect_interval=1500;
u64_t laste_detect_time=0;

int use_udp_for_detection=0;
int use_tcp_for_detection=1;


int client_on_timer(conn_info_t &conn_info) //for client. called when a timer is ready in epoll
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;
	conn_info.blob->conv_manager.clear_inactive();
	mylog(log_trace,"timer!\n");

	mylog(log_trace,"roller my %d,oppsite %d,%lld\n",int(conn_info.my_roller),int(conn_info.oppsite_roller),conn_info.last_oppsite_roller_time);

	mylog(log_trace,"<client_on_timer,send_info.ts_ack= %u>\n",send_info.ts_ack);


	//mylog(log_debug,"pcap cnt :%d\n",pcap_cnt);
	if(send_with_pcap&&!pcap_header_captured)
	{

		if(get_current_time()-laste_detect_time>detect_interval)
		{
			laste_detect_time=get_current_time();
		}
		else
		{
			return 0;
		}

		struct sockaddr_in remote_addr_in={0};

		socklen_t slen = sizeof(sockaddr_in);
		//memset(&remote_addr_in, 0, sizeof(remote_addr_in));
		int port=get_true_random_number()%65534+1;
		remote_addr_in.sin_family = AF_INET;
		remote_addr_in.sin_port = htons(port);
		remote_addr_in.sin_addr.s_addr = remote_ip_uint32;

		if(use_udp_for_detection)
		{
			int new_udp_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(new_udp_fd<0)
			{
				mylog(log_warn,"create new_udp_fd error\n");
				return -1;
			}
			setnonblocking(new_udp_fd);
			u64_t tmp=get_true_random_number();

			int ret=sendto(new_udp_fd,(char*)(&tmp),sizeof(tmp),0,(struct sockaddr *)&remote_addr_in,sizeof(remote_addr_in));
			if(ret==-1)
			{
				mylog(log_warn,"sendto() failed\n");
			}
			close(new_udp_fd);
		}

		if(use_tcp_for_detection)
		{
			static int last_tcp_fd=-1;

			int new_tcp_fd=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if(new_tcp_fd<0)
			{
				mylog(log_warn,"create new_tcp_fd error\n");
				return -1;
			}
			setnonblocking(new_tcp_fd);
			connect(new_tcp_fd,(struct sockaddr *)&remote_addr_in,sizeof(remote_addr_in));
			if(last_tcp_fd!=-1)
				close(last_tcp_fd);
			last_tcp_fd=new_tcp_fd;
			//close(new_tcp_fd);
		}



		mylog(log_info,"waiting for a use-able packet to be captured\n");

		return 0;
	}

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



		u32_t new_ip=0;
		if(!force_source_ip&&get_src_adress(new_ip,remote_ip_uint32,remote_port)==0)
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
			send_info.src_port = client_bind_to_a_new_port(bind_fd,local_ip_uint32);
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
					raw_info.reserved_send_seq=send_info.seq;
				}
				send_info.seq=raw_info.reserved_send_seq;
				send_info.psh = 0;
				send_info.syn = 0;
				send_info.ack = 1;
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

	if(conn_info.state.client_current_state==client_idle )
	{
		g_packet_buf_cnt--;
		//recv(raw_recv_fd, 0,0, 0  );
		//pthread_mutex_lock(&queue_mutex);
		//my_queue.pop_front();
		//pthread_mutex_unlock(&queue_mutex);
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

void udp_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	char buf[buf_len];

	conn_info_t & conn_info= *((conn_info_t*)watcher->data);;

	int recv_len;
	struct sockaddr_in udp_new_addr_in={0};
	socklen_t udp_new_addr_len = sizeof(sockaddr_in);
	if ((recv_len = recvfrom(udp_fd, buf, max_data_len+1, 0,
			(struct sockaddr *) &udp_new_addr_in, &udp_new_addr_len)) == -1) {
		mylog(log_error,"recv_from error,this shouldnt happen at client\n");
		myexit(1);
	};

	if(recv_len==max_data_len+1)
	{
		mylog(log_warn,"huge packet, data_len > %d,dropped\n",max_data_len);
		return;
	}

	if(recv_len>=mtu_warn)
	{
		mylog(log_warn,"huge packet,data len=%d (>=%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ",recv_len,mtu_warn);
	}
	mylog(log_trace,"Received packet from %s:%d,len: %d\n", inet_ntoa(udp_new_addr_in.sin_addr),
			ntohs(udp_new_addr_in.sin_port),recv_len);

	u64_t u64=((u64_t(udp_new_addr_in.sin_addr.s_addr))<<32u)+ntohs(udp_new_addr_in.sin_port);
	u32_t conv;

	if(!conn_info.blob->conv_manager.is_u64_used(u64))
	{
		if(conn_info.blob->conv_manager.get_size() >=max_conv_num)
		{
			mylog(log_warn,"ignored new udp connect bc max_conv_num exceed\n");
			return;
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
		send_data_safer(conn_info,buf,recv_len,conv);
	}

}

void raw_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	assert(0==1);
	conn_info_t & conn_info= *((conn_info_t*)watcher->data);
	client_on_raw_recv(conn_info);
}
void async_cb(struct ev_loop *loop, struct ev_async *watcher, int revents)
{
	conn_info_t & conn_info= *((conn_info_t*)watcher->data);

	if(send_with_pcap&&!pcap_header_captured)
	{
		int empty=0;char *p;int len;
		pthread_mutex_lock(&queue_mutex);
		empty=my_queue.empty();
		if(!empty)
		{
			my_queue.peek_front(p,len);
			my_queue.pop_front();
		}
		pthread_mutex_unlock(&queue_mutex);
		if(empty) return;

		pcap_header_captured=1;
		assert(pcap_link_header_len!=-1);
		memcpy(pcap_header_buf,p,pcap_link_header_len);

		log_bare(log_info,"link level header captured:\n");
		for(int i=0;i<pcap_link_header_len;i++)
		log_bare(log_info,"<%x>",(u32_t)(unsigned char)pcap_header_buf[i]);
		log_bare(log_info,"\n");
		return ;
	}

	//mylog(log_info,"async_cb called\n");
	while(1)
	{
		int empty=0;char *p;int len;
		pthread_mutex_lock(&queue_mutex);
		empty=my_queue.empty();
		if(!empty)
		{
			my_queue.peek_front(p,len);
			my_queue.pop_front();
		}
		pthread_mutex_unlock(&queue_mutex);

		if(empty) break;

		int new_len=len-pcap_link_header_len;
		memcpy(g_packet_buf,p+pcap_link_header_len,new_len);
		g_packet_buf_len=new_len;
		assert(g_packet_buf_cnt==0);
		g_packet_buf_cnt++;
		client_on_raw_recv(conn_info);
	}
}
void clear_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	conn_info_t & conn_info= *((conn_info_t*)watcher->data);
	//u64_t value;
	//read(timer_fd, &value, 8);
	client_on_timer(conn_info);
	mylog(log_trace,"epoll_trigger_counter:  %d \n",epoll_trigger_counter);
	epoll_trigger_counter=0;
}

void fifo_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	conn_info_t & conn_info= *((conn_info_t*)watcher->data);

	char buf[buf_len];
	int fifo_fd=watcher->fd;

	int len=read (fifo_fd, buf, sizeof (buf));
	if(len<0)
	{
		mylog(log_warn,"fifo read failed len=%d,errno=%s\n",len,strerror(errno));
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
	
	if(source_ip_uint32==0)
	{
		mylog(log_info,"get_src_adress called\n");
		if(retry_on_error==0)
		{
			if(get_src_adress(source_ip_uint32,remote_ip_uint32,remote_port)!=0)
			{
				mylog(log_fatal,"the trick to auto get source ip failed, maybe you dont have internet access\n");
				myexit(-1);
			}
		}
		else
		{
			int ok=0;
			while(!ok)
			{
				if(get_src_adress(source_ip_uint32,remote_ip_uint32,remote_port)!=0)
				{
					mylog(log_warn,"the trick to auto get source ip failed, maybe you dont have internet access, retry in %d seconds\n",retry_on_error_interval);
					sleep(retry_on_error_interval);
				}
				else
				{
					ok=1;
				}

			}
		}

	}
	in_addr tmp;
	tmp.s_addr=source_ip_uint32;
	mylog(log_info,"source ip = %s\n",inet_ntoa(tmp));
	//printf("done\n");


	if(try_to_list_and_bind(bind_fd,local_ip_uint32,source_port)!=0)
	{
		mylog(log_fatal,"bind to source_port:%d fail\n ",source_port);
		myexit(-1);
	}
	send_info.src_port=source_port;
	send_info.src_ip = source_ip_uint32;

	int i, j, k;int ret;


	send_info.dst_ip=remote_ip_uint32;
	send_info.dst_port=remote_port;


    udp_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    set_buf_size(udp_fd,socket_buf_size,force_socket_buf);

	int yes = 1;

	struct sockaddr_in local_me={0};

	socklen_t slen = sizeof(sockaddr_in);
	local_me.sin_family = AF_INET;
	local_me.sin_port = htons(local_port);
	local_me.sin_addr.s_addr = local_ip_uint32;


	if (::bind(udp_fd, (struct sockaddr*) &local_me, slen) == -1) {
		mylog(log_fatal,"socket bind error\n");
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

	//struct ev_io raw_watcher;

	//raw_watcher.data=&conn_info;
   // ev_io_init(&raw_watcher, raw_recv_cb, raw_recv_fd, EV_READ);
    //ev_io_start(loop, &raw_watcher);

	g_default_loop=loop;
	async_watcher.data=&conn_info;
	ev_async_init(&async_watcher,async_cb);
	ev_async_start(loop,&async_watcher);

	init_raw_socket();



	int unbind=1;

	//set_timer(epollfd,timer_fd);

	struct ev_timer clear_timer;

	clear_timer.data=&conn_info;
	ev_timer_init(&clear_timer, clear_timer_cb, 0, timer_interval/1000.0);
	ev_timer_start(loop, &clear_timer);

	mylog(log_debug,"send_raw : from %x %d  to %x %d\n",send_info.src_ip,send_info.src_port,send_info.dst_ip,send_info.dst_port);

	int fifo_fd=-1;

	struct ev_io fifo_watcher;
	fifo_watcher.data=&conn_info;

	if(fifo_file[0]!=0)
	{
		fifo_fd=create_fifo(fifo_file);
		//ev.events = EPOLLIN;
		//ev.data.u64 = fifo_fd;

		//ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, fifo_fd, &ev);
		//if (ret!= 0) {
		//	mylog(log_fatal,"add fifo_fd to epoll error %s\n",strerror(errno));
		//	myexit(-1);
		//}

	    ev_io_init(&fifo_watcher, fifo_cb, fifo_fd, EV_READ);
	    ev_io_start(loop, &fifo_watcher);

		mylog(log_info,"fifo_file=%s\n",fifo_file);
	}

	ev_run(loop, 0);
	/*
	while(1)////////////////////////
	{
		if(about_to_exit) myexit(0);
		epoll_trigger_counter++;
		int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
		if (nfds < 0) {  //allow zero
			if(errno==EINTR  )
			{
				mylog(log_info,"epoll interrupted by signal,continue\n");
			}
			else
			{
				mylog(log_fatal,"epoll_wait return %d,%s\n", nfds,strerror(errno));
				myexit(-1);
			}
		}
		int idx;
		for (idx = 0; idx < nfds; ++idx) {
			if (events[idx].data.u64 == (u64_t)raw_recv_fd)
			{
				iphdr *iph;tcphdr *tcph;

			}
			else if(events[idx].data.u64 ==(u64_t)timer_fd)
			{

			}
			else if (events[idx].data.u64 == (u64_t)fifo_fd)
			{
			}
			else if (events[idx].data.u64 == (u64_t)udp_fd)
			{

			}
			else
			{
				mylog(log_fatal,"unknown fd,this should never happen\n");
				myexit(-1);
			}
		}
	}*/

	return 0;
}

void sigpipe_cb(struct ev_loop *l, ev_signal *w, int revents)
{
	mylog(log_info, "got sigpipe, ignored");
}

void sigterm_cb(struct ev_loop *l, ev_signal *w, int revents)
{
	mylog(log_info, "got sigterm, exit");
	myexit(0);
}

void sigint_cb(struct ev_loop *l, ev_signal *w, int revents)
{
	mylog(log_info, "got sigint, exit");
	myexit(0);
}


int main(int argc, char *argv[])
{
	//libnet_t *l;	/* the libnet context */
	//char errbuf[LIBNET_ERRBUF_SIZE];

	//l = libnet_init(LIBNET_RAW4, NULL, errbuf);

	dup2(1, 2);//redirect stderr to stdout
	//signal(SIGINT, signal_handler);
	//signal(SIGHUP, signal_handler);
	//signal(SIGKILL, signal_handler);
	//signal(SIGTERM, signal_handler);
	//signal(SIGQUIT, signal_handler);

	struct ev_loop* loop=ev_default_loop(0);
    ev_signal signal_watcher_sigpipe;
    ev_signal_init(&signal_watcher_sigpipe, sigpipe_cb, SIGPIPE);
    ev_signal_start(loop, &signal_watcher_sigpipe);

    ev_signal signal_watcher_sigterm;
    ev_signal_init(&signal_watcher_sigterm, sigterm_cb, SIGTERM);
    ev_signal_start(loop, &signal_watcher_sigterm);

    ev_signal signal_watcher_sigint;
    ev_signal_init(&signal_watcher_sigint, sigint_cb, SIGINT);
    ev_signal_start(loop, &signal_watcher_sigint);


	pre_process_arg(argc,argv);

	if(geteuid() != 0)
	{
		mylog(log_warn,"root check failed, it seems like you are using a non-root account. we can try to continue, but it may fail. If you want to run udp2raw as non-root, you have to add iptables rule manually, and grant udp2raw CAP_NET_RAW capability, check README.md in repo for more info.\n");
	}
	else
	{
		mylog(log_warn,"you can run udp2raw with non-root account for better security. check README.md in repo for more info.\n");
	}

	local_ip_uint32=inet_addr(local_ip);
	source_ip_uint32=inet_addr(source_ip);

	strcpy(remote_ip,remote_address);
	mylog(log_info,"remote_ip=[%s], make sure this is a vaild IP address\n",remote_ip);
	remote_ip_uint32=inet_addr(remote_ip);

	init_random_number_fd();
	srand(get_true_random_number_nz());
	const_id=get_true_random_number_nz();

	mylog(log_info,"const_id:%x\n",const_id);

	char tmp[1000]="";

	strcat(tmp,key_string);

	strcat(tmp,"key1");

	md5((uint8_t*)tmp,strlen(tmp),(uint8_t*)key);

	iptables_rule();

	if(program_mode==client_mode)
	{
		client_event_loop();
	}
	else
	{
		mylog(log_fatal,"server mode not supported in portable version\n");
		myexit(-1);
		//server_event_loop();
	}

	return 0;
}
