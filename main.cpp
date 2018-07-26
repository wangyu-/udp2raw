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

int server_easytcp=0;//currently only for test

int client_on_timer(conn_info_t &conn_info) //for client. called when a timer is ready in epoll
{
	//keep_iptables_rule();
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
	if(pre_recv_raw_packet()<0) return -1;

	if(conn_info.state.client_current_state==client_idle )
	{

		discard_raw_packet();
		//recv(raw_recv_fd, 0,0, 0  );
	}
	else if(conn_info.state.client_current_state==client_tcp_handshake)//received syn ack
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
		//id_t tmp_oppsite_id=  ntohl(* ((u32_t *)&data[0]));
		my_id_t tmp_oppsite_id;
		memcpy(&tmp_oppsite_id,&data[0],sizeof(tmp_oppsite_id));
		tmp_oppsite_id=ntohl(tmp_oppsite_id);

		//id_t tmp_my_id=ntohl(* ((u32_t *)&data[sizeof(id_t)]));
		my_id_t tmp_my_id;
		memcpy(&tmp_my_id,&data[sizeof(my_id_t)],sizeof(tmp_my_id));
		tmp_my_id=ntohl(tmp_my_id);

		//id_t tmp_oppsite_const_id=ntohl(* ((u32_t *)&data[sizeof(id_t)*2]));
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

		//send_handshake(raw_info,conn_info.my_id,conn_info.oppsite_id,const_id);  //////////////send
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

			//u32_t tmp_conv_id= ntohl(* ((u32_t *)&data[0]));
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
		    	mylog(log_warn,"sento returned %d,%s,%02x,%s\n",ret,strerror(errno),int(tmp_addr.get_type()),tmp_addr.get_str());
				//perror("ret<0");
			}
			//mylog(log_trace,"%s :%d\n",inet_ntoa(tmp_sockaddr.sin_addr),ntohs(tmp_sockaddr.sin_port));
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
int client_on_udp_recv(conn_info_t &conn_info)
{
	int recv_len;
	char buf[buf_len];
	address_t::storage_t udp_new_addr_in={0};
	socklen_t udp_new_addr_len = sizeof(address_t::storage_t);
	if ((recv_len = recvfrom(udp_fd, buf, max_data_len+1, 0,
			(struct sockaddr *) &udp_new_addr_in, &udp_new_addr_len)) == -1) {
		mylog(log_warn,"recv_from error,%s\n",strerror(errno));
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
	//mylog(log_trace,"Received packet from %s:%d,len: %d\n", inet_ntoa(udp_new_addr_in.sin_addr),
		//	ntohs(udp_new_addr_in.sin_port),recv_len);

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
	address_t tmp_addr;
	tmp_addr.from_sockaddr((sockaddr *)&udp_new_addr_in,udp_new_addr_len);
	//u64_t u64=((u64_t(udp_new_addr_in.sin_addr.s_addr))<<32u)+ntohs(udp_new_addr_in.sin_port);
	u32_t conv;

	//u64_t u64;//////todo
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
		/*
		char buf2[6000];
		int ret1=send_raw(conn_info.raw_info,buf2,40);
		int ret2=send_raw(conn_info.raw_info,buf2,500);
		int ret3=send_raw(conn_info.raw_info,buf2,1000);
		int ret4=send_raw(conn_info.raw_info,buf2,2000);
		mylog(log_warn,"ret= %d %d %d %d\n",ret1,ret2,ret3,ret4);*/

		send_data_safer(conn_info,buf,recv_len,conv);
	}
	return 0;
}



/*
int server_on_raw_recv_handshake1(conn_info_t &conn_info,id_t tmp_oppsite_id )
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;



	return 0;
}*/
int server_on_timer_multi(conn_info_t &conn_info)  //for server. called when a timer is ready in epoll.for server,there will be one timer for every connection
// there is also a global timer for server,but its not handled here
{
	char ip_port[40];
	//u32_t ip=conn_info.raw_info.send_info.dst_ip;
	//u32_t port=conn_info.raw_info.send_info.dst_port;

	address_t tmp_addr;
	tmp_addr.from_ip_port_new(raw_ip_version,&conn_info.raw_info.send_info.new_dst_ip,conn_info.raw_info.send_info.dst_port);
	//sprintf(ip_port,"%s:%d",my_ntoa(ip),port);
	tmp_addr.to_str(ip_port);

	//keep_iptables_rule();
	mylog(log_trace,"server timer!\n");
	raw_info_t &raw_info=conn_info.raw_info;

	assert(conn_info.state.server_current_state==server_ready);


	if(conn_info.state.server_current_state==server_ready)
	{
		conn_info.blob->conv_manager.s.clear_inactive(ip_port);
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

		if(hb_mode==0)
			send_safer(conn_info,'h',hb_buf,0);  /////////////send
		else
			send_safer(conn_info,'h',hb_buf,hb_len);
		conn_info.last_hb_sent_time=get_current_time();

		mylog(log_debug,"heart beat sent<%x,%x>\n",conn_info.my_id,conn_info.oppsite_id);
	}
	else
	{
		mylog(log_fatal,"this shouldnt happen!\n");
		myexit(-1);
	}
	return 0;

}
int server_on_raw_recv_ready(conn_info_t &conn_info,char * ip_port,char type,char *data,int data_len)  //called while the state for a connection is server_ready
//receives data and heart beat by recv_safer.
{

	raw_info_t &raw_info = conn_info.raw_info;
	packet_info_t &send_info = conn_info.raw_info.send_info;
	packet_info_t &recv_info = conn_info.raw_info.recv_info;
	//char ip_port[40];

	//sprintf(ip_port,"%s:%d",my_ntoa(recv_info.src_ip),recv_info.src_port);


/*
	if (recv_info.src_ip != send_info.dst_ip
			|| recv_info.src_port != send_info.dst_port) {
		mylog(log_debug, "unexpected adress\n");
		return 0;
	}*/

	if (type == 'h' && data_len >= 0) {
		//u32_t tmp = ntohl(*((u32_t *) &data[sizeof(u32_t)]));
		mylog(log_debug,"[%s][hb]received hb \n",ip_port);
		conn_info.last_hb_recv_time = get_current_time();
		return 0;
	} else if (type== 'd' && data_len >=int( sizeof(u32_t) ))
	{

		//u32_t tmp_conv_id = ntohl(*((u32_t *) &data[0]));
		my_id_t tmp_conv_id;
		memcpy(&tmp_conv_id,&data[0],sizeof(tmp_conv_id));
		tmp_conv_id=ntohl(tmp_conv_id);


		if(hb_mode==0)
			conn_info.last_hb_recv_time = get_current_time();

		mylog(log_trace, "conv:%u\n", tmp_conv_id);
		if (!conn_info.blob->conv_manager.s.is_conv_used(tmp_conv_id)) {
			if (conn_info.blob->conv_manager.s.get_size() >= max_conv_num) {
				mylog(log_warn,
						"[%s]ignored new conv %x connect bc max_conv_num exceed\n",ip_port,
						tmp_conv_id);
				return 0;
			}
			
			/*
			struct sockaddr_in remote_addr_in={0};

			socklen_t slen = sizeof(sockaddr_in);
			//memset(&remote_addr_in, 0, sizeof(remote_addr_in));
			remote_addr_in.sin_family = AF_INET;
			remote_addr_in.sin_port = htons(remote_port);
			remote_addr_in.sin_addr.s_addr = remote_ip_uint32;



			int new_udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);


			if (new_udp_fd < 0) {
				mylog(log_warn, "[%s]create udp_fd error\n",ip_port);
				return -1;
			}
			setnonblocking(new_udp_fd);
			set_buf_size(new_udp_fd,socket_buf_size);

			mylog(log_debug, "[%s]created new udp_fd %d\n",ip_port, new_udp_fd);
			int ret = connect(new_udp_fd, (struct sockaddr *) &remote_addr_in,
					slen);
			if (ret != 0) {
				mylog(log_warn, "udp fd connect fail\n");
				close(new_udp_fd);
				return -1;
			}*/

			int new_udp_fd=remote_addr.new_connected_udp_fd();
			if (new_udp_fd < 0) {
				mylog(log_warn, "[%s]new_connected_udp_fd() failed\n",ip_port);
				return -1;
			}

			struct epoll_event ev;

			fd64_t new_udp_fd64 =  fd_manager.create(new_udp_fd);
			fd_manager.get_info(new_udp_fd64).p_conn_info=&conn_info;

			mylog(log_trace, "[%s]u64: %lld\n",ip_port, new_udp_fd64);
			ev.events = EPOLLIN;

			ev.data.u64 = new_udp_fd64;

			int ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, new_udp_fd, &ev);

			if (ret != 0) {
				mylog(log_warn, "[%s]add udp_fd error\n",ip_port);
				close(new_udp_fd);
				return -1;
			}

			conn_info.blob->conv_manager.s.insert_conv(tmp_conv_id, new_udp_fd64);



			//assert(conn_manager.udp_fd_mp.find(new_udp_fd)==conn_manager.udp_fd_mp.end());

			//conn_manager.udp_fd_mp[new_udp_fd] = &conn_info;

			//pack_u64(conn_info.raw_info.recv_info.src_ip,conn_info.raw_info.recv_info.src_port);

			mylog(log_info, "[%s]new conv conv_id=%x, assigned fd=%d\n",ip_port,
					tmp_conv_id, new_udp_fd);



		}

		fd64_t fd64 = conn_info.blob->conv_manager.s.find_data_by_conv(tmp_conv_id);

		conn_info.blob->conv_manager.s.update_active_time(tmp_conv_id);

		int fd = fd_manager.to_fd(fd64);

		mylog(log_trace, "[%s]received a data from fake tcp,len:%d\n",ip_port, data_len);
		int ret = send(fd, data + sizeof(u32_t),
				data_len - ( sizeof(u32_t)), 0);

		mylog(log_trace, "[%s]%d byte sent  ,fd :%d\n ",ip_port, ret, fd);
		if (ret < 0) {
			mylog(log_warn, "send returned %d\n", ret);
			//perror("what happened????");
		}
		return 0;
	}
	return 0;
}

int server_on_raw_recv_pre_ready(conn_info_t &conn_info,char * ip_port,u32_t tmp_oppsite_const_id)// do prepare work before state change to server ready for a specifc connection
//connection recovery is also handle here
{
	//u32_t ip;uint16_t port;
	//ip=conn_info.raw_info.recv_info.src_ip;
	//port=conn_info.raw_info.recv_info.src_port;
	//char ip_port[40];
	//sprintf(ip_port,"%s:%d",my_ntoa(ip),port);

	mylog(log_info,"[%s]received handshake oppsite_id:%x  my_id:%x\n",ip_port,conn_info.oppsite_id,conn_info.my_id);

	mylog(log_info,"[%s]oppsite const_id:%x \n",ip_port,tmp_oppsite_const_id);
	if(conn_manager.const_id_mp.find(tmp_oppsite_const_id)==conn_manager.const_id_mp.end())
	{
		//conn_manager.const_id_mp=

		if(conn_manager.ready_num>=max_ready_conn_num)
		{
			mylog(log_info,"[%s]max_ready_conn_num,cant turn to ready\n",ip_port);
			conn_info.state.server_current_state =server_idle;
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

		if(hb_mode==0)
			send_safer(conn_info,'h',hb_buf,0);/////////////send
		else
			send_safer(conn_info,'h',hb_buf,hb_len);

		mylog(log_info, "[%s]changed state to server_ready\n",ip_port);
		conn_info.blob->anti_replay.re_init();

		//g_conn_info=conn_info;
		int new_timer_fd;
		set_timer_server(epollfd, new_timer_fd,conn_info.timer_fd64);

		fd_manager.get_info(conn_info.timer_fd64).p_conn_info=&conn_info;
		//assert(conn_manager.timer_fd_mp.find(new_timer_fd)==conn_manager.timer_fd_mp.end());
		//conn_manager.timer_fd_mp[new_timer_fd] = &conn_info;//pack_u64(ip,port);


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
				 conn_info.state.server_current_state=server_idle;
				 conn_info.oppsite_const_id=0;
				 return 0;
			}
			address_t addr1;addr1.from_ip_port_new(raw_ip_version,&ori_conn_info.raw_info.recv_info.new_src_ip,ori_conn_info.raw_info.recv_info.src_port);
			if(!conn_manager.exist(addr1))//TODO remove this
			{
				mylog(log_fatal,"[%s]this shouldnt happen\n",ip_port);
				myexit(-1);
			}
			address_t addr2;addr2.from_ip_port_new(raw_ip_version,&conn_info.raw_info.recv_info.new_src_ip,conn_info.raw_info.recv_info.src_port);
			if(!conn_manager.exist(addr2))//TODO remove this
			{
				mylog(log_fatal,"[%s]this shouldnt happen2\n",ip_port);
				myexit(-1);
			}
			conn_info_t *&p_ori=conn_manager.find_insert_p(addr1);
			conn_info_t *&p=conn_manager.find_insert_p(addr2);
			conn_info_t *tmp=p;
			p=p_ori;
			p_ori=tmp;


			mylog(log_info,"[%s]grabbed a connection\n",ip_port);


			//ori_conn_info.state.server_current_state=server_ready;
			ori_conn_info.recover(conn_info);

			//send_safer(ori_conn_info, 'h',hb_buf, hb_len);
			//ori_conn_info.blob->anti_replay.re_init();
			if(hb_mode==0)
				send_safer(ori_conn_info,'h',hb_buf,0);/////////////send
			else
				send_safer(ori_conn_info,'h',hb_buf,hb_len);

			ori_conn_info.last_hb_recv_time=get_current_time();



			conn_info.state.server_current_state=server_idle;
			conn_info.oppsite_const_id=0;

		}
		else
		{
			mylog(log_fatal,"[%s]this should never happen\n",ip_port);
			myexit(-1);
		}
		return 0;
	}
	return 0;
}
int server_on_raw_recv_handshake1(conn_info_t &conn_info,char * ip_port,char * data, int data_len)//called when server received a handshake1 packet from client
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;

	//u32_t ip=conn_info.raw_info.recv_info.src_ip;
	//uint16_t port=conn_info.raw_info.recv_info.src_port;

	//char ip_port[40];
	//sprintf(ip_port,"%s:%d",my_ntoa(ip),port);

	if(data_len<int( 3*sizeof(my_id_t)))
	{
		mylog(log_debug,"[%s] data_len=%d too short to be a handshake\n",ip_port,data_len);
		return -1;
	}
	//id_t tmp_oppsite_id=  ntohl(* ((u32_t *)&data[0]));
	my_id_t tmp_oppsite_id;
	memcpy(&tmp_oppsite_id,(u32_t *)&data[0],sizeof(tmp_oppsite_id));
	tmp_oppsite_id=ntohl(tmp_oppsite_id);

	//id_t tmp_my_id=ntohl(* ((u32_t *)&data[sizeof(id_t)]));
	my_id_t tmp_my_id;
	memcpy(&tmp_my_id,&data[sizeof(my_id_t)],sizeof(tmp_my_id));
	tmp_my_id=ntohl(tmp_my_id);

	if(tmp_my_id==0)  //received  init handshake again
	{
		if(raw_mode==mode_faketcp)
		{
			send_info.seq=recv_info.ack_seq;
			send_info.ack_seq=recv_info.seq+raw_info.recv_info.data_len;
			send_info.ts_ack=recv_info.ts;
		}
		if(raw_mode==mode_icmp)
		{
			send_info.my_icmp_seq=recv_info.my_icmp_seq;
		}
		send_handshake(raw_info,conn_info.my_id,tmp_oppsite_id,const_id);  //////////////send

		mylog(log_info,"[%s]changed state to server_handshake1,my_id is %x\n",ip_port,conn_info.my_id);
	}
	else if(tmp_my_id==conn_info.my_id)
	{
		conn_info.oppsite_id=tmp_oppsite_id;
		//id_t tmp_oppsite_const_id=ntohl(* ((u32_t *)&data[sizeof(id_t)*2]));

		my_id_t tmp_oppsite_const_id;
		memcpy(&tmp_oppsite_const_id,&data[sizeof(my_id_t)*2],sizeof(tmp_oppsite_const_id));
		tmp_oppsite_const_id=ntohl(tmp_oppsite_const_id);


		if(raw_mode==mode_faketcp)
		{
			send_info.seq=recv_info.ack_seq;
			send_info.ack_seq=recv_info.seq+raw_info.recv_info.data_len;
			send_info.ts_ack=recv_info.ts;
		}

		if(raw_mode==mode_icmp)
		{
			send_info.my_icmp_seq=recv_info.my_icmp_seq;
		}

		server_on_raw_recv_pre_ready(conn_info,ip_port,tmp_oppsite_const_id);

	}
	else
	{
		mylog(log_debug,"[%s]invalid my_id %x,my_id is %x\n",ip_port,tmp_my_id,conn_info.my_id);
	}
	return 0;
}

int server_on_raw_recv_multi() //called when server received an raw packet
{
	char dummy_buf[buf_len];
	raw_info_t peek_raw_info;
	peek_raw_info.peek=1;
	packet_info_t &peek_info=peek_raw_info.recv_info;
	mylog(log_trace,"got a packet\n");
	if(pre_recv_raw_packet()<0) return -1;
	if(peek_raw(peek_raw_info)<0)
	{
		discard_raw_packet();
		//recv(raw_recv_fd, 0,0, 0  );//
		//struct sockaddr saddr;
		//socklen_t saddr_size=sizeof(saddr);
		///recvfrom(raw_recv_fd, 0,0, 0 ,&saddr , &saddr_size);//
		mylog(log_trace,"peek_raw failed\n");
		return -1;
	}else
	{
		mylog(log_trace,"peek_raw success\n");
	}
	//u32_t ip=peek_info.src_ip;uint16_t port=peek_info.src_port;


	int data_len; char *data;

	address_t addr;
	addr.from_ip_port_new(raw_ip_version,&peek_info.new_src_ip,peek_info.src_port);

	char ip_port[40];
	addr.to_str(ip_port);
	//sprintf(ip_port,"%s:%d",my_ntoa(ip),port);
	mylog(log_trace,"[%s]peek_raw\n",ip_port);

	if(raw_mode==mode_faketcp&&peek_info.syn==1)
	{
		if(!conn_manager.exist(addr)||conn_manager.find_insert(addr).state.server_current_state!=server_ready)
		{//reply any syn ,before state become ready

			raw_info_t tmp_raw_info;
			if(recv_raw0(tmp_raw_info,data,data_len)<0)
			{
				return 0;
			}
			if(server_easytcp!=0)
				return 0;
			raw_info_t &raw_info=tmp_raw_info;
			packet_info_t &send_info=raw_info.send_info;
			packet_info_t &recv_info=raw_info.recv_info;

			send_info.new_src_ip=recv_info.new_dst_ip;
			send_info.src_port=recv_info.dst_port;

			send_info.dst_port = recv_info.src_port;
			send_info.new_dst_ip = recv_info.new_src_ip;

			if(lower_level)
			{
				handle_lower_level(raw_info);
			}

			if(data_len==0&&raw_info.recv_info.syn==1&&raw_info.recv_info.ack==0)
			{
				send_info.ack_seq = recv_info.seq + 1;

				send_info.psh = 0;
				send_info.syn = 1;
				send_info.ack = 1;
				send_info.ts_ack=recv_info.ts;

				mylog(log_info,"[%s]received syn,sent syn ack back\n",ip_port);
				send_raw0(raw_info, 0, 0);
				return 0;
			}
		}
		else
		{
			discard_raw_packet();
			//recv(raw_recv_fd, 0,0,0);
		}
		return 0;
	}
	if(!conn_manager.exist(addr))
	{
		if(conn_manager.mp.size()>=max_handshake_conn_num)
		{
			mylog(log_info,"[%s]reached max_handshake_conn_num,ignored new handshake\n",ip_port);
			discard_raw_packet();
			//recv(raw_recv_fd, 0,0, 0  );//
			return 0;
		}

		raw_info_t tmp_raw_info;


		if(raw_mode==mode_icmp)
		{
			tmp_raw_info.send_info.dst_port=tmp_raw_info.send_info.src_port=addr.get_port();
		}
		if(recv_bare(tmp_raw_info,data,data_len)<0)
		{
			return 0;
		}
		if(data_len<int( 3*sizeof(my_id_t)))
		{
			mylog(log_debug,"[%s]too short to be a handshake\n",ip_port);
			return -1;
		}

		//id_t zero=ntohl(* ((u32_t *)&data[sizeof(id_t)]));
		my_id_t zero;
		memcpy(&zero,&data[sizeof(my_id_t)],sizeof(zero));
		zero=ntohl(zero);

		if(zero!=0)
		{
			mylog(log_debug,"[%s]not a invalid initial handshake\n",ip_port);
			return -1;
		}

		mylog(log_info,"[%s]got packet from a new ip\n",ip_port);

		conn_info_t &conn_info=conn_manager.find_insert(addr);
		conn_info.raw_info=tmp_raw_info;
		raw_info_t &raw_info=conn_info.raw_info;

		packet_info_t &send_info=conn_info.raw_info.send_info;
		packet_info_t &recv_info=conn_info.raw_info.recv_info;

		//conn_info.ip_port.ip=ip;
		//conn_info.ip_port.port=port;



		send_info.new_src_ip=recv_info.new_dst_ip;
		send_info.src_port=recv_info.dst_port;

		send_info.dst_port = recv_info.src_port;
		send_info.new_dst_ip = recv_info.new_src_ip;

		if(lower_level)
		{
			handle_lower_level(raw_info);
		}

		//id_t tmp_oppsite_id=  ntohl(* ((u32_t *)&data[0]));
		//mylog(log_info,"[%s]handshake1 received %x\n",ip_port,tmp_oppsite_id);

		conn_info.my_id=get_true_random_number_nz();


		mylog(log_info,"[%s]created new conn,state: server_handshake1,my_id is %x\n",ip_port,conn_info.my_id);

		conn_info.state.server_current_state = server_handshake1;
		conn_info.last_state_time = get_current_time();

		server_on_raw_recv_handshake1(conn_info,ip_port,data,data_len);
		return 0;
	}




	conn_info_t & conn_info=conn_manager.find_insert(addr);//insert if not exist
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;

	if(conn_info.state.server_current_state==server_handshake1)
	{
		if(recv_bare(raw_info,data,data_len)!=0)
		{
			return -1;
		}
		return server_on_raw_recv_handshake1(conn_info,ip_port,data,data_len);
	}
	if(conn_info.state.server_current_state==server_ready)
	{
		char type;
		//mylog(log_info,"before recv_safer\n");
		if (recv_safer(conn_info,type, data, data_len) != 0) {
			return -1;
		}
		//mylog(log_info,"after recv_safer\n");
		return server_on_raw_recv_ready(conn_info,ip_port,type,data,data_len);
	}

	if(conn_info.state.server_current_state==server_idle)
	{
		discard_raw_packet();
		//recv(raw_recv_fd, 0,0, 0  );//
		return 0;
	}
	mylog(log_fatal,"we should never run to here\n");
	myexit(-1);
	return -1;
}

int server_on_udp_recv(conn_info_t &conn_info,fd64_t fd64)
{
	char buf[buf_len];

	if(conn_info.state.server_current_state!=server_ready)//TODO remove this for peformance
	{
		mylog(log_fatal,"p_conn_info->state.server_current_state!=server_ready!!!this shouldnt happen\n");
		myexit(-1);
	}

	//conn_info_t &conn_info=*p_conn_info;

	assert(conn_info.blob->conv_manager.s.is_data_used(fd64));

	u32_t conv_id=conn_info.blob->conv_manager.s.find_conv_by_data(fd64);

	int fd=fd_manager.to_fd(fd64);

	int recv_len=recv(fd,buf,max_data_len+1,0);

	mylog(log_trace,"received a packet from udp_fd,len:%d\n",recv_len);

	if(recv_len==max_data_len+1)
	{
		mylog(log_warn,"huge packet, data_len > %d,dropped\n",max_data_len);
		return -1;
	}

	if(recv_len<0)
	{
		mylog(log_debug,"udp fd,recv_len<0 continue,%s\n",strerror(errno));
		return -1;
	}

	if(recv_len>=mtu_warn)
	{
		mylog(log_warn,"huge packet,data len=%d (>=%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ",recv_len,mtu_warn);
	}

	//conn_info.conv_manager->update_active_time(conv_id);  server dosnt update from upd side,only update from raw side.  (client updates at both side)

	if(conn_info.state.server_current_state==server_ready)
	{
		send_data_safer(conn_info,buf,recv_len,conv_id);
		//send_data(g_packet_info_send,buf,recv_len,my_id,oppsite_id,conv_id);
		mylog(log_trace,"send_data_safer ,sent !!\n");
	}


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
	
	/*

	address_t new_addr;

	if(!force_source_ip)
	{
		mylog(log_info,"get_src_adress called\n");
		if(retry_on_error==0)
		{
			if(get_src_adress2(new_addr,remote_addr)!=0)
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
				if(get_src_adress2(new_addr,remote_addr)!=0)
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
	else
	{
		new_addr=source_addr;
	}
	//in_addr tmp;
	//tmp.s_addr=source_ip_uint32;
	mylog(log_info,"source ip = %s\n",new_addr.get_ip());*/
	//printf("done\n");


	/*
	if(try_to_list_and_bind(bind_fd,local_ip_uint32,source_port)!=0)
	{
		mylog(log_fatal,"bind to source_port:%d fail\n ",source_port);
		myexit(-1);
	}*/
	send_info.src_port=0;
	memset(&send_info.new_src_ip,0,sizeof(send_info.new_src_ip));

	int i, j, k;int ret;


	//init_filter(source_port);

	send_info.new_dst_ip.from_address_t(remote_addr);

	send_info.dst_port=remote_addr.get_port();

	//g_packet_info.src_ip=source_address_uint32;
	//g_packet_info.src_port=source_port;

    udp_fd=socket(local_addr.get_type(), SOCK_DGRAM, IPPROTO_UDP);
    set_buf_size(udp_fd,socket_buf_size);

	int yes = 1;
	//setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	//struct sockaddr_in local_me={0};

	//socklen_t slen = sizeof(sockaddr_in);
	//memset(&local_me, 0, sizeof(local_me));
	//local_me.sin_family = AF_INET;
	//local_me.sin_port = local_addr.get_type();
	//local_me.sin_addr.s_addr = local_addr.inner.ipv4.sin_addr.s_addr;


	if (bind(udp_fd, (struct sockaddr*) &local_addr.inner, local_addr.get_len()) == -1) {
		mylog(log_fatal,"socket bind error\n");
		//perror("socket bind error");
		myexit(1);
	}
	setnonblocking(udp_fd);
	epollfd = epoll_create1(0);

	const int max_events = 4096;
	struct epoll_event ev, events[max_events];
	if (epollfd < 0) {
		mylog(log_fatal,"epoll return %d\n", epollfd);
		myexit(-1);
	}

	ev.events = EPOLLIN;
	ev.data.u64 = udp_fd;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, udp_fd, &ev);
	if (ret!=0) {
		mylog(log_fatal,"add  udp_listen_fd error\n");
		myexit(-1);
	}
	ev.events = EPOLLIN;
	ev.data.u64 = raw_recv_fd;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
	if (ret!= 0) {
		mylog(log_fatal,"add raw_fd error\n");
		myexit(-1);
	}

	////add_timer for fake_tcp_keep_connection_client

	//sleep(10);

	//memset(&udp_old_addr_in,0,sizeof(sockaddr_in));
	int unbind=1;

	set_timer(epollfd,timer_fd);

	mylog(log_debug,"send_raw : from %s %d  to %s %d\n",send_info.new_src_ip.get_str1(),send_info.src_port,send_info.new_dst_ip.get_str2(),send_info.dst_port);
	int fifo_fd=-1;

	if(fifo_file[0]!=0)
	{
		fifo_fd=create_fifo(fifo_file);
		ev.events = EPOLLIN;
		ev.data.u64 = fifo_fd;

		ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, fifo_fd, &ev);
		if (ret!= 0) {
			mylog(log_fatal,"add fifo_fd to epoll error %s\n",strerror(errno));
			myexit(-1);
		}
		mylog(log_info,"fifo_file=%s\n",fifo_file);
	}
	while(1)////////////////////////
	{
		if(about_to_exit) myexit(0);
		epoll_trigger_counter++;
		int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
		if (nfds < 0) {  //allow zero
			if(errno==EINTR  )
			{
				mylog(log_info,"epoll interrupted by signal,continue\n");
				//close(fifo_fd);
				//myexit(0);
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
				//iphdr *iph;tcphdr *tcph;
				client_on_raw_recv(conn_info);
			}
			else if(events[idx].data.u64 ==(u64_t)timer_fd)
			{
				u64_t value;
				read(timer_fd, &value, 8);
				client_on_timer(conn_info);
				mylog(log_trace,"epoll_trigger_counter:  %d \n",epoll_trigger_counter);
				epoll_trigger_counter=0;
			}
			else if (events[idx].data.u64 == (u64_t)udp_fd)
			{
				client_on_udp_recv(conn_info);
			}
			else if (events[idx].data.u64 == (u64_t)fifo_fd)
			{
				int len=read (fifo_fd, buf, sizeof (buf));
				//assert(len>=0);
				if(len<0)
				{
					mylog(log_warn,"fifo read failed len=%d,errno=%s\n",len,strerror(errno));
					continue;
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
			else
			{
				mylog(log_fatal,"unknown fd,this should never happen\n");
				myexit(-1);
			}
		}
	}
	return 0;
}

int server_event_loop()
{
	char buf[buf_len];

	int i, j, k;int ret;

	if(raw_ip_version==AF_INET)
	{
		if(local_addr.inner.ipv4.sin_addr.s_addr!=0)
		{
			bind_addr_used=1;
			bind_addr.v4=local_addr.inner.ipv4.sin_addr.s_addr;
		}
	}
	else
	{
		assert(raw_ip_version==AF_INET6);
		char zero_arr[16]={0};
		if(memcmp(&local_addr.inner.ipv6.sin6_addr,zero_arr,16)!=0)
		{
			bind_addr_used=1;
			bind_addr.v6=local_addr.inner.ipv6.sin6_addr;
		}
	}
	//bind_address_uint32=local_ip_uint32;//only server has bind adress,client sets it to zero

	if(lower_level)
	{
		if(lower_level_manual)
		{
			init_ifindex(if_name,raw_send_fd,ifindex);
			mylog(log_info,"we are running at lower-level (manual) mode\n");
		}
		else
		{
			mylog(log_info,"we are running at lower-level (auto) mode\n");
		}

	}

	 if(raw_mode==mode_faketcp)
	 {
		 bind_fd=socket(local_addr.get_type(),SOCK_STREAM,0);
	 }
	 else  if(raw_mode==mode_udp||raw_mode==mode_icmp)//bind an adress to avoid collision,for icmp,there is no port,just bind a udp port
	 {
		 bind_fd=socket(local_addr.get_type(),SOCK_DGRAM,0);
	 }

	 //struct sockaddr_in temp_bind_addr={0};
    // bzero(&temp_bind_addr, sizeof(temp_bind_addr));

     //temp_bind_addr.sin_family = AF_INET;
     //temp_bind_addr.sin_port = local_addr.get_port();
     //temp_bind_addr.sin_addr.s_addr = local_addr.inner.ipv4.sin_addr.s_addr;

     if (bind(bind_fd, (struct sockaddr*)&local_addr.inner, local_addr.get_len()) !=0)
     {
    	 mylog(log_fatal,"bind fail\n");
    	 myexit(-1);
     }

	 if(raw_mode==mode_faketcp)
	 {

		 if(listen(bind_fd, SOMAXCONN) != 0 )
		 {
			 mylog(log_fatal,"listen fail\n");
			 myexit(-1);
		 }
	 }



	//init_raw_socket();
	init_filter(local_addr.get_port());//bpf filter

	epollfd = epoll_create1(0);
	const int max_events = 4096;

	struct epoll_event ev, events[max_events];
	if (epollfd < 0) {
		mylog(log_fatal,"epoll return %d\n", epollfd);
		myexit(-1);
	}

	ev.events = EPOLLIN;
	ev.data.u64 = raw_recv_fd;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
	if (ret!= 0) {
		mylog(log_fatal,"add raw_fd error\n");
		myexit(-1);
	}
	int timer_fd;

	set_timer(epollfd,timer_fd);

	u64_t begin_time=0;
	u64_t end_time=0;

	mylog(log_info,"now listening at %s\n",local_addr.get_str());

	int fifo_fd=-1;

	if(fifo_file[0]!=0)
	{
		fifo_fd=create_fifo(fifo_file);
		ev.events = EPOLLIN;
		ev.data.u64 = fifo_fd;

		ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, fifo_fd, &ev);
		if (ret!= 0) {
			mylog(log_fatal,"add fifo_fd to epoll error %s\n",strerror(errno));
			myexit(-1);
		}
		mylog(log_info,"fifo_file=%s\n",fifo_file);
	}


	while(1)////////////////////////
	{

		if(about_to_exit) myexit(0);

		int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
		if (nfds < 0) {  //allow zero
			if(errno==EINTR  )
			{
				mylog(log_info,"epoll interrupted by signal,continue\n");
				//myexit(0);
			}
			else
			{
				mylog(log_fatal,"epoll_wait return %d,%s\n", nfds,strerror(errno));
				myexit(-1);
			}
		}
		int idx;
		for (idx = 0; idx < nfds; ++idx)
		{
			//mylog(log_debug,"ndfs:  %d \n",nfds);
			epoll_trigger_counter++;
			//printf("%d %d %d %d\n",timer_fd,raw_recv_fd,raw_send_fd,n);
			if ((events[idx].data.u64 ) == (u64_t)timer_fd)
			{
				if(debug_flag)begin_time=get_current_time();
				conn_manager.clear_inactive();
				u64_t dummy;
				read(timer_fd, &dummy, 8);
				//current_time_rough=get_current_time();
				if(debug_flag)
				{
					end_time=get_current_time();
					mylog(log_debug,"timer_fd,%llu,%llu,%llu\n",begin_time,end_time,end_time-begin_time);
				}

				mylog(log_trace,"epoll_trigger_counter:  %d \n",epoll_trigger_counter);
				epoll_trigger_counter=0;

			}
			else if (events[idx].data.u64 == (u64_t)raw_recv_fd)
			{
				if(debug_flag)begin_time=get_current_time();
				server_on_raw_recv_multi();
				if(debug_flag)
				{
					end_time=get_current_time();
					mylog(log_debug,"raw_recv_fd,%llu,%llu,%llu  \n",begin_time,end_time,end_time-begin_time);
				}
			}
			else if (events[idx].data.u64 == (u64_t)fifo_fd)
			{
				int len=read (fifo_fd, buf, sizeof (buf));
				if(len<0)
				{
					mylog(log_warn,"fifo read failed len=%d,errno=%s\n",len,strerror(errno));
					continue;
				}
				//assert(len>=0);
				buf[len]=0;
				while(len>=1&&buf[len-1]=='\n')
					buf[len-1]=0;
				mylog(log_info,"got data from fifo,len=%d,s=[%s]\n",len,buf);
				mylog(log_info,"unknown command\n");
			}
			else if (events[idx].data.u64>u32_t(-1) )
			{

				fd64_t fd64=events[idx].data.u64;
				if(!fd_manager.exist(fd64))
				{
					mylog(log_trace ,"fd64 no longer exist\n");
					return -1;
				}
				assert(fd_manager.exist_info(fd64));
				conn_info_t* p_conn_info=fd_manager.get_info(fd64).p_conn_info;
				conn_info_t &conn_info=*p_conn_info;
				if(fd64==conn_info.timer_fd64)//////////timer_fd64
				{

					if(debug_flag)begin_time=get_current_time();
					int fd=fd_manager.to_fd(fd64);
					u64_t dummy;
					read(fd, &dummy, 8);
					assert(conn_info.state.server_current_state == server_ready); //TODO remove this for peformance
					server_on_timer_multi(conn_info);
					if(debug_flag)
					{
						end_time=get_current_time();
						mylog(log_debug,"(events[idx].data.u64 >>32u) == 2u ,%llu,%llu,%llu  \n",begin_time,end_time,end_time-begin_time);
					}
				}
				else//udp_fd64
				{
					if(debug_flag)begin_time=get_current_time();
					server_on_udp_recv(conn_info,fd64);
					if(debug_flag)
					{
						end_time=get_current_time();
						mylog(log_debug,"(events[idx].data.u64 >>32u) == 1u,%lld,%lld,%lld  \n",begin_time,end_time,end_time-begin_time);
					}
				}
			}
			else
			{
				mylog(log_fatal,"unknown fd,this should never happen\n");
				myexit(-1);
			}

		}
	}
	return 0;
}

/*
int test()
{

	char ip_str[100]="8.8.8.8";
	u32_t ip=inet_addr(ip_str);
	u32_t dest_ip;
	string if_name;
	string hw;
	find_lower_level_info(ip,dest_ip,if_name,hw);
	printf("%s %s %s\n",my_ntoa(dest_ip),if_name.c_str(),hw.c_str());
	exit(0);
	return 0;
}*/
int main(int argc, char *argv[])
{
	//printf("%llu\n",u64_t(-1));
	//test();
	//printf("%s\n",my_ntoa(0x00ffffff));
	//auto a=string_to_vec("a b c d ");
	//printf("%d\n",(int)a.size());
	//printf("%d %d %d %d",larger_than_u32(1,2),larger_than_u32(2,1),larger_than_u32(0xeeaaeebb,2),larger_than_u32(2,0xeeaaeebb));
	//assert(0==1);
	dup2(1, 2);//redirect stderr to stdout
	signal(SIGINT, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGKILL, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGQUIT, signal_handler);

	pre_process_arg(argc,argv);

	if(geteuid() != 0)
	{
		mylog(log_warn,"root check failed, it seems like you are using a non-root account. we can try to continue, but it may fail. If you want to run udp2raw as non-root, you have to add iptables rule manually, and grant udp2raw CAP_NET_RAW capability, check README.md in repo for more info.\n");
	}
	else
	{
		mylog(log_warn,"you can run udp2raw with non-root account for better security. check README.md in repo for more info.\n");
	}

	//local_ip_uint32=inet_addr(local_ip);
	//source_ip_uint32=inet_addr(source_ip);

	
#if ENABLE_DNS_RESOLVE

	//if(enable_dns_resolve)
	//{

	struct hostent        *he;
	if ( (he = gethostbyname(remote_address) ) == NULL ) {
		mylog(log_error,"Unable to resolve hostname: %s, error:%s \n",remote_address,hstrerror(h_errno) );
		myexit(1); /* error */
	}
	struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
	assert( he->h_addrtype ==AF_INET);
	assert(addr_list!=NULL);

	remote_ip_uint32=(*addr_list[0]).s_addr;
	mylog(log_info,"remote_address[%s] has been resolved to [%s]\n",remote_address, my_ntoa(remote_ip_uint32));


	strcpy(remote_ip,my_ntoa(remote_ip_uint32));

	//}
	//else

#endif

	mylog(log_info,"remote_ip=[%s], make sure this is a vaild IP address\n",remote_addr.get_ip());

	//current_time_rough=get_current_time();

	init_random_number_fd();
	srand(get_true_random_number_nz());
	const_id=get_true_random_number_nz();

	mylog(log_info,"const_id:%x\n",const_id);

	my_init_keys(key_string,program_mode==client_mode?1:0);

	iptables_rule();
	init_raw_socket();

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
