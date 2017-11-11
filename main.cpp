#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "log.h"
#include "lib/md5.h"
#include "encrypt.h"
#include "fd_manager.h"

int mtu_warn=1375;//if a packet larger than mtu warn is receviced,there will be a warning


char hb_buf[buf_len];


int server_on_raw_recv_pre_ready(conn_info_t &conn_info,char * ip_port,u32_t tmp_oppsite_const_id);
int server_on_raw_recv_ready(conn_info_t &conn_info,char * ip_port,char type,char *data,int data_len);
int server_on_raw_recv_handshake1(conn_info_t &conn_info,char * ip_port,char * data, int data_len);

int client_on_timer(conn_info_t &conn_info) //for client. called when a timer is ready in epoll
{
	//keep_iptables_rule();
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;
	conn_info.blob->conv_manager.clear_inactive();
	mylog(log_trace,"timer!\n");

	mylog(log_trace,"roller my %d,oppsite %d,%lld\n",int(conn_info.my_roller),int(conn_info.oppsite_roller),conn_info.last_oppsite_roller_time);

	mylog(log_trace,"<client_on_timer,send_info.ts_ack= %u>\n",send_info.ts_ack);


	if(conn_info.state.client_current_state==client_idle)
	{
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
					send_info.icmp_seq++;
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
					send_info.icmp_seq++;
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

		if(get_current_time()-conn_info.last_hb_sent_time<heartbeat_interval)
		{
			return 0;
		}

		if(get_current_time()- conn_info.last_oppsite_roller_time>client_conn_uplink_timeout)
		{
			conn_info.state.client_current_state=client_idle;
			conn_info.my_id=get_true_random_number_nz();
			mylog(log_info,"state back to client_idle from  client_ready bc of client-->server direction timeout\n");
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
int server_on_timer_multi(conn_info_t &conn_info,char * ip_port)  //for server. called when a timer is ready in epoll.for server,there will be one timer for every connection

{
	//keep_iptables_rule();
	mylog(log_trace,"server timer!\n");
	raw_info_t &raw_info=conn_info.raw_info;

	assert(conn_info.state.server_current_state==server_ready);


	if(conn_info.state.server_current_state==server_ready)
	{
		conn_info.blob->conv_manager.clear_inactive(ip_port);
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
int client_on_raw_recv(conn_info_t &conn_info) //called when raw fd received a packet.
{
	char* data;int data_len;
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;

	raw_info_t &raw_info=conn_info.raw_info;

	mylog(log_trace,"<client_on_raw_recv,send_info.ts_ack= %u>\n",send_info.ts_ack);

	if(conn_info.state.client_current_state==client_idle )
	{
		recv(raw_recv_fd, 0,0, 0  );
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
		if(data_len<int( 3*sizeof(id_t)))
		{
			mylog(log_debug,"too short to be a handshake\n");
			return -1;
		}
		//id_t tmp_oppsite_id=  ntohl(* ((u32_t *)&data[0]));
		id_t tmp_oppsite_id;
		memcpy(&tmp_oppsite_id,&data[0],sizeof(tmp_oppsite_id));
		tmp_oppsite_id=ntohl(tmp_oppsite_id);

		//id_t tmp_my_id=ntohl(* ((u32_t *)&data[sizeof(id_t)]));
		id_t tmp_my_id;
		memcpy(&tmp_my_id,&data[sizeof(id_t)],sizeof(tmp_my_id));
		tmp_my_id=ntohl(tmp_my_id);

		//id_t tmp_oppsite_const_id=ntohl(* ((u32_t *)&data[sizeof(id_t)*2]));
		id_t tmp_oppsite_const_id;
		memcpy(&tmp_oppsite_const_id,&data[sizeof(id_t)*2],sizeof(tmp_oppsite_const_id));
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

			//u32_t tmp_conv_id= ntohl(* ((u32_t *)&data[0]));
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
				//perror("ret<0");
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

int server_on_raw_recv_multi() //called when server received an raw packet
{
	char dummy_buf[buf_len];
	packet_info_t peek_info;
	if(peek_raw(peek_info)<0)
	{
		recv(raw_recv_fd, 0,0, 0  );//
		//struct sockaddr saddr;
		//socklen_t saddr_size=sizeof(saddr);
		///recvfrom(raw_recv_fd, 0,0, 0 ,&saddr , &saddr_size);//
		mylog(log_trace,"peek_raw failed\n");
		return -1;
	}else
	{
		mylog(log_trace,"peek_raw success\n");
	}
	u32_t ip=peek_info.src_ip;uint16_t port=peek_info.src_port;

	char ip_port[40];
	sprintf(ip_port,"%s:%d",my_ntoa(ip),port);
	mylog(log_trace,"[%s]peek_raw\n",ip_port);
	int data_len; char *data;

	if(raw_mode==mode_faketcp&&peek_info.syn==1)
	{
		if(!conn_manager.exist(ip,port)||conn_manager.find_insert(ip,port).state.server_current_state!=server_ready)
		{//reply any syn ,before state become ready

			raw_info_t tmp_raw_info;
			if(recv_raw0(tmp_raw_info,data,data_len)<0)
			{
				return 0;
			}
			raw_info_t &raw_info=tmp_raw_info;
			packet_info_t &send_info=raw_info.send_info;
			packet_info_t &recv_info=raw_info.recv_info;

			send_info.src_ip=recv_info.dst_ip;
			send_info.src_port=recv_info.dst_port;

			send_info.dst_port = recv_info.src_port;
			send_info.dst_ip = recv_info.src_ip;

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
			recv(raw_recv_fd, 0,0,0);
		}
		return 0;
	}
	if(!conn_manager.exist(ip,port))
	{
		if(conn_manager.mp.size()>=max_handshake_conn_num)
		{
			mylog(log_info,"[%s]reached max_handshake_conn_num,ignored new handshake\n",ip_port);
			recv(raw_recv_fd, 0,0, 0  );//
			return 0;
		}

		raw_info_t tmp_raw_info;


		if(raw_mode==mode_icmp)
		{
			tmp_raw_info.send_info.dst_port=tmp_raw_info.send_info.src_port=port;
		}
		if(recv_bare(tmp_raw_info,data,data_len)<0)
		{
			return 0;
		}
		if(data_len<int( 3*sizeof(id_t)))
		{
			mylog(log_debug,"[%s]too short to be a handshake\n",ip_port);
			return -1;
		}

		//id_t zero=ntohl(* ((u32_t *)&data[sizeof(id_t)]));
		id_t zero;
		memcpy(&zero,&data[sizeof(id_t)],sizeof(zero));
		zero=ntohl(zero);

		if(zero!=0)
		{
			mylog(log_debug,"[%s]not a invalid initial handshake\n",ip_port);
			return -1;
		}

		mylog(log_info,"[%s]got packet from a new ip\n",ip_port);

		conn_info_t &conn_info=conn_manager.find_insert(ip,port);
		conn_info.raw_info=tmp_raw_info;

		//conn_info.ip_port.ip=ip;
		//conn_info.ip_port.port=port;

		packet_info_t &send_info=conn_info.raw_info.send_info;
		packet_info_t &recv_info=conn_info.raw_info.recv_info;
		raw_info_t &raw_info=conn_info.raw_info;

		send_info.src_ip=recv_info.dst_ip;
		send_info.src_port=recv_info.dst_port;

		send_info.dst_port = recv_info.src_port;
		send_info.dst_ip = recv_info.src_ip;

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


	conn_info_t & conn_info=conn_manager.find_insert(ip,port);//insert if not exist
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
		recv(raw_recv_fd, 0,0, 0  );//
		return 0;
	}
	mylog(log_fatal,"we should never run to here\n");
	myexit(-1);
	return -1;
}

/*
int server_on_raw_recv_handshake1(conn_info_t &conn_info,id_t tmp_oppsite_id )
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;



	return 0;
}*/
int server_on_raw_recv_handshake1(conn_info_t &conn_info,char * ip_port,char * data, int data_len)//called when server received a handshake1 packet from client
{
	packet_info_t &send_info=conn_info.raw_info.send_info;
	packet_info_t &recv_info=conn_info.raw_info.recv_info;
	raw_info_t &raw_info=conn_info.raw_info;

	//u32_t ip=conn_info.raw_info.recv_info.src_ip;
	//uint16_t port=conn_info.raw_info.recv_info.src_port;

	//char ip_port[40];
	//sprintf(ip_port,"%s:%d",my_ntoa(ip),port);

	if(data_len<int( 3*sizeof(id_t)))
	{
		mylog(log_debug,"[%s] data_len=%d too short to be a handshake\n",ip_port,data_len);
		return -1;
	}
	//id_t tmp_oppsite_id=  ntohl(* ((u32_t *)&data[0]));
	id_t tmp_oppsite_id;
	memcpy(&tmp_oppsite_id,(u32_t *)&data[0],sizeof(tmp_oppsite_id));
	tmp_oppsite_id=ntohl(tmp_oppsite_id);

	//id_t tmp_my_id=ntohl(* ((u32_t *)&data[sizeof(id_t)]));
	id_t tmp_my_id;
	memcpy(&tmp_my_id,&data[sizeof(id_t)],sizeof(tmp_my_id));
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
			send_info.icmp_seq=recv_info.icmp_seq;
		}
		send_handshake(raw_info,conn_info.my_id,tmp_oppsite_id,const_id);  //////////////send

		mylog(log_info,"[%s]changed state to server_handshake1,my_id is %x\n",ip_port,conn_info.my_id);
	}
	else if(tmp_my_id==conn_info.my_id)
	{
		conn_info.oppsite_id=tmp_oppsite_id;
		//id_t tmp_oppsite_const_id=ntohl(* ((u32_t *)&data[sizeof(id_t)*2]));

		id_t tmp_oppsite_const_id;
		memcpy(&tmp_oppsite_const_id,&data[sizeof(id_t)*2],sizeof(tmp_oppsite_const_id));
		tmp_oppsite_const_id=ntohl(tmp_oppsite_const_id);


		if(raw_mode==mode_faketcp)
		{
			send_info.seq=recv_info.ack_seq;
			send_info.ack_seq=recv_info.seq+raw_info.recv_info.data_len;
			send_info.ts_ack=recv_info.ts;
		}

		if(raw_mode==mode_icmp)
		{
			send_info.icmp_seq=recv_info.icmp_seq;
		}

		server_on_raw_recv_pre_ready(conn_info,ip_port,tmp_oppsite_const_id);

	}
	else
	{
		mylog(log_debug,"[%s]invalid my_id %x,my_id is %x\n",ip_port,tmp_my_id,conn_info.my_id);
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
		id_t tmp_conv_id;
		memcpy(&tmp_conv_id,&data[0],sizeof(tmp_conv_id));
		tmp_conv_id=ntohl(tmp_conv_id);


		if(hb_mode==0)
			conn_info.last_hb_recv_time = get_current_time();

		mylog(log_trace, "conv:%u\n", tmp_conv_id);
		if (!conn_info.blob->conv_manager.is_conv_used(tmp_conv_id)) {
			if (conn_info.blob->conv_manager.get_size() >= max_conv_num) {
				mylog(log_warn,
						"[%s]ignored new conv %x connect bc max_conv_num exceed\n",ip_port,
						tmp_conv_id);
				return 0;
			}
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
			set_buf_size(new_udp_fd,socket_buf_size,force_socket_buf);

			mylog(log_debug, "[%s]created new udp_fd %d\n",ip_port, new_udp_fd);
			int ret = connect(new_udp_fd, (struct sockaddr *) &remote_addr_in,
					slen);
			if (ret != 0) {
				mylog(log_warn, "udp fd connect fail\n");
				close(new_udp_fd);
				return -1;
			}
			struct epoll_event ev;

			fd64_t new_udp_fd64 =  fd_manager.create(new_udp_fd);
			fd_manager.get_info(new_udp_fd64).p_conn_info=&conn_info;

			mylog(log_trace, "[%s]u64: %lld\n",ip_port, new_udp_fd64);
			ev.events = EPOLLIN;

			ev.data.u64 = new_udp_fd64;

			ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, new_udp_fd, &ev);

			if (ret != 0) {
				mylog(log_warn, "[%s]add udp_fd error\n",ip_port);
				close(new_udp_fd);
				return -1;
			}

			conn_info.blob->conv_manager.insert_conv(tmp_conv_id, new_udp_fd64);



			//assert(conn_manager.udp_fd_mp.find(new_udp_fd)==conn_manager.udp_fd_mp.end());

			//conn_manager.udp_fd_mp[new_udp_fd] = &conn_info;

			//pack_u64(conn_info.raw_info.recv_info.src_ip,conn_info.raw_info.recv_info.src_port);

			mylog(log_info, "[%s]new conv conv_id=%x, assigned fd=%d\n",ip_port,
					tmp_conv_id, new_udp_fd);



		}

		fd64_t fd64 = conn_info.blob->conv_manager.find_u64_by_conv(tmp_conv_id);

		conn_info.blob->conv_manager.update_active_time(tmp_conv_id);

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
			if(!conn_manager.exist(ori_conn_info.raw_info.recv_info.src_ip,ori_conn_info.raw_info.recv_info.src_port))//TODO remove this
			{
				mylog(log_fatal,"[%s]this shouldnt happen\n",ip_port);
				myexit(-1);
			}
			if(!conn_manager.exist(conn_info.raw_info.recv_info.src_ip,conn_info.raw_info.recv_info.src_port))//TODO remove this
			{
				mylog(log_fatal,"[%s]this shouldnt happen2\n",ip_port);
				myexit(-1);
			}
			conn_info_t *&p_ori=conn_manager.find_insert_p(ori_conn_info.raw_info.recv_info.src_ip,ori_conn_info.raw_info.recv_info.src_port);
			conn_info_t *&p=conn_manager.find_insert_p(conn_info.raw_info.recv_info.src_ip,conn_info.raw_info.recv_info.src_port);
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
			init_ifindex(if_name,index);
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
			if(find_lower_level_info(remote_ip_uint32,dest_ip,if_name_string,hw_string)!=0)
			{
				mylog(log_fatal,"auto detect lower-level info failed for %s,specific it manually\n",remote_ip);
				myexit(-1);
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
			init_ifindex(if_name_string.c_str(),index);

			memset(&send_info.addr_ll, 0, sizeof(send_info.addr_ll));
			send_info.addr_ll.sll_family = AF_PACKET;
			send_info.addr_ll.sll_ifindex = index;
			send_info.addr_ll.sll_halen = ETHER_ADDR_LEN;
			send_info.addr_ll.sll_protocol = htons(ETH_P_IP);
			memcpy(&send_info.addr_ll.sll_addr, dest_hw_addr, ETHER_ADDR_LEN);
			//mylog(log_info,"we are running at lower-level (manual) mode\n");
		}

	}
	//printf("?????\n");
	if(source_ip_uint32==0)
	{
		mylog(log_info,"get_src_adress called\n");
		if(get_src_adress(source_ip_uint32,remote_ip_uint32,remote_port)!=0)
		{
			mylog(log_fatal,"the trick to auto get source ip failed,you should specific an ip by --source-ip\n");
			myexit(-1);
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


	//init_filter(source_port);
	send_info.dst_ip=remote_ip_uint32;
	send_info.dst_port=remote_port;

	//g_packet_info.src_ip=source_address_uint32;
	//g_packet_info.src_port=source_port;

    udp_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    set_buf_size(udp_fd,socket_buf_size,force_socket_buf);

	int yes = 1;
	//setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	struct sockaddr_in local_me={0};

	socklen_t slen = sizeof(sockaddr_in);
	//memset(&local_me, 0, sizeof(local_me));
	local_me.sin_family = AF_INET;
	local_me.sin_port = htons(local_port);
	local_me.sin_addr.s_addr = local_ip_uint32;


	if (bind(udp_fd, (struct sockaddr*) &local_me, slen) == -1) {
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

	mylog(log_debug,"send_raw : from %x %d  to %x %d\n",send_info.src_ip,send_info.src_port,send_info.dst_ip,send_info.dst_port);

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
				mylog(log_info,"epoll interrupted by signal\n");
				//close(fifo_fd);
				myexit(0);
			}
			else
			{
				mylog(log_fatal,"epoll_wait return %d\n", nfds);
				myexit(-1);
			}
		}
		int idx;
		for (idx = 0; idx < nfds; ++idx) {
			if (events[idx].data.u64 == (u64_t)raw_recv_fd)
			{
				iphdr *iph;tcphdr *tcph;
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
			else if (events[idx].data.u64 == (u64_t)udp_fd)
			{

				int recv_len;
				struct sockaddr_in udp_new_addr_in={0};
				socklen_t udp_new_addr_len = sizeof(sockaddr_in);
				if ((recv_len = recvfrom(udp_fd, buf, max_data_len, 0,
						(struct sockaddr *) &udp_new_addr_in, &udp_new_addr_len)) == -1) {
					mylog(log_error,"recv_from error,this shouldnt happen at client\n");
					myexit(1);
				};

				if(recv_len>=mtu_warn)
				{
					mylog(log_warn,"huge packet,data len=%d (>=%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ",recv_len,mtu_warn);
				}
				mylog(log_trace,"Received packet from %s:%d,len: %d\n", inet_ntoa(udp_new_addr_in.sin_addr),
						ntohs(udp_new_addr_in.sin_port),recv_len);

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
				u64_t u64=((u64_t(udp_new_addr_in.sin_addr.s_addr))<<32u)+ntohs(udp_new_addr_in.sin_port);
				u32_t conv;

				if(!conn_info.blob->conv_manager.is_u64_used(u64))
				{
					if(conn_info.blob->conv_manager.get_size() >=max_conv_num)
					{
						mylog(log_warn,"ignored new udp connect bc max_conv_num exceed\n");
						continue;
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
					/*
					char buf2[6000];
					int ret1=send_raw(conn_info.raw_info,buf2,40);
					int ret2=send_raw(conn_info.raw_info,buf2,500);
					int ret3=send_raw(conn_info.raw_info,buf2,1000);
					int ret4=send_raw(conn_info.raw_info,buf2,2000);
					mylog(log_warn,"ret= %d %d %d %d\n",ret1,ret2,ret3,ret4);*/

					send_data_safer(conn_info,buf,recv_len,conv);
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

	bind_address_uint32=local_ip_uint32;//only server has bind adress,client sets it to zero

	if(lower_level)
	{
		if(lower_level_manual)
		{
			init_ifindex(if_name,ifindex);
			mylog(log_info,"we are running at lower-level (manual) mode\n");
		}
		else
		{
			mylog(log_info,"we are running at lower-level (auto) mode\n");
		}

	}

	 if(raw_mode==mode_faketcp)
	 {
		 bind_fd=socket(AF_INET,SOCK_STREAM,0);
	 }
	 else  if(raw_mode==mode_udp||raw_mode==mode_icmp)//bind an adress to avoid collision,for icmp,there is no port,just bind a udp port
	 {
		 bind_fd=socket(AF_INET,SOCK_DGRAM,0);
	 }

	 struct sockaddr_in temp_bind_addr={0};
    // bzero(&temp_bind_addr, sizeof(temp_bind_addr));

     temp_bind_addr.sin_family = AF_INET;
     temp_bind_addr.sin_port = htons(local_port);
     temp_bind_addr.sin_addr.s_addr = local_ip_uint32;

     if (bind(bind_fd, (struct sockaddr*)&temp_bind_addr, sizeof(temp_bind_addr)) !=0)
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
	init_filter(local_port);//bpf filter

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

	mylog(log_info,"now listening at %s:%d\n",my_ntoa(local_ip_uint32),local_port);

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
				mylog(log_info,"epoll interrupted by signal\n");
				myexit(0);
			}
			else
			{
				mylog(log_fatal,"epoll_wait return %d\n", nfds);
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
					continue;
				}

				assert(fd_manager.exist_info(fd64));

				conn_info_t* p_conn_info=fd_manager.get_info(fd64).p_conn_info;
				u32_t ip=p_conn_info->raw_info.send_info.dst_ip;
				u32_t port=p_conn_info->raw_info.send_info.dst_port;

				//assert(conn_manager.exist(ip,port));

				///conn_info_t* p_conn_info=conn_manager.find_insert_p(ip,port);


				if(fd64==p_conn_info->timer_fd64)//////////timer_fd64
				{

				if(debug_flag)begin_time=get_current_time();
				//int fd=get_u64_l(events[idx].data.u64);
				int fd=fd_manager.to_fd(fd64);
				u64_t dummy;
				read(fd, &dummy, 8);

				/*if(conn_manager.timer_fd_mp.find(fd)==conn_manager.timer_fd_mp.end()) //this can happen,when fd is a just closed fd
				{
					mylog(log_info,"timer_fd no longer exits\n");
					continue;
				}*/
				//conn_info_t* p_conn_info=conn_manager.timer_fd_mp[fd];
				//u32_t ip=p_conn_info->raw_info.recv_info.src_ip;
				//u32_t port=p_conn_info->raw_info.recv_info.src_port;
				//assert(conn_manager.exist(ip,port));//TODO remove this for peformance

				assert(p_conn_info->state.server_current_state == server_ready); //TODO remove this for peformance

				//conn_info_t &conn_info=conn_manager.find(ip,port);
				char ip_port[40];

				sprintf(ip_port,"%s:%d",my_ntoa(ip),port);

				server_on_timer_multi(*p_conn_info,ip_port);

				if(debug_flag)
				{
					end_time=get_current_time();
					mylog(log_debug,"(events[idx].data.u64 >>32u) == 2u ,%llu,%llu,%llu  \n",begin_time,end_time,end_time-begin_time);
				}

				}
				else//udp_fd64
				{
			//}
			//else if ((events[idx].data.u64 >>32u) == 1u)
			//{
				//uint32_t conv_id=events[n].data.u64>>32u;

				if(debug_flag)begin_time=get_current_time();

				//int fd=int((events[idx].data.u64<<32u)>>32u);

				/*
				if(conn_manager.udp_fd_mp.find(fd)==conn_manager.udp_fd_mp.end()) //this can happen,when fd is a just closed fd
				{
					mylog(log_debug,"fd no longer exists in udp_fd_mp,udp fd %d\n",fd);
					recv(fd,0,0,0);
					continue;
				}*/
				//conn_info_t* p_conn_info=conn_manager.udp_fd_mp[fd];

				//u32_t ip=p_conn_info->raw_info.recv_info.src_ip;
				//u32_t port=p_conn_info->raw_info.recv_info.src_port;

				/*if(!conn_manager.exist(ip,port))//TODO remove this for peformance
				{
					mylog(log_fatal,"ip port no longer exits 2!!!this shouldnt happen\n");
					myexit(-1);
				}*/

				if(p_conn_info->state.server_current_state!=server_ready)//TODO remove this for peformance
				{
					mylog(log_fatal,"p_conn_info->state.server_current_state!=server_ready!!!this shouldnt happen\n");
					myexit(-1);
				}

				conn_info_t &conn_info=*p_conn_info;

				assert(conn_info.blob->conv_manager.is_u64_used(fd64));

				u32_t conv_id=conn_info.blob->conv_manager.find_conv_by_u64(fd64);

				int fd=fd_manager.to_fd(fd64);

				int recv_len=recv(fd,buf,max_data_len,0);

				mylog(log_trace,"received a packet from udp_fd,len:%d\n",recv_len);

				if(recv_len<0)
				{
					mylog(log_debug,"udp fd,recv_len<0 continue,%s\n",strerror(errno));

					continue;
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
		mylog(log_error,"root check failed,make sure you run this program with root,we can try to continue,but it will likely fail\n");
	}

	local_ip_uint32=inet_addr(local_ip);
	remote_ip_uint32=inet_addr(remote_ip);
	source_ip_uint32=inet_addr(source_ip);


	//current_time_rough=get_current_time();

	init_random_number_fd();
	srand(get_true_random_number_nz());
	const_id=get_true_random_number_nz();

	mylog(log_info,"const_id:%x\n",const_id);

	char tmp[1000]="";

	strcat(tmp,key_string);

	strcat(tmp,"key1");

	md5((uint8_t*)tmp,strlen(tmp),(uint8_t*)key);

	/*
	tmp[0]=0;

	strcat(tmp,key_string);

	strcat(tmp,"key2");

	md5((uint8_t*)tmp,strlen(tmp),(uint8_t*)key2);*/

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
