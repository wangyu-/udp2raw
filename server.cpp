/*
 * server.cpp
 *
 *  Created on: Aug 29, 2018
 *      Author: root
 */


#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "log.h"
#include "lib/md5.h"
#include "encrypt.h"
#include "fd_manager.h"

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
int server_on_recv_safer_multi(conn_info_t &conn_info,char type,char *data,int data_len)
{
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
			if(use_tcp_dummy_socket!=0)
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
        vector<char> type_vec;
        vector<string> data_vec;
        recv_safer_multi(conn_info,type_vec,data_vec);
        if(data_vec.empty())
        {
            mylog(log_debug,"recv_safer failed!\n");
            return -1;
        }

        for(int i=0;i<(int)type_vec.size();i++)
        {
            char type=type_vec[i];
            char *data=(char *)data_vec[i].c_str(); //be careful, do not append data to it
            int data_len=data_vec[i].length();
            server_on_raw_recv_ready(conn_info,ip_port,type,data,data_len);
        }
        return 0;

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
				int unused=read(timer_fd, &dummy, 8);
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
					int unused=read(fd, &dummy, 8);
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
