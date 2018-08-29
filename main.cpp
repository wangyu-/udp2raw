#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "log.h"
#include "lib/md5.h"
#include "encrypt.h"
#include "fd_manager.h"

int client_event_loop();
int server_event_loop();
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
