#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "log.h"
#include "lib/md5.h"
#include "encrypt.h"
#include "fd_manager.h"

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

int client_event_loop();

int main(int argc, char *argv[])
{
	assert(sizeof(unsigned short)==2);
	assert(sizeof(unsigned int)==4);
	assert(sizeof(unsigned long long)==8);

	init_ws();

	dup2(1, 2);//redirect stderr to stdout
#if defined(__MINGW32__)
    enable_log_color=0;
#endif

	pre_process_arg(argc,argv);

	if(program_mode==client_mode)
	{
		struct ev_loop* loop=ev_default_loop(0);
#if !defined(__MINGW32__)
		ev_signal signal_watcher_sigpipe;
		ev_signal_init(&signal_watcher_sigpipe, sigpipe_cb, SIGPIPE);
		ev_signal_start(loop, &signal_watcher_sigpipe);
#endif
		ev_signal signal_watcher_sigterm;
		ev_signal_init(&signal_watcher_sigterm, sigterm_cb, SIGTERM);
		ev_signal_start(loop, &signal_watcher_sigterm);

		ev_signal signal_watcher_sigint;
		ev_signal_init(&signal_watcher_sigint, sigint_cb, SIGINT);
		ev_signal_start(loop, &signal_watcher_sigint);
	}
	else
	{
		mylog(log_fatal,"server mode not supported in multi-platform version\n");
		myexit(-1);
		/*
		signal(SIGINT, signal_handler);
		signal(SIGHUP, signal_handler);
		signal(SIGKILL, signal_handler);
		signal(SIGTERM, signal_handler);
		signal(SIGQUIT, signal_handler);
		 */
	}
#if !defined(__MINGW32__)
	if(geteuid() != 0)
	{
		mylog(log_warn,"root check failed, it seems like you are using a non-root account. we can try to continue, but it may fail. If you want to run udp2raw as non-root, you have to add iptables rule manually, and grant udp2raw CAP_NET_RAW capability, check README.md in repo for more info.\n");
	}
	else
	{
		mylog(log_warn,"you can run udp2raw with non-root account for better security. check README.md in repo for more info.\n");
	}
#endif

	mylog(log_info,"remote_ip=[%s], make sure this is a vaild IP address\n",remote_addr.get_ip());

	//init_random_number_fd();
	srand(get_true_random_number_nz());
	const_id=get_true_random_number_nz();

	mylog(log_info,"const_id:%x\n",const_id);

	my_init_keys(key_string,program_mode==client_mode?1:0);

	iptables_rule();
	//init_raw_socket();
	//init_raw_socket() has to be done after dev dectection in mp version

	if(program_mode==client_mode)
	{
		client_event_loop();
	}
	else
	{
		mylog(log_fatal,"server mode not supported in multi-platform version\n");
		myexit(-1);
		/*
		server_event_loop();
		*/
	}

	return 0;
}
