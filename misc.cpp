/*
 * misc.cpp
 *
 *  Created on: Sep 23, 2017
 *      Author: root
 */
#include "git_version.h"
#include "common.h"
#include "encrypt.h"
#include "misc.h"
#include "network.h"
#include "connection.h"
#include "fd_manager.h"


int hb_mode=1;
int hb_len=1200;

int mtu_warn=1375;//if a packet larger than mtu warn is receviced,there will be a warning


fd_manager_t fd_manager;

char local_ip[100]="0.0.0.0", remote_ip[100]="255.255.255.255",source_ip[100]="0.0.0.0";//local_ip is for -l option,remote_ip for -r option,source for --source-ip
u32_t local_ip_uint32,remote_ip_uint32,source_ip_uint32;//convert from last line.
int local_port = -1, remote_port=-1,source_port=0;//similiar to local_ip  remote_ip,buf for port.source_port=0 indicates --source-port is not enabled

int force_source_ip=0; //if --source-ip is enabled

id_t const_id=0;//an id used for connection recovery,its generated randomly,it never change since its generated

int udp_fd=-1;  //for client only. client use this fd to listen and handle udp connection
int bind_fd=-1; //bind only,never send or recv.  its just a dummy fd for bind,so that other program wont occupy the same port
int epollfd=-1; //fd for epoll
int timer_fd=-1;   //the general timer fd for client and server.for server this is not the only timer find,every connection has a timer fd.
int fail_time_counter=0;//determine if the max_fail_time is reached
int epoll_trigger_counter=0;//for debug only
int debug_flag=0;//for debug only


int simple_rule=0;  //deprecated.
int keep_rule=0; //whether to monitor the iptables rule periodly,re-add if losted
int auto_add_iptables_rule=0;//if -a is set
int generate_iptables_rule=0;//if -g is set
int generate_iptables_rule_add=0;// if --gen-add is set

int debug_resend=0; // debug only

char key_string[1000]= "secret key";// -k option

char fifo_file[1000]="";

int clear_iptables=0;
int wait_xtables_lock=0;
string iptables_command0="iptables ";
string iptables_command="";
string iptables_pattern="";
int iptables_rule_added=0;
int iptables_rule_keeped=0;
int iptables_rule_keep_index=0;

program_mode_t program_mode=unset_mode;//0 unset; 1client 2server
raw_mode_t raw_mode=mode_faketcp;
unordered_map<int, const char*> raw_mode_tostring = {{mode_faketcp, "faketcp"}, {mode_udp, "udp"}, {mode_icmp, "icmp"}};

int about_to_exit=0;





int socket_buf_size=1024*1024;
int force_socket_buf=0;

//char lower_level_arg[1000];
int process_lower_level_arg()//handle --lower-level option
{
	lower_level=1;
	if(strcmp(optarg,"auto")==0)
	{
		return 0;
	}

	lower_level_manual=1;
	if (strchr(optarg, '#') == 0) {
		mylog(log_fatal,
				"lower-level parameter invaild,check help page for format\n");
		myexit(-1);
	}
	lower_level = 1;
	u32_t hw[6];
	memset(hw, 0, sizeof(hw));
	sscanf(optarg, "%[^#]#%x:%x:%x:%x:%x:%x", if_name, &hw[0], &hw[1], &hw[2],
			&hw[3], &hw[4], &hw[5]);

	mylog(log_warn,
			"make sure this is correct:   if_name=<%s>  dest_mac_adress=<%02x:%02x:%02x:%02x:%02x:%02x>  \n",
			if_name, hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
	for (int i = 0; i < 6; i++) {
		dest_hw_addr[i] = uint8_t(hw[i]);
	}
	return 0;
}
void print_help()
{
	char git_version_buf[100]={0};
	strncpy(git_version_buf,gitversion,10);
	printf("udp2raw-tunnel\n");
	printf("git version:%s    ",git_version_buf);
	printf("build date:%s %s\n",__DATE__,__TIME__);

	printf("repository: https://github.com/wangyu-/udp2raw-tunnel\n");
	printf("\n");
	printf("usage:\n");
	printf("    run as client : ./this_program -c -l local_listen_ip:local_port -r server_ip:server_port  [options]\n");
	printf("    run as server : ./this_program -s -l server_listen_ip:server_port -r remote_ip:remote_port  [options]\n");
	printf("\n");
	printf("common options,these options must be same on both side:\n");
	printf("    --raw-mode            <string>        avaliable values:faketcp(default),udp,icmp\n");
	printf("    -k,--key              <string>        password to gen symetric key,default:\"secret key\"\n");
	printf("    --cipher-mode         <string>        avaliable values:aes128cbc(default),xor,none\n");
	printf("    --auth-mode           <string>        avaliable values:md5(default),crc32,simple,none\n");
	printf("    -a,--auto-rule                        auto add (and delete) iptables rule\n");
	printf("    -g,--gen-rule                         generate iptables rule then exit,so that you can copy and\n");
	printf("                                          add it manually.overrides -a\n");
	printf("    --disable-anti-replay                 disable anti-replay,not suggested\n");

	//printf("\n");
	printf("client options:\n");
	printf("    --source-ip           <ip>            force source-ip for raw socket\n");
	printf("    --source-port         <port>          force source-port for raw socket,tcp/udp only\n");
	printf("                                          this option disables port changing while re-connecting\n");
//	printf("                                          \n");
	printf("other options:\n");
	printf("    --conf-file           <string>        read options from a configuration file instead of command line.\n");
	printf("                                          check example.conf in repo for format\n");
	printf("    --fifo                <string>        use a fifo(named pipe) for sending commands to the running program,\n");
	printf("                                          check readme.md in repository for supported commands.\n");
	printf("    --log-level           <number>        0:never    1:fatal   2:error   3:warn \n");
	printf("                                          4:info (default)     5:debug   6:trace\n");
//	printf("\n");
	printf("    --log-position                        enable file name,function name,line number in log\n");
	printf("    --disable-color                       disable log color\n");
	printf("    --disable-bpf                         disable the kernel space filter,most time its not necessary\n");
	printf("                                          unless you suspect there is a bug\n");
//	printf("\n");
	printf("    --sock-buf            <number>        buf size for socket,>=10 and <=10240,unit:kbyte,default:1024\n");
	printf("    --force-sock-buf                      bypass system limitation while setting sock-buf\n");
	printf("    --seq-mode            <number>        seq increase mode for faketcp:\n");
	printf("                                          0:static header,do not increase seq and ack_seq\n");
	printf("                                          1:increase seq for every packet,simply ack last seq\n");
	printf("                                          2:increase seq randomly, about every 3 packets,simply ack last seq\n");
	printf("                                          3:simulate an almost real seq/ack procedure(default)\n");
	printf("                                          4:similiar to 3,but do not consider TCP Option Window_Scale,\n");
	printf("                                          maybe useful when firewall doesnt support TCP Option \n");
//	printf("\n");
	printf("    --lower-level         <string>        send packets at OSI level 2, format:'if_name#dest_mac_adress'\n");
	printf("                                          ie:'eth0#00:23:45:67:89:b9'.or try '--lower-level auto' to obtain\n");
	printf("                                          the parameter automatically,specify it manually if 'auto' failed\n");
	printf("    --wait-lock                           wait for xtables lock while invoking iptables, need iptables v1.4.20+\n");
	printf("    --gen-add                             generate iptables rule and add it permanently,then exit.overrides -g\n");
	printf("    --keep-rule                           monitor iptables and auto re-add if necessary.implys -a\n");
	printf("    --hb-len              <number>        length of heart-beat packet, >=0 and <=1500\n");
	printf("    --mtu-warn            <number>        mtu warning threshold, unit:byte, default:1375\n");
	printf("    --clear                               clear any iptables rules added by this program.overrides everything\n");
	printf("    -h,--help                             print this help message\n");

	//printf("common options,these options must be same on both side\n");
}

int load_config(char *file_name, int &argc, vector<string> &argv) //load conf file and append to argv
{
	// Load configurations from config_file instead of the command line.
	// See config.example for example configurations
	std::ifstream conf_file(file_name);
	std::string line;
	if(conf_file.fail())
	{
		mylog(log_fatal,"conf_file %s open failed,reason :%s\n",file_name,strerror(errno));
		myexit(-1);
	}
	while(std::getline(conf_file,line))
	{
		auto res=parse_conf_line(line);

		argc+=res.size();
		for(int i=0;i<(int)res.size();i++)
		{
			argv.push_back(res[i]);
		}
	}
	conf_file.close();

	return 0;
}

int process_log_level(int argc,char *argv[])//process  --log-level and --disable-cloer --log-postion options
{
	int i,j,k;
	for (i = 0; i < argc; i++)
	{
		if(strcmp(argv[i],"--log-level")==0)
		{
			if(i<argc -1)
			{
				sscanf(argv[i+1],"%d",&log_level);
				if(0<=log_level&&log_level<log_end)
				{
				}
				else
				{
					log_bare(log_fatal,"invalid log_level\n");
					myexit(-1);
				}
			}
		}
		if(strcmp(argv[i],"--disable-color")==0)
		{
			enable_log_color=0;
		}
		if(strcmp(argv[i],"--log-position")==0)
		{
			enable_log_position=1;
		}
	}
	return 0;
}
void process_arg(int argc, char *argv[])  //process all options
{
	int i,j,k,opt;

	int option_index = 0;

	char options[]="l:r:schk:ag";
	static struct option long_options[] =
	  {
	    /* These options set a flag. */
	    {"source-ip", required_argument,    0, 1},
	    {"source-port", required_argument,    0, 1},
		{"log-level", required_argument,    0, 1},
		{"key", required_argument,    0, 'k'},
		{"auth-mode", required_argument,    0, 1},
		{"cipher-mode", required_argument,    0, 1},
		{"raw-mode", required_argument,    0, 1},
		{"disable-color", no_argument,    0, 1},
		{"log-position", no_argument,    0, 1},
		{"disable-bpf", no_argument,    0, 1},
		{"disable-anti-replay", no_argument,    0, 1},
		{"auto-rule", no_argument,    0, 'a'},
		{"gen-rule", no_argument,    0, 'g'},
		{"gen-add", no_argument,    0, 1},
		{"debug", no_argument,    0, 1},
		{"clear", no_argument,    0, 1},
		{"simple-rule", no_argument,    0, 1},
		{"keep-rule", no_argument,    0, 1},
		{"lower-level", required_argument,    0, 1},
		{"sock-buf", required_argument,    0, 1},
		{"seq-mode", required_argument,    0, 1},
		{"conf-file", required_argument,   0, 1},
		{"force-sock-buf", no_argument,   0, 1},
		{"wait-lock", no_argument,   0, 1},
		{"random-drop", required_argument,    0, 1},
		{"fifo", required_argument,    0, 1},
		{"hb-mode", required_argument,    0, 1},
		{"hb-len", required_argument,    0, 1},
		{"mtu-warn", required_argument,    0, 1},
		{NULL, 0, 0, 0}
	  };

   process_log_level(argc,argv);

   set<string> all_options;
   map<string,string> shortcut_map;

   all_options.insert("--help");
   all_options.insert("-h");
   string dummy="";
   for(i=0;i<(int)strlen(options);i++)
   {

	   char val=options[i];
	   if( ( val>='0'&&val<='9') ||( val>='a'&&val<='z')||(val>='A'&&val<='Z'))
	   {
		   all_options.insert(dummy+'-'+val);
	   }
   }
   for(i=0;i<int(       sizeof(long_options)/sizeof(long_options[0])      );i++)
   {
	   if(long_options[i].name==NULL) break;
	   int val=long_options[i].val;
	   if( ( val>='0'&&val<='9') ||( val>='a'&&val<='z')||(val>='A'&&val<='Z'))
	   {
		   shortcut_map[dummy+"--"+long_options[i].name]= dummy+"-"+ char(val);
	   }
	  all_options.insert(dummy+"--"+long_options[i].name);
   }

	for (i = 0; i < argc; i++)
	{
		int len=strlen(argv[i]);
		if(len==0)
		{
			mylog(log_fatal,"found an empty string in options\n");
			myexit(-1);
		}
		if(len==1&&argv[i][0]=='-' )
		{
			mylog(log_fatal,"invaild option '-' in argv\n");
			myexit(-1);
		}
		if(len==2&&argv[i][0]=='-'&&argv[i][1]=='-' )
		{
			mylog(log_fatal,"invaild option '--' in argv\n");
			myexit(-1);
		}
	}

   mylog(log_info,"argc=%d ", argc);

	for (i = 0; i < argc; i++) {
		log_bare(log_info, "%s ", argv[i]);
	}
	log_bare(log_info, "\n");

	//string dummy="";
   for(i=+1;i<argc;i++)
   {
	   if(argv[i][0]!='-') continue;
	   string a=argv[i];
	   if(a[0]=='-'&&a[1]!='-')
		   a=dummy+a[0]+a[1];

	   if(all_options.find(a.c_str())==all_options.end())
	   {
			mylog(log_fatal,"invaild option %s\n",a.c_str());
			myexit(-1);
	   }
	   for(j=i+1;j<argc;j++)
	   {
		   if(argv[j][0]!='-') continue;

		   string b=argv[j];

		   if(b[0]=='-'&&b[1]!='-')
			   b=dummy+b[0]+b[1];

		   if(shortcut_map.find(a)!=shortcut_map.end())
				   a=shortcut_map[a];
		   if(shortcut_map.find(b)!=shortcut_map.end())
				   b=shortcut_map[b];
		   if(a==b)
		   {
				mylog(log_fatal,"%s duplicates with %s\n",argv[i],argv[j]);
				myexit(-1);
		   }
	   }
   }





	int no_l = 1, no_r = 1;
	while ((opt = getopt_long(argc, argv,options,long_options,&option_index)) != -1) {
		//string opt_key;
		//opt_key+=opt;
		switch (opt) {
		case 'l':
			no_l = 0;
			if (strchr(optarg, ':') != 0) {
				sscanf(optarg, "%[^:]:%d", local_ip, &local_port);
				if(local_port==22)
				{
					mylog(log_fatal,"port 22 not allowed\n");
					myexit(-1);
				}
			} else {
				mylog(log_fatal,"invalid parameter for -l ,%s,should be ip:port\n",optarg);
				myexit(-1);

			}
			break;
		case 'r':
			no_r = 0;
			if (strchr(optarg, ':') != 0) {
				sscanf(optarg, "%[^:]:%d", remote_ip, &remote_port);
				if(remote_port==22)
				{
					mylog(log_fatal,"port 22 not allowed\n");
					myexit(-1);
				}
			} else {
				mylog(log_fatal,"invalid parameter for -r ,%s,should be ip:port\n",optarg);
				myexit(-1);
			}
			break;
		case 's':
			if(program_mode==0)
			{
				program_mode=server_mode;
			}
			else
			{
				mylog(log_fatal,"-s /-c has already been set,conflict\n");
				myexit(-1);
			}
			break;
		case 'c':
			if(program_mode==0)
			{
				program_mode=client_mode;
			}
			else
			{
				mylog(log_fatal,"-s /-c has already been set,conflict\n");
				myexit(-1);
			}
			break;
		case 'h':
			break;
		case 'a':
			auto_add_iptables_rule=1;
			break;
		case 'g':
			generate_iptables_rule=1;
			break;
		case 'k':
			mylog(log_debug,"parsing key option\n");
			sscanf(optarg,"%s",key_string);
			break;
		case 1:
			mylog(log_debug,"option_index: %d\n",option_index);
			if(strcmp(long_options[option_index].name,"clear")==0)
			{
				clear_iptables=1;
			}
			else if(strcmp(long_options[option_index].name,"source-ip")==0)
			{
				mylog(log_debug,"parsing long option :source-ip\n");
				sscanf(optarg, "%s", source_ip);
				mylog(log_debug,"source: %s\n",source_ip);
				force_source_ip=1;
			}
			else if(strcmp(long_options[option_index].name,"source-port")==0)
			{
				mylog(log_debug,"parsing long option :source-port\n");
				sscanf(optarg, "%d", &source_port);
				mylog(log_info,"source: %d\n",source_port);
			}
			else if(strcmp(long_options[option_index].name,"raw-mode")==0)
			{
				for(i=0;i<mode_end;i++)
				{
					if(strcmp(optarg,raw_mode_tostring[i])==0)
					{
						//printf("%d i\n",i);
						//printf("%s",raw_mode_tostring[i]);
						raw_mode=(raw_mode_t)i;
						break;
					}
				}
				if(i==mode_end)
				{
					mylog(log_fatal,"no such raw_mode %s\n",optarg);
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"auth-mode")==0)
			{
				for(i=0;i<auth_end;i++)
				{
					if(strcmp(optarg,auth_mode_tostring[i])==0)
					{
						auth_mode=(auth_mode_t)i;
						if(auth_mode==auth_none)
						{
							disable_anti_replay=1;
						}
						break;
					}
				}
				if(i==auth_end)
				{
					mylog(log_fatal,"no such auth_mode %s\n",optarg);
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"cipher-mode")==0)
			{
				for(i=0;i<cipher_end;i++)
				{
					if(strcmp(optarg,cipher_mode_tostring[i])==0)
					{
						cipher_mode=(cipher_mode_t)i;
						break;
					}
				}
				if(i==cipher_end)
				{

					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"log-level")==0)
			{
			}
			else if(strcmp(long_options[option_index].name,"lower-level")==0)
			{
				process_lower_level_arg();
				//lower_level=1;
				//strcpy(lower_level_arg,optarg);
			}
			else if(strcmp(long_options[option_index].name,"simple-rule")==0)
			{
				simple_rule=1;
			}
			else if(strcmp(long_options[option_index].name,"keep-rule")==0)
			{
				keep_rule=1;
			}
			else if(strcmp(long_options[option_index].name,"gen-add")==0)
			{
				generate_iptables_rule_add=1;
			}
			else if(strcmp(long_options[option_index].name,"disable-color")==0)
			{
				//enable_log_color=0;
			}
			else if(strcmp(long_options[option_index].name,"debug")==0)
			{
				debug_flag=1;
				//enable_log_color=0;
			}
			else if(strcmp(long_options[option_index].name,"debug-resend")==0)
			{
				//debug_resend=1;
				//enable_log_color=0;
			}
			else if(strcmp(long_options[option_index].name,"log-position")==0)
			{
				//enable_log_position=1;
			}
			else if(strcmp(long_options[option_index].name,"force-sock-buf")==0)
			{
				force_socket_buf=1;
			}
			else if(strcmp(long_options[option_index].name,"wait-lock")==0)
			{
				wait_xtables_lock=1;
			}
			else if(strcmp(long_options[option_index].name,"disable-bpf")==0)
			{
				disable_bpf_filter=1;
			}
			else if(strcmp(long_options[option_index].name,"disable-anti-replay")==0)
			{
				disable_anti_replay=1;
			}
			else if(strcmp(long_options[option_index].name,"sock-buf")==0)
			{
				int tmp=-1;
				sscanf(optarg,"%d",&tmp);
				if(10<=tmp&&tmp<=10*1024)
				{
					socket_buf_size=tmp*1024;
				}
				else
				{
					mylog(log_fatal,"sock-buf value must be between 1 and 10240 (kbyte) \n");
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"seq-mode")==0)
			{
				sscanf(optarg,"%d",&seq_mode);
				if(0<=seq_mode&&seq_mode<=max_seq_mode)
				{
				}
				else
				{
					mylog(log_fatal,"seq_mode value must be  0,1,or 2 \n");
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"random-drop")==0)
			{
				sscanf(optarg,"%d",&random_drop);
				if(random_drop<0||random_drop>10000)
				{
					mylog(log_fatal,"random_drop must be between 0 10000 \n");
					myexit(-1);
				}
				mylog(log_info,"random_drop =%d \n",random_drop);
			}
			else if(strcmp(long_options[option_index].name,"fifo")==0)
			{
				sscanf(optarg,"%s",fifo_file);

				mylog(log_info,"fifo_file =%s \n",fifo_file);
			}
			else if(strcmp(long_options[option_index].name,"conf-file")==0)
			{
				mylog(log_info,"configuration loaded from %s\n",optarg);
			}
			else if(strcmp(long_options[option_index].name,"hb-mode")==0)
			{
				sscanf(optarg,"%d",&hb_mode);
				assert(hb_mode==0||hb_mode==1);
				mylog(log_info,"hb_mode =%d \n",hb_mode);
			}
			else if(strcmp(long_options[option_index].name,"hb-len")==0)
			{
				sscanf(optarg,"%d",&hb_len);
				assert(hb_len>=0&&hb_len<=1500);
				mylog(log_info,"hb_len =%d \n",hb_len);
			}
			else if(strcmp(long_options[option_index].name,"mtu-warn")==0)
			{
				sscanf(optarg,"%d",&mtu_warn);
				assert(mtu_warn>0);
				mylog(log_info,"mtu_warn=%d \n",mtu_warn);
			}
			else
			{
				mylog(log_warn,"ignored unknown long option ,option_index:%d code:<%x>\n",option_index, optopt);
			}
			break;
		default:
			mylog(log_fatal,"unknown option ,code:<%c>,<%x>\n",optopt, optopt);
			myexit(-1);
		}
	}

	if (no_l)
		mylog(log_fatal,"error: -l not found\n");
	if (no_r)
		mylog(log_fatal,"error: -r not found\n");
	if(program_mode==0)
		mylog(log_fatal,"error: -c /-s  hasnt been set\n");
	if (no_l || no_r||program_mode==0)
	{
		print_help();
		myexit(-1);
	}

	//if(lower_level)
		//process_lower_level_arg();

	 mylog(log_info,"important variables: ");

	 log_bare(log_info,"log_level=%d:%s ",log_level,log_text[log_level]);
	 log_bare(log_info,"raw_mode=%s ",raw_mode_tostring[raw_mode]);
	 log_bare(log_info,"cipher_mode=%s ",cipher_mode_tostring[cipher_mode]);
	 log_bare(log_info,"auth_mode=%s ",auth_mode_tostring[auth_mode]);

	 log_bare(log_info,"key=%s ",key_string);

	 log_bare(log_info,"local_ip=%s ",local_ip);
	 log_bare(log_info,"local_port=%d ",local_port);
	 log_bare(log_info,"remote_ip=%s ",remote_ip);
	 log_bare(log_info,"remote_port=%d ",remote_port);
	 log_bare(log_info,"source_ip=%s ",source_ip);
	 log_bare(log_info,"source_port=%d ",source_port);

	 log_bare(log_info,"socket_buf_size=%d ",socket_buf_size);

	 log_bare(log_info,"\n");
}

void pre_process_arg(int argc, char *argv[])//mainly for load conf file
{
	int i,j,k;
	for (i = 0; i < argc; i++)
	{
		if(strcmp(argv[i],"--unit-test")==0)
		{
			unit_test();
			myexit(0);
		}

	}

	for (i = 0; i < argc; i++)
	{
		if(strcmp(argv[i],"-h")==0||strcmp(argv[i],"--help")==0)
		{
			print_help();
			myexit(0);
		}

	}

	if (argc == 1)
	{
		print_help();
		myexit(-1);
	}

	process_log_level(argc,argv);

	int new_argc=0;
	vector<string> new_argv;

	int count=0;
	int pos=-1;

	for (i = 0; i < argc; i++)
	{
		if(strcmp(argv[i],"--conf-file")==0)
		{
			count++;
			pos=i;
			if(i==argc)
			{
				mylog(log_fatal,"--conf-file need a parameter\n");
				myexit(-1);
			}
			if(argv[i+1][0]=='-')
			{
				mylog(log_fatal,"--conf-file need a parameter\n");
				myexit(-1);
			}
			i++;
		}
		else
		{
			//printf("<%s>",argv[i]);
			new_argc++;
			new_argv.push_back(argv[i]);
		}
	}
	if(count>1)
	{
		mylog(log_fatal,"duplicated --conf-file option\n");
		myexit(-1);
	}

	if(count>0)
	{
		load_config(argv[pos+1],new_argc,new_argv);
	}
	char* new_argv_char[new_argv.size()];

	new_argc=0;
	for(i=0;i<(int)new_argv.size();i++)
	{
		if(strcmp(new_argv[i].c_str(),"--conf-file")==0)
		{
			mylog(log_fatal,"cant have --conf-file in a config file\n");
			myexit(-1);
		}
		new_argv_char[new_argc++]=(char *)new_argv[i].c_str();
	}
	process_arg(new_argc,new_argv_char);

}
void *run_keep(void *none)  //called in a new thread for --keep-rule option
{

	while(1)
	{
		sleep(iptables_rule_keep_interval);
		keep_iptables_rule();
		if(about_to_exit)   //just incase it runs forever if there is some bug,not necessary
		{
			sleep(10);
			keep_thread_running=0; //not thread safe ,but wont cause problem
			break;
		}
	}
	return NULL;

}
void iptables_rule()  // handles -a -g --gen-add  --keep-rule --clear --wait-lock
{
	if(!wait_xtables_lock)
	{
		iptables_command=iptables_command0;
	}
	else
	{
		iptables_command=iptables_command0+"-w ";
	}

	if(clear_iptables)
	{
		char *output;
		//int ret =system("iptables-save |grep udp2raw_dWRwMnJhdw|sed -n 's/^-A/iptables -D/p'|sh");
		int ret =run_command(iptables_command+"-S|sed -n '/udp2rawDwrW/p'|sed -n 's/^-A/"+iptables_command+"-D/p'|sh",output);

		int ret2 =run_command(iptables_command+"-S|sed -n '/udp2rawDwrW/p'|sed -n 's/^-N/"+iptables_command+"-X/p'|sh",output);
		//system("iptables-save |grep udp2raw_dWRwMnJhdw|sed 's/^-A/iptables -D/'|sh");
		//system("iptables-save|grep -v udp2raw_dWRwMnJhdw|iptables-restore");
		mylog(log_info,"tried to clear all iptables rule created previously,return value %d %d\n",ret,ret2);
		myexit(-1);
	}

	if(auto_add_iptables_rule&&generate_iptables_rule)
	{
		mylog(log_warn," -g overrides -a\n");
		auto_add_iptables_rule=0;
		//myexit(-1);
	}
	if(generate_iptables_rule_add&&generate_iptables_rule)
	{
		mylog(log_warn," --gen-add overrides -g\n");
		generate_iptables_rule=0;
		//myexit(-1);
	}

	if(keep_rule&&auto_add_iptables_rule==0)
	{
		auto_add_iptables_rule=1;
		mylog(log_warn," --keep_rule implys -a\n");
		generate_iptables_rule=0;
		//myexit(-1);
	}
	char tmp_pattern[200];
	string pattern="";

	if(program_mode==client_mode)
	{
		if(raw_mode==mode_faketcp)
		{
			sprintf(tmp_pattern,"-s %s/32 -p tcp -m tcp --sport %d",remote_ip,remote_port);
		}
		if(raw_mode==mode_udp)
		{
			sprintf(tmp_pattern,"-s %s/32 -p udp -m udp --sport %d",remote_ip,remote_port);
		}
		if(raw_mode==mode_icmp)
		{
			sprintf(tmp_pattern,"-s %s/32 -p icmp",remote_ip);
		}
		pattern=tmp_pattern;
	}
	if(program_mode==server_mode)
	{

		if(raw_mode==mode_faketcp)
		{
			sprintf(tmp_pattern,"-p tcp -m tcp --dport %d",local_port);
		}
		if(raw_mode==mode_udp)
		{
			sprintf(tmp_pattern,"-p udp -m udp --dport %d",local_port);
		}
		if(raw_mode==mode_icmp)
		{
			if(local_ip_uint32==0)
			{
				sprintf(tmp_pattern,"-p icmp");
			}
			else
			{
				sprintf(tmp_pattern,"-d %s/32 -p icmp",local_ip);
			}
		}
		pattern=tmp_pattern;
	}
/*
	if(!simple_rule)
	{
		pattern += " -m comment --comment udp2rawDwrW_";

		char const_id_str[100];
		sprintf(const_id_str, "%x_", const_id);

		pattern += const_id_str;

		time_t timer;
		char buffer[26];
		struct tm* tm_info;

		time(&timer);
		tm_info = localtime(&timer);

		strftime(buffer, 26, "%Y-%m-%d-%H:%M:%S", tm_info);

		pattern += buffer;


	}*/

	if(auto_add_iptables_rule)
	{
		iptables_rule_init(pattern.c_str(),const_id,keep_rule);
		if(keep_rule)
		{
			if(pthread_create(&keep_thread, NULL, run_keep, 0)) {

				mylog(log_fatal, "Error creating thread\n");
				myexit(-1);
			}
			keep_thread_running=1;
		}
	}
	if(generate_iptables_rule)
	{
		string rule=iptables_command+"-I INPUT ";
		rule+=pattern;
		rule+=" -j DROP";

		printf("generated iptables rule:\n");
		printf("%s\n",rule.c_str());
		myexit(0);
	}
	if(generate_iptables_rule_add)
	{
		iptables_gen_add(pattern.c_str(),const_id);
		myexit(0);
	}


}

int unit_test()
{
	printf("running unit test\n");
	vector<string> conf_lines= {"---aaa","--aaa bbb","-a bbb"," \t \t \t-a\t \t \t bbbbb\t \t \t "};
	for(int i=0;i<int(conf_lines.size());i++)
	{
		printf("orign:%s\n",conf_lines[i].c_str());
		auto res=parse_conf_line(conf_lines[i]);
		printf("pasrse_result: size %d",int(res.size()));
		for(int j=0;j<int(res.size());j++)
		{
			printf("<%s>",res[j].c_str());
		}
		printf("\n");
	}

	char s1[]={1,2,3,4,5};

	char s2[]={1};

	short c1=csum((unsigned short*)s1,5);
	short c2=csum((unsigned short*)s2,1);
	//c2=0;

	printf("%x %x\n",(int)c1,(int)c2);

	const char buf[]={1,2,3,4,5,6,7,8,9,10,11,2,13,14,15,16};
	char key[100]={0};
	char buf2[100]={0};
	char buf3[100]={0};
	char buf4[100]={0};
	int len=16;
	for(int i=0;i<len;i++)
	{
		printf("<%d>",buf[i]);
	}
	printf("\n");
	cipher_encrypt(buf,buf2,len,key);
	for(int i=0;i<len;i++)
	{
		printf("<%d>",buf2[i]);
	}
	printf("\n");
	int temp_len=len;
	cipher_decrypt(buf2,buf3,len,key);
	for(int i=0;i<len;i++)
	{
		printf("<%d>",buf3[i]);
	}
	printf("\n");
	cipher_encrypt(buf2,buf4,temp_len,key);
	for(int i=0;i<temp_len;i++)
	{
		printf("<%d>",buf4[i]);
	}
	return 0;
}


int set_timer(int epollfd,int &timer_fd)//put a timer_fd into epoll,general function,used both in client and server
{
	int ret;
	epoll_event ev;

	itimerspec its;
	memset(&its,0,sizeof(its));

	if((timer_fd=timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK)) < 0)
	{
		mylog(log_fatal,"timer_fd create error\n");
		myexit(1);
	}
	its.it_interval.tv_sec=(timer_interval/1000);
	its.it_interval.tv_nsec=(timer_interval%1000)*1000ll*1000ll;
	its.it_value.tv_nsec=1; //imidiately
	timerfd_settime(timer_fd,0,&its,0);


	ev.events = EPOLLIN;
	ev.data.u64 = timer_fd;

	ret=epoll_ctl(epollfd, EPOLL_CTL_ADD, timer_fd, &ev);
	if (ret < 0) {
		mylog(log_fatal,"epoll_ctl return %d\n", ret);
		myexit(-1);
	}
	return 0;
}


int set_timer_server(int epollfd,int &timer_fd,fd64_t &fd64)//only for server
{
	int ret;
	epoll_event ev;

	itimerspec its;
	memset(&its,0,sizeof(its));

	if((timer_fd=timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK)) < 0)
	{
		mylog(log_fatal,"timer_fd create error\n");
		myexit(1);
	}
	its.it_interval.tv_sec=(timer_interval/1000);
	its.it_interval.tv_nsec=(timer_interval%1000)*1000ll*1000ll;
	its.it_value.tv_nsec=1; //imidiately
	timerfd_settime(timer_fd,0,&its,0);

	fd64=fd_manager.create(timer_fd);


	ev.events = EPOLLIN;
	ev.data.u64 = fd64;////difference

	ret=epoll_ctl(epollfd, EPOLL_CTL_ADD, timer_fd, &ev);
	if (ret < 0) {
		mylog(log_fatal,"epoll_ctl return %d\n", ret);
		myexit(-1);
	}
	return 0;
}

int handle_lower_level(raw_info_t &raw_info)//fill lower_level info,when --lower-level is enabled,only for server
{
	packet_info_t &send_info=raw_info.send_info;
	packet_info_t &recv_info=raw_info.recv_info;

	if(lower_level_manual)
	{
		memset(&send_info.addr_ll,0,sizeof(send_info.addr_ll));
		send_info.addr_ll.sll_family=AF_PACKET;
		send_info.addr_ll.sll_ifindex=ifindex;
		send_info.addr_ll.sll_halen=ETHER_ADDR_LEN;
		send_info.addr_ll.sll_protocol=htons(ETH_P_IP);
		memcpy(&send_info.addr_ll.sll_addr,dest_hw_addr,ETHER_ADDR_LEN);
		 mylog(log_debug,"[manual]lower level info %x %x\n ",send_info.addr_ll.sll_halen,send_info.addr_ll.sll_protocol);
	}
	else
	{
	memset(&send_info.addr_ll,0,sizeof(send_info.addr_ll));
	send_info.addr_ll.sll_family=recv_info.addr_ll.sll_family;
	send_info.addr_ll.sll_ifindex=recv_info.addr_ll.sll_ifindex;
	send_info.addr_ll.sll_protocol=recv_info.addr_ll.sll_protocol;
	send_info.addr_ll.sll_halen=recv_info.addr_ll.sll_halen;
	memcpy(send_info.addr_ll.sll_addr,recv_info.addr_ll.sll_addr,sizeof(send_info.addr_ll.sll_addr));
	//other bytes should be kept zero.

	  mylog(log_debug,"[auto]lower level info %x %x\n ",send_info.addr_ll.sll_halen,send_info.addr_ll.sll_protocol);
	}
	return 0;
}


string chain[2];
string rule_keep[2];
string rule_keep_add[2];
string rule_keep_del[2];
u64_t keep_rule_last_time=0;

pthread_t keep_thread;
int keep_thread_running=0;
int iptables_gen_add(const char * s,u32_t const_id)
{
	string dummy="";
	iptables_pattern=s;
	chain[0] =dummy+ "udp2rawDwrW_C";
	rule_keep[0]=dummy+ iptables_pattern+" -j " +chain[0];
	rule_keep_add[0]=iptables_command+"-I INPUT "+rule_keep[0];

	char *output;
	run_command(iptables_command+"-N "+chain[0],output,show_none);
	run_command(iptables_command+"-F "+chain[0],output);
	run_command(iptables_command+"-I "+chain[0] + " -j DROP",output);

	rule_keep_del[0]=iptables_command+"-D INPUT "+rule_keep[0];

	run_command(rule_keep_del[0],output,show_none);
	run_command(rule_keep_del[0],output,show_none);

	if(run_command(rule_keep_add[0],output)!=0)
	{
		mylog(log_fatal,"auto added iptables failed by: %s\n",rule_keep_add[0].c_str());
		myexit(-1);
	}
	return 0;
}
int iptables_rule_init(const char * s,u32_t const_id,int keep)
{
	iptables_pattern=s;
	iptables_rule_added=1;
	iptables_rule_keeped=keep;

	string dummy="";
	char const_id_str[100];
	sprintf(const_id_str, "%x", const_id);

	chain[0] =dummy+ "udp2rawDwrW_"+const_id_str+"_C0";
	chain[1] =dummy+ "udp2rawDwrW_"+const_id_str+"_C1";

	rule_keep[0]=dummy+ iptables_pattern+" -j " +chain[0];
	rule_keep[1]=dummy+ iptables_pattern+" -j " +chain[1];

	rule_keep_add[0]=iptables_command+"-I INPUT "+rule_keep[0];
	rule_keep_add[1]=iptables_command+"-I INPUT "+rule_keep[1];

	rule_keep_del[0]=iptables_command+"-D INPUT "+rule_keep[0];
	rule_keep_del[1]=iptables_command+"-D INPUT "+rule_keep[1];

	keep_rule_last_time=get_current_time();

	char *output;

	for(int i=0;i<=iptables_rule_keeped;i++)
	{
		run_command(iptables_command+"-N "+chain[i],output);
		run_command(iptables_command+"-F "+chain[i],output);
		run_command(iptables_command+"-I "+chain[i] + " -j DROP",output);

		if(run_command(rule_keep_add[i],output)!=0)
		{
			mylog(log_fatal,"auto added iptables failed by: %s\n",rule_keep_add[i].c_str());
			myexit(-1);
		}
	}
	mylog(log_warn,"auto added iptables rules\n");
	return 0;
}

int keep_iptables_rule()  //magic to work on a machine without grep/iptables --check/-m commment
{
	/*
	if(iptables_rule_keeped==0) return  0;


	uint64_t tmp_current_time=get_current_time();
	if(tmp_current_time-keep_rule_last_time<=iptables_rule_keep_interval)
	{
		return 0;
	}
	else
	{
		keep_rule_last_time=tmp_current_time;
	}*/

	mylog(log_debug,"keep_iptables_rule begin %llu\n",get_current_time());
	iptables_rule_keep_index+=1;
	iptables_rule_keep_index%=2;

	string dummy="";
	char *output;

	int i=iptables_rule_keep_index;

	run_command(iptables_command + "-N " + chain[i], output,show_none);

	if (run_command(iptables_command + "-F " + chain[i], output,show_none) != 0)
		mylog(log_warn, "iptables -F failed %d\n",i);

	if (run_command(iptables_command + "-I " + chain[i] + " -j DROP",output,show_none) != 0)
		mylog(log_warn, "iptables -I failed %d\n",i);

	if (run_command(rule_keep_del[i], output,show_none) != 0)
		mylog(log_warn, "rule_keep_del failed %d\n",i);

	run_command(rule_keep_del[i], output,show_none); //do it twice,incase it fails for unknown random reason

	if(run_command(rule_keep_add[i], output,show_log)!=0)
		mylog(log_warn, "rule_keep_del failed %d\n",i);

	mylog(log_debug,"keep_iptables_rule end %llu\n",get_current_time());
	return 0;
}

int clear_iptables_rule()
{
	char *output;
	string dummy="";
	if(!iptables_rule_added) return 0;

	for(int i=0;i<=iptables_rule_keeped;i++ )
	{
		run_command(rule_keep_del[i],output);
		run_command(iptables_command+"-F "+chain[i],output);
		run_command(iptables_command+"-X "+chain[i],output);
	}
	return 0;
}

void  signal_handler(int sig)
{
	about_to_exit=1;
    // myexit(0);
}



