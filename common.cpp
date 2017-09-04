/*
 * comm.cpp
 *
 *  Created on: Jul 29, 2017
 *      Author: wangyu
 */

#include "common.h"
#include "log.h"



int about_to_exit=0;

raw_mode_t raw_mode=mode_faketcp;
unordered_map<int, const char*> raw_mode_tostring = {{mode_faketcp, "faketcp"}, {mode_udp, "udp"}, {mode_icmp, "icmp"}};
int socket_buf_size=1024*1024;
int force_socket_buf=0;

static int random_number_fd=-1;
string iptables_pattern="";
int iptables_rule_added=0;
int iptables_rule_keeped=0;
int iptables_rule_keep_index=0;
//int iptables_rule_no_clear=0;



program_mode_t program_mode=unset_mode;//0 unset; 1client 2server

u64_t get_current_time()
{
	timespec tmp_time;
	clock_gettime(CLOCK_MONOTONIC, &tmp_time);
	return tmp_time.tv_sec*1000+tmp_time.tv_nsec/(1000*1000l);
}

u64_t pack_u64(u32_t a,u32_t b)
{
	u64_t ret=a;
	ret<<=32u;
	ret+=b;
	return ret;
}
u32_t get_u64_h(u64_t a)
{
	return a>>32u;
}
u32_t get_u64_l(u64_t a)
{
	return (a<<32u)>>32u;
}

char * my_ntoa(u32_t ip)
{
	in_addr a;
	a.s_addr=ip;
	return inet_ntoa(a);
}


/*
int add_iptables_rule(const char * s)
{

	iptables_pattern=s;

	string rule="iptables -I INPUT ";
	rule+=iptables_pattern;
	rule+=" -j DROP";

	char *output;
	if(run_command(rule.c_str(),output)==0)
	{
		mylog(log_warn,"auto added iptables rule by:  %s\n",rule.c_str());
	}
	else
	{
		mylog(log_fatal,"auto added iptables failed by: %s\n",rule.c_str());
		//mylog(log_fatal,"reason : %s\n",strerror(errno));
		myexit(-1);
	}
	iptables_rule_added=1;
	return 0;
}*/
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
	rule_keep_add[0]=dummy+"iptables -I INPUT "+rule_keep[0];

	char *output;
	run_command(dummy+"iptables -N "+chain[0],output,show_none);
	run_command(dummy+"iptables -F "+chain[0],output);
	run_command(dummy+"iptables -I "+chain[0] + " -j DROP",output);

	rule_keep_del[0]=dummy+"iptables -D INPUT "+rule_keep[0];

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

	rule_keep_add[0]=dummy+"iptables -I INPUT "+rule_keep[0];
	rule_keep_add[1]=dummy+"iptables -I INPUT "+rule_keep[1];

	rule_keep_del[0]=dummy+"iptables -D INPUT "+rule_keep[0];
	rule_keep_del[1]=dummy+"iptables -D INPUT "+rule_keep[1];

	keep_rule_last_time=get_current_time();

	char *output;

	for(int i=0;i<=iptables_rule_keeped;i++)
	{
		run_command(dummy+"iptables -N "+chain[i],output);
		run_command(dummy+"iptables -F "+chain[i],output);
		run_command(dummy+"iptables -I "+chain[i] + " -j DROP",output);

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

	run_command(dummy + "iptables -N " + chain[i], output,show_none);

	if (run_command(dummy + "iptables -F " + chain[i], output,show_none) != 0)
		mylog(log_warn, "iptables -F failed %d\n",i);

	if (run_command(dummy + "iptables -I " + chain[i] + " -j DROP",output,show_none) != 0)
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
		run_command(dummy+"iptables -F "+chain[i],output);
		run_command(dummy+"iptables -X "+chain[i],output);
	}
	return 0;
}


void init_random_number_fd()
{

	random_number_fd=open("/dev/urandom",O_RDONLY);

	if(random_number_fd==-1)
	{
		mylog(log_fatal,"error open /dev/urandom\n");
		myexit(-1);
	}
	setnonblocking(random_number_fd);
}
u64_t get_true_random_number_64()
{
	u64_t ret;
	int size=read(random_number_fd,&ret,sizeof(ret));
	if(size!=sizeof(ret))
	{
		mylog(log_fatal,"get random number failed %d\n",size);
		myexit(-1);
	}

	return ret;
}
u32_t get_true_random_number()
{
	u32_t ret;
	int size=read(random_number_fd,&ret,sizeof(ret));
	if(size!=sizeof(ret))
	{
		mylog(log_fatal,"get random number failed %d\n",size);
		myexit(-1);
	}
	return ret;
}
u32_t get_true_random_number_nz() //nz for non-zero
{
	u32_t ret=0;
	while(ret==0)
	{
		ret=get_true_random_number();
	}
	return ret;
}
u64_t ntoh64(u64_t a)
{
	if(__BYTE_ORDER == __LITTLE_ENDIAN)
	{
		return bswap_64( a);
	}
	else return a;

}
u64_t hton64(u64_t a)
{
	if(__BYTE_ORDER == __LITTLE_ENDIAN)
	{
		return bswap_64( a);
	}
	else return a;

}

void setnonblocking(int sock) {
	int opts;
	opts = fcntl(sock, F_GETFL);

	if (opts < 0) {
    	mylog(log_fatal,"fcntl(sock,GETFL)\n");
		//perror("fcntl(sock,GETFL)");
		myexit(1);
	}
	opts = opts | O_NONBLOCK;
	if (fcntl(sock, F_SETFL, opts) < 0) {
    	mylog(log_fatal,"fcntl(sock,SETFL,opts)\n");
		//perror("fcntl(sock,SETFL,opts)");
		myexit(1);
	}

}

/*
    Generic checksum calculation function
*/
unsigned short csum(const unsigned short *ptr,int nbytes) {//works both for big and little endian
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}


int set_buf_size(int fd)
{
	if(force_socket_buf)
	{
		if(setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
		{
			mylog(log_fatal,"SO_SNDBUFFORCE fail  socket_buf_size=%d  errno=%s\n",socket_buf_size,strerror(errno));
			myexit(1);
		}
		if(setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
		{
			mylog(log_fatal,"SO_RCVBUFFORCE fail  socket_buf_size=%d  errno=%s\n",socket_buf_size,strerror(errno));
			myexit(1);
		}
	}
	else
	{
		if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &socket_buf_size, sizeof(socket_buf_size))<0)
		{
			mylog(log_fatal,"SO_SNDBUF fail  socket_buf_size=%d  errno=%s\n",socket_buf_size,strerror(errno));
			myexit(1);
		}
		if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &socket_buf_size, sizeof(socket_buf_size))<0)
		{
			mylog(log_fatal,"SO_RCVBUF fail  socket_buf_size=%d  errno=%s\n",socket_buf_size,strerror(errno));
			myexit(1);
		}
	}
	return 0;
}

void myexit(int a)
{
    if(enable_log_color)
   	printf("%s\n",RESET);
    if(keep_thread_running)
    {
		if(pthread_cancel(keep_thread))
		{
			mylog(log_warn,"pthread_cancel failed\n");
		}
		else
		{
			mylog(log_info,"pthread_cancel success\n");
		}
    }
	clear_iptables_rule();
	exit(a);
}
void  signal_handler(int sig)
{
	about_to_exit=1;
    // myexit(0);
}

int numbers_to_char(id_t id1,id_t id2,id_t id3,char * &data,int &len)
{
	static char buf[buf_len];
	data=buf;
	id_t tmp=htonl(id1);
	memcpy(buf,&tmp,sizeof(tmp));

	tmp=htonl(id2);
	memcpy(buf+sizeof(tmp),&tmp,sizeof(tmp));

	tmp=htonl(id3);
	memcpy(buf+sizeof(tmp)*2,&tmp,sizeof(tmp));

	len=sizeof(id_t)*3;
	return 0;
}


int char_to_numbers(const char * data,int len,id_t &id1,id_t &id2,id_t &id3)
{
	if(len<int(sizeof(id_t)*3)) return -1;
	//id1=ntohl(  *((id_t*)(data+0)) );
	memcpy(&id1,data+0,sizeof(id1));
	id1=ntohl(id1);
	//id2=ntohl(  *((id_t*)(data+sizeof(id_t))) );
	memcpy(&id2,data+sizeof(id_t),sizeof(id2));
	id2=ntohl(id2);
	//id3=ntohl(  *((id_t*)(data+sizeof(id_t)*2)) );
	memcpy(&id3,data+sizeof(id_t)*2,sizeof(id3));
	id3=ntohl(id3);
	return 0;
}
int hex_to_u32(const string & a,u32_t &output)
{
	//string b="0x";
	//b+=a;
	if(sscanf(a.c_str(),"%x",&output)==1)
	{
		//printf("%s %x\n",a.c_str(),output);
		return 0;
	}
	mylog(log_error,"<%s> doesnt contain a hex\n",a.c_str());
	return -1;
}
int hex_to_u32_with_endian(const string & a,u32_t &output)
{
	//string b="0x";
	//b+=a;
	if(sscanf(a.c_str(),"%x",&output)==1)
	{
		output=htonl(output);
		//printf("%s %x\n",a.c_str(),output);
		return 0;
	}
	mylog(log_error,"<%s> doesnt contain a hex\n",a.c_str());
	return -1;
}
bool larger_than_u32(u32_t a,u32_t b)
//TODO
//looks like this can simply be done by return ((i32_t)(a-b) >0)
{

	u32_t smaller,bigger;
	smaller=min(a,b);//smaller in normal sense
	bigger=max(a,b);
	u32_t distance=min(bigger-smaller,smaller+(0xffffffff-bigger+1));
	if(distance==bigger-smaller)
	{
		if(bigger==a)
		{
			return 1;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		if(smaller==b)
		{
			return 0;
		}
		else
		{
			return 1;
		}
	}
}

bool larger_than_u16(uint16_t a,uint16_t b)
{

	uint16_t smaller,bigger;
	smaller=min(a,b);//smaller in normal sense
	bigger=max(a,b);
	uint16_t distance=min(bigger-smaller,smaller+(0xffff-bigger+1));
	if(distance==bigger-smaller)
	{
		if(bigger==a)
		{
			return 1;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		if(smaller==b)
		{
			return 0;
		}
		else
		{
			return 1;
		}
	}
}
vector<string> string_to_vec(const char * s,const char * sp) {
	  vector<string> res;
	  string str=s;
	  char *p = strtok ((char *)str.c_str(),sp);
	  while (p != NULL)
	  {
		 res.push_back(p);
	    //printf ("%s\n",p);
	    p = strtok(NULL, sp);
	  }

	 /* for(int i=0;i<(int)res.size();i++)
	  {
		  printf("<<%s>>\n",res[i].c_str());
	  }*/
	  return res;
}

vector< vector <string> > string_to_vec2(const char * s)
{
	vector< vector <string> > res;
	vector<string> lines=string_to_vec(s,"\n");
	for(int i=0;i<int(lines.size());i++)
	{
		vector<string> tmp;
		tmp=string_to_vec(lines[i].c_str(),"\t ");
		res.push_back(tmp);
	}
	return res;
}
int read_file(const char * file,string &output)
{
	const int max_len=3*1024*1024;
   // static char buf[max_len+100];
	string buf0;
	buf0.reserve(max_len+200);
	char * buf=(char *)buf0.c_str();
	buf[max_len]=0;
    //buf[sizeof(buf)-1]=0;
	int fd=open(file,O_RDONLY);
	if(fd==-1)
	{
		 mylog(log_error,"read_file %s fail\n",file);
		 return -1;
	}
	int len=read(fd,buf,max_len);
	if(len==max_len)
	{
		buf[0]=0;
        mylog(log_error,"%s too long,buf not large enough\n",file);
        return -2;
	}
	else if(len<0)
	{
		buf[0]=0;
        mylog(log_error,"%s read fail %d\n",file,len);
        return -3;
	}
	else
	{
		buf[len]=0;
		output=buf;
	}
	return 0;
}
int run_command(string command0,char * &output,int flag) {
    FILE *in;


    if((flag&show_log)==0) command0+=" 2>&1 ";

    const char * command=command0.c_str();

    int level= (flag&show_log)?log_warn:log_debug;

    if(flag&show_command)
    {
    	mylog(log_info,"run_command %s\n",command);
    }
    else
    {
    	mylog(log_debug,"run_command %s\n",command);
    }
    static __thread char buf[1024*1024+100];
    buf[sizeof(buf)-1]=0;
    if(!(in = popen(command, "r"))){
        mylog(level,"command %s popen failed,errno %s\n",command,strerror(errno));
        return -1;
    }

    int len =fread(buf, 1024*1024, 1, in);
    if(len==1024*1024)
    {
    	buf[0]=0;
        mylog(level,"too long,buf not larger enough\n");
        return -2;
    }
    else
    {
       	buf[len]=0;
    }
    int ret;
    if(( ret=ferror(in) ))
    {
        mylog(level,"command %s fread failed,ferror return value %d \n",command,ret);
        return -3;
    }
    //if(output!=0)
    output=buf;
    ret= pclose(in);

    int ret2=WEXITSTATUS(ret);

    if(ret!=0||ret2!=0)
    {
    	mylog(level,"commnad %s ,pclose returned %d ,WEXITSTATUS %d,errnor :%s \n",command,ret,ret2,strerror(errno));
    	return -4;
    }

    return 0;

}
/*
int run_command_no_log(string command0,char * &output) {
    FILE *in;
    command0+=" 2>&1 ";
    const char * command=command0.c_str();
    mylog(log_debug,"run_command_no_log %s\n",command);
    static char buf[1024*1024+100];
    buf[sizeof(buf)-1]=0;
    if(!(in = popen(command, "r"))){
        mylog(log_debug,"command %s popen failed,errno %s\n",command,strerror(errno));
        return -1;
    }

    int len =fread(buf, 1024*1024, 1, in);
    if(len==1024*1024)
    {
    	buf[0]=0;
        mylog(log_debug,"too long,buf not larger enough\n");
        return -2;
    }
    else
    {
       	buf[len]=0;
    }
    int ret;
    if(( ret=ferror(in) ))
    {
        mylog(log_debug,"command %s fread failed,ferror return value %d \n",command,ret);
        return -3;
    }
    //if(output!=0)
    output=buf;
    ret= pclose(in);

    int ret2=WEXITSTATUS(ret);

    if(ret!=0||ret2!=0)
    {
    	mylog(log_debug,"commnad %s ,pclose returned %d ,WEXITSTATUS %d,errnor :%s \n",command,ret,ret2,strerror(errno));
    	return -4;
    }

    return 0;

}*/

// Remove preceding and trailing characters
string trim(const string& str, char c) {
	size_t first = str.find_first_not_of(c);
	if(string::npos==first)
	{
		return "";
	}
	size_t last = str.find_last_not_of(c);
	return str.substr(first,(last-first+1));
}

vector<string> parse_conf_line(const string& s0)
{
	string s=s0;
	s.reserve(s.length()+200);
	char *buf=(char *)s.c_str();
	//char buf[s.length()+200];
	char *p=buf;
	int i=int(s.length())-1;
	int j;
	vector<string>res;
	strcpy(buf,(char *)s.c_str());
	while(i>=0)
	{
		if(buf[i]==' ' || buf[i]== '\t')
			buf[i]=0;
		else break;
		i--;
	}
	while(*p!=0)
	{
		if(*p==' ' || *p== '\t')
		{
			p++;
		}
		else break;
	}
	int new_len=strlen(p);
	if(new_len==0)return res;
	if(p[0]=='#') return res;
	if(p[0]!='-')
	{
		mylog(log_fatal,"line :<%s> not begin with '-' ",s.c_str());
		myexit(-1);
	}

	for(i=0;i<new_len;i++)
	{
		if(p[i]==' '||p[i]=='\t')
		{
			break;
		}
	}
	if(i==new_len)
	{
		res.push_back(p);
		return res;
	}

	j=i;
	while(p[j]==' '||p[j]=='\t')
		j++;
	p[i]=0;
	res.push_back(p);
	res.push_back(p+j);
	return res;
}
















