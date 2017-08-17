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
static int random_number_fd=-1;
char iptables_rule[200]="";
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


int add_iptables_rule(char * s)
{
	strcpy(iptables_rule,s);
	char buf[300]="iptables -I ";
	strcat(buf,s);
	char *output;
	if(run_command(buf,output)==0)
	{
		mylog(log_warn,"auto added iptables rule by:  %s\n",buf);
	}
	else
	{
		mylog(log_fatal,"auto added iptables failed by: %s\n",buf);
		//mylog(log_fatal,"reason : %s\n",strerror(errno));
		myexit(-1);
	}
	return 0;
}

int clear_iptables_rule()
{
	if(iptables_rule[0]!=0)
	{
		char buf[300]="iptables -D ";
		strcat(buf,iptables_rule);
		char *output;
		if(run_command(buf,output)==0)
		{
			mylog(log_warn,"iptables rule cleared by: %s \n",buf);
		}
		else
		{
			mylog(log_error,"clear iptables failed by: %s\n",buf);
			//mylog(log_error,"reason : %s\n",strerror(errno));
		}

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
unsigned short csum(const unsigned short *ptr,int nbytes) {
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
    if(setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
    {
    	mylog(log_fatal,"SO_SNDBUFFORCE fail,fd %d\n",fd);
    	myexit(1);
    }
    if(setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &socket_buf_size, sizeof(socket_buf_size))<0)
    {
    	mylog(log_fatal,"SO_RCVBUFFORCE fail,fd %d\n",fd);
    	myexit(1);
    }
	return 0;
}

void myexit(int a)
{
    if(enable_log_color)
   	 printf("%s\n",RESET);
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
	id1=ntohl(  *((id_t*)(data+0)) );
	id2=ntohl(  *((id_t*)(data+sizeof(id_t))) );
	id3=ntohl(  *((id_t*)(data+sizeof(id_t)*2)) );
	return 0;
}

bool larger_than_u32(u32_t a,u32_t b)
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
	    p = strtok (NULL, sp);
	  }
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
int read_file(const char * file,char * &output)
{
    static char buf[1024*1024+100];
    buf[sizeof(buf)-1]=0;
	int fd=open(file,O_RDONLY);
	if(fd==-1)
	{
		 mylog(log_error,"read_file %s fail\n",file);
		 return -1;
	}
	int len=read(fd,buf,1024*1024);
	if(len==1024*1024)
	{
		buf[0]=0;
        mylog(log_error,"too long,buf not larger enough\n");
        return -2;
	}
	else if(len<0)
	{
		buf[0]=0;
        mylog(log_error,"read fail %d\n",len);
        return -3;
	}
	else
	{
		output=buf;
		buf[len]=0;
	}
	return 0;
}
int run_command(const char * command,char * &output) {
    FILE *in;
    mylog(log_debug,"run_command %s\n",command);
    static char buf[1024*1024+100];
    buf[sizeof(buf)-1]=0;
    if(!(in = popen(command, "r"))){
        mylog(log_error,"command %s popen failed,errno %s\n",command,strerror(errno));
        return -1;
    }

    int len =fread(buf, 1024*1024, 1, in);
    if(len==1024*1024)
    {
    	buf[0]=0;
        mylog(log_error,"too long,buf not larger enough\n");
        return -2;
    }
    else
    {
       	buf[len]=0;
    }
    int ret;
    if(( ret=ferror(in) ))
    {
        mylog(log_error,"command %s fread failed,ferror return value %d \n",command,ret);
        return -2;
    }
    //if(output!=0)
    output=buf;
    ret= pclose(in);

    int ret2=WEXITSTATUS(ret);

    if(ret!=0||ret2!=0)
    {
    	mylog(log_error,"commnad %s ,pclose returned %d ,WEXITSTATUS %d,errnor :%s \n",command,ret,ret2,strerror(errno));
    	return -3;
    }

    return 0;

}

