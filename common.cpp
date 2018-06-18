/*
 * comm.cpp
 *
 *  Created on: Jul 29, 2017
 *      Author: wangyu
 */

#include "common.h"
#include "log.h"
#include "misc.h"

#include <random>
#include <cmath>

static int random_number_fd=-1;

int init_ws()
{
#if defined(__MINGW32__)
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		/* Tell the user that we could not find a usable */
		/* Winsock DLL.                                  */
		printf("WSAStartup failed with error: %d\n", err);
		exit(-1);
	}

	/* Confirm that the WinSock DLL supports 2.2.*/
	/* Note that if the DLL supports versions greater    */
	/* than 2.2 in addition to 2.2, it will still return */
	/* 2.2 in wVersion since that is the version we      */
	/* requested.                                        */

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		printf("Could not find a usable version of Winsock.dll\n");
		WSACleanup();
		exit(-1);
	}
	else
	{
		printf("The Winsock 2.2 dll was found okay");
	}

	int tmp[]={0,100,200,300,500,800,1000,2000,3000,4000,-1};
	int succ=0;
	for(int i=1;tmp[i]!=-1;i++)
	{
		if(_setmaxstdio(100)==-1) break;
		else succ=i;
	}
	printf(", _setmaxstdio() was set to %d\n",tmp[succ]);
#endif
return 0;
}

#if defined(__MINGW32__)
char *get_sock_error()
{
	static char buf[1000];
	int e=WSAGetLastError();
	wchar_t *s = NULL;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, e,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPWSTR)&s, 0, NULL);
	sprintf(buf, "%d:%S", e,s);
	int len=strlen(buf);
	if(len>0&&buf[len-1]=='\n') buf[len-1]=0;
	LocalFree(s);
	return buf;
}
int get_sock_errno()
{
	return WSAGetLastError();
}
#else
char *get_sock_error()
{
	static char buf[1000];
	sprintf(buf, "%d:%s", errno,strerror(errno));
	return buf;
}
int get_sock_errno()
{
	return errno;
}
#endif


u64_t get_current_time()
{
	timespec tmp_time;
	clock_gettime(CLOCK_MONOTONIC, &tmp_time);
	return ((u64_t)tmp_time.tv_sec)*1000llu+((u64_t)tmp_time.tv_nsec)/(1000*1000llu);
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

#if !defined(__MINGW32__)
struct random_fd_t
{
	int random_number_fd;
	random_fd_t()
	{
			random_number_fd=open("/dev/urandom",O_RDONLY);

			if(random_number_fd==-1)
			{
				mylog(log_fatal,"error open /dev/urandom\n");
				myexit(-1);
			}
			setnonblocking(random_number_fd);
	}
	int get_fd()
	{
		return random_number_fd;
	}
}random_fd;
#else
struct my_random_t
{
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<u64_t> dis64;
    std::uniform_int_distribution<u32_t> dis32;

    std::uniform_int_distribution<unsigned char> dis8;

    my_random_t()
	{
    	std::mt19937 gen_tmp(rd());
    	gen=gen_tmp;
    	gen.discard(700000);  //magic
	}
    u64_t gen64()
    {
    	return dis64(gen);
    }
    u32_t gen32()
    {
    	return dis32(gen);
    }

    unsigned char gen8()
    {
    	return dis8(gen);
    }
	/*int random_number_fd;
	random_fd_t()
	{
			random_number_fd=open("/dev/urandom",O_RDONLY);
			if(random_number_fd==-1)
			{
				mylog(log_fatal,"error open /dev/urandom\n");
				myexit(-1);
			}
			setnonblocking(random_number_fd);
	}
	int get_fd()
	{
		return random_number_fd;
	}*/
}my_random;
#endif

u64_t get_true_random_number_64()
{
#if !defined(__MINGW32__)
	u64_t ret;
	int size=read(random_fd.get_fd(),&ret,sizeof(ret));
	if(size!=sizeof(ret))
	{
		mylog(log_fatal,"get random number failed %d\n",size);

		myexit(-1);
	}
	return ret;
#else
	return my_random.gen64();  //fake random number
#endif
}
u32_t get_true_random_number()
{
#if !defined(__MINGW32__)
	u32_t ret;
	int size=read(random_fd.get_fd(),&ret,sizeof(ret));
	if(size!=sizeof(ret))
	{
		mylog(log_fatal,"get random number failed %d\n",size);
		myexit(-1);
	}
	return ret;
#else
	return my_random.gen64();  //fake random number
#endif
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

inline int is_big_endian()
{
    int i=1;
    return ! *((char *)&i);
}
u64_t ntoh64(u64_t a)
{
	#ifdef UDP2RAW_LITTLE_ENDIAN
		u32_t h=get_u64_h(a);
		u32_t l=get_u64_l(a);
		return pack_u64(ntohl(l),ntohl(h));
		//return bswap_64( a);
	#else
	return a;
	#endif

}
u64_t hton64(u64_t a)
{
	return ntoh64(a);
}

void setnonblocking(int sock) {
#if !defined(__MINGW32__)
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
#else
	int iResult;
	u_long iMode = 1;
	iResult = ioctlsocket(sock, FIONBIO, &iMode);
	if (iResult != NO_ERROR)
		printf("ioctlsocket failed with error: %d\n", iResult);

#endif
}

/*
    Generic checksum calculation function
*/
unsigned short csum(const unsigned short *ptr,int nbytes) {//works both for big and little endian
    long sum;
    unsigned short oddbyte;
    short answer;

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

int set_buf_size(int fd,int socket_buf_size,int force_socket_buf)
{
	if(force_socket_buf)
	{
#if defined(__MINGW32__)
	assert(0==1);
#else
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
#endif

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

int numbers_to_char(my_id_t id1,my_id_t id2,my_id_t id3,char * &data,int &len)
{
	static char buf[buf_len];
	data=buf;
	my_id_t tmp=htonl(id1);
	memcpy(buf,&tmp,sizeof(tmp));

	tmp=htonl(id2);
	memcpy(buf+sizeof(tmp),&tmp,sizeof(tmp));

	tmp=htonl(id3);
	memcpy(buf+sizeof(tmp)*2,&tmp,sizeof(tmp));

	len=sizeof(my_id_t)*3;
	return 0;
}

int char_to_numbers(const char * data,int len,my_id_t &id1,my_id_t &id2,my_id_t &id3)
{
	if(len<int(sizeof(my_id_t)*3)) return -1;
	//id1=ntohl(  *((id_t*)(data+0)) );
	memcpy(&id1,data+0,sizeof(id1));
	id1=ntohl(id1);
	//id2=ntohl(  *((id_t*)(data+sizeof(id_t))) );
	memcpy(&id2,data+sizeof(my_id_t),sizeof(id2));
	id2=ntohl(id2);
	//id3=ntohl(  *((id_t*)(data+sizeof(id_t)*2)) );
	memcpy(&id3,data+sizeof(my_id_t)*2,sizeof(id3));
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
    assert(0==1 && "not implemented\n");
#if 0
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

#endif
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


int create_fifo(char * file)
{
#if !defined(__MINGW32__)
	if(mkfifo (file, 0666)!=0)
	{
		if(errno==EEXIST)
		{
			mylog(log_warn,"warning fifo file %s exist\n",file);
		}
		else
		{
			mylog(log_fatal,"create fifo file %s failed\n",file);
			myexit(-1);
		}
	}
	int fifo_fd=open (file, O_RDWR);
	if(fifo_fd<0)
	{
		mylog(log_fatal,"create fifo file %s failed\n",file);
		myexit(-1);
	}
	struct stat st;
	if (fstat(fifo_fd, &st)!=0)
	{
		mylog(log_fatal,"fstat failed for fifo file %s\n",file);
		myexit(-1);
	}

	if(!S_ISFIFO(st.st_mode))
	{
		mylog(log_fatal,"%s is not a fifo\n",file);
		myexit(-1);
	}

	setnonblocking(fifo_fd);
	return fifo_fd;
#else
	assert(0==1&&"not implemented");
	return 0;
#endif
}

void ip_port_t::from_u64(u64_t u64)
{
	ip=get_u64_h(u64);
	port=get_u64_l(u64);
}
u64_t ip_port_t::to_u64()
{
	return pack_u64(ip,port);
}
char * ip_port_t::to_s()
{
	static char res[40];
	sprintf(res,"%s:%d",my_ntoa(ip),port);
	return res;
}








