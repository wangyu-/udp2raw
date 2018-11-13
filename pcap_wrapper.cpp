#include <windows.h>
#include <pcap_wrapper.h>
#include <assert.h>
#include <stdio.h>
int	(*pcap_loop )(pcap_t *, int, pcap_handler, u_char *);
int	(*pcap_breakloop )(pcap_t *);

pcap_t* (*pcap_create)(const char *, char *);

int	(*pcap_set_snaplen) (pcap_t *, int)=0;
int	(*pcap_set_promisc) (pcap_t *, int)=0;
int	(*pcap_can_set_rfmon) (pcap_t *)=0;
int	(*pcap_set_rfmon )(pcap_t *, int)=0;
int	(*pcap_set_timeout)(pcap_t *, int)=0;
int	(*pcap_set_buffer_size)(pcap_t *, int)=0;
int	(*pcap_activate)(pcap_t *)=0;

int	(*pcap_setfilter)(pcap_t *, struct bpf_program *)=0;
int 	(*pcap_setdirection)(pcap_t *, pcap_direction_t)=0;

int	(*pcap_datalink)(pcap_t *)=0;

void	(*pcap_freecode)(struct bpf_program *)=0;

int	(*pcap_compile)(pcap_t *, struct bpf_program *, const char *, int,
     bpf_u_int32)=0;

char*   (*pcap_geterr)(pcap_t *)=0;
int	(*pcap_sendpacket)(pcap_t *, const u_char *, int)=0;

char* (*pcap_lookupdev)(char *)=0;

int	(*pcap_findalldevs)(pcap_if_t **, char *)=0;

struct init_pcap_t
{
	init_pcap_t()
	{
		init_pcap();
	}
	
}do_it;

static void init_npcap_dll_path()
{
	BOOL(WINAPI *SetDllDirectory)(LPCTSTR);
	char sysdir_name[512];
	int len;

	SetDllDirectory = (BOOL(WINAPI *)(LPCTSTR)) GetProcAddress(GetModuleHandle("kernel32.dll"), "SetDllDirectoryA");
	if (SetDllDirectory == NULL) {
		printf("Error in SetDllDirectory\n");
	}
	else {
		len = GetSystemDirectory(sysdir_name, 480);	//	be safe
		if (!len)
			printf("Error in GetSystemDirectory (%d)\n", (int)GetLastError());
		strcat(sysdir_name, "\\Npcap");
		if (SetDllDirectory(sysdir_name) == 0)
			printf("Error in SetDllDirectory(\"System32\\Npcap\")\n");
	}
}

#define EXPORT_FUN(XXX) do{ XXX= (__typeof__(XXX)) GetProcAddress(wpcap, #XXX); }while(0)
int init_pcap()
{
	HMODULE wpcap=LoadLibrary("wpcap.dll");
	if(wpcap!=0)
	{
		printf("using system32/wpcap.dll\n");
	}
	else
	{
		init_npcap_dll_path();
		//SetDllDirectory("C:\\Windows\\System32\\Npcap\\");
		wpcap=LoadLibrary("wpcap.dll");
		if(wpcap!=0)
			printf("using system32/npcap/wpcap.dll\n");
	}
	if(wpcap==0)
	{
		printf("cant not open wpcap.dll, make sure winpcap/npcap is installed\n");
		exit(-1);
	}
	assert(wpcap!=0);

	EXPORT_FUN(pcap_loop);
	EXPORT_FUN(pcap_breakloop);
	EXPORT_FUN(pcap_create);
	EXPORT_FUN(pcap_set_snaplen);
	EXPORT_FUN(pcap_set_promisc);
	EXPORT_FUN(pcap_set_timeout);
	EXPORT_FUN(pcap_activate);
	EXPORT_FUN(pcap_setfilter);
	EXPORT_FUN(pcap_setdirection);
	EXPORT_FUN(pcap_datalink);
	EXPORT_FUN(pcap_freecode);
	EXPORT_FUN(pcap_compile);
	EXPORT_FUN(pcap_geterr);
	EXPORT_FUN(pcap_sendpacket);
	EXPORT_FUN(pcap_lookupdev);
	EXPORT_FUN(pcap_findalldevs);
	/*
	pcap_loop = (__typeof__(pcap_loop))GetProcAddress(wpcap, "pcap_loop");
	pcap_create = (__typeof__(pcap_create))GetProcAddress(wpcap, "pcap_create");
	pcap_set_snaplen = (__typeof__(pcap_set_snaplen))GetProcAddress(wpcap, "pcap_set_snaplen");
	pcap_set_promisc = (__typeof__(pcap_set_promisc))GetProcAddress(wpcap, "pcap_set_promisc");
	pcap_set_timeout = (__typeof__(pcap_set_timeout))GetProcAddress(wpcap, "pcap_set_timeout");
	pcap_activate = (__typeof__(pcap_activate))GetProcAddress(wpcap, "pcap_activate");
	pcap_setfilter = (__typeof__(pcap_setfilter))GetProcAddress(wpcap, "pcap_setfilter");
	pcap_setdirection = (__typeof__(pcap_setdirection))GetProcAddress(wpcap, "pcap_setdirection");
	pcap_datalink = (__typeof__(pcap_datalink))GetProcAddress(wpcap, "pcap_datalink");
	pcap_freecode = (__typeof__(pcap_freecode))GetProcAddress(wpcap, "pcap_freecode");
	pcap_compile = (__typeof__(pcap_compile))GetProcAddress(wpcap, "pcap_compile");
	pcap_geterr = (__typeof__(pcap_geterr))GetProcAddress(wpcap, "pcap_geterr");
	pcap_sendpacket = (__typeof__(pcap_sendpacket))GetProcAddress(wpcap, "pcap_sendpacket");
	pcap_lookupdev = (__typeof__(pcap_lookupdev))GetProcAddress(wpcap, "pcap_lookupdev");
	pcap_findalldevs = (__typeof__(pcap_findalldevs))GetProcAddress(wpcap, "pcap_findalldevs");
	//pcap_loop = (__typeof__(pcap_loop))GetProcAddress(wpcap, "pcap_loop");
	//pcap_loop = (__typeof__(pcap_loop))GetProcAddress(wpcap, "pcap_loop");
	//pcap_loop = (__typeof__(pcap_loop))GetProcAddress(wpcap, "pcap_loop");
	*/
	return 0;

}
