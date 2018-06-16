#include <windows.h>
#include <pcap_wrapper.h>
#include <assert.h>

int	(*pcap_loop )(pcap_t *, int, pcap_handler, u_char *);

pcap_t* (*pcap_create)(const char *, char *);

int	(*pcap_set_snaplen) (pcap_t *, int);
int	(*pcap_set_promisc) (pcap_t *, int);
int	(*pcap_can_set_rfmon) (pcap_t *);
int	(*pcap_set_rfmon )(pcap_t *, int);
int	(*pcap_set_timeout)(pcap_t *, int);
int	(*pcap_set_buffer_size)(pcap_t *, int);
int	(*pcap_activate)(pcap_t *);

int	(*pcap_setfilter)(pcap_t *, struct bpf_program *);
int 	(*pcap_setdirection)(pcap_t *, pcap_direction_t);

int	(*pcap_datalink)(pcap_t *);

void	(*pcap_freecode)(struct bpf_program *);

int	(*pcap_compile)(pcap_t *, struct bpf_program *, const char *, int,
     bpf_u_int32);

char*   (*pcap_geterr)(pcap_t *);
int	(*pcap_sendpacket)(pcap_t *, const u_char *, int);

char* (*pcap_lookupdev)(char *);

int	(*pcap_findalldevs)(pcap_if_t **, char *);

struct init_pcap_t
{
	init_pcap_t()
	{
		init_pcap();
	}
	
}do_it;

int init_pcap()
{
	HMODULE wpcap=LoadLibrary("wpcap.dll");
	assert(wpcap!=0);

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

	return 0;

}
