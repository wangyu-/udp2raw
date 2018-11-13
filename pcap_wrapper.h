#pragma once

//#ifdef __cplusplus
//extern "C" {
//#endif

//#include <sys/time.h>
//#include <stdint.h>

struct bpf_program
{
 char a[2000];
};

struct pcap_t
{
 char a[2000];
};

typedef unsigned int bpf_u_int32;

typedef struct my_timeval {
  int tv_sec;
  int tv_usec;
} my_timeval;

struct pcap_pkthdr {
	struct my_timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length this packet (off wire) */
};

typedef enum {
       PCAP_D_INOUT = 0,
       PCAP_D_IN,
       PCAP_D_OUT
} pcap_direction_t;


struct pcap_addr {
	struct pcap_addr *next;
	struct sockaddr *addr;		/* address */
	struct sockaddr *netmask;	/* netmask for that address */
	struct sockaddr *broadaddr;	/* broadcast address for that address */
	struct sockaddr *dstaddr;	/* P2P destination address for that address */
};

struct pcap_if {
	struct pcap_if *next;
	char *name;		/* name to hand to "pcap_open_live()" */
	char *description;	/* textual description of interface, or NULL */
	struct pcap_addr *addresses;
	bpf_u_int32 flags;	/* PCAP_IF_ interface flags */
};

typedef struct pcap_if pcap_if_t;
typedef struct pcap_addr pcap_addr_t;



typedef unsigned char u_char;


#define PCAP_ERRBUF_SIZE 256

#define DLT_NULL	0	/* BSD loopback encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define DLT_AX25	3	/* Amateur Radio AX.25 */
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_CHAOS	5	/* Chaos */
#define DLT_IEEE802	6	/* 802.5 Token Ring */
#define DLT_ARCNET	7	/* ARCNET, with BSD-style header */
#define DLT_SLIP	8	/* Serial Line IP */
#define DLT_PPP		9	/* Point-to-point Protocol */
#define DLT_FDDI	10	/* FDDI */
#define DLT_LINUX_SLL   113

#define PCAP_NETMASK_UNKNOWN	0xffffffff

typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
			     const u_char *);

extern int	(*pcap_loop )(pcap_t *, int, pcap_handler, u_char *);

extern int	(*pcap_breakloop )(pcap_t *);

extern pcap_t*	(*pcap_create)(const char *, char *);

extern int	(*pcap_set_snaplen) (pcap_t *, int);
extern int	(*pcap_set_promisc) (pcap_t *, int);
extern int	(*pcap_can_set_rfmon) (pcap_t *);
extern int	(*pcap_set_rfmon )(pcap_t *, int);
extern int	(*pcap_set_timeout)(pcap_t *, int);
extern int	(*pcap_set_buffer_size)(pcap_t *, int);
extern int	(*pcap_activate)(pcap_t *);

extern int	(*pcap_setfilter)(pcap_t *, struct bpf_program *);
extern int 	(*pcap_setdirection)(pcap_t *, pcap_direction_t);

extern int	(*pcap_datalink)(pcap_t *);

extern void	(*pcap_freecode)(struct bpf_program *);

extern int	(*pcap_compile)(pcap_t *, struct bpf_program *, const char *, int,
	    bpf_u_int32);

extern char*   (*pcap_geterr)(pcap_t *);
extern int	(*pcap_sendpacket)(pcap_t *, const u_char *, int);

extern char* (*pcap_lookupdev)(char *);

extern int	(*pcap_findalldevs)(pcap_if_t **, char *);

inline int pcap_set_immediate_mode(pcap_t *,int)
{
	return 0;
}



//#ifdef __cplusplus
//}
//#endif

int init_pcap();

