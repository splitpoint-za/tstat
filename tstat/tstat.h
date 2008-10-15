/*
 *
 * Copyright (c) 2001
 *	Politecnico di Torino.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Author:	Marco Mellia, Andrea Carpani, Luca Muscariello, Dario Rossi
 * 		Telecomunication Networks Group
 * 		Politecnico di Torino
 * 		Torino, Italy
 *              http://www.tlc-networks.polito.it/index.html
 *		mellia@mail.tlc.polito.it, rossi@mail.tlc.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
 * v1.2.0 memcpy optimization
*/

/* add autoconf header file */
#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#if __FreeBSD__ >= 2
#include <osreldate.h>
#if __FreeBSD_version >= 300000
#include <net/if_var.h>
#endif
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdlib.h>
#include <math.h>


#ifdef linux
#ifdef strncpy
  /* stupid Linux (redhat?) bug in macro */
#undef strncpy
#endif /* strncpy */
#endif /* linux */

/* #include "memwatch.h" */
/* #include <mpatrol.h> */

/* IPv6 support */
#include "ipv6.h"


#include "param.h"
#include "skype.h"
#include "msn.h"
#include "ymsg.h"
#include "jabber.h"
#include "l7types.h"
#include "struct.h"
#include "naivebayes.h"
/* include the histo management functions and declaration */
#include "histo.h"

#include "rtp.h"
#include "freelists.h"
#include "rrdtool.h"
#include "plugin.h"
#include "protocol.h"
#include "dump.h"
#include "inireader.h"
#include "../include/libtstat.h"

#include "ipp2p_tstat.h"

extern struct bayes_settings *bayes_settings_avgipg;
extern struct bayes_settings *bayes_settings_pktsize;

#define min(x,y) (((x)<(y))?(x):(y))
#define max(x,y) (((x)>(y))?(x):(y))


/* several places in the code NEED numbers of a specific size. */
/* since the definitions aren't standard across everything we're */
/* trying to support, the types are gathered up here */
/* specifically, we need:
   tt_uint32	unsigned 32 bit 
   tt_uint16	unsigned 16 bit 
   tt_int32	signed 32 bit 
   tt_int16	signed 16 bit
*/
/* first, do the 32 bit ones */
#if SIZEOF_UNSIGNED_LONG_INT == 4
typedef unsigned long tt_uint32;
typedef long tt_int32;
#else
#if SIZEOF_UNSIGNED_INT == 4
typedef unsigned int tt_uint32;
typedef int tt_int32;
#else
OOPS:Please insert an appropriate 32 - bit unsigned type here !
  OOPS:Please insert an appropriate 32 - bit signed type here !
#endif				/* SIZEOF_UNSIGNED_INT == 4 */
#endif				/* SIZEOF_UNSIGNED_LONG_INT == 4 */
/* first, do the 16 bit ones */
#if SIZEOF_UNSIGNED_INT == 2
typedef unsigned int tt_uint16;
typedef int tt_int16;
#else
#if SIZEOF_UNSIGNED_SHORT == 2
typedef unsigned short tt_uint16;
typedef short tt_int16;
#else
 
  OOPS:Please insert an appropriate 16 - bit unsigned type here !
  OOPS:Please insert an appropriate 16 - bit signed type here !
#endif				/* SIZEOF_UNSIGNED_INT == 4 */
#endif				/* SIZEOF_UNSIGNED_LONG_INT == 4 */
typedef unsigned char tt_uint8;

/* declaration of global variables */
char global_data_dir[256];
extern char runtime_conf_fname[];
extern int num_udp_pairs;	/* how many pairs are in use */
extern udp_pair **utp;		/* array of pointers to allocated pairs */


/* option flags */
extern Bool internal_src;
extern Bool internal_dst;

extern Bool warn_ooo;
extern Bool warn_IN_OUT;
extern Bool warn_printtrunc;
extern Bool warn_printbadmbz;
extern Bool warn_printbad_syn_fin_seq;
extern Bool save_tcp_data;
extern Bool do_udp;
extern int debug;
extern u_long pnum;

extern u_long ctrunc;
extern timeval current_time;

/* first and last packet timestamp */
extern timeval first_packet;
extern timeval last_packet;

/* global routine decls */

void *time_out_flow_closing ();	/* thread flow_close */
void *stats_dumping ();		/* thread Stat_dump */

void *MallocZ (int);
void *ReallocZ (void *oldptr, int obytes, int nbytes);
void trace_init (void);
struct tcphdr *tcp_header_stat (struct tcphdr *ptcp, struct ip *pip,
				void *plast);
tcp_pair *tcp_flow_stat (struct ip *, struct tcphdr *ptcp, void *plast,
			 int *dir);
double elapsed (timeval, timeval);
int tv_cmp (struct timeval lhs, struct timeval rhs);
char *elapsed2str (double etime);
double Average (double sum, int count);
double Stdev (double sum, double sum2, int n);
char *ts2ascii (timeval *);
char *ts2ascii_date (timeval *);
char *ServiceName (portnum);
char *HostName (ipaddr);
char *HostAddr (ipaddr);
char * Timestamp (void);
int rexmit (tcb * ptcb, seqnum seq, seglen len, Bool * pout_order,
	    u_short this_ip_id);
enum t_ack ack_in (tcb *, seqnum, unsigned tcp_data_length);
struct mfile *Mfopen (char *fname, char *mode);
void Minit (void);
int Mfileno (MFILE * pmf);
int Mvfprintf (MFILE * pmf, char *format, va_list ap);
int Mfwrite (void *buf, u_long size, u_long nitems, MFILE * pmf);
long Mftell (MFILE * pmf);
int Mfseek (MFILE * pmf, long offset, int ptrname);
int Mfprintf (MFILE * pmf, char *format, ...);
int Mfflush (MFILE * pmf);
int Mfclose (MFILE * pmf);
int Mfpipe (int pipes[]);
struct tcp_options *ParseOptions (struct tcphdr *ptcp, void *plast);

extern Bool swap_stdin;
extern FILE *second_file;
FILE *CompOpenHeader (char *filename);
FILE *CompOpenFile (char *filename);
char *CompGetCommand (char *filename);

void CompCloseFile (char *filename);
void CompFormats (void);
int CompIsCompressed (void);
Bool FileIsStdin (char *filename);
struct tcb *ptp2ptcb (tcp_pair * ptp, struct ip *pip, struct tcphdr *ptcp);
void IP_COPYADDR (ipaddr * toaddr, ipaddr fromaddr);
int IP_SAMEADDR (ipaddr addr1, ipaddr addr2);
void PcapSavePacket (char *filename, struct ip *pip, void *plast);
void StringToArgv (char *buf, int *pargc, char ***pargv);
void CopyAddr (tcp_pair_addrblock *, struct ip *pip, portnum, portnum);
int WhichDir (tcp_pair_addrblock *, tcp_pair_addrblock *);
int SameConn (tcp_pair_addrblock *, tcp_pair_addrblock *, int *);
Bool ip_cksum_valid (struct ip *pip, void *plast);
Bool tcp_cksum_valid (struct ip *pip, struct tcphdr *ptcp, void *plast);
Bool udp_cksum_valid (struct ip *pip, struct udphdr *pudp, void *plast);
ipaddr *str2ipaddr (char *str);
int IPcmp (ipaddr * pipA, ipaddr * pipB);

/* UDP support routines */
void udptrace_init (void);
void udptrace_done (void);
udp_pair *udp_flow_stat (struct ip *pip, struct udphdr *pudp, void *plast);
void close_udp_flow (udp_pair * pup, int ix, int dir);

/* TCP flags macros */
#define SYN_SET(ptcp)((ptcp)->th_flags & TH_SYN)
#define FIN_SET(ptcp)((ptcp)->th_flags & TH_FIN)
#define ACK_SET(ptcp)((ptcp)->th_flags & TH_ACK)
#define RESET_SET(ptcp)((ptcp)->th_flags & TH_RST)
#define PUSH_SET(ptcp)((ptcp)->th_flags & TH_PUSH)
#define URGENT_SET(ptcp)((ptcp)->th_flags & TH_URG)
#define FLAG6_SET(ptcp)((ptcp)->th_flags & 0x40)
#define FLAG7_SET(ptcp)((ptcp)->th_flags & 0x80)
#define CWR_SET(ptcp)((ptcp)->th_x2 & TH_CWR)
#define ECN_ECHO_SET(ptcp)((ptcp)->th_x2 & TH_ECN_ECHO)

/* connection directions.
	for hyper_histo:
	network and flow directions
	v1.2.0
*/


#define C2S 1
#define S2C -1
#define DIR_C2S   C2S
#define DIR_S2C   C2S

#define OUT_FLOW 1
#define IN_FLOW 2
#define LOC_FLOW 3
#define EXT_FLOW 4


/*macros for maintaining the seqspace used for rexmit*/
#define QUADSIZE	(0x40000000)
#define QUADNUM(seq)	((seq>>30)+1)
#define IN_Q1(seq)	(QUADNUM(seq)==1)
#define IN_Q2(seq)	(QUADNUM(seq)==2)
#define IN_Q3(seq)	(QUADNUM(seq)==3)
#define IN_Q4(seq)	(QUADNUM(seq)==4)
#define FIRST_SEQ(quadnum)	(QUADSIZE*(quadnum-1))
#define LAST_SEQ(quadnum)	((QUADSIZE-1)*quadnum)
#define BOUNDARY(beg,fin) (QUADNUM((beg)) != QUADNUM((fin)))


/* physical layers currently understood					*/
#define PHYS_ETHER	1
#define PHYS_FDDI       2

/*
 * SEQCMP - sequence space comparator
 *	This handles sequence space wrap-around. Overlow/Underflow makes
 * the result below correct ( -, 0, + ) for any a, b in the sequence
 * space. Results:	result	implies
 *			  - 	 a < b
 *			  0 	 a = b
 *			  + 	 a > b
 */
#define	SEQCMP(a, b)		((long)(a) - (long)(b))
#define	SEQ_LESSTHAN(a, b)	(SEQCMP(a,b) < 0)
#define	SEQ_GREATERTHAN(a, b)	(SEQCMP(a,b) > 0)


/* SACK TCP options (not an RFC yet, mostly from draft and RFC 1072) */
/* I'm assuming, for now, that the draft version is correct */
/* sdo -- Tue Aug 20, 1996 */
#define	TCPOPT_SACK_PERM 4	/* sack-permitted option */
#define	TCPOPT_SACK      5	/* sack attached option */
#define	MAX_SACKS       10	/* max number of sacks per segment (rfc1072) */
typedef struct sack_block
{
  seqnum sack_left;		/* left edge */
  seqnum sack_right;		/* right edge */
}
sack_block;

#define MAX_UNKNOWN 16
typedef struct opt_unknown
{
  u_char unkn_opt;
  u_char unkn_len;
}
opt_unknown;

/* RFC 1323 TCP options (not usually in tcp.h yet) */
#define	TCPOPT_WS	3	/* window scaling */
#define	TCPOPT_TS	8	/* timestamp */

/* other options... */
#define	TCPOPT_ECHO		6	/* echo (rfc1072) */
#define	TCPOPT_ECHOREPLY	7	/* echo (rfc1072) */
#define TCPOPT_TIMESTAMP	8	/* timestamps (rfc1323) */
#define TCPOPT_CC		11	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCNEW		12	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCECHO		13	/* T/TCP CC options (rfc1644) */

/* RFC 2481 (ECN) IP and TCP flags (not usually defined yet) */
#define IPTOS_ECT	0x02	/* ECN-Capable Transport */
#define IPTOS_CE	0x01	/* Experienced Congestion */

#define TH_ECN_ECHO	0x02	/* Used by receiver to echo CE bit */
#ifndef TH_CWR
#define TH_CWR		0x01	/* Congestion Window Reduced */
#endif


/* some compilers seem to want to make "char" unsigned by default, */
/* which is breaking stuff.  Rather than introduce (more) ugly */
/* machine dependencies, I'm going to FORCE some chars to be */
/* signed... */
typedef signed char s_char;

struct tcp_options
{
  short mss;			/* maximum segment size         */
  s_char ws;			/* window scale (1323)          */
  long tsval;			/* Time Stamp Val (1323)        */
  long tsecr;			/* Time Stamp Echo Reply (1323) */

  Bool sack_req;		/* sacks requested              */
  s_char sack_count;		/* sack count in this packet */
  sack_block sacks[MAX_SACKS];	/* sack blocks */

  /* echo request and reply */
  /* assume that value of -1 means unused  (?) */
  u_long echo_req;
  u_long echo_repl;

  /* T/TCP stuff */
  /* assume that value of -1 means unused  (?) */
  u_long cc;
  u_long ccnew;
  u_long ccecho;

  /* record the stuff we don't understand, too */
  char unknown_count;		/* number of unknown options */
  opt_unknown unknowns[MAX_UNKNOWN];	/* unknown options */
};


/* packet-reading options... */
/* the type for a packet reading routine */
typedef int pread_f (struct timeval *, int *, int *, void **,
		     int *, struct ip **, void **);

/* give the prototypes for the is_GLORP() routines supported */

/* give the prototypes for the is_GLORP() routines supported */
#ifdef GROK_SNOOP
pread_f *is_snoop (char *);
#endif /* GROK_SNOOP */
#ifdef GROK_NETM
pread_f *is_netm (char *);
#endif /* GROK_NETM */
#ifdef GROK_TCPDUMP
pread_f *is_tcpdump (char *);
#endif /* GROK_TCPDUMP */
#ifdef GROK_ETHERPEEK
pread_f *is_EP (char *);
#endif /* GROK_ETHERPEEK */
#ifdef GROK_NS
pread_f *is_ns (char *);
#endif /* GROK_NS */
#ifdef GROK_NLANR
pread_f *is_nlanr (char *);
#endif /* GROK_NLANR */
#ifdef GROK_NETSCOUT
pread_f *is_netscout (char *);
#endif /* GROK_NETSCOUT */
#ifdef GROK_ERF
pread_f *is_erf (char *);
#endif /* GROK_ERF */
#ifdef GROK_DAG
pread_f *is_dag (char *);
int
pread_dag (struct timeval *ptime,
	   int *plen,
	   int *ptlen,
	   void **pphys, int *pphystype, struct ip **ppip, void **pplast);
#endif /* GROK_DAG */
#ifdef GROK_ERF_LIVE
pread_f *init_live_tcpdump (char *);
int
pread_tcpdump (struct timeval *ptime,
	       int *plen,
	       int *ptlen,
	       void **pphys, int *pphystype, struct ip **ppip, void **pplast);
#endif /* GROK_LIVE_TCPDUMP */
#ifdef GROK_LIVE_TCPDUMP
pread_f *init_live_tcpdump (char *);
int
pread_tcpdump (struct timeval *ptime,
	       int *plen,
	       int *ptlen,
	       void **pphys, int *pphystype, struct ip **ppip, void **pplast);
#endif /* GROK_ERF_LIVE */
#ifdef GROK_ERF_LIVE
pread_f *init_erf_live (char *);
int pread_erf_live (struct timeval *ptime, int *plen,
		    int *ptlen, void **pphys, int *pphystype,
		    struct ip **ppip, void **pplast);
int pread_multi_erf_live (struct timeval *ptime, int *plen,
			  int *ptlen, void **pphys, int *pphystype,
			  struct ip **ppip, void **pplast);
#endif /* GROK_ERF_LIVE */


/*------------------* v1.2.0 *----------------------*/
#ifdef GROK_DPMI
pread_f *is_DPMI (char *);
int pread_DPMI (struct timeval *ptime, int *plen,
		int *ptlen, void **pphys, int *pphystype,
		struct ip **ppip, void **pplast);
#endif /* GROK_DPMI */

int fExists (const char *fname);
//void ArgsFromFile (const char *fname, int *_argc, char *_argv[]);
char ** ArgsFromFile(char *fname, int *pargc);


int dpmi_parse_config (const char *fname);

/* I've had problems with the memcpy function that gcc stuffs into the program
   and alignment problems.  This should fix it! 
   v.1.2.0 added optimization by .:nonsns:. 
   WARNING: it does not work on 64 bit architectures */

void *MemCpy_TCPTRACE (void *p1, void *p2, size_t n);	/* in tstat.c */
void *MemCpy_OPTIMIZED (void *p1, void *p2, size_t n);	/* in tcptrace.c */
#define memcpy(p1,p2,n) MemCpy_OPTIMIZED(p1,p2,n);

#ifndef EOL
#define EOL          0xa
#endif
extern Bool internal_wired;
extern Bool net_conf;
/*------------------* v1.2.0 *----------------------*/


/*
 * timeval compare macros
 */
#define tv_ge(lhs,rhs) (tv_cmp((lhs),(rhs)) >= 0)
#define tv_gt(lhs,rhs) (tv_cmp((lhs),(rhs)) >  0)
#define tv_le(lhs,rhs) (tv_cmp((lhs),(rhs)) <= 0)
#define tv_lt(lhs,rhs) (tv_cmp((lhs),(rhs)) <  0)
#define tv_eq(lhs,rhs) (tv_cmp((lhs),(rhs)) == 0)

/* handy constants */
#define US_PER_SEC 1000000	/* microseconds per second */
#define MS_PER_SEC 1000		/* milliseconds per second */


/*
 * Macros to simplify access to IPv4/IPv6 header fields
 */
#define PIP_VERS(pip) (((struct ip *)(pip))->ip_v)
#ifdef SUPPORT_IPV6
#define PIP_ISV6(pip) (PIP_VERS(pip) == 6)
#else
#define PIP_ISV6(pip) FALSE
#endif
#define PIP_ISV4(pip) (PIP_VERS(pip) == 4)
#define PIP_V6(pip) ((struct ipv6 *)(pip))
#define PIP_V4(pip) ((struct ip *)(pip))
#define PIP_EITHERFIELD(pip,fld4,fld6) \
   (PIP_ISV4(pip)?(PIP_V4(pip)->fld4):(PIP_V6(pip)->fld6))
#define PIP_LEN(pip) (PIP_EITHERFIELD(pip,ip_len,ip6_lngth))

/*
 * Macros to simplify access to IPv4/IPv6 addresses
 */
#define ADDR_VERSION(paddr) ((paddr)->addr_vers)
#define ADDR_ISV4(paddr) (ADDR_VERSION((paddr)) == 4)
#ifdef SUPPORT_IPV6
#define ADDR_ISV6(paddr) (ADDR_VERSION((paddr)) == 6)
#else
#define ADDR_ISV6(paddr) (FALSE)
#endif
struct ipaddr *IPV4ADDR2ADDR (struct in_addr *addr4);
struct ipaddr *IPV6ADDR2ADDR (struct in6_addr *addr6);

/*
 * Macros to check for congestion experienced bits
 */
#define IP_CE(pip) (((struct ip *)(pip))->ip_tos & IPTOS_CE)
#define IP_ECT(pip) (((struct ip *)(pip))->ip_tos & IPTOS_ECT)

/*
 * fixes for various systems that aren't exactly like Solaris
 */
#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif /* IP_MAXPACKET */

#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP        0x8035
#endif /* ETHERTYPE_REVARP */

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN		0x8100
#endif /* 802.1Q Virtual LAN */

/* support for vlan tagging */
#ifndef IEEE8021Q_SIZE
#define IEEE8021Q_SIZE		18
#endif /* VLAN header size */

/* support for PPPoE encapsulation added by Yann Samama (ysamama@nortelnetworks.com)*/
#ifndef ETHERTYPE_PPPOE_SESSION
#define ETHERTYPE_PPPOE_SESSION	0x8864
#endif /* PPPoE ether type */
#ifndef PPPOE_SIZE
#define PPPOE_SIZE		22
#endif /* PPPOE header size */

#define TCP_TYPE        0
#define UDP_TYPE        1
#define ICMP_TYPE       2
#define IP_TYPE         3

/* LM start- possible classification of out of order and retransmission */
#define IN_SEQUENCE			0
#define RETRANSMISSION_RTO   		1
#define RETRANSMISSION_FR  		2
#define REORDERING			3
#define NETWORK_DUPLICATE		4
#define FLOW_CONTROL			5
#define UNNECESSARY_RETRANSMISSION_RTO	6
#define UNNECESSARY_RETRANSMISSION_FR	7

#define DUPLICATE_WITH_RC_LESS_THAN_RTT_NOT_3DUP_ACK   8
#define DUPLICATE_WITH_RC_LESS_THAN_RTO_AND_GREATER_THAN_RTT_NOT_3DUP_ACK 9

#define OOO_WITH_RC_LESS_THAN_RTT_NOT_3DUP_ACK 10
#define OOO_WITH_RC_LESS_THAN_RTO_AND_GREATER_THAN_RTT_NOT_3DUP_ACK 11

#define UNNECESSARY_RETRANSMISSION_WITH_RC_LESS_THAN_RTT_NOT_3DUP_ACK 12
#define UNNECESSARY_RETRANSMISSION_WITH_RC_LESS_THAN_RTO_AND_GREATER_THAN_RTT_NOT_3DUP_ACK 13

#define NUM_TCP_ANOMALIES 64
/* for compatibility - should never be used */
#define UNKNOWN           (NUM_TCP_ANOMALIES - 1)

#define BATCH_CLASSIFICATION 16
#define NO_RTT_SAMPLE_CLASSIFICATION 32

/* define the minimum rto [microsecond] */
#define RTO_MIN 100000
#define RTT_MIN 1000

#define INITIAL_RTO 500000
#define INITIAL_RTT_MIN 5000

#define CLASSIFICATION(X) ( (validRTT) ? X : (X | NO_RTT_SAMPLE_CLASSIFICATION) )


/* LM stop */

char *get_basename (char *filename);
char curr_data_dir[512];
extern char runtime_conf_fname[];
timeval last_time_step;
timeval last_cleaned;

extern Bool runtime_engine;
extern Bool rrd_engine;
extern Bool con_cat;
extern FILE *fp_stdout;
extern FILE *fp_stderr;
extern Bool redirect_output; 

unsigned long tot_conn_TCP;
unsigned long tot_conn_UDP;
void trace_done_periodic ();
void create_new_outfiles (char *filename);
void freequad (quadrant ** ppquad);

#define adx_index_frozen (adx_index_first==adx_index_current?adx_index_second:adx_index_first)
#define SRC_ADX 0
#define DST_ADX 1

void swap_adx ();
void make_conn_stats (tcp_pair * ptp_save, Bool flusso_nc);
void make_udp_conn_stats (udp_pair * pup_save, Bool flusso_nc);
void trace_done (void);
void tcpdump_cleanup (FILE * wheref);


/* skype */
int skype_feat2code (char *str);
struct skype_hdr *getSkype (struct udphdr *pudp, int tproto, void *pdir,
			    void *plast);

Bool is_skype_pkt (struct ip *pip, struct udphdr *pudp, void *pdir,
		   struct skype_hdr *NAK, void *last);

void
skype_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
		 int dir, void *hdr, void *last);

void make_skype_conn_stats (void *thisdir, int tproto);

/* msn.c */
#ifdef MSN_CLASSIFIER
u_int32_t FindConTypeMsn (tcp_pair * ptp, struct ip *pip, struct tcphdr *ptcp,
			  void *plast, int dir);
void classify_msn_flow (tcp_pair * ptp, int dir);
void print_msn_conn_stats (tcp_pair * ptp);
void init_msn ();
void msn_get_average ();
#endif

/* ymsg.c */
#ifdef YMSG_CLASSIFIER
u_int32_t FindConTypeYmsg (tcp_pair * ptp, struct ip *pip,
			   struct tcphdr *ptcp, void *plast, int dir);
void classify_ymsg_flow (tcp_pair * ptp, int dir);
void print_ymsg_conn_stats (tcp_pair * ptp);
void init_ymsg ();
void ymsg_get_average ();
#endif

/* jabber.c */
#ifdef XMPP_CLASSIFIER
u_int32_t FindConTypeJabber (tcp_pair * ptp, struct ip *pip,
			     struct tcphdr *ptcp, void *plast, int dir);
void classify_jabber_flow (tcp_pair * ptp, int dir);
void print_jabber_conn_stats (tcp_pair * ptp);
void init_jabber ();
void jabber_get_average ();
#endif

/* misc.c */

void AVE_departure (timeval tc, win_stat * w);
void AVE_arrival (timeval tc, win_stat * w);
double AVE_get_stat (timeval tc, win_stat * w);
void AVE_init (win_stat * stat, char *name, timeval tc);

int in_out_loc (int internal_src, int internal_dst, int dir);

/* generic UDP */

/* P2P plugin */
void p2p_init ();
void *getp2p (struct udphdr *pudp, int tproto, void *pdir, void *plast);

void p2p_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
                    int dir, void *hdr, void *plast);


int p2p_tcp_match(struct ip *pip, void *pproto, int tproto, void *pdir,
                    int dir, void *hdr, void *plast);
int p2p_udp_match(struct ip *pip, void *pproto, int tproto, void *pdir,
                    int dir, void *hdr, void *plast);
void make_p2p_conn_stats (void * thisdir, int tproto);
int TCP_p2p_to_L7type (tcp_pair *thisdir);

/* tcpL7 */
void tcpL7_init ();
void *gettcpL7 (struct udphdr *pudp, int tproto, void *pdir, void *plast);
void tcpL7_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
	       int dir, void *hdr, void *plast);
void make_tcpL7_conn_stats (void * thisdir, int tproto);
void make_tcpL7_rate_stats (tcp_pair *thisflow, int len);
void make_udpL7_rate_stats (ucb * thisflow, int len);

tstat_report * get_stats_report(tstat_report *report);
void log_parse_ini_arg(char *param_name, int param_value);
