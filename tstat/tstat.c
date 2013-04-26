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
 * For bug report and other information please visit Tstat site:
 * http://tstat.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/

static char const copyright[] =
  "@(#)Copyright (c) 2001-2009 -- Telecomunication Network Group \
     -- Politecnico di Torino.  All rights reserved.\
     Tstat is based on TCPTRACE,\
    @(#)Copyright (c) 1999 -- Shawn Ostermann -- Ohio University.\n";

#include "tstat.h"
#include "file_formats.h"
#include "version.h"
#include <time.h>
#include "tcpL7.h"
#include "inireader.h"
#include <sys/wait.h>
#include <getopt.h>
#include <sys/types.h>
#include <fcntl.h>
#include "videoL7.h"


/* version information */
char *tstat_version = VERSION;

/* seem to be missing from pthread.h */
int pthread_mutexattr_settype (pthread_mutexattr_t * attr, int kind);
#ifndef __FreeBSD__
#if !(defined PTHREAD_MUTEX_ERRORCHECK || defined __USE_UNIX98)
#define PTHREAD_MUTEX_ERRORCHECK PTHREAD_MUTEX_ERRORCHECK_NP
#endif
#endif

/* local routines */
void QuitSig (int);
void Usr1Sig (int);
static void Formats (void);
static void Help ();
static void CheckArguments (int *pargc, char *argv[]);
static void ParseArgs (int *pargc, char *argv[]);
static void Usage (void);
static void BadArg (char *argsource, char *format, ...);
static void Version (void);
static int LoadInternalNets (char *file);
static int LoadCloudNets (char *file);
#ifndef TSTAT_RUNASLIB
static void ProcessFile (char *filename, Bool last);
#endif

static Bool internal_ip (struct in_addr adx);
static Bool cloud_ip (struct in_addr adx);
/*
static Bool internal_ip_string (char *adx);
*/
Bool internal_eth (uint8_t *eth_addr, eth_filter *filter);
int LoadInternalEth (char *file);


static int ip_header_stat (int phystype, struct ip *pip, u_long * fpnum,
			   u_long * pcount, int file_count, char *filename,
			   long int location, int tlen, void *plast,
			   int ip_direction);

void stat_dumping_old_style ();
static void flush_histo_engine(void);

/* thread mutex and conditional variables  */

Bool threaded = FALSE;
pthread_mutex_t ttp_lock_mutex;
pthread_mutex_t utp_lock_mutex;
pthread_mutex_t flow_close_started_mutex;
pthread_mutex_t flow_close_cond_mutex;
pthread_cond_t flow_close_cond;
pthread_mutex_t stat_dump_cond_mutex;
pthread_mutex_t stat_dump_mutex;
pthread_cond_t stat_dump_cond;

Bool filter_specified = FALSE;
char *filter_filename;
char *dev;

static Bool basedirspecified = FALSE;
static char *basenamedir;
static char basename[FILENAME_SIZE];
Bool internal_src = FALSE;
Bool internal_dst = FALSE;

struct in_addr internal_net_list[MAX_INTERNAL_HOSTS];
struct in_addr internal_net_mask2[MAX_INTERNAL_HOSTS];
int internal_net_mask[MAX_INTERNAL_HOSTS];
int tot_internal_nets;

/* Variables for Cloud definition*/
Bool cloud_src = FALSE;
Bool cloud_dst = FALSE;

struct in_addr cloud_net_list[MAX_CLOUD_HOSTS];
struct in_addr cloud_net_mask2[MAX_CLOUD_HOSTS];
int cloud_net_mask[MAX_CLOUD_HOSTS];
int tot_cloud_nets;

unsigned int ip_obfuscate_mask = 0x00000000; /* This is already in network order */

#ifdef SUPPORT_IPV6
struct in6_addr internal_net_listv6;
int tot_internal_netsv6;
int contr_flag = 0;
#endif

/* option flags and default values */
Bool live_flag = FALSE;

Bool printticks = FALSE;
Bool dump_all_histo_definition = FALSE;

Bool warn_IN_OUT = TRUE;
Bool warn_ooo = FALSE;
Bool warn_MAX_ = TRUE;
Bool warn_printtrunc = FALSE;
Bool warn_printbadmbz = FALSE;
Bool warn_printbadcsum = FALSE;
Bool warn_printbad_syn_fin_seq = FALSE;
Bool do_udp = TRUE;
int debug = 0;
char **filenames = NULL;
Bool swap_stdin = FALSE;
FILE *second_file, *first_file;
int two_files = 1;		/* used if you have two traces that store packet in
				   two different direction... works only with DAG for now.
				 */
Bool con_cat = FALSE;		/* Concatenate the input files */
Bool first_ip_packet = TRUE;
u_long pnum = 0;
u_long ctrunc = 0;
u_long bad_ip_checksums = 0;
u_long bad_tcp_checksums = 0;
u_long bad_udp_checksums = 0;

/* globals */
int *coredump;
struct timeval current_time;

unsigned long int fcount = 0;	/* total flow number */
unsigned long int f_TCP_count = 0;	/* total TCP  flow number */
unsigned long int f_UDP_count = 0;	/* total UDP flow number */
unsigned long int f_RTP_count = 0;	/* total RTP flow number */
unsigned long int f_RTCP_count = 0;	/* total RTP flow number */
unsigned long int f_RTP_tunneled_TCP_count = 0;	/* total RTP flow tunneled on TCP */

struct L4_bitrates L4_bitrate;
struct L7_bitrates L7_bitrate;
struct L7_bitrates L7_udp_bitrate;
struct HTTP_bitrates HTTP_bitrate;
struct WEB_bitrates WEB_bitrate;

struct VIDEO_rates VIDEO_rate;

#ifdef L3_BITRATE
unsigned long long L3_bitrate_in;
unsigned long long L3_bitrate_out;
unsigned long long L3_bitrate_loc;
unsigned long long L3_bitrate_ip46_in;
unsigned long long L3_bitrate_ip46_out;
unsigned long long L3_bitrate_ip46_loc;
struct timeval L3_last_time;
#define L3_BITRATE_DELTA 10000000   /* 10 sec */
#endif
struct timeval adx2_last_time;
unsigned long adx2_bitrate_delta;
struct timeval adx3_last_time;
unsigned long adx3_bitrate_delta;

static u_long pcount = 0;   //global packet counter
static u_long fpnum = 0;    //per file packet counter
static int file_count = 0;

#ifdef HAVE_RRDTOOL
/*-----------------------------------------------------------*/
/* RRDtools 				                     */
/*-----------------------------------------------------------*/
Bool rrdset_path = FALSE;	/* database path flag */
Bool rrdset_conf = FALSE;	/* configuration file flag */
/*-----------------------------------------------------------*/
#endif

Bool histo_engine = TRUE;	    /* -S */
Bool adx_engine = FALSE;	    /* to allow disabling via -H */
Bool adx2_engine = FALSE;	    /* secondary engine, enabled by histo.conf */
Bool global_histo = FALSE;	    /* -g */

Bool bayes_engine = FALSE;	    /* -B */
Bool runtime_engine = FALSE;    /* -T */
Bool rrd_engine = FALSE;
Bool histo_engine_log = TRUE;
#ifdef L3_BITRATE
Bool l3_engine_log = FALSE;   /* -3 */
#endif
Bool zlib_logs = FALSE;   /* -Z */
Bool zlib_dump = FALSE;   /* -P */

int log_version = 2;            /* -1 */

struct bayes_settings *bayes_settings_pktsize;
struct bayes_settings *bayes_settings_avgipg;

unsigned int adx_addr_mask[3] = { ADDR_MASK , ADDR2_MASK , ADDR2_MASK};

/* locally global variables */
static u_long filesize = 0;
static int num_files = 0;
#ifndef TSTAT_RUNASLIB
static u_int numfiles;
#endif
static char *cur_filename;
static unsigned int step = 0;	/* counter to track the dir storing the
				   periodic dumping of histograms. */
static Bool first_packet_readed = FALSE; 

static time_t last_mtime;           //last time runtime config file is changed
static time_t last_mtime_check;
static int mtime_stable_counter;    //when this counter is 0, read again runtime config    

//XXX
typedef enum
{ ETH, DAG } Live_Cap_Type;
int livecap_type;		/* indicate the type of live capture */
#ifdef GROK_ERF_LIVE
char *dag_dev_list;		/* list of DAG cards device names */
#define DAG_NAME_BUFSIZE 25
#endif

int snaplen = DEFAULT_SNAPLEN;    /* Snaplen for the live capture */

/* for elapsed processing time */
struct timeval wallclock_start;
struct timeval wallclock_finished;
struct timeval wallclock_temp;

struct timeval last_skypeprint_time;

/* first and last packet timestamp */
timeval first_packet = { 0, 0 };
timeval last_packet = { 0, 0 };
timeval last_skypeprint_time = { 0, 0 };

/* .a.c. */
Bool is_stdin;
FILE *fp_stdout = NULL;
FILE *fp_stderr = NULL;
FILE *fp_logc = NULL;
FILE *fp_lognc = NULL;
FILE *fp_rtp_logc = NULL;
FILE *fp_skype_logc = NULL;
FILE *fp_udp_logc = NULL;
#if defined(MSN_CLASSIFIER) || defined(YMSG_CLASSIFIER) || defined(XMPP_CLASSIFIER)
FILE *fp_chat_logc = NULL;
FILE *fp_chat_log_msg = NULL;
#ifdef MSN_OTHER_COMMANDS
FILE *fp_msn_log_othercomm = NULL;
#endif
#endif
#ifdef L3_BITRATE
FILE *fp_l3bitrate = NULL;
#endif

/* LM */
/* AF: THIS IS USELESS!!! 
  1) It's creation is not integrated in the workflow 
  2) in some points the code refer to a fp_dup_ooo which is never defined
*/
#ifdef LOG_OOO
FILE *fp_dup_ooo_log;
#endif

#ifdef VIDEO_DETAILS
FILE *fp_video_logc = NULL;
#endif

#ifdef STREAMING_CLASSIFIER
FILE *fp_streaming_logc = NULL;
#endif

long log_bitmask = LOG_ALL;

/* discriminate Direction */
/* used when checking by Ethernet MAC */
eth_filter mac_filter;
Bool internal_dhost;
Bool internal_shost;
/* used when having two separate files or interfaces */
Bool coming_in;
Bool internal_wired = FALSE;
/* used when relying on IP addresses */
Bool net_conf = FALSE;
Bool cloud_conf = FALSE;
Bool net6_conf = FALSE;
Bool eth_conf = FALSE;

long int tcp_packet_count;
extern long not_id_p;
extern int search_count;
extern long int tot_adx_hash_count[3], tot_adx_list_count[3], adx_search_hash_count[3],
  adx_search_list_count[3];
extern void max_adx(int, int, double);

extern char dump_conf_fname[];
char runtime_conf_fname[200];
//static timeval last_runtime_check = {-1,-1};

/* PROFILE VARIABLES */
int prof_last_clk;              // last amount of clock usage
double prof_last_tm;            // last overall running time
struct tms prof_last_tms;       // last running time (user and sys)
double prof_cps;                // clock per seconds give by sysconf()

#ifdef SIG_CHILD_HANDLER
/* SIG_CHILD handler (to avoid zombie processes)*/
void
sigchld_h (int signum)
{
  pid_t pid;
  int status;
  while ((pid = waitpid (-1, &status, WNOHANG)) > 0)
    {
      if (debug > 1)
	fprintf (fp_stdout, "Child (pid %d) terminated with status %d\n.", pid,
		 status);
    }
  /* some OS reset the signal handler to SIG_DFL */
  signal (SIGCHLD, sigchld_h);
}

/* end SIG_CHILD handler */
#endif


static void
Help (void)
{
  fprintf (fp_stderr,
    "Usage:\n"
    "\ttstat [-htuvwpgSL] [-d[-d]]\n"
    "\t      [-s dir]\n"
    "\t      [-N file]\n"
    "\t      [-M file]\n"
    "\t      [-C file]\n"
    "\t      [-B bayes.conf]\n"
    "\t      [-T runtime.conf]\n"
    "\t      [-z file]\n"
    "\t      [-A mask]\n"
    "\t      [-H ?|file ]\n"
#ifdef SUPPORT_IPV6
    "\t      [-y] [-6 file]\n"
#endif
#ifdef HAVE_ZLIB
    "\t      [-Z] [-P]\n"
#endif
#ifdef HAVE_RRDTOOL
    "\t      [-r RRD_out_dir] [-R rrd_conf]\n"
#endif
#ifdef GROK_LIVE_TCPDUMP
    "\t      [-l] [-i interface] [-E snaplen]\n"
#endif
#ifdef GROK_ERF_LIVE
    "\t      [--dag device_name device_name ...]\n"
#endif
    "\t      [-f filterfile]\n"
    "\t      <file1 file2>\n"
    "\n"
    "Options:\n"
    "\t-h: print this help and exit\n"
    "\t-t: print ticks showing the trace analysis progress\n"
    "\t-u: do not trace UDP packets\n"
    "\t-v: print version and exit\n"
    "\t-w: print [lots] of warning\n"
    "\t-c: concatenate the finput files\n"
    "\t    (input files should already be in the correct order)\n"
    "\t-p: enable multi-threaded engine (useful for live capture)\n"
    "\t-d: increase debug level (repeat to increase debug level)\n"
    "\n"
    "\t-s dir: puts the trace analysis results into directory\n"
    "\t        tree dir (otherwise will be <file>.out)\n"
    "\t-N file: specify the file name which contains the\n"
    "\t         description of the internal networks.\n"
    "\t         This file must contain the subnets that will be\n"
    "\t         considered as 'internal' during the analysis.\n"
    "\t         Each subnet can be specified in one of the following types:\n"
    "\t         - <Network IP/NetMask> on a single line \n"
    "\t             130.192.0.0/255.255.0.0\n"
    "\t         - <Network IP/MaskLen> on a single line \n"
    "\t             130.192.0.0/16\n"
    "\t         - Pairs of lines with <Network IP> and <NetMask>\n"
    "\t             130.192.0.0\n"
    "\t             255.255.0.0\n"
    "\t         If the option is not specified all networks are\n"
    "\t         considered internal\n"
    "\n"
    "\t-M file: specify the file name which contains the\n"
    "\t         description of the MAC addesses that are to be considered internal.\n"
    "\t         MAC addreses must be in the 6 digit - hex notation.\n"
    "\t         Example:\n"
    "\t                11:22:33:44:55:66 \n"
    "\t                66:55:44:33:22:11 \n"
    "\t         If this option is specified, the -N param is ignored.\n"
    "\n"
    "\t-C file: specify the file name which contains the\n"
    "\t         description of the cloud networks.\n"
    "\t         This file must contain the subnets that will be\n"
    "\t         considered as belonging to a specific group of networks\n"
    "\t         (cloud) during the analysis.\n"
    "\t         Subnets are specified like in the -N option.\n"
    "\n"
	"\t-H ?: print internal histograms names and definitions\n"
    "\t-H file: Read histogram configuration from file\n"
	"\t         file describes which histograms tstat should collect\n"
	"\t         'include histo_name' includes a single histogram\n"
	"\t         'include_matching string' includes all histograms\n"
    "\t         whose name includes the string\n"
    "\t         special names are:\n"
    "\t         'ALL' to include all histograms\n"
    "\t         'ADX' to include address hits histogram\n"
    "\t         for example, to include all TCP related\n"
	"\t         and the address hits histograms, file should be:\n"
    "\t         include ADX\n"
    "\t         include_matching tcp\n"
    "\t         'adx_mask N' is a special command to define the\n"
    "\t         size of the netmask used to aggregate the address histograms\n"
    "\t         (e.g. 'adx_mask 24' to use the 255.255.255.0 mask)\n"  
    "\n"
    "\t-g: Enable global histo engine\n"
    "\t-S: No histo engine: do not create histograms files \n"
    "\t-L: No log engine: do not create log_* files \n"
    //"\t-1: Use old (v1) log_mm format\n"
	"\t-B Bayes_Dir: enable Bayesian traffic classification\n"
    "\t              configuration files from Bayes_Dir\n"
    "\t-T runtime.conf: configuration file to enable/disable dumping\n"
    "\t                 of traces and logs at runtime\n" 
    "\t-z file: redirect all the stdout/stderr messages to the file specified\n"
    "\t-A mask: enable XOR-based anonymization for internal IPv4 addresses.\n"
    "\t         'mask' is a decimal, octal, or hexadecimal value.\n"
#ifdef SUPPORT_IPV6
    "\t-6 file: specify the file name which contains the\n"
    "\t         description of the internal IPv6 network.\n"
#endif
#ifdef HAVE_ZLIB
    "\t-Z: Create gzip compressed (.gz) log files.\n"
    "\t-P: Create gzip compressed (.gz) pcap dump files.\n"
#endif
#ifdef HAVE_RRDTOOL
/*----------------------------------------------------------- 
   RRDtools 				                     
   these flags test for both the -r and -R options to be 
   specified when using RR database integration */
    "\t-R conf: specify the configuration file for integration with\n"
    "\t         RRDtool. See README.RRDtool for further information\n"
    "\t-r path: path to use to create/update the RRDtool database\n"
/*-----------------------------------------------------------*/
#endif
#ifdef GROK_DPMI
    "\t-D conf: DPMI configuration file\n"
#endif /* GROK_DPMI */
#ifdef GROK_LIVE_TCPDUMP
    "\t-l: enable live capture using libpcap\n"
    "\t-i interface: specifies the interface to be used to capture traffic\n"
    "\t-E snaplen: specifies the snaplen size used to capture traffic.\n"
    "\t            It might be overridden by the interface slen size\n"
#endif /* GROK_LIVE_TCPDUMP */

#ifdef GROK_ERF_LIVE
    "\t--dag: enable live capture using Endace DAG cards. The\n"
	"\t       list of device_name can contain at most four names\n"
#endif /* GROK_ERF_LIVE */
#ifdef L3_BITRATE
    "\t-3: collect separate IP bitrate log (log_l3_bitrate)\n"
#endif

    "\t-f filterfile: specifies the libpcap filter file. Syntax as in tcpdump\n"
    "\n"
    "\tfile: trace file to be analyzed\n"
    "\t      Use 'stdin' to read from standard input.\n"
    "\n"
    "Note:\n"
	"\tWhen tstat is called with no arguments (on the command line),\n"
	"\tit will first check if a file <tstat.conf> is provided in the\n"
    "\tsame directory where the execution started.\n"
	"\tIn the latter case, arguments will be read from <tstat.conf>\n"
    "\trather than from the command line\n"
    "\n");
  Formats ();
  Version ();
}



static void
BadArg (char *argsource, char *format, ...)
{
  va_list ap;

  Help ();

  fprintf (fp_stderr, "\nArgument error");
  if (argsource)
    fprintf (fp_stderr, " (from %s)", argsource);
  fprintf (fp_stderr, ": ");

  va_start (ap, format);
  vfprintf (fp_stderr, format, ap);
  va_end (ap);
  fprintf (fp_stderr, "\n");
  exit (EXIT_FAILURE);

}



static void
Usage (void)
{
  Help ();
  exit (0);
}



static void
Version (void)
{
  fprintf (fp_stderr, "\nVersion: %s\n", tstat_version);
  fprintf (fp_stderr, "Compiled by <%s>, the <%s> on machine <%s>\n\n",
	   built_bywhom, built_when, built_where);
}


static void
Formats (void)
{
  int i;

  fprintf (fp_stderr, "Supported Input File Formats:\n");
  for (i = 0; i < (int) NUM_FILE_FORMATS; ++i)
    fprintf (fp_stderr, "\t%-15s  %s\n",
	     file_formats[i].format_name, file_formats[i].format_descr);
}

#ifdef TSTAT_RUNASLIB
int tstat_init(char *config_fname) {
    int argc = 1;
    char *argv[1];
    argv[0] = (config_fname == NULL) ? "tstat.conf" : config_fname;
#else
/* add a fake function */
int tstat_init(char *config_fname) {
    return 0;
}

int
main (int argc, char *argv[]) {
  int i, j;
  double etime;
#endif
  pthread_t thread_done_periodic;
  pthread_t thread_all_dumping;
  pthread_mutexattr_t attr;
  struct timeval prof_tm;

/*
  if ((argc == 1) && !fExists ("tstat.conf"))
    {
      Help ();
      exit (1);
    }
*/
  /* let's catch  SIG_CHILD signals */
#ifdef SIG_CHILD_HANDLER
  signal (SIGCHLD, sigchld_h);
#endif
  /* initialize internals */
  trace_init ();

  /* parse the flags */
  CheckArguments (&argc, argv);
  

  /* optional UDP */
  if (do_udp)
    udptrace_init ();

  /* get starting wallclock time */
  gettimeofday (&wallclock_start, NULL);

/* allocate all histo structs */
  create_all_histo ();
  histo_parse_conf ();

  if (dump_all_histo_definition == TRUE)
    {
      print_all_histo_definition ();
      exit (0);
    }


#ifndef TSTAT_RUNASLIB
  if (live_flag == FALSE)
    { //no remaing arg is live capture
      num_files = argc;
      fprintf (fp_stdout, "%d arg%s remaining, starting with '%s'\n",
	      num_files, num_files > 1 ? "s" : "", 
          (filenames) ? filenames[0] : "");
    }

  // knock, knock...
  fprintf (fp_stdout, "%s\n\n", VERSION);
#endif


#ifdef HAVE_RRDTOOL
  /*-----------------------------------------------------------*/
  /* RRDtools                                                   */
  /*   now that all the histo have been creaed, we may          */
  /*   parse rrdtool configuration file                         */
  if (rrdset_path && rrdset_conf) {
    rrd_engine = TRUE;
    rrdtool_init ();
  }
  /*-----------------------------------------------------------*/
#endif

  /* register the protocol analyzer over TCP/UDP */
  proto_init ();

  if (runtime_engine) {
    ini_read(runtime_conf_fname);
  }


/* inititializing adx_index_current */
  alloc_adx (EXTERNAL_ADX_HISTO);
  if (adx_engine && adx2_engine) 
    { 
      alloc_adx (INTERNAL_ADX_HISTO);
      alloc_adx (INTERNAL_ADX_MAX);
    }

/* thread creation and management  */

  if (threaded)
    {
      /* Initialize mutex and condition variable objects */
      pthread_mutexattr_init (&attr);
      pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_ERRORCHECK);
      pthread_mutex_init (&ttp_lock_mutex, &attr);


      /* Inizializzazione di attr2 e del mutex relativo ai flussi udp */
      pthread_mutex_init (&utp_lock_mutex, NULL);


      pthread_mutex_init (&flow_close_cond_mutex, NULL);
      pthread_mutex_init (&flow_close_started_mutex, NULL);
      pthread_cond_init (&flow_close_cond, NULL);

      pthread_mutex_init (&stat_dump_mutex, NULL);
      pthread_mutex_init (&stat_dump_cond_mutex, NULL);
      pthread_cond_init (&stat_dump_cond, NULL);
      /* flow_closing thread */
      pthread_create (&thread_done_periodic, NULL, time_out_flow_closing,
		      NULL);
      /* stat_dump thread */
      pthread_create (&thread_all_dumping, NULL, stats_dumping, NULL);
      /* allow the thread to start... */
      usleep (200);
    }

  /* initialize bitrate struct */
  memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
  memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
  memset (&L7_udp_bitrate, 0, sizeof (struct L7_bitrates));
  memset (&HTTP_bitrate, 0, sizeof (struct HTTP_bitrates));
  memset (&WEB_bitrate, 0, sizeof (struct WEB_bitrates));
  memset (&VIDEO_rate, 0, sizeof (struct VIDEO_rates));

  /* init profile variables */
  prof_last_clk = (int)clock();
  gettimeofday(&prof_tm, NULL);
  prof_last_tm = time2double(prof_tm)/1e6;
  times(&prof_last_tms);
  prof_cps = sysconf(_SC_CLK_TCK) * 1.0;
  
#ifndef TSTAT_RUNASLIB
  /* read each file in turn */
  if (live_flag == FALSE)
    {
      numfiles = argc;
      for (i = 0; i < argc; i++)
	{
	  for (j = 0; j < two_files; j++)
	    {
	      if ((debug > 0) || (numfiles > 1))
		{
		  if (argc > 1)
		    fprintf (fp_stdout, "\nRunning file '%s' (%d of %d)\n",
			    filenames[i + j], i + j + 1, numfiles);
		  else
		    fprintf (fp_stdout, "Running file '%s'\n", filenames[i]);
		}
	    }

	  /* do the real work */
	  ProcessFile (filenames[i], (i + j == numfiles));
	  i += j - 1;
	}
    }
  else
    {
      ProcessFile ("stdin", TRUE);	/* When live capture is on, no files are needed */
    }


  if (threaded)
    {
      /* Closing flow_closing thread */
      pthread_cancel (thread_done_periodic);
      pthread_cancel (thread_all_dumping);
    }

  /* clean up output */
  if (printticks)
    fprintf (fp_stdout, "\n");

  /* get ending wallclock time */
  gettimeofday(&wallclock_finished, NULL);

  /* general output */
  fprintf(fp_stdout, "%lu packets seen, %lu TCP packets traced",
	   pnum, tcp_trace_count_outgoing + tcp_trace_count_incoming
	   + tcp_trace_count_local);
  if (do_udp)
    fprintf(fp_stdout, ", %lu UDP packets traced", udp_trace_count);
  fprintf(fp_stdout, "\n");

  /* actual tracefile times */
  etime = elapsed (first_packet, last_packet);
  fprintf(fp_stdout, "trace %s elapsed time: %s\n",
	   (num_files == 1) ? "file" : "files", elapsed2str (etime));
  if (debug > 0)
    {
      fprintf(fp_stdout, "\tfirst packet:  %s\n", ts2ascii (&first_packet));
      fprintf(fp_stdout, "\tlast packet:   %s\n", ts2ascii (&last_packet));
    }
  exit(EXIT_SUCCESS);
#else
  return EXIT_SUCCESS;
#endif //TSTAT_RUNASLIB
}

void reopen_logfile(FILE **fp_ref, const char *basename, const char *filename)
{
  static char logfile[FILENAME_SIZE+50];

#ifdef HAVE_ZLIB
  if (zlib_logs)
   {
    snprintf (logfile,FILENAME_SIZE,"%s/%s.gz", basename, filename);
    if (*fp_ref != NULL)
      gzclose (*fp_ref);
    *fp_ref = gzopen (logfile, "a");
   }
  else
#endif
   {
    snprintf (logfile,FILENAME_SIZE,"%s/%s", basename, filename);
    if (*fp_ref != NULL)
      fclose (*fp_ref);
    *fp_ref = fopen (logfile, "a");
   }
  
  if (*fp_ref == NULL)
    {
      fprintf (fp_stderr, "Could not open file %s\n", logfile);
    }
}

void write_log_header(FILE *fp, int log_type) {
    int i, col;


    /*****************************************************
     * LOG_TCP_COMPLETE + LOG_TCP_NOCOMPLETE
     *****************************************************/
    if (log_type == LOG_TCP_COMPLETE || log_type == LOG_TCP_NOCOMPLETE) {
        wfprintf (fp, 
            /*******************************
             * client stats
             *******************************/
            "#c_ip:1"            // 1: ip address
            " c_port:2"         // 2: port 
            " c_pkts_all:3"     // 3: total number of segments uploaded
            " c_rst_cnt:4"      // 4: number of RST pkts sent
            " c_ack_cnt:5"      // 5: number of pkts with ACK flag set
            " c_ack_cnt_p:6"    // 6: number of pure ACK pkts (i.e. ACK set but no payload)
            " c_bytes_uniq:7"   // 7: number of unique bytes uploaded
            " c_pkts_data:8"    // 8: number of segments with payload
            " c_bytes_all:9"    // 9: total number of bytes = unique + retransmitted
            " c_pkts_retx:10"    // 10: number of segments retransmitted
            " c_bytes_retx:11"   // 11: number of bytes retransmitted
            " c_pkts_ooo:12"     // 12: number of packets out of order
            " c_syn_cnt:13"      // 13: number of segments with SYN set
            " c_fin_cnt:14"      // 14: number of segments with FIN set
            " c_f1323_opt:15"    // 15: window scale option (0/1)
            " c_tm_opt:16"       // 16: timestamp option (0/1)
            " c_win_scl:17"      // 17: window scale option
            " c_sack_opt:18"     // 18: SACK option (0/1)
            " c_sack_cnt:19"     // 19: number of SACK sent
            " c_mss:20"          // 20: maximum segment size declared
            " c_mss_max:21"      // 21: maximum segment size observed
            " c_mss_min:22"      // 22: minimum segment size observed
            " c_win_max:23"      // 23: maximum receiver window announced
            " c_win_min:24"      // 24: minimum receiver window announced
            " c_win_0:25"        // 25: number of segments with receiver window = 0
            " c_cwin_max:26"     // 26: congestion window max
            " c_cwin_min:27"     // 27: congestion window min
            " c_cwin_ini:28"     // 28: congestion window initial
            " c_rtt_avg:29"      // 29: RTT average
            " c_rtt_min:30"      // 30: RTT minimum
            " c_rtt_max:31"      // 31: RTT maximum
            " c_rtt_std:32"      // 32: RTT standard deviation
            " c_rtt_cnt:33"      // 33: number of RTT valid samples
            " c_ttl_min:34"      // 34: TTL minimum
            " c_ttl_max:35"      // 35: TTL maximum
            " c_pkts_rto:36"     // 36: number of segments retransmitted due to timeout
            " c_pkts_fs:37"      // 37: number of segments retransmitted due to fast retransmitt
            " c_pkts_reor:38"    // 38: number of segments reordering
            " c_pkts_dup:39"     // 39: number of segments duplicated
            " c_pkts_unk:40"     // 40: number of segments not in sequence or duplicate which are not classified as specific events
            " c_pkts_fc:41"      // 41: number of segments retransmitted to probe receiver window
            " c_pkts_unrto:42"   // 42: number of un-necessary transmission following a timeout
            " c_pkts_unfs:43"    // 43: number of un-necessary transmission following fast retransmit
            " c_syn_retx:44"     // 44: retransmitted SYN with different initial seqno (0/1)
            /*******************************
             * server stats
             *******************************/
            " s_ip:45"           // 45: ip address
            " s_port:46"         // 46: port 
            " s_pkts_all:47"     // 47: total number of segments uploaded
            " s_rst_cnt:48"      // 48: number of RST pkts sent
            " s_ack_cnt:49"      // 49: number of pkts with ACK flag set
            " s_ack_cnt_p:50"    // 50: number of pure ACK pkts (i.e. ACK set but no payload)
            " s_bytes_uniq:51"   // 51: number of unique bytes
            " s_pkts_data:52"    // 52: number of segments with payload
            " s_bytes_all:53"    // 53: total number of bytes = unique + retransmitted
            " s_pkts_retx:54"    // 54: number of segments retransmitted
            " s_bytes_retx:55"   // 55: number of bytes retransmitted
            " s_pkts_ooo:56"     // 56: number of packets out of order
            " s_syn_cnt:57"      // 57: number of segments with SYN set
            " s_fin_cnt:58"      // 58: number of segments with FIN set
            " s_f1323_opt:59"    // 59: window scale option (0/1)
            " s_tm_opt:60"       // 60: timestamp option (0/1)
            " s_win_scl:61"      // 61: window scale option
            " s_sack_opt:62"     // 62: SACK option (0/1)
            " s_sack_cnt:63"     // 63: number of SACK sent
            " s_mss:64"          // 64: maximum segment size declared
            " s_mss_max:65"      // 65: maximum segment size observed
            " s_mss_min:66"      // 66: minimum segment size observed
            " s_win_max:67"      // 67: maximum receiver window announced
            " s_win_min:68"      // 68: minimum receiver window announced
            " s_win_0:69"        // 69: number of segments with receiver window = 0
            " s_cwin_max:70"     // 70: congestion window max
            " s_cwin_min:71"     // 71: congestion window min
            " s_cwin_ini:72"     // 72: congestion window initial
            " s_rtt_avg:73"      // 73: RTT average
            " s_rtt_min:74"      // 74: RTT minimum
            " s_rtt_max:75"      // 75: RTT maximum
            " s_rtt_std:76"      // 76: RTT standard deviation
            " s_rtt_cnt:77"      // 77: number of RTT valid samples
            " s_ttl_min:78"      // 78: TTL minimum
            " s_ttl_max:79"      // 79: TTL maximum
            " s_pkts_rto:80"     // 80: number of segments retransmitted due to timeout
            " s_pkts_fs:81"      // 81: number of segments retransmitted due to fast retransmitt
            " s_pkts_reor:82"    // 82: number of segments reordering
            " s_pkts_dup:83"     // 83: number of segments duplicated
            " s_pkts_unk:84"     // 84: number of segments not in sequence or duplicate which are not classified as specific events
            " s_pkts_fc:85"      // 85: number of segments retransmitted to probe receiver window
            " s_pkts_unrto:86"   // 86: number of un-necessary transmission following a timeout
            " s_pkts_unfs:87"    // 87: number of un-necessary transmission following fast retransmit
            " s_syn_retx:88"     // 88: retransmitted SYN with different initial seqno (0/1)
            /********************************
             * timestamps 
             ********************************/
            " durat:89"        // 89: completion time
            " first:90"        // 90: first packet since first segment ever
            " last:91"         // 91: last packet since first segment ever
            " c_first:92"      // 92: first client packet since first segment ever
            " s_first:93"      // 93: first server packet since first segment ever
            " c_last:94"       // 94: last client packet since first segment ever
            " s_last:95"       // 95: last server packet since first segment ever
            " c_first_ack:96"  // 96: first client ack since first segment ever
            " s_first_ack:97"  // 97: first server ack since first segment ever
            " first_abs:98"    // 98: first packet absolute
            " c_isint:99"      // 99: internal client ip
            " s_isint:100"      // 100: internal server ip
            /********************************
             * classification
             ********************************/
            " con_t:101"        // 101: connection type
            " p2p_t:102"        // 102: p2p type
            " p2p_st:103"       // 103: p2p subtype
            " ed2k_data:104"    // 104: number of ed2k data messages
            " ed2k_sig:105"     // 105: number of ed2k signalin messages
            " ed2k_c2s:106"     // 106: number of ed2k client 2 server messages
            " ed2k_c2c:107"     // 107: number of ed2k client 2 client messages
            " ed2k_chat:108"    // 108: number of ed2k chat messages
            " http_t:109"        // 109: http type
            );
        // columns now can be variable
        col = 110;
#ifdef LOST_PACKET_STAT
        wfprintf(fp, " c_pkts_drop:%d", col++); // number of drop client packets counted from seqno
        wfprintf(fp, " s_pkts_drop:%d", col++); // number of dopt server packets counted from seqno
#endif
#ifndef PACKET_STATS
        wfprintf(fp, " c_pkts_push:%d", col++);  // number of client push separated messages
        wfprintf(fp, " s_pkts_push:%d", col++);  // number of server push separated messages
#endif
        wfprintf(fp, " c_ssl:%d", col++); // server name of SSL client hello message
        wfprintf(fp, " s_ssl:%d", col++); // subject name in SSL server certificate
#ifdef SNOOP_DROPBOX
        wfprintf(fp, " dropbox_id:%d", col++);    // dropbox device id
#endif

#ifdef PACKET_STATS
        /*******************************
         * PSH-delimited Message sizes 
         *******************************/
//        wfprintf(fp, " -:%d", col++);  // '-' is used as delimiter
        wfprintf(fp, " c_msgsize:%d", col++); 
        for (i=0;i<MAX_COUNT_MESSAGES;i++) 
            wfprintf(fp, " c_msgsize%d:%d", i+1, col++);

//        wfprintf(fp, " -:%d", col++);  // '-' is used as delimiter
        wfprintf(fp, " s_msgsize:%d", col++);     // number of valid samples (out of MAX_COUNT_MESSAGES)
        for (i=0;i<MAX_COUNT_MESSAGES;i++) 
            wfprintf(fp, " s_msgsize%d:%d", i+1, col++);

        /*******************************
         * segment sizes 
         *******************************/
//        wfprintf(fp, " -:%d", col++);  // '-' is used as delimiter
        wfprintf(fp, " c_pktsize:%d", col++);   // number of valid samples (out of MAX_COUNT_SEGMENTS)
        for (i=0;i<MAX_COUNT_SEGMENTS;i++) 
          wfprintf (fp, " c_pktsize%d:%d", i+1, col++);

//        wfprintf(fp, " -:%d", col++);  // '-' is used as delimiter
        wfprintf(fp, " s_pktsize:%d", col++);     // number of valid samples (out of MAX_COUNT_SEGMENTS)
        for (i=0;i<MAX_COUNT_SEGMENTS;i++) 
          wfprintf (fp, " s_pktsize%d:%d", i+1, col++);
       

        /*******************************
         * segment intertimes
         *******************************/
//        wfprintf(fp, " -:%d", col++);  // '-' is used as delimiter
        for (i=0; i < MAX_COUNT_SEGMENTS-1; i++)
            wfprintf (fp, " c_sit%d:%d", i+1, col++);

//        wfprintf(fp, " -:%d", col++);  // '-' is used as delimiter
        for (i=0;i<MAX_COUNT_SEGMENTS-1;i++)
            wfprintf (fp, " s_sit%d:%d", i+1, col++);


        /*******************************
         * averages
         *******************************/
//        wfprintf(fp, " -:%d", col++);  // '-' is used as delimiter
        wfprintf (fp, " c_pkts_data:%d", col++);
        wfprintf (fp, " c_pkts_data_avg:%d", col++);
        wfprintf (fp, " c_pkts_data_std:%d", col++);
        wfprintf (fp, " s_pkts_data:%d", col++);
        wfprintf (fp, " s_pkts_data_avg:%d", col++);
        wfprintf (fp, " s_pkts_data_std:%d", col++);
//        wfprintf(fp, " -:%d", col++);  // '-' is used as delimiter
        wfprintf (fp, " c_seg_cnt:%d", col++);
        wfprintf (fp, " c_sit_avg:%d", col++);
        wfprintf (fp, " c_sit_std:%d", col++);
//        wfprintf(fp, " -:%d", col++);  // '-' is used as delimiter
        wfprintf (fp, " s_seg_cnt:%d", col++);
        wfprintf (fp, " s_sit_avg:%d", col++);
        wfprintf (fp, " s_sit_std:%d", col++);

        /******************************
         * PSH
         ******************************/
//        wfprintf(fp, " -:%d", col++);  // '-' is used as delimiter
        wfprintf(fp, " c_pkts_push:%d", col++);
        wfprintf(fp, " s_pkts_push:%d", col++);
#endif
        wfprintf (fp, "\n");
    }

    /**************************************************
     * LOG_UDP_COMPLETE
     **************************************************/
    else if (log_type == LOG_UDP_COMPLETE) {
        col = 0;
        wfprintf(fp, "#c_ip:%d", col++);            // client ip
        wfprintf(fp, " c_port:%d", col++);          // client port
        wfprintf(fp, " c_first_abs:%d", col++);     // first time absolute
        wfprintf(fp, " c_durat:%d", col++);         // connection duration
        wfprintf(fp, " c_bytes_all:%d", col++);     // bytes uploaded
        wfprintf(fp, " c_pkts_all:%d", col++);      // packets uploaded
        wfprintf(fp, " c_isint:%d", col++);         // client ip is internal
        wfprintf(fp, " c_type:%d", col++);          // flow type
#ifdef P2P_DETAILS
        wfprintf(fp, " c_p2p_pkts:%d", col++);      // number of p2p packets
        wfprintf(fp, " c_p2p_pkts_edk:%d", col++);  // number of Emule-EDK packets
        wfprintf(fp, " c_p2p_pkts_kad:%d", col++);  // number of Emule-KAD packets
        wfprintf(fp, " c_p2p_pkts_kadu:%d", col++); // number of Emule-KADU packets
        wfprintf(fp, " c_p2p_pkts_gnu:%d", col++);  // number of Gnutella packets
        wfprintf(fp, " c_p2p_pkts_bit:%d", col++);  // number of Bittorrent packets
        wfprintf(fp, " c_p2p_pkts_dc:%d", col++);   // number of DirectConnect packets
        wfprintf(fp, " c_p2p_pkts_kaz:%d", col++);  // number of Kazaa packets
        wfprintf(fp, " c_p2p_pkts_ppl:%d", col++);  // number of PPLive packets
        wfprintf(fp, " c_p2p_pkts_sop:%d", col++);  // number of SopCast packets
        wfprintf(fp, " c_p2p_pkts_tva:%d", col++);  // number of TVAnts packets
#endif
        wfprintf(fp, " s_ip:%d", col++);            // server ip
        wfprintf(fp, " s_port:%d", col++);          // server port
        wfprintf(fp, " s_first_abs:%d", col++);     // first time absolute
        wfprintf(fp, " s_durat:%d", col++);         // connection duration
        wfprintf(fp, " s_bytes_all:%d", col++);     // bytes downloaded
        wfprintf(fp, " s_pkts_all:%d", col++);      // packets downloaded
        wfprintf(fp, " s_isint:%d", col++);         // server ip is internal
        wfprintf(fp, " s_type:%d", col++);          // flow type
#ifdef P2P_DETAILS
        wfprintf(fp, " s_p2p_pkts:%d", col++);      // number of p2p packets
        wfprintf(fp, " s_p2p_pkts_edk:%d", col++);  // number of Emule-EDK packets
        wfprintf(fp, " s_p2p_pkts_kad:%d", col++);  // number of Emule-KAD packets
        wfprintf(fp, " s_p2p_pkts_kadu:%d", col++); // number of Emule-KADU packets
        wfprintf(fp, " s_p2p_pkts_gnu:%d", col++);  // number of Gnutella packets
        wfprintf(fp, " s_p2p_pkts_bit:%d", col++);  // number of Bittorrent packets
        wfprintf(fp, " s_p2p_pkts_dc:%d", col++);   // number of DirectConnect packets
        wfprintf(fp, " s_p2p_pkts_kaz:%d", col++);  // number of Kazaa packets
        wfprintf(fp, " s_p2p_pkts_ppl:%d", col++);  // number of PPLive packets
        wfprintf(fp, " s_p2p_pkts_sop:%d", col++);  // number of SopCast packets
        wfprintf(fp, " s_p2p_pkts_tva:%d", col++);  // number of TVAnts packets
#endif
        wfprintf (fp, "\n");
    }

    /**************************************************
     * LOG_VIDEO_COMPLETE
     **************************************************/
    else if (log_type == LOG_VIDEO_COMPLETE) {
        wfprintf (fp,
            /************************
             * client side
             ************************/
            "#c_ip:1"              // 1: client ip
            " c_port:2"            // 2: client port
            " c_pkts_all:3"        // 3: total number of segments uploaded
            " c_rst_cnt:4"         // 4: number of RST pkts sent 
            " c_bytes_uniq:5"      // 5: number of unique bytes uploaded
            " c_pkts_data:6"       // 6: number of segments with payload
            " c_bytes_all:7"       // 7: total number of bytes = unique + retransmitted
            " c_pkts_retx:8"       // 8: number of segments retransmitted
            " c_bytes_retx:9"      // 9: number of bytes retransmitted
            " c_pkts_ooo:10"       // 10: number of packets out of order
            " c_fin_cnt:11"        // 11: number of segments with FIN set
            " c_mss_max:12"        // 12: maximum segment size observed
            " c_win_max:13"        // 13: maximum receiver window announced
            " c_win_min:14"        // 14: minimum receiver window announced
            " c_rtt_avg:15"        // 15: RTT average
            " c_rtt_min:16"        // 16: RTT minimum
            " c_rtt_max:17"        // 17: RTT maximum
            " c_rtt_std:18"        // 18: RTT standard deviation
            " c_rtt_cnt:19"        // 19: number of RTT valid samples
            " c_ttl_min:20"        // 20: TTL minimum
            " c_ttl_max:21"        // 21: TTL maximum
            " c_rate_smpl:22"      // 22: number of rate samples
            " c_rate_zero:23"      // 23: number of empty rate samples 
            " c_rate_streak:24"    // 24: maximum number of consecutive empty rate samples
            " c_rate_avg:25"       // 25: average upload rate 
            " c_rate_std:26"       // 26: standard deviation of upload rate
            " c_rate_min:27"       // 27: minimum upload rate
            " c_rate_max:28"       // 28: maximum upload rate
            " c_isint:29"          // 29: internal client ip
            /************************
             * server side
             ************************/
            " s_ip:30"             // 30: client ip
            " s_port:31"           // 31: client port
            " s_pkts_all:32"       // 32: total number of segments uploaded
            " s_rst_cnt:33"        // 33: number of RST pkts sent 
            " s_bytes_uniq:34"     // 34: number of unique bytes uploaded
            " s_pkts_data:35"      // 35: number of segments with payload
            " s_bytes_all:36"      // 36: total number of bytes = unique + retransmitted
            " s_pkts_retx:37"      // 37: number of segments retransmitted
            " s_bytes_retx:38"     // 38: number of bytes retransmitted
            " s_pkts_ooo:39"       // 39: number of packets out of order
            " s_fin_cnt:40"        // 40: number of segments with FIN set
            " s_mss_max:41"        // 41: maximum segment size observed
            " s_win_max:42"        // 42: maximum receiver window announced
            " s_win_min:43"        // 43: minimum receiver window announced
            " s_rtt_avg:44"        // 44: RTT average
            " s_rtt_min:45"        // 45: RTT minimum
            " s_rtt_max:46"        // 46: RTT maximum
            " s_rtt_std:47"        // 47: RTT standard deviation
            " s_rtt_cnt:48"        // 48: number of RTT valid samples
            " s_ttl_min:49"        // 49: TTL minimum
            " s_ttl_max:50"        // 50: TTL maximum
            " s_rate_smpl:51"      // 51: number of rate samples
            " s_rate_zero:52"      // 52: number of empty rate samples 
            " s_rate_streak:53"    // 53: maximum number of consecutive empty rate samples
            " s_rate_avg:54"       // 54: average upload rate 
            " s_rate_std:55"       // 55: standard deviation of upload rate
            " s_rate_min:56"       // 56: minimum upload rate
            " s_rate_max:57"       // 57: maximum upload rate
            " s_isint:58"          // 58: internal client ip
            /********************************
             * timestamps 
             ********************************/
            " durat:59"            // 59: completion time
            " first:60"            // 60: first packet since first segment ever
            " last:61"             // 61: last packet since first segment ever
            " c_first:62"          // 62: first client packet since first segment ever
            " s_first:63"          // 63: first server packet since first segment ever
            " c_last:64"           // 64: last client packet since first segment ever
            " s_last:65"           // 65: last server packet since first segment ever
            " c_first_ack:66"      // 66: first client ack since first segment ever
            " s_first_ack:67"      // 67: first server ack since first segment ever
            " first_abs:68"        // 68: first packet absolute
            /********************************
             * classification
             ********************************/
            " con_t:69"           // 69: connection type
            " p2p_t:70"           // 70: p2p type
            " http_t:71"          // 71: http type
            " http_res:72"        // 72: http response code
            " yt_id16_46:73"      // 73: youtube, id16/46
            " yt_id11:74"         // 74: youtube, id11
            " yt_itag:75"         // 75: youtube, itag value (format type)
            " yt_seek:76"         // 76: youtube, seek value (begin offset)
            " flv_dur_tot:77"     // 77: flash video, total duration
            " flv_start:78"       // 78: flash video, start position
            " flv_dur:79"         // 79: flash video, remaining time to download
            " flv_width:80"       // 80: flash video, pixel width
            " flv_height:81"      // 81: flash video, pixel height
            " flv_rate_vd:82"     // 82: flash video, data rate
            " flv_rate_au:83"     // 83: flash video, audio rate
            " flv_rate_tot:84"    // 84: flash video, total rate
            " flv_rate_fr:85"     // 85: flash video, frame rate
            " flv_bytes:86"       // 86: flash video, remaining video bytes to download
            " yt_red_mode:87"     // 87: youtube redirection mode
            " yt_red_cnt:88"      // 88: youtube redirection count
            " yt_ismob:89"        // 89: youtube, is mobile
            " yt_mob_t:90"        // 90: youtube, type of mobile device
        );

        col = 90;
        for (i=0;i<10;i++) 
            wfprintf (fp, " c_rate%d:%d", i+1, col++); 

        for (i=0;i<10;i++)
            wfprintf (fp, " s_rate%d:%d", i+1, col++); 

        wfprintf (fp, " s_msg:%d", col++);
        for (i=0;i<MAX_COUNT_MESSAGES;i++) 
            wfprintf (fp, " s_msgsize%d:%d", i+1, col++);
       

      wfprintf (fp_video_logc, "\n");
    }

    /**************************************************
     * LOG_STREAMING_COMPLETE
     **************************************************/
    else if (log_type == LOG_STREAMING_COMPLETE) {
        wfprintf (fp,
            /************************
             * client side
             ************************/
            "#c_ip:1"             // 1: client ip
            " c_port:2"           // 2: client port
            " c_pkts_all:3"       // 3: total number of segments uploaded
            " c_rst_cnt:4"        // 4: number of RST pkts sent 
            " c_bytes_uniq:5"     // 5: number of unique bytes uploaded
            " c_pkts_data:6"      // 6: number of segments with payload
            " c_bytes_all:7"      // 7: total number of bytes = unique + retransmitted
            " c_pkts_retx:8"      // 8: number of segments retransmitted
            " c_bytes_retx:9"     // 9: number of bytes retransmitted
            " c_pkts_ooo:10"       // 10: number of packets out of order
            " c_fin_cnt:11"        // 11: number of segments with FIN set
            " c_mss_max:12"        // 12: maximum segment size observed
            " c_win_max:13"        // 13: maximum receiver window announced
            " c_win_min:14"        // 14: minimum receiver window announced
            " c_rtt_avg:15"        // 15: RTT average
            " c_rtt_min:16"        // 16: RTT minimum
            " c_rtt_max:17"        // 17: RTT maximum
            " c_rtt_std:18"        // 18: RTT standard deviation
            " c_rtt_cnt:19"        // 19: number of RTT valid samples
            " c_ttl_min:20"        // 20: TTL minimum
            " c_ttl_max:21"        // 21: TTL maximum
            " c_rate_smpl:22"      // 22: number of rate samples
            " c_rate_zero:23"      // 23: number of empty rate samples 
            " c_rate_streak:24"    // 24: maximum number of consecutive empty rate samples
            " c_rate_avg:25"       // 25: average upload rate 
            " c_rate_std:26"       // 26: standard deviation of upload rate
            " c_rate_min:27"       // 27: minimum upload rate
            " c_rate_max:28"       // 28: maximum upload rate
            " c_isint:29"          // 29: internal client ip
            /************************
             * server side
             ************************/
            " s_ip:30"             // 30: client ip
            " s_port:31"           // 31: client port
            " s_pkts_all:32"       // 32: total number of segments uploaded
            " s_rst_cnt:33"        // 33: number of RST pkts sent 
            " s_bytes_uniq:34"     // 34: number of unique bytes uploaded
            " s_pkts_data:35"      // 35: number of segments with payload
            " s_bytes_all:36"      // 36: total number of bytes = unique + retransmitted
            " s_pkts_retx:37"      // 37: number of segments retransmitted
            " s_bytes_retx:38"     // 38: number of bytes retransmitted
            " s_pkts_ooo:39"       // 39: number of packets out of order
            " s_fin_cnt:40"        // 40: number of segments with FIN set
            " s_mss_max:41"        // 41: maximum segment size observed
            " s_win_max:42"        // 42: maximum receiver window announced
            " s_win_min:43"        // 43: minimum receiver window announced
            " s_rtt_avg:44"        // 44: RTT average
            " s_rtt_min:45"        // 45: RTT minimum
            " s_rtt_max:46"        // 46: RTT maximum
            " s_rtt_std:47"        // 47: RTT standard deviation
            " s_rtt_cnt:48"        // 48: number of RTT valid samples
            " s_ttl_min:49"        // 49: TTL minimum
            " s_ttl_max:50"        // 50: TTL maximum
            " s_rate_smpl:51"      // 51: number of rate samples
            " s_rate_zero:52"      // 52: number of empty rate samples 
            " s_rate_streak:53"    // 53: maximum number of consecutive empty rate samples
            " s_rate_avg:54"       // 54: average upload rate 
            " s_rate_std:55"       // 55: standard deviation of upload rate
            " s_rate_min:56"       // 56: minimum upload rate
            " s_rate_max:57"       // 57: maximum upload rate
            " s_isint:58"          // 58: internal client ip
            /********************************
             * timestamps 
             ********************************/
            " durat:59"            // 59: completion time
            " first:60"            // 60: first packet since first segment ever
            " last:61"             // 61: last packet since first segment ever
            " c_first:62"          // 62: first client packet since first segment ever
            " s_first:63"          // 63: first server packet since first segment ever
            " c_last:64"           // 64: last client packet since first segment ever
            " s_last:65"           // 65: last server packet since first segment ever
            " c_first_ack:66"      // 66: first client ack since first segment ever
            " s_first_ack:67"      // 67: first server ack since first segment ever
            " first_abs:68"        // 68: first packet absolute
            /********************************
             * classification
             ********************************/
            " con_t:69"            // 69: connection type
            " p2p_t:70"            // 70: p2p type
            " http_t:71"           // 71: http type
            " http_res:72"         // 72: http response code
            " yt_id16_46:73"       // 73: youtube, id16/46
            " yt_id11:74"          // 74: youtube, id11
            " yt_itag:75"          // 75: youtube, itag value (format type)
            " yt_seek:76"          // 76: youtube, seek value (begin offset)
            " vd_type_cont:77"     // 77: video type classification from HTTP content-type
            " vd_type_pay:78"      // 78: video type classification from payload
            " vd_dur:79"           // 79: video duration
            " vd_rate_tot:80"      // 80: video rate total
            " vd_width:81"         // 81: video width pixel
            " vd_height:82"        // 82: video height pixel
        );
        col = 83;
        wfprintf(fp, "\n");
    }

    /**************************************************
     * LOG_CHAT_MESSAGES
     **************************************************/
    else if (log_type == LOG_CHAT_MESSAGES) {
	    wfprintf (fp,
		   "#idflow:1"        // 1: TCP id flow
           " type:2"          // 2: message type
           " dir:3"           // 3: direction
           " paylen:4"        // 4: payload length
           " first_tm:5"      // 5: first time (as string)
           " durat:6"         // 6: duration 
           " con_t:7"         // 7: connection type
           "\n"
        );
    }

    /**************************************************
     * LOG_CHAT_COMPLETE
     **************************************************/
    else if (log_type == LOG_CHAT_COMPLETE) {
        wfprintf(fp,
            /*****************
             * client
             *****************/
            "#c_ip:1"           // 1: client ip
            " c_port:2"         // 2: client port
            " c_bytes_uniq:3"   // 3: number of unique bytes uploaded
            " c_pkts_all:4"     // 4: total number of segments uploaded
            " c_msn:5"          // 5: total number of MSN messages
            " c_msn_a:6"        // 6: number of MSN messages type A
            " c_msn_d:7"        // 7: number of MSN messages type D
            " c_msn_n:8"        // 8: number of MSN messages type N
            " c_msn_u:9"        // 9: number of MSN messages type U
            " c_msn_y:10"       // 10: number of MSN messages type Y
            /*****************
             * server
             *****************/
            " s_ip:11"          // 11: server ip                           
            " s_port:12"        // 12: server port
            " s_bytes_uniq:13"  // 13: number of unique bytes uploaded
            " s_pkts_all:14"    // 14: total number of segments uploaded
            " s_msn:15"         // 15: total number of MSN messages
            " s_msn_a:16"       // 16: number of MSN messages type A
            " s_msn_d:17"       // 17: number of MSN messages type D
            " s_msn_n:18"       // 18: number of MSN messages type N
            " s_msn_u:19"       // 19: number of MSN messages type U
            " s_msn_y:20"       // 20: number of MSN messages type Y
            /***********/
            " first_tm:21"      // 21: absolute start time
            " durat:22"         // 22: duration
            " type:23"          // 23: chat flow type
            " ver:24"           // 24: chat version
            " c_isint:25"       // 25: client is internal
            " flowid:26"        // 26: TCP flow id
            " T:27"             // 27: T = TCP
            " con_t:28"         // 28: TCP connect type
        );
        wfprintf (fp, "\n");
    }
}


// MGM
/* Create subdirs into which out files will be put */
void
create_new_outfiles (char *filename, Bool reuse_dir)
{
  char tmpstr[FILENAME_SIZE+20];
  struct stat fbuf;
  char date[50];


  if (!histo_engine && !log_bitmask && !global_histo && !runtime_engine)
    return;

  if (reuse_dir == FALSE) {
      if (!basedirspecified) {
          /* get the basename from the tracefile */
          if (is_stdin || strcmp(filename, "TSTAT_RUNASLIB") == 0) {
              basenamedir = strdup ("stdin");
          } else {
              basenamedir = get_basename (filename);
          }
      }
      if (stat (basenamedir, &fbuf) != 0) {
          mkdir (basenamedir, 0775);
      }
      strftime (date, 49, "%Y_%m_%d_%H_%M", localtime (&current_time.tv_sec));
      sprintf (basename, "%s/%s.out", basenamedir, date);
      if (stat (basename, &fbuf) != -1) {
          /* remove the previous directory */
          sprintf (tmpstr, "rm -rf %s", basename);
          system (tmpstr);
      }
      if (mkdir (basename, 0775) == -1) {
          fprintf(fp_stderr, "Cannot create directory %s\n", basename);
      }
      fprintf(fp_stdout, "[%s] created new outdir %s\n", Timestamp(), basename);

      if (global_histo)
        sprintf (global_data_dir, "%s/GLOBAL", basename);
  }

  if (!histo_engine && !log_bitmask && !runtime_engine)
    return;

  if (LOG_IS_ENABLED(LOG_TCP_COMPLETE)) {
      reopen_logfile(&fp_logc,basename,"log_tcp_complete");
      write_log_header(fp_logc, LOG_TCP_COMPLETE);
  }


  if (LOG_IS_ENABLED(LOG_TCP_NOCOMPLETE)) {
      reopen_logfile(&fp_lognc,basename,"log_tcp_nocomplete");
      write_log_header(fp_lognc, LOG_TCP_NOCOMPLETE);
  }

#ifdef RTP_CLASSIFIER
  if (LOG_IS_ENABLED(LOG_MM_COMPLETE)) {
      //TOFIX: missing header in this log file
      reopen_logfile(&fp_rtp_logc, basename, "log_mm_complete");
  }

#endif

#ifdef SKYPE_CLASSIFIER
  if (bayes_engine && LOG_IS_ENABLED(LOG_SKYPE_COMPLETE)) {
      //TOFIX: missing header in this log file
     reopen_logfile(&fp_skype_logc, basename, "log_skype_complete");
  }
#endif

#ifdef P2P_CLASSIFIER
  if (LOG_IS_ENABLED(LOG_UDP_COMPLETE)) {
      reopen_logfile(&fp_udp_logc,basename,"log_udp_complete");
      write_log_header(fp_udp_logc, LOG_UDP_COMPLETE);
  }

#endif 

      /* MSN+Yahoo+Jabber log */
#if defined(MSN_CLASSIFIER) || defined(YMSG_CLASSIFIER) || defined(XMPP_CLASSIFIER)
  if (LOG_IS_ENABLED(LOG_CHAT_COMPLETE)) {
      reopen_logfile(&fp_chat_logc,basename,"log_chat_complete");
      write_log_header(fp_chat_logc, LOG_CHAT_COMPLETE);
  }

  if (LOG_IS_ENABLED(LOG_CHAT_MESSAGES)) {
      reopen_logfile(&fp_chat_log_msg,basename,"log_chat_messages");
      write_log_header(fp_chat_log_msg, LOG_CHAT_MESSAGES);
  }
#ifdef MSN_OTHER_COMMANDS
  if (LOG_IS_ENABLED(LOG_CHAT_MSNOTHER)) {
          //TOFIX: add the header
      reopen_logfile(&fp_msn_log_othercomm,basename,"log_msn_OtherCommands");
  }
#endif
#endif

#ifdef L3_BITRATE
  if (LOG_IS_ENABLED(LOG_L3_BITRATE)) {
      //TOFIX: add the header
      reopen_logfile(&fp_l3bitrate,basename,"log_l3_bitrate");
  }
#endif

#ifdef VIDEO_DETAILS
  if (LOG_IS_ENABLED(LOG_VIDEO_COMPLETE)) {
      reopen_logfile(&fp_video_logc,basename,"log_video_complete");
      write_log_header(fp_video_logc, LOG_VIDEO_COMPLETE);
  }
#endif

#ifdef STREAMING_CLASSIFIER
  if (LOG_IS_ENABLED(LOG_STREAMING_COMPLETE)) {
      reopen_logfile(&fp_streaming_logc,basename,"log_streaming_complete");
      write_log_header(fp_streaming_logc,LOG_STREAMING_COMPLETE);
  }
#endif

//AF: this is legacy code
#ifdef LOG_OOO
  if (LOG_IS_ENABLED(LOG_DUP_OOO)) {
      /* MGM start */
      /* Open the files for dup and ooo logging */
      reopen_logfile(&fp_dup_ooo,basename,"dup_ooo");
  }
#endif

    if (runtime_engine)
        dump_create_outdir(basename);
}

void close_all_logfiles()
{
#ifdef HAVE_ZLIB
  if (zlib_logs)
    {
      if (fp_logc != NULL) { gzclose(fp_logc); fp_logc=NULL; }
      if (fp_lognc != NULL) { gzclose(fp_lognc); fp_lognc=NULL; }

#ifdef RTP_CLASSIFIER
      if (fp_rtp_logc != NULL) { gzclose(fp_rtp_logc); fp_rtp_logc=NULL; }
#endif

#ifdef SKYPE_CLASSIFIER
      if (fp_skype_logc != NULL) { gzclose(fp_skype_logc); fp_skype_logc=NULL; }
#endif

#ifdef P2P_CLASSIFIER
      if (fp_udp_logc != NULL) { gzclose(fp_udp_logc); fp_udp_logc=NULL; }
#endif 

#if defined(MSN_CLASSIFIER) || defined(YMSG_CLASSIFIER) || defined(XMPP_CLASSIFIER)
      if (fp_chat_logc != NULL) { gzclose(fp_chat_logc); fp_chat_logc=NULL; }
      if (fp_chat_log_msg != NULL) { gzclose(fp_chat_log_msg); fp_chat_log_msg=NULL; }
#ifdef MSN_OTHER_COMMANDS
      if (fp_msn_log_othercomm != NULL) { gzclose(fp_msn_log_othercomm); fp_msn_log_othercomm=NULL; }
#endif
#endif

#ifdef L3_BITRATE
      if (fp_l3bitrate != NULL) { gzclose(fp_l3bitrate); fp_l3bitrate=NULL; }
#endif

#ifdef VIDEO_DETAILS
      if (fp_video_logc != NULL) { gzclose(fp_video_logc); fp_video_logc=NULL; }
#endif

#ifdef STREAMING_CLASSIFIER
      if (fp_streaming_logc != NULL) { gzclose(fp_streaming_logc); fp_streaming_logc=NULL; }
#endif

#ifdef LOG_OOO
      if (fp_dup_ooo != NULL) { gzclose(fp_dup_ooo); fp_dup_ooo=NULL; }
#endif
    }
  else
#endif   /* HAVE_ZLIB */
    {
      if (fp_logc != NULL) { fclose(fp_logc); fp_logc=NULL; }
      if (fp_lognc != NULL) { fclose(fp_lognc); fp_lognc=NULL; }

#ifdef RTP_CLASSIFIER
      if (fp_rtp_logc != NULL) { fclose(fp_rtp_logc); fp_rtp_logc=NULL; }
#endif

#ifdef SKYPE_CLASSIFIER
      if (fp_skype_logc != NULL) { fclose(fp_skype_logc); fp_skype_logc=NULL; }
#endif

#ifdef P2P_CLASSIFIER
      if (fp_udp_logc != NULL) { fclose(fp_udp_logc); fp_udp_logc=NULL; }
#endif 

#if defined(MSN_CLASSIFIER) || defined(YMSG_CLASSIFIER) || defined(XMPP_CLASSIFIER)
      if (fp_chat_logc != NULL) { fclose(fp_chat_logc); fp_chat_logc=NULL; }
      if (fp_chat_log_msg != NULL) { fclose(fp_chat_log_msg); fp_chat_log_msg=NULL; }
#ifdef MSN_OTHER_COMMANDS
      if (fp_msn_log_othercomm != NULL) { fclose(fp_msn_log_othercomm); fp_msn_log_othercomm=NULL; }
#endif
#endif

#ifdef L3_BITRATE
      if (fp_l3bitrate != NULL) { fclose(fp_l3bitrate); fp_l3bitrate=NULL; }
#endif

#ifdef VIDEO_DETAILS
      if (fp_video_logc != NULL) { fclose(fp_video_logc); fp_video_logc=NULL; }
#endif

#ifdef STREAMING_CLASSIFIER
      if (fp_streaming_logc != NULL) { fclose(fp_streaming_logc); fp_streaming_logc=NULL; }
#endif

#ifdef LOG_OOO
      if (fp_dup_ooo != NULL) { fclose(fp_dup_ooo); fp_dup_ooo=NULL; }
#endif
    }
}

void ip_histo_stat(struct ip *pip)
{
  /* Code for the update of IP histograms */
  
  if (internal_src && !internal_dst)
    {
      L4_bitrate.out[IP_TYPE] += ntohs (pip->ip_len);
      if (pip->ip_p == IPPROTO_ICMP)
    	L4_bitrate.out[ICMP_TYPE] += ntohs (pip->ip_len);
      add_histo (ip_protocol_out, pip->ip_p);
      add_histo (ip_len_out, (float) ntohs (pip->ip_len));
      add_histo (ip_ttl_out, (float) pip->ip_ttl);
      add_histo (ip_tos_out, (float) pip->ip_tos);

      if (cloud_dst)
       {
         L4_bitrate.c_out[IP_TYPE] += ntohs (pip->ip_len);
         if (pip->ip_p == IPPROTO_ICMP)
    	   L4_bitrate.c_out[ICMP_TYPE] += ntohs (pip->ip_len);
       }
      else
       {
         L4_bitrate.nc_out[IP_TYPE] += ntohs (pip->ip_len);
         if (pip->ip_p == IPPROTO_ICMP)
    	   L4_bitrate.nc_out[ICMP_TYPE] += ntohs (pip->ip_len);
       }
#ifdef L3_BITRATE
      L3_bitrate_out += ntohs (pip->ip_len);
      L3_bitrate_ip46_out += max(ntohs(pip->ip_len),46);
#endif
    }
  else if (!internal_src && internal_dst)
    {
      L4_bitrate.in[IP_TYPE] += ntohs (pip->ip_len);
      if (pip->ip_p == IPPROTO_ICMP)
    	L4_bitrate.in[ICMP_TYPE] += ntohs (pip->ip_len);
      add_histo (ip_protocol_in, pip->ip_p);
      add_histo (ip_len_in, (float) ntohs (pip->ip_len));
      add_histo (ip_ttl_in, (float) pip->ip_ttl);
      add_histo (ip_tos_in, (float) pip->ip_tos);
      if (cloud_src)
       {
         L4_bitrate.c_in[IP_TYPE] += ntohs (pip->ip_len);
         if (pip->ip_p == IPPROTO_ICMP)
    	   L4_bitrate.c_in[ICMP_TYPE] += ntohs (pip->ip_len);
       }
      else
       {
         L4_bitrate.nc_in[IP_TYPE] += ntohs (pip->ip_len);
         if (pip->ip_p == IPPROTO_ICMP)
    	   L4_bitrate.nc_in[ICMP_TYPE] += ntohs (pip->ip_len);
       }
#ifdef L3_BITRATE
      L3_bitrate_in += ntohs (pip->ip_len);
      L3_bitrate_ip46_in += max(ntohs(pip->ip_len),46);
#endif
    }
#ifndef LOG_UNKNOWN
  else if (internal_src && internal_dst)
#else
  else
#endif
    {
      L4_bitrate.loc[IP_TYPE] += ntohs (pip->ip_len);
      if (pip->ip_p == IPPROTO_ICMP)
    	L4_bitrate.loc[ICMP_TYPE] += ntohs (pip->ip_len);
      add_histo (ip_protocol_loc, pip->ip_p);
      add_histo (ip_len_loc, (float) ntohs (pip->ip_len));
      add_histo (ip_ttl_loc, (float) pip->ip_ttl);
      add_histo (ip_tos_loc, (float) pip->ip_tos);
#ifdef L3_BITRATE
      L3_bitrate_loc += ntohs (pip->ip_len);
      L3_bitrate_ip46_loc += max(ntohs(pip->ip_len),46);
#endif
    }


   if (adx_engine)
    {
      /* If neither -N or -M are used, all addresses are internal, 
        and the ADX histo would be empty */
      if (!internal_src || !(net_conf || eth_conf) )
        add_adx (EXTERNAL_ADX_HISTO, &(pip->ip_src), SRC_ADX, ntohs(pip->ip_len));
      if (!internal_dst || !(net_conf || eth_conf) )
        add_adx (EXTERNAL_ADX_HISTO, &(pip->ip_dst), DST_ADX, ntohs(pip->ip_len));

      if (adx2_engine)
        {
      	  if (internal_src)
           {
      	    add_adx (INTERNAL_ADX_HISTO, &(pip->ip_src), SRC_ADX, ntohs(pip->ip_len));
      	    add_adx (INTERNAL_ADX_MAX, &(pip->ip_src), SRC_ADX, ntohs(pip->ip_len));
           }
      	  if (internal_dst)
           {
      	    add_adx (INTERNAL_ADX_HISTO, &(pip->ip_dst), DST_ADX, ntohs(pip->ip_len));
      	    add_adx (INTERNAL_ADX_MAX, &(pip->ip_dst), DST_ADX, ntohs(pip->ip_len));
           }
        }
    }
    
} 

inline static int
ip_header_stat (int phystype, 
                struct ip *pip, 
                u_long *fpnum, 
                u_long *pcount,
		        int file_count, 
                char *filename, 
                long int location, 
                int tlen,
		void *plast,
		int ip_direction)
{
  /* another sanity check, only understand ETHERNET right now */

  if (phystype != PHYS_ETHER)
    {
      static int not_ether = 0;

      ++not_ether;
      if (not_ether < 5)
	{
	  fprintf(fp_stderr,
		   "Skipping packet %lu, not an ethernet packet\n", pnum);
	}			/* else, just shut up */
      return 0;
    }

#ifdef SUPPORT_IPV6
  if (PIP_ISV6 (pip))
    {

      //fprintf(fp_stderr,"IPv6 packet \n");
      //It does all the statistics about IPv6 packets

      /*IPv6 SUPPORT */
      IPv6_support (pip, internal_net_listv6, plast);



    }				//if it isnt an IPv6 packet I do statistics thinking that it's an IPv4
  else
    {
#endif
      /* decide wheater this is internal or external */
      if (internal_wired)
	{
          /* use thedirections as hardwired by the files of nics */
	  internal_src = coming_in;
	  internal_dst = !coming_in;
	}
      else
      {
        if(mac_filter.tot_internal_eth >0 )
        {
        /* going to use the Ethernet MAC here */
	  internal_src = internal_shost;
	  internal_dst = internal_dhost;
        }
        else
	{
         /* stick with ip networks - or trust what you have been told */
	 switch(ip_direction)
	  {
           case SRC_IN_DST_IN:
   	    internal_src = 1;
	    internal_dst = 1;
	    break;
           case SRC_IN_DST_OUT:
   	    internal_src = 1;
	    internal_dst = 0;
	    break;
           case SRC_OUT_DST_IN:
   	    internal_src = 0;
	    internal_dst = 1;
	    break;
           case SRC_OUT_DST_OUT:
   	    internal_src = 0;
	    internal_dst = 0;
	    break;
           case DEFAULT_NET:
           default:
   	    internal_src = internal_ip (pip->ip_src);
	    internal_dst = internal_ip (pip->ip_dst);
	    break;
	  }
	}
      }

      cloud_src = cloud_ip (pip->ip_src);
      cloud_dst = cloud_ip (pip->ip_dst);
      /* .a.c. */
      
      /* 
         Histograms done only if packet is not duplicated, 
         so code is executed in ProcessPacket after the TCP/UDP processing
      */
      
      /* ip_histo_stat(pip); */

      /* Now it is safe to apply internal IP addresses obfuscation */
      if (internal_src)
          pip->ip_src.s_addr ^= ip_obfuscate_mask;
      if (internal_dst)
          pip->ip_dst.s_addr ^= ip_obfuscate_mask;          

#ifdef SUPPORT_IPV6
    }
#endif
  /* update global and per-file packet counters */
  ++pnum;			/* global */
  ++(*fpnum);			/* local to this file */
  ++(*pcount);			/* counter per chiudere i pendenti */

  /* the last_time_step is assigned only at the first packet */
  if (first_ip_packet == TRUE)
   {
    first_ip_packet = FALSE;
    last_time_step = last_cleaned = current_time;
   }

  /* check for re-ordered packets */
  if (!ZERO_TIME (&last_packet))
    {
      if (elapsed (last_packet, current_time) < 0)
	{
	  /* out of order */
	  if ((file_count > 1) && ((*fpnum) == 1))
	    {
	      fprintf (fp_stderr, 
            "Warning, first packet in file %s comes BEFORE the last packet\n"
            "in the previous file.  That will likely confuse the program, please\n"
            "order the files in time if you have trouble\n", filename);
	    }
	  else
	    {
	      static int warned = 0;

	      if (warn_ooo)
		{
		  fprintf (fp_stderr, 
            "Warning, packet %ld in file %s comes BEFORE the previous packet\n"
            "That will likely confuse the program, so be careful!\n", 
            (*fpnum), filename);
		}
	      else if (!warned)
		{
		  fprintf (fp_stderr, 
            "Packets in file %s are out of order.\n"
            "That will likely confuse the program, so be careful!\n", 
            filename);
		}
	      warned = 1;
	    }

	}
    }


#ifndef TSTAT_RUNASLIB
  /* install signal handler */
  if ((*fpnum) == 1)
    {
      signal (SIGINT, QuitSig);
      signal (SIGUSR1, Usr1Sig);
    }
#endif

#ifndef TSTAT_RUNASLIB
  /* progress counters */
  if (printticks)
    {
      if (CompIsCompressed ())
	location += tlen;	/* just guess... */
      if ((((*fpnum) < 100) && ((*fpnum) % 10 == 0)) ||
	  (((*fpnum) < 1000) && ((*fpnum) % 100 == 0)) ||
	  (((*fpnum) < 10000) && ((*fpnum) % 1000 == 0)) ||
	  (((*fpnum) < 100000) && ((*fpnum) % 10000 == 0)) ||
	  (((*fpnum) >= 100000) && ((*fpnum) % 100000 == 0)))
	{

	  unsigned frac;

	  if (debug)
	    fprintf(fp_stdout, "%s: ", cur_filename);
	  fprintf(fp_stdout, "Tp= %lu Tf=%lu ", (*fpnum), fcount);
	  if (CompIsCompressed ())
	    {
	      frac = location / filesize * 100;
	      if (frac <= 100)
		fprintf(fp_stdout, "~%u%% (compressed)", frac);
	      else
		fprintf(fp_stdout, "~100%% + %u%% (compressed)", frac - 100);
	    }
	  else if (!is_stdin)
	    {
	      location = ftell (stdin);
	      frac = location / filesize * 100;
	      fprintf(fp_stdout, "%u%%", frac);
	    }
	  /* print elapsed time */
	  {
	    double etime = elapsed (first_packet, last_packet);
	    fprintf(fp_stdout, " (%s)", elapsed2str (etime));
	  }
	  /* print number of opened flow */
	  {
	    fprintf(fp_stdout, " Nf(TCP)=%lu Nf(UDP)=%lu", tot_conn_TCP,
		     tot_conn_UDP);
	    fprintf(fp_stdout, " Ntrash=%lu", not_id_p);
	  }

	  /* carriage return (but not newline) */
	  fprintf(fp_stdout, "\r");
	}
      fflush(fp_stdout);
    }
#endif //TSTAT_RUNASLIB

  /* keep track of global times */
  if (ZERO_TIME (&first_packet))
   {
     first_packet = current_time;
#ifdef L3_BITRATE
     L3_last_time = current_time;
     L3_bitrate_in=0;
     L3_bitrate_out=0;
     L3_bitrate_loc=0;
     L3_bitrate_ip46_in=0;
     L3_bitrate_ip46_out=0;
     L3_bitrate_ip46_loc=0;
#endif
     adx2_last_time = current_time;
     adx3_last_time = current_time;
   }
  last_packet = current_time;

#ifdef L3_BITRATE
  if (elapsed (L3_last_time, current_time) > L3_BITRATE_DELTA)
   {
     double L3_delta = elapsed (L3_last_time, current_time);
     if (LOG_IS_ENABLED(LOG_L3_BITRATE) && fp_l3bitrate!=NULL)
        wfprintf(fp_l3bitrate,"%.6f %.2f %.2f %.2f %.2f %.2f %.2f\n",
            (double)current_time.tv_sec + (double) current_time.tv_usec / 1000000.0,
             L3_bitrate_in*8.0/L3_delta*1000.,
             L3_bitrate_out*8.0/L3_delta*1000.,
             L3_bitrate_loc*8.0/L3_delta*1000.,
             L3_bitrate_ip46_in*8.0/L3_delta*1000.,
             L3_bitrate_ip46_out*8.0/L3_delta*1000.,
             L3_bitrate_ip46_loc*8.0/L3_delta*1000.
	     );
     L3_bitrate_in=0;
     L3_bitrate_out=0;
     L3_bitrate_loc=0;
     L3_bitrate_ip46_in=0;
     L3_bitrate_ip46_out=0;
     L3_bitrate_ip46_loc=0;
     L3_last_time = current_time;     
   }
#endif

 if (adx_engine && adx2_engine)
  { 
   double adx2_delta = elapsed (adx2_last_time, current_time);
   double adx3_delta = elapsed (adx3_last_time, current_time);

   if (adx2_delta > adx2_bitrate_delta)
    {
      sprintf (curr_data_dir, "%s/%03d", basename, step);
      swap_adx(INTERNAL_ADX_MAX);
      max_adx(INTERNAL_ADX_HISTO,INTERNAL_ADX_MAX,adx3_delta);
      swap_adx (INTERNAL_ADX_HISTO);
      print_adx (INTERNAL_ADX_HISTO,adx2_delta);
      adx2_last_time = current_time;     
      adx3_last_time = current_time;
    }
   else if (adx3_delta > adx3_bitrate_delta)
    {
      swap_adx(INTERNAL_ADX_MAX);
      max_adx(INTERNAL_ADX_HISTO,INTERNAL_ADX_MAX,adx3_delta);
      adx3_last_time = current_time;
    }
  }
  return 1;			/*finished ok */
}

void InitAfterFirstPacketReaded(char *filename, int file_count) {
  if ((con_cat == FALSE) || (file_count == 1)) {
    create_new_outfiles (filename, FALSE);
  }

  if (con_cat == FALSE)
    {
      // reset bitrate stats
      memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
      memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
      memset (&L7_udp_bitrate, 0, sizeof (struct L7_bitrates));
      memset (&HTTP_bitrate, 0, sizeof (struct HTTP_bitrates));
      memset (&WEB_bitrate, 0, sizeof (struct WEB_bitrates));
      memset (&VIDEO_rate, 0, sizeof (struct VIDEO_rates));
      
      tot_conn_TCP = 0;
      tot_conn_UDP = 0;
    }

  // init struct that rely on the time of the current packets 
  if ((con_cat == FALSE) || (file_count == 1))
    {
#ifdef MSN_CLASSIFIER
      init_msn ();
#endif
#ifdef YMSG_CLASSIFIER
      init_ymsg ();
#endif
#ifdef XMPP_CLASSIFIER
      init_jabber ();
#endif
    }
}


//return 0: packet skipped
//return 1: packet analized
static int ProcessPacket(struct timeval *pckt_time, 
                         struct ip *pip,
                         void *plast,
                         int tlen, 
                         int phystype, 
                         u_long *fpnum, 
                         u_long *pcount, 
                         int file_count, 
                         char *filename, 
                         long int location,
			 int ip_direction)
{
    struct tcphdr *ptcp = NULL;
    int flow_stat_code;
    struct udphdr *pudp;
    int dir;
    struct stat finfo;
    int stat_error;
    static int stat_err_counter = 3;

    current_time = *pckt_time;
    
    //------------------ skip very close pkts 
    //  if (elapsed (last_packet, current_time) <= 0)
    //    continue;
    //  fprintf(fp_stderr,"%f \n", elapsed (last_packet, current_time));


    /* quick sanity check, better be an IPv4/v6 packet */
    if (!PIP_ISV4 (pip) && !PIP_ISV6 (pip))
    {
        static Bool warned = FALSE;

        if (!warned)
        {
            fprintf(fp_stderr, "Warning: saw at least one non-ip packet\n");
            warned = TRUE;
        }

        if (debug > 1)
#ifdef SUPPORT_IPV6
            fprintf(fp_stderr,
                    "Skipping packet %lu, not an IPv4/v6 packet (version:%d)\n",
                    pnum, pip->ip_v);
#else
        fprintf (fp_stderr,
                "Skipping packet %lu, not an IPv4 packet (version:%d)\n",
                pnum, pip->ip_v);
#endif
        return 0;
    }

    /* If it's IP-over-IP, skip the external IP header */
    if (PIP_ISV4(pip) && pip->ip_p == IPPROTO_IPIP)
     {
       pip = (struct ip *)((char *)pip+4*pip->ip_hl);
       if (!PIP_ISV4 (pip) && !PIP_ISV6 (pip))
        {
	  /* The same sanity check than above, but without warnings*/
          return 0;
        }
     }

    /* Statistics from IP HEADER */
    if (ip_header_stat
            (phystype, pip, fpnum, pcount, file_count, filename, location,
             tlen, plast, ip_direction) == 0)
        return 0;

/*
    if (elapsed (last_time_step, current_time) > MAX_TIME_STEP)
    {
        update_num++;

        if (threaded)
        {
#ifdef DEBUG_THREAD
            fprintf (fp_stdout, "Signaling thread stat dump\n");
#endif
            pthread_mutex_lock (&stat_dump_cond_mutex);
            pthread_cond_signal (&stat_dump_cond);
            pthread_mutex_unlock (&stat_dump_cond_mutex);
            pthread_mutex_lock (&stat_dump_mutex);
            pthread_mutex_unlock (&stat_dump_mutex);
        }
        else
        {
            stat_dumping_old_style ();
        }
        last_time_step = current_time;
        // reset bitrate stats 
        memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
        memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
        memset (&L7_udp_bitrate, 0, sizeof (struct L7_bitrates));
    }
*/

    /* create a dump file at ip level */
    dump_ip(pip, plast);

    /* Statistics from LAYER 4 (TCP/UDP) HEADER */


    flow_stat_code = FLOW_STAT_NONE;  /* No flow (and dup) check done yet */

    if ( (ptcp = gettcp (pip, &plast)) != NULL)
     {
        ++tcp_packet_count;
        flow_stat_code = tcp_flow_stat (pip, ptcp, plast, &dir);
	if ( flow_stat_code!=FLOW_STAT_DUP && 
	     flow_stat_code!=FLOW_STAT_SHORT )
	   tcp_header_stat (ptcp, pip);
     }	   
    else if (do_udp)
     {
        /* look for a UDP header */
        if ((pudp = getudp (pip, &plast)) != NULL)
	 { 
           flow_stat_code = udp_flow_stat (pip, pudp, plast);
	   if ( flow_stat_code!=FLOW_STAT_DUP && 
	        flow_stat_code!=FLOW_STAT_SHORT )
	      udp_header_stat (pudp, pip);
	 }
     }

    if (flow_stat_code != FLOW_STAT_DUP)
     {
       if (!(PIP_ISV6 (pip)))
        {
          /* Collect IPv4 histograms only on not duplicated flows */
          ip_histo_stat(pip);
	} 
     }

    if (flow_stat_code != FLOW_STAT_OK)
      return 0;

    //********************************************/
    //* check if the runtime config file is changed */
    //********************************************/
    if (runtime_engine && 
        difftime(time(NULL), last_mtime_check) >= RUNTIME_CONFIG_IDLE) 
    {
        last_mtime_check = time(NULL);

        // for sanity check we use a counter to check the max number
        // of stat fails. A fail may be related to the editor in case
        // of direct editing of the runtime config file
            // (Vim for example use a temporary file and replace this
            // with the original file when a change is made)
        stat_error = stat(runtime_conf_fname, &finfo);
        if (!stat_error) {
            stat_err_counter = 5;
            if (difftime(finfo.st_mtime, last_mtime)) {
                mtime_stable_counter = RUNTIME_MTIME_COUNTER;
                last_mtime = finfo.st_mtime;
                if (debug) 
                    fprintf(fp_stdout, "Runtime configuration is changed\n");
            }
            // postpone reload runtime configuration until
            // the timestamp isn't changed for RUNTIME_MTIME_COUNTER times
            else if (mtime_stable_counter >= 0) {
                mtime_stable_counter--;
                // reload runtime configuration
                if (mtime_stable_counter == 0) {
                    if (debug)
                        fprintf(fp_stdout, "Reload runtime configuration...\n");
                    ini_read(runtime_conf_fname);
                    //dump_create_outdir(basename);
                }
            }
        }
        else if (stat_err_counter) {
            stat_err_counter--;
        }
        else {
            fprintf(fp_stderr, "err: '%s' - No such file\n", runtime_conf_fname);
            exit(1);
        }
    }

    //check if is need to flush histograms
    if ((histo_engine || rrd_engine) && elapsed (last_time_step, current_time) > MAX_TIME_STEP)
    //if (histo_engine && elapsed (last_time_step, current_time) > 1000000)
    {
        flush_histo_engine();
    }

    /*
       however, if we do not have
       many packets, we'd wait forever
    // for efficiency, only allow a signal every 1000 packets       
    // (otherwise the system call overhead will kill us)            
    if (pnum % 1000 == 0)
    {
    sigset_t mask;

    sigemptyset (&mask);
    sigaddset (&mask, SIGINT);

    sigprocmask (SIG_UNBLOCK, &mask, NULL);
    // signal can happen EXACTLY HERE, when data structures are consistant 
    sigprocmask (SIG_BLOCK, &mask, NULL);
    }
    */
    return 1;
}

void ProcessFileCompleted(Bool last) {
    tstat_report report;
#ifndef TSTAT_RUNASLIB
    /* set ^C back to the default */
    /* (so we can kill the output if needed) */
    {
        sigset_t mask;

        sigemptyset (&mask);
        sigaddset (&mask, SIGINT);

        sigprocmask (SIG_UNBLOCK, &mask, NULL);
        signal (SIGINT, SIG_DFL);
    }
#endif

    /* statistics dumping modified for -c option*/

    if (con_cat == TRUE && last == FALSE)
    {
        stat_dumping_old_style ();
        flush_histo_engine();
    }
    else
    {
        /* wait for the stat_dump thread to be idle */
        if (threaded)
            pthread_mutex_lock (&stat_dump_cond_mutex);
        else
        {
            sprintf (curr_data_dir, "%s/LAST", basename);
            if (debug > 1)
                fprintf (fp_stdout, "DEB: writing stats for uncomplete traces... ");
            trace_done ();
            if (do_udp)
                udptrace_done ();
            /*DB*/
            /*
               else 
               if (((elapsed (last_skypeprint_time, last_packet) )/1000.0/1000.0) >= 5.0 )
               {
               fprintf (fp_stdout, "\nSono dentro !");
               last_skypeprint_time = last_packet;
               udptrace_part ();
               }
               */
            if (debug > 1)
                fprintf (fp_stdout, "DEB: writing addresses... ");


            /* update average histos */
            update_fake_histos ();

            /* swap since the frozen ones are printed out */
            swap_adx (EXTERNAL_ADX_HISTO);
            swap_histo ();
            if (global_histo)
                print_all_histo (HISTO_PRINT_GLOBAL);

            print_all_histo (HISTO_PRINT_CURRENT);
            print_adx (EXTERNAL_ADX_HISTO,0.0);
	    if (adx_engine && adx2_engine)
	     {
              swap_adx(INTERNAL_ADX_MAX);
              max_adx(INTERNAL_ADX_HISTO,INTERNAL_ADX_MAX,elapsed(adx3_last_time,current_time));
              swap_adx (INTERNAL_ADX_HISTO);
	      print_adx(INTERNAL_ADX_HISTO,elapsed(adx2_last_time,current_time));
             }
	     
            clear_all_histo ();
            step = 0;


            /* dump engine */
            if (runtime_engine)
                dump_flush(TRUE);
            if (log_bitmask)
                close_all_logfiles();
        }
    }

#ifndef TSTAT_RUNASLIB
    /* close the input file */
    CompCloseFile(cur_filename);
    get_stats_report(&report);
    //dump_internal_stats(&report, stdout);
    tstat_print_report(&report, fp_stdout);
#endif
}


// !!!fake function for normal use!!!
void tstat_new_logdir(char *filename, 
                      struct timeval *pckt_time) 
{
#ifdef TSTAT_RUNASLIB
    current_time = *pckt_time;
    cur_filename = filename;
    fpnum = 0;
    if (filename == NULL)
        filename = "TSTAT_RUNASLIB";
    InitAfterFirstPacketReaded(filename, 1);
#endif
}

// !!!fake function for normal use!!!
int tstat_next_pckt(struct timeval *pckt_time, 
                    void *ip_hdr, 
                    void *last_ip_byte,
                    int tlen,
		    int ip_direction) 
{
#ifdef TSTAT_RUNASLIB
    //use some fake parameter
    return ProcessPacket(pckt_time, (struct ip*)ip_hdr, last_ip_byte, tlen, 
                         PHYS_ETHER, &fpnum, &pcount, 1, cur_filename, 0,
			 ip_direction);
#else
    return 0;
#endif
}

// !!!fake function for normal use!!!
tstat_report * tstat_close(tstat_report *report) {
#ifdef TSTAT_RUNASLIB
    double etime;
    gettimeofday(&wallclock_temp, NULL);
    etime = elapsed (wallclock_start, wallclock_temp);

    //write stats to file
    ProcessFileCompleted(TRUE);
    return get_stats_report(report);
#else
    return NULL;
#endif
}



#ifndef TSTAT_RUNASLIB
static void
ProcessFile (char *filename, Bool last)
{
  pread_f *ppread = NULL;
  int ret = 0;
  struct ip *pip;
  //struct tcphdr *ptcp = NULL;
  int phystype;
  void *phys;			/* physical transport header */
  //tcp_pair *ptp;
  int fix;
  int len;
  int tlen;
  void *plast;
  struct stat str_stat;
  long int location = 0;
//  u_long fpnum = 0;
/* used to count the opened flows...*/
  //int dir;
  //tstat_report report;

  /* share the current file name */
  cur_filename = filename;
  fpnum = 0;
  first_packet_readed = FALSE;

  if (con_cat == FALSE)
    pcount = 0;


/*--------------------------------------------------- */
#ifdef __WIN32
  /* If the file is compressed, exit (Windows version does not support compressed dump files) */
  if (CompOpenHeader (filename) == (FILE *) - 1)
    {
      exit (-1);
    }
#else
  /* open the file header */
  if (CompOpenHeader (filename) == NULL)
    {
      exit (-1);
    }
#endif /* __WIN32 */

  /* see how big the file is */
  is_stdin = FALSE;
  filesize = 1;

  struct stat f_info;
  stat(filename, &f_info);
  if (FileIsStdin (filename) || S_ISFIFO(f_info.st_mode)) 
    {
      filesize = 1;
      is_stdin = TRUE;
    }
  else
    {
      if (stat (filename, &str_stat) != 0)
	{
	  fprintf (fp_stderr, "stat: %s\n", strerror(errno));
	  exit (EXIT_FAILURE);
	}
      else
	{
	  if (str_stat.st_mode == S_IFREG)
	    filesize = str_stat.st_size;
	}

    }

  if (live_flag == TRUE)
    {				/*is a live capture */
      switch (livecap_type)
	{
#ifdef GROK_LIVE_TCPDUMP
	case ETH:
	  ppread = (*file_formats[ETH_LIVE].test_func) (filename);
	  if (debug > 0)
	    fprintf(fp_stderr, "Capturing using '%s' (%s)\n",
		     file_formats[ETH_LIVE].format_name,
		     file_formats[ETH_LIVE].format_descr);
	  break;
#endif

#ifdef GROK_ERF_LIVE
	case DAG:
	  ppread = (*file_formats[ERF_LIVE].test_func) (dag_dev_list);
	  free (dag_dev_list);
	  if (debug > 0)
	    fprintf(fp_stderr, "Capturing using '%s' (%s)\n",
		     file_formats[ERF_LIVE].format_name,
		     file_formats[ERF_LIVE].format_descr);
	  break;
#endif
	}
    }

  else
    {
      /* determine which input file format it is... */
      ppread = NULL;
      if (debug > 1)
	fprintf (fp_stdout, "NUM_FILE_FORMATS: %d\n", (int) NUM_FILE_FORMATS);
      for (fix = 0; fix < (int) NUM_FILE_FORMATS - NUM_LIVE_FORMATS; ++fix)
	{
	  if (debug > 0)
	    fprintf(fp_stderr, "Checking for file format '%s' (%s)\n",
		     file_formats[fix].format_name,
		     file_formats[fix].format_descr);
#ifndef __WIN32
	  rewind (stdin);
#endif
	  ppread = (*file_formats[fix].test_func) (filename);	/* determine the
								   input file format */
	  if (ppread)
	    {
	      if (debug > 0)
		fprintf(fp_stderr, "File format is '%s' (%s)\n",
			 file_formats[fix].format_name,
			 file_formats[fix].format_descr);
	      break;
	    }
	  else if (debug > 0)
	    {
	      fprintf(fp_stderr, "File format is NOT '%s'\n",
		       file_formats[fix].format_name);
	    }
	}

      /* if we haven't found a reader, then we can't continue */
      if (ppread == NULL)
	{
	  int count = 0;

	  fprintf(fp_stderr, "Unknown input file format\n");
	  Formats ();

	  /* check for ASCII, a common problem */
	  rewind (stdin);
	  while (TRUE)
	    {
	      int ch;
	      if ((ch = getchar ()) == EOF)
		break;
	      if (!isprint (ch))
		break;
	      if (++count >= 20)
		{
		  /* first 20 are all ASCII */
		  fprintf(fp_stderr,
			   "\nThis looks like an ASCII input file to me.\n");
		  exit (EXIT_FAILURE);
		}
	    }
	  exit (EXIT_FAILURE);
	}

#ifndef __WIN32
      /* open the file for processing */
      if (CompOpenFile (filename) == NULL)
	{
	  exit (-1);
	}
#endif /* __WIN32 */

      /* how big is it.... (possibly compressed) */
      if (debug > 0)
	{
	  /* print file size */
	  fprintf (fp_stdout, "Trace file size: %lu bytes\n", filesize);
	}
      location = 0;


      /* count the files */
      ++file_count;

    }			/************************end else di if (filename==NULL) per la cattura live *****************/
/*--------------------------------------------------------------------*/


  // MGM
  // read the first packet, to get the timestamp of the trace 
  //
  // bugfix for not-matching output -- Fri Jul 14 18:51:06 CEST 2006
  do
    {
      ret = (*ppread) (&current_time, &len, &tlen, &phys, &phystype, &pip,
		       &plast);
    }
  while ((ret > 0)
	 && (current_time.tv_sec == 0 && current_time.tv_usec == 0));

  if (ret <= 0)
    {
      fprintf(fp_stderr,
	       "Not even a single packet read (check tcpdump filter)! "
               "Skipping current file.\n");
      return;
    }

    InitAfterFirstPacketReaded(filename, file_count);
    first_packet_readed = TRUE;
/*
  if ((con_cat == FALSE) || (file_count == 1))
    create_new_outfiles (filename);

  if (con_cat == FALSE)
    {
      // reset bitrate stats
      memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
      memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
      memset (&L7_udp_bitrate, 0, sizeof (struct L7_bitrates));
      
      tot_conn_TCP = 0;
      tot_conn_UDP = 0;
    }


  // init struct that rely on the time of the current packets 
#ifdef MSN_CLASSIFIER
  init_msn ();
#endif
#ifdef YMSG_CLASSIFIER
  init_ymsg ();
#endif
#ifdef XMPP_CLASSIFIER
  init_jabber ();
#endif
*/
  /* read each packet */
  do
    {
        ProcessPacket(&current_time, pip, plast, tlen, phystype, &fpnum, &pcount, 
                      file_count, cur_filename, location, DEFAULT_NET);

    }
  while ((ret =
	  (*ppread) (&current_time, &len, &tlen, &phys, &phystype, &pip,
		     &plast)) > 0);

  ProcessFileCompleted(last);
}
#endif //TSTAT_RUNASLIB

void
QuitSig (int signum)
{
    tstat_report report;

  fprintf (fp_stdout, "%c\n\n", 7); /* BELL */
  fprintf (fp_stdout, "Terminating processing early on signal %d\n", signum);
  fprintf (fp_stdout, "Partial result after processing %lu packets:\n\n\n", pnum);

  if (threaded)
    pthread_mutex_lock (&stat_dump_cond_mutex);

  sprintf (curr_data_dir, "%s/LAST", basename);

  if (debug > 1)
    fprintf (fp_stdout, "DEB: writing addresses... ");

  if (debug > 1)
    fprintf (fp_stdout, "DEB: writing stats for uncomplete traces... ");
  trace_done ();
  if (do_udp)
    udptrace_done ();

  if (debug > 1)
    fprintf (fp_stdout, "DEB: writing stats for complete traces... ");

/* update average histos */
  update_fake_histos ();

  /* swap since the frozen ones are printed out */
  swap_histo ();
  swap_adx (EXTERNAL_ADX_HISTO);
  if (global_histo)
    print_all_histo (HISTO_PRINT_GLOBAL);
  print_all_histo (HISTO_PRINT_CURRENT);
  print_adx (EXTERNAL_ADX_HISTO,0.0);

  if (adx_engine && adx2_engine)
   {
     swap_adx(INTERNAL_ADX_MAX);
     max_adx(INTERNAL_ADX_HISTO,INTERNAL_ADX_MAX,elapsed(adx3_last_time,current_time));
     swap_adx (INTERNAL_ADX_HISTO);
     print_adx(INTERNAL_ADX_HISTO,elapsed(adx2_last_time,current_time));
   }

    get_stats_report(&report);
  //dump_internal_stats (&report, stderr);
  tstat_print_report(&report, fp_stderr);
  if (threaded)
    pthread_mutex_unlock (&stat_dump_cond_mutex);

  if (runtime_engine)
      dump_flush(TRUE);
  if (log_bitmask)
      close_all_logfiles();
  exit (EXIT_FAILURE);
}


#ifdef MEMDEBUG
void memory_debug ();
#endif
void
Usr1Sig (int signum)
{
    tstat_report report;

  fprintf (fp_stdout, "%c\n\n", 7);	/* BELL */
  fprintf (fp_stdout, "Got a signal USR1\n");
  get_stats_report(&report);
  //dump_internal_stats(&report, stderr);
  tstat_print_report(&report, fp_stderr);
#ifdef MEMDEBUG
  memory_debug ();
#endif
}


tstat_report * get_stats_report(tstat_report *report) {
    double etime;
    gettimeofday (&wallclock_temp, NULL);
    etime = elapsed (wallclock_start, wallclock_temp);

    if (report != NULL) {
        report->pnum = pnum;
        report->fcount = fcount;
        report->f_TCP_count = f_TCP_count;
        report->f_UDP_count = f_UDP_count;
        report->f_RTP_count = f_RTP_count;
        report->f_RTCP_count = f_RTCP_count;
        report->f_RTP_tunneled_TCP_count = f_RTP_tunneled_TCP_count;
        report->search_count = search_count;
        report->tcp_packet_count = tcp_packet_count;
        report->udp_trace_count = udp_trace_count;
        report->not_id_p = not_id_p;
        report->avg_search = (double)search_count / (double)tcp_packet_count;
        report->tot_conn_TCP = tot_conn_TCP;
        report->tot_conn_UDP = tot_conn_UDP;
        report->num_tcp_pairs = num_tcp_pairs;
        report->tot_adx_hash_count = tot_adx_hash_count[0];
        report->tot_adx_list_count = tot_adx_list_count[0];
        report->adx_search_hash_count = adx_search_hash_count[0];
        report->adx_search_list_count = adx_search_list_count[0];
        report->wallclock = etime;
        report->pcktspersec = (int) ((double) pnum / (etime / 1000000));
        report->flowspersec = (int) ((double) fcount / (etime / 1000000));
    }
    return report;
}

void
tstat_print_report (tstat_report *rep, FILE *wheref)
{
    fprintf(wheref, 
        "\n---\n"
        "Dumping internal status variables:\n"
        "---\n");
    fprintf(wheref, "total packet analized : %ld\n", rep->pnum);
    fprintf(wheref, "total flows analized : %lu\n", rep->fcount);
    fprintf(wheref, "total TCP flows analized : %lu\n", rep->f_TCP_count);
    fprintf(wheref, "total UDP flows analized : %lu\n", rep->f_UDP_count);
    fprintf(wheref, "total RTP flows analized : %lu\n", rep->f_RTP_count);
    fprintf(wheref, "total RTCP flows analized : %lu\n", rep->f_RTCP_count);
    fprintf(wheref, "total tunneled RTP flows analized : %lu\n", 
            rep->f_RTP_tunneled_TCP_count); /*topix */
    fprintf(wheref, "total iteration spent in the hash search routine : %d\n",
            rep->search_count);
    fprintf(wheref, "total analyzed TCP packet: %ld \n", rep->tcp_packet_count);
    fprintf(wheref, "total analyzed UDP packet: %ld \n", rep->udp_trace_count);

    fprintf(wheref, "total trash TCP packet: %ld \n", rep->not_id_p);
    if (tcp_packet_count != 0)
        fprintf(wheref, "average TCP search length: %f\n", rep->avg_search);
    fprintf(wheref, "Current opened flows: TCP = %ld UDP = %ld\n",
            rep->tot_conn_TCP, rep->tot_conn_UDP);
    fprintf(wheref, "Current flow vector index: %d (%d)\n", 
            rep->num_tcp_pairs, MAX_TCP_PAIRS);
    fprintf(wheref, "Total adx used in hash: %ld \n", rep->tot_adx_hash_count);
    fprintf(wheref, "Total adx used in list: %ld \n", rep->tot_adx_list_count);
    fprintf(wheref, "Total adx hash search: %ld\n", rep->adx_search_hash_count);
    fprintf(wheref, "Total adx list search: %ld\n", rep->adx_search_list_count);
    fprintf(wheref, "elapsed wallclock time: %s\n", elapsed2str(rep->wallclock));
    fprintf(wheref, "%d pkts/sec analyzed\n", rep->pcktspersec);
    fprintf(wheref, "%d flows/sec analyzed\n", rep->flowspersec);

#ifdef GROK_LIVE_TCPDUMP
    if (live_flag == TRUE && livecap_type == ETH)
        tcpdump_cleanup (wheref);
    /* print out libpcap live capture stats */
#endif
}

void *
MallocZ (int nbytes)
{
  char *ptr;

  ptr = malloc (nbytes);
  if (ptr == NULL)
    {
      fprintf (fp_stderr, "Malloc failed, fatal: %s\n", strerror(errno));
      fprintf(fp_stderr, 
        "when memory allocation fails, it's either because:\n"
        "1) You're out of swap space, talk to your local "
        "sysadmin about making more\n"
        "(look for system commands 'swap' or 'swapon' for quick fixes)\n"
        "2) The amount of memory that your OS gives each process "
        "is too little\n"
        "That's a system configuration issue that you'll need to discuss\n"
        "with the system administrator\n");
      exit (EXIT_FAILURE);
    }

  memset (ptr, 0, nbytes);	/* BZERO */

  return (ptr);
}

void *
ReallocZ (void *oldptr, int obytes, int nbytes)
{
  char *ptr;

  ptr = realloc (oldptr, nbytes);
  if (ptr == NULL)
    {
      fprintf (fp_stderr, "Realloc failed (%d bytes --> %d bytes), fatal\n",
	       obytes, nbytes);
      exit (EXIT_FAILURE);
    }
  if (obytes < nbytes)
    {
      memset ((char *) ptr + obytes, 0, nbytes - obytes);	/* BZERO */
    }

  return (ptr);
}


/* convert a buffer to an argc,argv[] pair 
void
StringToArgv (char *buf, int *pargc, char ***pargv)
{
  char **argv;
  int nargs = 0;

  // discard the original string, use a copy 
  buf = strdup (buf);

  // (very pessimistically) make the argv array 
  argv = malloc (sizeof (char *) * ((strlen (buf) / 2) + 1));

  // skip leading blanks 
  while ((*buf != '\00') && (isspace ((int) *buf)))
    {
      if (debug > 10)
	fprintf (fp_stdout, "skipping isspace('%c')\n", *buf);
      ++buf;
    }

  // break into args 
  for (nargs = 1; *buf != '\00'; ++nargs)
    {
      char *stringend;
      argv[nargs] = buf;

      // search for separator 
      while ((*buf != '\00') && (!isspace ((int) *buf)))
	{
	  if (debug > 10)
	    fprintf (fp_stdout, "'%c' (%d) is NOT a space\n", *buf, (int) *buf);
	  ++buf;
	}
      stringend = buf;

      // skip spaces 
      while ((*buf != '\00') && (isspace ((int) *buf)))
	{
	  if (debug > 10)
	    fprintf (fp_stdout, "'%c' (%d) IS a space\n", *buf, (int) *buf);
	  ++buf;
	}

    // terminate the previous string 
      *stringend = '\00';	

      if (debug)
	fprintf (fp_stdout, "  argv[%d] = '%s'\n", nargs, argv[nargs]);
    }

  *pargc = nargs;
  *pargv = argv;
}
*/



char **
ArgsFromFile(char *fname, int *pargc) {
    FILE *f;
    char buffer[1024];
    char *word;
    int i;
    char **argv, **tmpargv;

    f = fopen(fname, "r");    
    if (f == NULL) {
//        Help();
        fprintf(fp_stderr, "No '%s' file. Try 'tstat -h' for more information.\n", fname);
        exit(1);
    }

    //init argc/argv
    *pargc = 1;
    argv = malloc(sizeof(char *));
    argv[0] = strdup("tstat");
    
    //debug message
    //fprintf(fp_stdout, "Reading options from %s\n", fname);

    while(fgets(buffer, 1024, f)) {
        word = strtok(buffer, " \t\n");
        while(word != NULL) {
            //skip comments and void lines
            if (word[0] == '#' || word[0] == '\0')
                break;
           
            //increase cmdline buffer size
            tmpargv = malloc(sizeof(char *) * (*pargc + 1));
            for (i = 0; i < *pargc; i++) {
                tmpargv[i] = argv[i];
            }
            free(argv);
            argv = tmpargv;

            //add new parameter
            i = strlen(word);
            if (word[i] == '\n')
                word[i] = '\0';
            argv[*pargc] = strdup(word);
            *pargc = *pargc + 1;

            //debug message
            //fprintf(fp_stdout, "new option/param: %s\n", word);

            word = strtok(NULL, " \t\n");
        }
    }

    //debug message
    //fprintf(fp_stdout, "Configuration file analized\n");
    return argv;
}


int
fExists (const char *fname)
{
  FILE *f;
  f = fopen (fname, "r");
  if (f)
    {
      fclose (f);
      return 1;
    }
  return 0;
}


static void
CheckArguments (int *pargc, char *argv[])
{
    char **tmpargv, *fname;
    int i, tot_args;

    fp_stdout = stdout;
    fp_stderr = stderr;
    if (*pargc == 1)
    {
#ifdef TSTAT_RUNASLIB
        fname = argv[0];
#else
        fname = "tstat.conf";
#endif
        tmpargv = ArgsFromFile (fname, pargc);
        tot_args = *pargc;
        ParseArgs (pargc, tmpargv);
        //debug messages
        if (debug >= 2) {
            fprintf(fp_stdout, "config: reading options from %s\n", fname);
            for (i = 0; i < tot_args; i++) {
                fprintf(fp_stdout, "config: added option/param: %s\n", tmpargv[i]);
            }
            fprintf(fp_stdout, "config: reading options completed\n");
        }
    }
    else
    {
        ParseArgs (pargc, argv);
    }

    /* make sure we found the files */
    /*
    if (filenames == NULL && 
        live_flag == FALSE && 
        dump_all_histo_definition == FALSE)
    {
        BadArg (NULL, "must specify at least one file name\n");
    }
    */
    if (net_conf == FALSE && eth_conf == FALSE) {
	    internal_net_mask[0] = 0;
        inet_aton ("0.0.0.0", &(internal_net_list[0]));
	    inet_aton ("0.0.0.0", &(internal_net_mask2[0]));
        tot_internal_nets = 1;
        if (debug)
        {
            fprintf (fp_stdout, "Adding: %s as internal net ",
                    inet_ntoa (internal_net_list[0]));
            fprintf (fp_stdout, "with mask %s (%u)\n", 
                    inet_ntoa (internal_net_mask2[0]),
                    internal_net_mask[0]);
        }
        fprintf(fp_stdout, 
            "Warning: -N option not specified.\n"
            "         All subnets are assumed to be internal\n");
    }
    if (cloud_conf == FALSE) {
        tot_cloud_nets = 0;
    }
#ifdef SUPPORT_IPV6
    if (net6_conf == FALSE) {
        fprintf(fp_stdout, 
            "Warning: IPv6 support enabled and -6 option not specified.\n"
            "         All IPv6 subnets are assumed to be internal\n");
    }
#endif
#ifdef HAVE_RRDTOOL
    /*-----------------------------------------------------------*/
    /* RRDtools                                                */
    /* make sure we found the files */
    if ((rrdset_path && !rrdset_conf) || (!rrdset_path && rrdset_conf))
        BadArg (NULL,
                "You MUST specify both the configuration file (-R) AND the database path (-r))\n");
#endif


}

#ifdef GROK_DPMI
#define GROK_DPMI_OPT "D:"
#else
#define GROK_DPMI_OPT ""
#endif

#ifdef GROK_LIVE_TCPDUMP
#define GROK_LIVE_TCPDUMP_OPT "li:E:"
#else
#define GROK_LIVE_TCPDUMP_OPT ""
#endif

#ifdef GROK_TCPDUMP
#define GROK_TCPDUMP_OPT "f:"
#else
#define GROK_TCPDUMP_OPT ""
#endif

#ifdef HAVE_RRDTOOL
#define HAVE_RRDTOOL_OPT "r:R:"
#else
#define HAVE_RRDTOOL_OPT ""
#endif

#ifdef SUPPORT_IPV6
#define SUPPORT_IPV6_OPT "6:"
#else
#define SUPPORT_IPV6_OPT ""
#endif

#ifdef HAVE_ZLIB
#define HAVE_ZLIB_OPT "ZP"
#else
#define HAVE_ZLIB_OPT ""
#endif


static void
ParseArgs (int *pargc, char *argv[])
{
  char bayes_dir[128];
  sprintf (bayes_dir, "skype");
  histo_set_conf (NULL);
  struct stat finfo;
  char *tmpstring;

#ifdef GROK_ERF_LIVE
  int num_dev;
  int dim;
  char *ptr_help;
#endif
  int option_index;
  int c;
  static struct option long_options[] = {
    /* {option_name,has_arg(0=none,1=recquired,2=optional),flag,return_value} */
    /* see man getopt for details                                             */
    {"dag", 2, 0, 1},
    {0, 0, 0, 0}
  };

  option_index = 0;
  opterr = 0;
  optind = 1;
  //check '-z' option immediatelly so we can redirect all the messages
  while(1) {
    c = getopt_long (*pargc, argv,
		     GROK_TCPDUMP_OPT GROK_LIVE_TCPDUMP_OPT GROK_DPMI_OPT
		     HAVE_RRDTOOL_OPT SUPPORT_IPV6_OPT HAVE_ZLIB_OPT
		     "A:B:N:M:C:H:s:T:z:gpdhtucSLvw32", long_options, &option_index);
    if (c == -1)
        break;
    if (c == 'z') {
      fp_stdout = fopen(optarg, "w");
      if (!fp_stdout) {
          fprintf(stderr, "Error creating %s\n", optarg);
          exit(1);
      }
      fp_stderr = fp_stdout;
      break;
    } 
  }

  //Note: RESET argument so we can parse again command line arguments!!!
  option_index = 0;
  optind = 1;
  opterr = 0;
  /* parse the args */
  while (1)
    {
      c = getopt_long (*pargc, argv,
		     GROK_TCPDUMP_OPT GROK_LIVE_TCPDUMP_OPT GROK_DPMI_OPT
		     HAVE_RRDTOOL_OPT SUPPORT_IPV6_OPT HAVE_ZLIB_OPT
		     "A:B:N:M:C:H:s:T:z:gpdhtucSLvw32", long_options, &option_index);

      if (c == -1) {
	    break;
      }

      if (debug > 2)
	fprintf (fp_stdout, "ParseArgs[%d]=%s\n", optind, argv[optind]);

      switch (c)
	{
	case 'M':
	  /* -M file */
	  tmpstring = strdup (optarg);
	  if (!LoadInternalEth (tmpstring))
	    {
	      fprintf (fp_stderr, 
            "Error while loading MAC addresses configuration\n"
	        "Wrong or missing %s\n", tmpstring);
	      exit (1);
	    }
	  eth_conf = TRUE;
	  if (eth_conf && net_conf)
	   {
         fprintf(fp_stdout, 
            "Warning: Both -M and -N options specified.\n"
            "         Ethernet filter is used and -N addresses are ineffective\n");
	   }
	  break;
	case 'N':
	  /* -N file */
	  tmpstring = strdup (optarg);
	  if (!LoadInternalNets (tmpstring))
	    {
	      fprintf (fp_stderr, 
            "Error while loading NET addresses configuration\n"
	        "Wrong or missing %s\n", tmpstring);
	      exit (1);
	    }
	  net_conf = TRUE;
	  if (eth_conf && net_conf)
	   {
         fprintf(fp_stdout, 
            "Warning: Both -M and -N options specified.\n"
            "         Ethernet filter is used and -N addresses are ineffective\n");
	   }
	  break;
	case 'C':
	  /* -C file */
	  tmpstring = strdup (optarg);
	  if (!LoadCloudNets (tmpstring))
	    {
	      fprintf (fp_stderr, 
            "Error while loading configuration\n"
	        "Wrong or missing %s\n", tmpstring);
	      exit (1);
	    }
	  cloud_conf = TRUE;
	  break;
	case 'A':		/* Enable anonymization with the mask indicated */
	   {
	     char *endptr;
	     errno = 0;
	     tmpstring = strdup (optarg);
	     long long obf_mask = strtoll(tmpstring,&endptr,0);
	     if (*endptr=='\0' && errno==0)
	      {
		/* Mask must be converted to network order */
	         ip_obfuscate_mask = htonl((unsigned int)(obf_mask & 0x00000000ffffffff));
 	        // if (debug > 0)
	         fprintf (fp_stdout, "Anonymization mask set to 0x%08x\n", ntohl(ip_obfuscate_mask));
	      }
	     else
	      { 
	        fprintf (fp_stdout, "Invalid value %s(0x%08x) for the anonymization mask - Using default value 0x%08x\n",
		         tmpstring,(unsigned int)obf_mask,ntohl(ip_obfuscate_mask));
	      }
	    }
	  break;
#ifdef SUPPORT_IPV6
	case '6':
	  /* -6file */
	  tmpstring = strdup (optarg);

	  if (!LoadInternalNetsv6
	      (tmpstring, &internal_net_listv6,
	       &tot_internal_netsv6))
	    {
	      fprintf (fp_stdout,
		       "Error while loading IPv6 configuration file\n");
	      fprintf (fp_stdout, "Could not open %s\n", tmpstring);
	      exit (1);
	    }
	  net6_conf = TRUE;
	  break;
#endif
	case 'p':
	  threaded = TRUE;
	  break;
#ifdef HAVE_ZLIB
	case 'Z':
	  zlib_logs = TRUE;
	  break;
	case 'P':
	  zlib_dump = TRUE;
	  break;
#endif
	case 'd':
	  ++debug;
	  break;
	case 'g':
	  global_histo = TRUE;
	  break;
	case 'h':
	  Usage ();
	  break;
	case 'H':
	  if (!strcmp (optarg, "?"))
	    {
	      dump_all_histo_definition = TRUE;
	    }
	  else
	    {
	      histo_set_conf (optarg);
	    }
        histo_engine_log = TRUE;
	  break;
#ifdef GROK_DPMI
	case 'D':
	  {
	    tmpstring = strdup (optarg);
	    if (!dpmi_parse_config (tmpstring))
	      {
		fprintf (fp_stderr, "Error while loading DPMI configuration\n");
		exit (1);
	      }
	  }
	  break;
#endif /* GROK_DPMI */

#ifdef GROK_LIVE_TCPDUMP
	case 'l':
	  live_flag = TRUE;
	  livecap_type = ETH;
	  break;
	case 'i':		/* choose the live capture interface card */
	  /* -ieth0 */
	  dev = strdup (optarg);
	  if (debug > 1)
	    fprintf (fp_stdout, "Capturing device set to %s\n", dev);
	  break;
	case 'E':		/* choose the snaplen for the live capture */
	   {
	     int slen = strtol(optarg,NULL,10);
	     if (slen>0 && slen<65536)
	      {
	        snaplen = slen;
 	        if (debug > 1)
	          fprintf (fp_stdout, "SnapLen set to %d\n", snaplen);
	      }
	     else
	      { 
	        fprintf (fp_stdout, "Invalid value %d for SnapLen - Using default value %d\n",slen,snaplen);
	      }
	    }
	  break;
#endif /* GROK_LIVE_TCPDUMP */
	case 't':
	  printticks = TRUE;
	  break;
	case 'u':
	  do_udp = FALSE;
	  break;
	case 'c':
	  con_cat = TRUE;
	  break;
	case 's':
	  /* -sdir */
	  basenamedir = strdup (optarg);
	  basedirspecified = TRUE;
	  if (debug > 1)
	    fprintf (fp_stdout, "basenamedir set to %s\n", basenamedir);
	  break;
#ifdef GROK_TCPDUMP
	case 'f':		/* pcap filter file */
	  /* -ffilter_file */
	  filter_filename = strdup (optarg);
	  filter_specified = TRUE;
	  break;
#endif /* GROK_LIVE_TCPDUMP */
#ifdef HAVE_RRDTOOL
		/*-----------------------------------------------------------*/
	  /* RRDtools                                                  */
	case 'r':
	  {
	    /* -Rfile */
	    char *rrdpath = strdup (optarg);
	    struct stat fbuf;
	    if ((stat (rrdpath, &fbuf) == 0) && S_ISDIR (fbuf.st_mode))
	      {
		if (debug)
		  fprintf (fp_stdout,
			   "RRDTool database path <%s> exists\n", rrdpath);
	      }
	    else
	      {
		mkdir (rrdpath, 0775);
		if (debug)
		  fprintf (fp_stdout,
			   "RRDTool database path <%s> created\n", rrdpath);
	      }
	    rrdtool_set_path (rrdpath);
	    rrdset_path = 1;
	  }
	  break;

	case 'R':
	  {
	    /* -Rfile */
	    char *rrdconf = strdup (optarg);
	    struct stat fbuf;
	    if (stat (rrdconf, &fbuf) == 0)
	      {
		if (debug)
		  fprintf (fp_stdout,
			   "RRDTool configuration file <%s> found (delayed parsing)\n",
			   rrdconf);
		rrdtool_set_conf (rrdconf);
	      }
	    else
	      {
		fprintf (fp_stderr, "err: Could not open %s\n", rrdconf);
		exit (1);
	      }
	    rrdset_conf = 1;
	  }
	  break;
		/*-----------------------------------------------------------*/
#endif
	case 'B':
	  sprintf (bayes_dir, "%s", optarg);
	  bayes_engine = TRUE;
	  break;

    case 'T':
      sprintf(runtime_conf_fname, "%s", optarg);
      if (stat(runtime_conf_fname, &finfo)) {
          fprintf(fp_stderr, "err: Could not open %s\n", runtime_conf_fname);
          exit(1);
      }
      else if (S_ISDIR(finfo.st_mode)) {
          fprintf(fp_stderr, "err: %s is a directory\n", runtime_conf_fname);
          exit(1);
      }
      runtime_engine = TRUE;
      last_mtime = finfo.st_mtime;
      last_mtime_check = time(NULL);
      mtime_stable_counter = -1;
      break;


	case 'S':
	  histo_engine = FALSE;
	  break;
	case 'L':
	  log_bitmask = 0;
	  break;
//        case '1':
//          log_version = 1;
	  break;
#ifdef L3_BITRATE
        case '3':
          log_bitmask |= LOG_L3_BITRATE;
	  break;
#endif
	case 'v':
	  Version ();
	  exit (EXIT_SUCCESS);
	  break;
	case 'w':
	  warn_printtrunc = TRUE;
	  warn_printbadmbz = TRUE;
	  warn_printbadcsum = TRUE;
	  warn_printbad_syn_fin_seq = TRUE;
	  warn_ooo = TRUE;
	  break;
	case '2':
	  two_files = 2;
	  internal_wired = TRUE;
	  break;
/* process long options */
	case 1:
	  switch (option_index)
	    {
#ifdef GROK_ERF_LIVE
	    case 0:
	      dim = DAG_NAME_BUFSIZE;
	      dag_dev_list = (char *) MallocZ (dim);
	      num_dev = 0;
	      live_flag = TRUE;
	      livecap_type = DAG;
	      while (argv[optind] != NULL && *argv[optind] != '-')
		{
		  if (num_dev == 4)
		    {
		      fprintf (fp_stderr,
			       "Error: are only supported at most four DAG card\n");
		      exit (1);
		    }
		  else if (strlen (argv[optind]) + strlen (dag_dev_list) >
			   dim)
		    {
		      dim += DAG_NAME_BUFSIZE;
		      ptr_help = (char *) MallocZ (dim);
		      strncpy (ptr_help, dag_dev_list, dim);
		      free (dag_dev_list);
		      dag_dev_list = ptr_help;
		    }
		  strcat (dag_dev_list, argv[optind]);
		  strcat (dag_dev_list, " ");
		  num_dev++;
		  optind++;
		}
	      if (num_dev == 0)
		{
		  strncpy (dag_dev_list, "/dev/dag0 ", dim);	/* default DAG card */
		  num_dev++;
		}
	      else if (num_dev == 2)
		{
		  internal_wired = TRUE;
		}
	      break;
#endif /* GROK_ERF_LIVE */

	    default:
	      fprintf (fp_stderr, "\n Error in parsing long opt %d\n", option_index);
	      break;
	    }
	  break;

    case 'z': //skip because we already readed it
        break;
	default:
      Help();
      fprintf (fp_stderr, "option -%c not valid or missing option argument\n", c);
      if (c == '3') {
          fprintf (fp_stderr, "check if L3_BITMASK is enabled in Makefile.conf\n");
      }
	  exit (EXIT_FAILURE);
	}
    }

  *pargc -= optind;
  if (*pargc)
    filenames = &argv[optind];


  if (bayes_engine)
    {
      char bayes_conf[256];
      sprintf (bayes_conf, "%s/pktsize.conf", bayes_dir);
      bayes_settings_pktsize =
	bayes_init (bayes_conf, NULL, (void *) skype_feat2code);

      sprintf (bayes_conf, "%s/avgipg.conf", bayes_dir);
      bayes_settings_avgipg =
	bayes_init (bayes_conf, NULL, (void *) skype_feat2code);
    }

  return;
}


int
LoadInternalNets (char *file) {
    FILE *fp;
    char *line, *ip_string, *mask_string, *err;
    int i, len;
    long int mask_bits;
    unsigned int full_local_mask;
    char s[16];
//    char *slash_p, *tmp;

    fp = fopen(file, "r");
    if (!fp) {
        fprintf(fp_stderr, "Unable to open file '%s'\n", file);
        return 0;
    }

    tot_internal_nets = 0;
    i = 0;
    while (1) {
        line = readline(fp, 1, 1);
        if (!line)
            break;

        len = strlen(line);
        if (line[len - 1] == '\n')
            line[len - 1] = '\0';
        ip_string = line;

        if (i == MAX_INTERNAL_HOSTS) {
            fprintf (fp_stderr, "Maximum number of internal hosts/networks (%d) exceeded\n", MAX_INTERNAL_HOSTS);
            return 0;
        }

        //single line format
        if (strchr(ip_string,'/'))
        {
            ip_string = strtok(ip_string,"/");
            mask_string = strtok(NULL,"/");

            if (!mask_string) {
                fprintf(fp_stderr, "Missing ip or network mask in net config n.%d\n", (i+1));
                return 0;
            }
            if (!inet_aton (ip_string, &(internal_net_list[i]))) {
                fprintf(fp_stderr, "Invalid ip address in net config n.%d\n", (i+1));
                return 0;
            }

            //network mask as a single number
            if (!strchr(mask_string,'.'))
            { 
                err = NULL;
                mask_bits = strtol(mask_string, &err, 10);
                if (*err || mask_bits < 1 || mask_bits > 32) {
                    fprintf(fp_stderr, "Invalid network mask in net config n.%d\n", (i+1));
                    return 0;
                }

                if (internal_net_list[i].s_addr == 0)
                   full_local_mask = 0;
                else
                   full_local_mask = 0xffffffff << (32 - mask_bits);

                sprintf(s,"%d.%d.%d.%d",
                    full_local_mask >> 24,
                    (full_local_mask >> 16)  & 0x00ff,
                    (full_local_mask >> 8 ) & 0x0000ff,
                    full_local_mask & 0xff);
                inet_aton (s, &(internal_net_mask2[i]));
                internal_net_mask[i] = inet_addr(s);
	        internal_net_list[i].s_addr &= internal_net_mask[i];
            }
            //mask in dotted format
            else
            {
                if (!inet_aton (mask_string, &(internal_net_mask2[i]))) {
                    fprintf(fp_stderr, "Invalid network mask in net config n.%d\n", (i+1));
                    return 0;
                }
                internal_net_mask[i] = inet_addr (mask_string);
	        internal_net_list[i].s_addr &= internal_net_mask[i];
            }
        }
        //old format
        else
        {
            if (!inet_aton (ip_string, &(internal_net_list[i]))) {
                fprintf(fp_stderr, "Invalid ip address in net config n.%d\n", (i+1));
                return 0;
            }

            mask_string = readline(fp, 1, 1);
            if (!mask_string){
                fprintf(fp_stderr, "Missing network mask in net config n.%d\n", (i+1));
                return 0;
            }

            len = strlen(mask_string);
            if (mask_string[len - 1] == '\n')
                mask_string[len - 1] = '\0';
            if (!inet_aton (mask_string, &(internal_net_mask2[i]))) {
                fprintf(fp_stderr, "Invalid network mask in net config n.%d\n", (i+1));
                return 0;
            }
            internal_net_mask[i] = inet_addr (mask_string);
	    internal_net_list[i].s_addr &= internal_net_mask[i];
        }
       if (debug)
        {
            fprintf (fp_stdout, "Adding: %s as internal net ",
                    inet_ntoa (internal_net_list[i]));
            fprintf (fp_stdout, "with mask %s (%u)\n", 
                    inet_ntoa (internal_net_mask2[i]),
                    internal_net_mask[i]);
        }

        tot_internal_nets++;
        i++;
    }
    return 1;
}

int
LoadCloudNets (char *file) {
    FILE *fp;
    char *line, *ip_string, *mask_string, *err;
    int i, len;
    long int mask_bits;
    unsigned int full_local_mask;
    char s[16];
//    char *slash_p, *tmp;

    fp = fopen(file, "r");
    if (!fp) {
        fprintf(fp_stderr, "Unable to open file '%s'\n", file);
        return 0;
    }

    tot_cloud_nets = 0;
    i = 0;
    while (1) {
        line = readline(fp, 1, 1);
        if (!line)
            break;

        len = strlen(line);
        if (line[len - 1] == '\n')
            line[len - 1] = '\0';
        ip_string = line;

        if (i == MAX_CLOUD_HOSTS) {
            fprintf (fp_stderr, "Maximum number of cloud hosts/networks (%d) exceeded\n", MAX_CLOUD_HOSTS);
            return 0;
        }

        //single line format
        if (strchr(ip_string,'/'))
        {
            ip_string = strtok(ip_string,"/");
            mask_string = strtok(NULL,"/");

            if (!mask_string) {
                fprintf(fp_stderr, "Missing ip or network mask in cloud config n.%d\n", (i+1));
                return 0;
            }
            if (!inet_aton (ip_string, &(cloud_net_list[i]))) {
                fprintf(fp_stderr, "Invalid ip address in cloud config n.%d\n", (i+1));
                return 0;
            }

            //network mask as a single number
            if (!strchr(mask_string,'.'))
            { 
                err = NULL;
                mask_bits = strtol(mask_string, &err, 10);
                if (*err || mask_bits < 1 || mask_bits > 32) {
                    fprintf(fp_stderr, "Invalid network mask in cloud config n.%d\n", (i+1));
                    return 0;
                }

                if (cloud_net_list[i].s_addr == 0)
                   full_local_mask = 0;
                else
                   full_local_mask = 0xffffffff << (32 - mask_bits);

                sprintf(s,"%d.%d.%d.%d",
                    full_local_mask >> 24,
                    (full_local_mask >> 16)  & 0x00ff,
                    (full_local_mask >> 8 ) & 0x0000ff,
                    full_local_mask & 0xff);
                inet_aton (s, &(cloud_net_mask2[i]));
                cloud_net_mask[i] = inet_addr(s);
		cloud_net_list[i].s_addr &= cloud_net_mask[i];
            }
            //mask in dotted format
            else
            {
                if (!inet_aton (mask_string, &(cloud_net_mask2[i]))) {
                    fprintf(fp_stderr, "Invalid network mask in cloud config n.%d\n", (i+1));
                    return 0;
                }
                cloud_net_mask[i] = inet_addr (mask_string);
		cloud_net_list[i].s_addr &= cloud_net_mask[i];
            }
        }
        //old format
        else
        {
            if (!inet_aton (ip_string, &(cloud_net_list[i]))) {
                fprintf(fp_stderr, "Invalid ip address in cloud config n.%d\n", (i+1));
                return 0;
            }

            mask_string = readline(fp, 1, 1);
            if (!mask_string){
                fprintf(fp_stderr, "Missing network mask in cloud config n.%d\n", (i+1));
                return 0;
            }

            len = strlen(mask_string);
            if (mask_string[len - 1] == '\n')
                mask_string[len - 1] = '\0';
            if (!inet_aton (mask_string, &(cloud_net_mask2[i]))) {
                fprintf(fp_stderr, "Invalid network mask in cloud config n.%d\n", (i+1));
                return 0;
            }
            cloud_net_mask[i] = inet_addr (mask_string);
            cloud_net_list[i].s_addr &= cloud_net_mask[i];
        }
       if (debug)
        {
            fprintf (fp_stdout, "Adding: %s as cloud net ",
                    inet_ntoa (cloud_net_list[i]));
            fprintf (fp_stdout, "with mask %s (%u)\n", 
                    inet_ntoa (cloud_net_mask2[i]),
                    cloud_net_mask[i]);
        }

        tot_cloud_nets++;
        i++;
    }
    return 1;
}

int 
LoadInternalEth (char *file) {
    FILE *fp;
    char *line;
    struct ether_addr *mac_addr;
    int i, len;

    fp = fopen(file, "r");
    if (!fp) {
        fprintf(fp_stderr, "Unable to open file '%s' when parsing the Ethernet filters\n", file);
        return 0;
    }

    i = 0;
    while (1) {
        line = readline(fp, 1, 1);
        if (!line)
            break;

        len = strlen(line);
        if ( line[len - 1] == '\n' )
            line[len - 1] = '\0';

		if ( i == MAX_INTERNAL_ETHERS )	{
            fprintf (fp_stderr, "Maximum number of internal Ethernet (%d) exceeded\n", MAX_INTERNAL_ETHERS);
            return 0;
        }

        mac_addr = ether_aton(line);
        if (mac_addr!=NULL)
         {
	        memcpy(mac_filter.addr[i], mac_addr, 6);
	     }
	    else
	     {
            fprintf(fp_stderr, "Wrong address format in Ethernet filter n.%d\n", (i+1));
            return 0;
	     }
        
        if (debug>1)
        {
            fprintf (fp_stdout, "Adding: %s as internal net ",
                    ether_ntoa ((const struct ether_addr *)mac_filter.addr[i]));
        }
        i++;
    }
    mac_filter.tot_internal_eth = i;    
    return 1;
}

/* the memcpy() function that gcc likes to stuff into the program has alignment
   problems, so here's MY version.  It's only used for small stuff, so the
   copy should be "cheap", but we can't be too fancy due to alignment boo boos */

void *
MemCpy_TCPTRACE (void *vp1, void *vp2, size_t n)
{
  char *p1 = vp1;
  char *p2 = vp2;

  while (n-- > 0)
    *p1++ = *p2++;

  return (vp1);
}

/*

.:nonsns:.  proposes long-wise optimization of the memcpy 
function, alternative to the one used by the original version
of MemCpy_TCPTRACE. A benchmarking study conducted following
the guidelines described in  (and using the code provided by
authors) yield the following results.

	Brian W. Kernighan and Christopher J. Van Wyk,
	``Timing trials, or the trials of timing: experiments with scripting and 
	user-interface languages'', Software Practice & Experience archive
	Volume 28 ,  Issue 8, July 1998, pp.819 - 843  


len=1
Null_Loop          170000    170000    190000    210000    170000   0.00
memcpy_system     4940000   4930000   4930000   4940000   4920000   0.05
MemCpy_OPTIMIZED  2030000   2010000   2010000   2000000   2010000   0.02
MemCpy_TCPTRACE   1850000   1850000   1840000   1850000   1860000   0.02

len=64
Null_Loop          170000    160000    170000	 170000    170000   0.00 
memcpy_system     8470000   8440000   8440000	8460000   8490000   0.08 
MemCpy_OPTIMIZED  8210000   7990000   8130000	8040000   8080000   0.08 
MemCpy_TCPTRACE  29360000  29250000  29150000  29220000  29390000   0.29 

*/

void *
MemCpy_OPTIMIZED (void *vp1, void *vp2, size_t n)
{
  static unsigned long *_lp1, *_lp2;
  static unsigned char *_cp1, *_cp2;
  static size_t _n, _last;

  _last = n & (SIZEOF_UNSIGNED_LONG_INT - 1);
  if ((_n = (n / SIZEOF_UNSIGNED_LONG_INT)))
    {
      _lp1 = vp1;
      _lp2 = vp2;
      while (_n-- > 0)
	*_lp1++ = *_lp2++;
      _cp1 = (unsigned char *) _lp1;
      _cp2 = (unsigned char *) _lp2;

    }
  else
    {
      _cp1 = vp1;
      _cp2 = vp2;
    }

  while (_last-- > 0)
    *_cp1++ = *_cp2++;

  return (vp1);
}




/* 
 * Check if the IP adx is included in the internal nets
 */

Bool
internal_ip (struct in_addr adx)
{
  int i;

  //fprintf(fp_stdout, "Checking %s \n",inet_ntoa(adx));
  for (i = 0; i < tot_internal_nets; i++)
    {
      //fprintf(fp_stdout, " Against: %s \n",inet_ntoa(internal_net_list[i]));
      if ((adx.s_addr & internal_net_mask[i]) == internal_net_list[i].s_addr)
	{
	  //fprintf(fp_stdout, "Internal: %s\n",inet_ntoa(adx));
	  return 1;
	}
    }
  //fprintf(fp_stdout, "External: %s\n",inet_ntoa(adx));
  return 0;
}

/* 
 * Check if the IP adx is included in the cloud nets
 */

Bool
cloud_ip (struct in_addr adx)
{
  int i;

  //fprintf(fp_stdout, "Checking %s \n",inet_ntoa(adx));
  for (i = 0; i < tot_cloud_nets; i++)
    {
      //fprintf(fp_stdout, " Against: %s \n",inet_ntoa(cloud_net_list[i]));
      if ((adx.s_addr & cloud_net_mask[i]) == cloud_net_list[i].s_addr)
	{
	  //fprintf(fp_stdout, "Cloud: %s\n",inet_ntoa(adx));
	  return 1;
	}
    }
  //fprintf(fp_stdout, "Not-cloud: %s\n",inet_ntoa(adx));
  return 0;
}

Bool
internal_eth (uint8_t *eth_addr, eth_filter *filter)
{
  int i;

  if (debug>1) 
    fprintf(fp_stdout, "Checking %s \n", ether_ntoa((const struct ether_addr *)eth_addr));
  for (i = 0; i < filter->tot_internal_eth; i++)
    {
      if (debug>1) 
        fprintf(fp_stdout, " Against: %s \n",ether_ntoa((const struct ether_addr *)filter->addr[i]));
      if (memcmp(eth_addr, filter->addr[i], 6) == 0)
       {
	     if (debug>1) 
	       fprintf(fp_stdout, "\t\tInternal: %s\n",ether_ntoa((const struct ether_addr *)eth_addr));
	     return 1;
       }
    }
  if (debug>1) 
    fprintf(fp_stdout, "\t\tExternal: %s\n",ether_ntoa((const struct ether_addr *)eth_addr));
  return 0;
}

/* 
 * Check if the IP adx is included in the internal nets
 * use the string dotted notation. Never used.
 */

/*Bool
internal_ip_string (char *adx)
{
  int i;

  for (i = 0; i < tot_internal_nets; i++)
    {
      if ((inet_addr (adx) & internal_net_mask[i]) ==
	  internal_net_list[i].s_addr)
	{
	  return 1;
	}
    }
  return 0;
}
*/

void *
stats_dumping ()
{

  if (debug > 0)
    fprintf (fp_stdout, "Created thread stat_dumping()\n");
  pthread_mutex_lock (&stat_dump_mutex);
  pthread_mutex_lock (&stat_dump_cond_mutex);
  while (1)
    {
      pthread_cond_wait (&stat_dump_cond, &stat_dump_cond_mutex);
#ifdef DEBUG_THREAD
      fprintf (fp_stdout, "\n\nSvegliato thread stats DUMP.\n");
#endif
      swap_adx (EXTERNAL_ADX_HISTO);
      /* update average histos */
      update_fake_histos ();

      swap_histo ();
      pthread_mutex_unlock (&stat_dump_mutex);
      usleep (200);

      /* Create the new path in curr_data_dir: its the base dir name plus
         the integrer step we reached so far. From 000 up to 999" */
      sprintf (curr_data_dir, "%s/%03d", basename, step);

      print_all_histo (HISTO_PRINT_CURRENT);	/* print out the data frozen histograms */
      print_adx (EXTERNAL_ADX_HISTO,0.0);

      clear_all_histo ();	/* then clear them */
      step++;

      /* In case we are processing live streams, create a new dir every
         DIRS steps */
      if (step >= DIRS && is_stdin)
	{
	  create_new_outfiles (NULL, FALSE);
	  step = 0;
	}
      pthread_mutex_lock (&stat_dump_mutex);
    }
  pthread_mutex_unlock (&stat_dump_cond_mutex);

  pthread_exit (NULL);
}


void
stat_dumping_old_style ()
{

/* update average histos */
  update_fake_histos ();

/* swap since the frozen ones are printed out */
  swap_adx (EXTERNAL_ADX_HISTO);
  swap_histo ();
  sprintf (curr_data_dir, "%s/%03d", basename, step);

  // update GLOBAL every hour
  if (global_histo && step && !step % 1200)
    print_all_histo (HISTO_PRINT_GLOBAL);
  print_all_histo (HISTO_PRINT_CURRENT);
  print_adx (EXTERNAL_ADX_HISTO,0.0);



  clear_all_histo ();


  step++;

  /* In case we are processing live streams, create a new dir every
     DIRS steps */
  if (step >= DIRS && is_stdin)
  //if (step >= DIRS)
    {
      create_new_outfiles (NULL, FALSE);
      step = 0;
    }
}

/****************************************************
 * AF: these functions are for parsing runtime.conf
 ****************************************************/

/* this function is to apply the same logic to different log files
 * Note: 'log_type' is one of the LOG_XXX values in tstat.h
 */
static long old_log_bitmask;
void log_parse_ini_arg_log_bitmask(FILE *fp, int log_type, char * log_name, int enabled) {
    if (enabled && !LOG_IS_ENABLED(log_type)) {
        fprintf(fp_stdout, "[%s] Enabling %s\n", Timestamp(), log_name);
        log_bitmask |= log_type;
    }
    else if (!enabled && LOG_IS_ENABLED(log_type)) {
        fprintf(fp_stdout, "[%s] Disabling %s\n", Timestamp(), log_name);
        log_bitmask &= ~log_type;
        // since we are stopping the collection of stats, we force a flush 
        if (fp != NULL) {
            fflush(fp);
        }
    }
}

void log_parse_start_section(void) {
    old_log_bitmask = log_bitmask;
}

void log_parse_end_section(void) {
    if (old_log_bitmask && !log_bitmask) {
        fprintf(fp_stdout, "[%s] All logs disabled\n", Timestamp());
    }
    if (old_log_bitmask != log_bitmask && first_packet_readed) {
        create_new_outfiles(NULL, TRUE);
    }
    old_log_bitmask = log_bitmask;
}

void log_parse_ini_arg(char *param_name, int enabled) {
    if (enabled != 0 && enabled != 1) {
        fprintf(fp_stderr, "ini reader: expected 0|1 value near '%s'\n", param_name);
        exit(1);
    }

    //histogram engine
    if (strcmp(param_name, "histo_engine") == 0) {
        //need to flush histo engine
//        if (((histo_engine && !enabled) || (!histo_engine && enabled)) &&
//            first_packet_readed) {
//            flush_histo_engine();
//        }
        //stdout messages
        if (!histo_engine_log && enabled)
            fprintf(fp_stdout, "[%s] Enabling histo engine logs\n", Timestamp());
        else if (histo_engine_log && !enabled)
            fprintf(fp_stdout, "[%s] Disabling histo engine logs\n", Timestamp());
        histo_engine_log = enabled;
    }
    
    //rrd engine
    else if (strcmp(param_name, "rrd_engine") == 0) {
        //stdout messages
        if (!rrd_engine && enabled)
            fprintf(fp_stdout, "[%s] Enabling rrd engine logs\n", Timestamp());
        else if (rrd_engine && !enabled)
            fprintf(fp_stdout, "[%s] Disabling rrd engine logs\n", Timestamp());
        rrd_engine = enabled;
    }

    else if (strcmp(param_name, "log_tcp_complete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_logc, LOG_TCP_COMPLETE, "log_tcp_complete", enabled);
    }
    else if (strcmp(param_name, "log_tcp_nocomplete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_lognc, LOG_TCP_NOCOMPLETE, "log_tcp_nocomplete", enabled);
    }
    else if (strcmp(param_name, "log_udp_complete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_udp_logc, LOG_UDP_COMPLETE, "log_udp_complete", enabled);
    }
    else if (strcmp(param_name, "log_mm_complete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_rtp_logc, LOG_MM_COMPLETE, "log_mm_complete", enabled);
    }
    else if (strcmp(param_name, "log_skype_complete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_skype_logc, LOG_SKYPE_COMPLETE, "log_skype_complete", enabled);
    }
    else if (strcmp(param_name, "log_chat_complete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_chat_logc, LOG_CHAT_COMPLETE, "log_chat_complete", enabled);
    }
    else if (strcmp(param_name, "log_chat_messages") == 0) {
        log_parse_ini_arg_log_bitmask(fp_chat_log_msg, LOG_CHAT_MESSAGES, "log_chat_messages", enabled);
    }
    else if (strcmp(param_name, "log_video_complete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_video_logc, LOG_VIDEO_COMPLETE, "log_video_complete", enabled);
    }
    else if (strcmp(param_name, "log_streaming_complete") == 0) {
        log_parse_ini_arg_log_bitmask(fp_streaming_logc, LOG_STREAMING_COMPLETE, "log_streaming_complete", enabled);
    }
    else {
        fprintf(fp_stderr, "ini reader: '%s' - unknown keyword\n", param_name);
        exit(1);
    }
}

void flush_histo_engine(void) {
    if (threaded)
    {
#ifdef DEBUG_THREAD
        fprintf (fp_stdout, "Signaling thread stat dump\n");
#endif
        pthread_mutex_lock (&stat_dump_cond_mutex);
        pthread_cond_signal (&stat_dump_cond);
        pthread_mutex_unlock (&stat_dump_cond_mutex);
        pthread_mutex_lock (&stat_dump_mutex);
        pthread_mutex_unlock (&stat_dump_mutex);
    }
    else
    {
        stat_dumping_old_style ();
    }
    last_time_step = current_time;
    // reset bitrate stats 
    memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
    memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
    memset (&L7_udp_bitrate, 0, sizeof (struct L7_bitrates));
    memset (&HTTP_bitrate, 0, sizeof (struct HTTP_bitrates));
    memset (&WEB_bitrate, 0, sizeof (struct WEB_bitrates));
    memset (&VIDEO_rate, 0, sizeof (struct VIDEO_rates));
}
