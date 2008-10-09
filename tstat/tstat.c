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
*/

static char const copyright[] =
  "@(#)Copyright (c) 2001 -- Telecomunication Network Group \
     -- Politecnico di Torino.  All rights reserved.\
     Tstat is based on TCPTRACE,\
    @(#)Copyright (c) 1999 -- Shawn Ostermann -- Ohio University.\n";

#include "tstat.h"
#include "file_formats.h"
#include "version.h"
#include <time.h>
#include "tcpL7.h"
#include <sys/wait.h>
#include <getopt.h>

/* version information */
char *tstat_version = VERSION;

/* seem to be missing from pthread.h */
int pthread_mutexattr_settype (pthread_mutexattr_t * attr, int kind);

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
#ifndef TSTAT_RUNASLIB
static void ProcessFile (char *filename, Bool last);
#endif

static Bool internal_ip (struct in_addr adx);
/*
static Bool internal_ip_string (char *adx);
*/

static int ip_header_stat (int phystype, struct ip *pip, u_long * fpnum,
			   u_long * pcount, int file_count, char *filename,
			   long int location, int tlen, void *plast);

void stat_dumping_old_style ();

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
static char basename[100];
Bool internal_src = FALSE;
Bool internal_dst = FALSE;

struct in_addr internal_net_list[MAX_INTERNAL_HOSTS];
struct in_addr internal_net_mask2[MAX_INTERNAL_HOSTS];
int internal_net_mask[MAX_INTERNAL_HOSTS];
char *internal_net_file;
int tot_internal_nets;

#ifdef SUPPORT_IPV6
struct in6_addr internal_net_listv6;
char *internal_net_filev6;
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

static u_long pcount = 0;   //global packet counter
static u_long fpnum = 0;    //per file packet counter
static int file_count = 0;
static int update_num = 0;

#ifdef HAVE_RRDTOOL
/*-----------------------------------------------------------*/
/* RRDtools 				                     */
/*-----------------------------------------------------------*/
Bool rrdset_path = FALSE;	/* database path flag */
Bool rrdset_conf = FALSE;	/* configuration file flag */
/*-----------------------------------------------------------*/
#endif

Bool histo_engine = TRUE;	/* -S */
Bool adx_engine = FALSE;	/* to allow disabling via -H */
Bool global_histo = FALSE;	/* -g */

Bool log_engine = TRUE;		/* -L */
Bool bayes_engine = FALSE;	/* -B */

int log_version = 2;            /* -1 */

struct bayes_settings *bayes_settings_pktsize;
struct bayes_settings *bayes_settings_avgipg;


/* locally global variables */
static u_long filesize = 0;
static int num_files = 0;
#ifndef TSTAT_RUNASLIB
static u_int numfiles;
#endif
static char *cur_filename;
static char *progname;
static unsigned int step = 0;	/* counter to track the dir storing the
				   periodic dumping of histograms. */

//XXX
typedef enum
{ ETH, DAG } Live_Cap_Type;
int livecap_type;		/* indicate the type of live capture */
#ifdef GROK_ERF_LIVE
char *dag_dev_list;		/* list of DAG cards device names */
#define DAG_NAME_BUFSIZE 25
#endif

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

/* LM */
#ifdef LOG_OOO
FILE *fp_dup_ooo_log;
#endif


/* discriminate Direction */
Bool coming_in;
Bool internal_wired = FALSE;
Bool net_conf = FALSE;
long int tcp_packet_count;

extern long not_id_p;
extern int search_count;
extern long int tot_adx_hash_count, tot_adx_list_count, adx_search_hash_count,
  adx_search_list_count;

extern char dump_conf_fname[];
Bool dump_engine = FALSE;

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
	fprintf (stdout, "Child (pid %d) terminated with status %d\n.", pid,
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
  fprintf (stderr,
	   "Usage:\n\ttstat  [-htuvwpg] [-d[-d]] [-N file] [-s dir]\n");
  fprintf (stderr, "              [-B bayes.conf] [-T dump.conf] [-S] [-L]\n"
	   "              [-H ?|file ]\n"
#ifdef SUPPORT_IPV6
	   "              [-y] [-6 file]\n"
#endif
#ifdef HAVE_RRDTOOL
	   "              [-r RRD_out_dir] [-R rrd_conf] [-S]\n"
#endif
#ifdef GROK_LIVE_TCPDUMP
	   "              [-l] [-i interface]\n"
#endif
#ifdef GROK_ERF_LIVE
	   "              [--dag device_name device_name ...]\n"
#endif
	   "              [-f filterfile] <file1 file2>\n\n");

  fprintf (stderr, "Options:\n");
  fprintf (stderr, "\t-h: print this help and exit\n");
  fprintf (stderr, "\t-t: print ticks showing the trace analysis progress\n");
  fprintf (stderr, "\t-u: do not trace UDP packets\n");
  fprintf (stderr, "\t-v: print version and exit\n");
  fprintf (stderr, "\t-w: print [lots] of warning\n");
  fprintf (stderr,
	   "\t-c: concatenate the finput files\n\t    (input files should already be in the correct order)\n");
  fprintf (stderr,
	   "\t-p: enable multi-threaded engine (useful for live capture)\n\n");
  fprintf (stderr,
	   "\t-d: increase debug level (repeat to increase debug level)\n");
  fprintf (stderr, "\t-N file: specify the file name which contains the\n");
  fprintf (stderr, "\t         description of the internal networks.\n");
  fprintf (stderr,
	   "\t         This file must contain the subnets that will be\n");
  fprintf (stderr,
	   "\t         considered as 'internal' during the analysis\n");
  fprintf (stderr,
	   "\t         Each subnet must be specified using network IP address\n");
  fprintf (stderr,
	   "\t         on the first line and NETMASK on the next line:\n");
  fprintf (stderr, "\t         130.192.0.0\n");
  fprintf (stderr, "\t         255.255.0.0\n");
  fprintf (stderr, "\t         193.204.134.0\n");
  fprintf (stderr, "\t         255.255.255.0\n\n");

  fprintf (stderr,
	   "\t-sdir: puts the trace analysis results into directory\n");
  fprintf (stderr, "\t       tree dir (otherwise will be <file>.out)\n");

  fprintf (stderr,
	   "\t-H ?: print internal histograms names and definitions\n");
  fprintf (stderr, "\t-H file: Read histogram configuration from file\n");
  fprintf (stderr,
	   "\t         file describes which histograms tstat should collect\n");
  fprintf (stderr,
	   "\t         'include histo_name' includes a single histogram\n");
  fprintf (stderr,
	   "\t         'include_matching string' includes all histograms\n");
  fprintf (stderr, "\t         whose name includes the string\n");
  fprintf (stderr, "\t         special names are:\n");
  fprintf (stderr, "\t         'ALL' to include all histograms\n");
  fprintf (stderr, "\t         'ADX' to include address hits histogram\n");
  fprintf (stderr, "\t         for example, to include all TCP related\n");
  fprintf (stderr,
	   "\t         and the address hits histograms, file should be:\n");
  fprintf (stderr, "\t         include ADX\n");
  fprintf (stderr, "\t         include_matching tcp\n\n");

  fprintf (stderr, "\t-H file: Read histogram configuration from file\n");
  fprintf (stderr, "\t-g: Enable global histo engine\n");
  fprintf (stderr,
	   "\t-S: No histo engine: do not create histograms files \n");
  fprintf (stderr, "\t-L: No log engine: do not create log_* files \n");
  fprintf (stderr, "\t-1: Use old (v1) log_mm format\n");
  fprintf (stderr,
	   "\t-B Bayes_Dir: enable Bayesian traffic classification\n");
  fprintf (stderr, "\t              configuration files from Bayes_Dir\n");
  fprintf (stderr, 
       "\t-T dump.conf: configurazion file for the dump engine\n");
#ifdef SUPPORT_IPV6
  fprintf (stderr,
	   "\t-y: to activate the security controls on 6to4 tunnels \n");
  fprintf (stderr, "\t-6file: specify the file name which contains the\n");
  fprintf (stderr, "\t        description of the internal IPv6 network.\n");
#endif
#ifdef HAVE_RRDTOOL
/*----------------------------------------------------------- 
   RRDtools 				                     
   these flags test for both the -r and -R options to be 
   specified when using RR database integration */
  fprintf (stderr,
	   "\t-Rconf: specify the configuration file for integration with"
	   "\n\t      RRDtool. See README.RRDtool for further information"
	   "\n\t-rpath: path to use to create/update the RRDtool database\n");
/*-----------------------------------------------------------*/
#endif
#ifdef GROK_DPMI
  fprintf (stderr, "\t-Dconf: DPMI configuration file\n");
#endif /* GROK_DPMI */
#ifdef GROK_LIVE_TCPDUMP
  fprintf (stderr, "\t-l: enable live capture using libpcap\n");
  fprintf (stderr,
	   "\t-iinterface: specifies the interface to be used to capture traffic\n");
#endif /* GROK_LIVE_TCPDUMP */

#ifdef GROK_ERF_LIVE
  fprintf (stderr,
	   "\t--dag: enable live capture using Endace DAG cards. The"
	   "\n\t     list of device_name can contain at most four names\n");
#endif /* GROK_ERF_LIVE */

  fprintf (stderr,
	   "\t-ffilterfile: specifies the libpcap filter file. Syntax as in tcpdump\n\n");
  fprintf (stderr, "\tfile: trace file to be analyzed\n");
  fprintf (stderr, "\t      Use 'stdin' to read from standard input.\n");

  fprintf (stderr, "\n");
  fprintf (stderr, "Note:\n");
  fprintf (stderr,
	   "\tWhen tstat is called with no arguments (on the command line),\n");
  fprintf (stderr,
	   "\tit will first check if a file <tstat.conf> is provided in the\n");
  fprintf (stderr, "\tsame directory where the execution started.\n");
  fprintf (stderr,
	   "\tIn the latter case, arguments will be read from <tstat.conf>\n");
  fprintf (stderr, "\trather than from the command line\n\n");
  Formats ();
  Version ();
}



static void
BadArg (char *argsource, char *format, ...)
{
  va_list ap;

  Help ();

  fprintf (stderr, "\nArgument error");
  if (argsource)
    fprintf (stderr, " (from %s)", argsource);
  fprintf (stderr, ": ");

  va_start (ap, format);
  vfprintf (stderr, format, ap);
  va_end (ap);
  fprintf (stderr, "\n");
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
  fprintf (stderr, "\nVersion: %s\n", tstat_version);
  fprintf (stderr, "Compiled by <%s>, the <%s> on machine <%s>\n\n",
	   built_bywhom, built_when, built_where);
}


static void
Formats (void)
{
  int i;

  fprintf (stderr, "Supported Input File Formats:\n");
  for (i = 0; i < (int) NUM_FILE_FORMATS; ++i)
    fprintf (stderr, "\t%-15s  %s\n",
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
      printf ("\n");
      exit (0);
    }


#ifndef TSTAT_RUNASLIB
  if (live_flag == FALSE)
    { //no remaing arg is live capture
      num_files = argc;
      printf ("%d arg%s remaining, starting with '%s'\n",
	      num_files, num_files > 1 ? "s" : "", filenames[0]);
    }

  // knock, knock...
  printf ("%s\n\n", VERSION);
#endif


#ifdef HAVE_RRDTOOL
  /*-----------------------------------------------------------*/
  /* RRDtools                                                   */
  /*   now that all the histo have been creaed, we may          */
  /*   parse rrdtool configuration file                         */
  if (rrdset_path && rrdset_conf)
    rrdtool_init ();
  /*-----------------------------------------------------------*/
#endif

  /* register the protocol analyzer over TCP/UDP */
  proto_init ();

/* inititializing adx_index_current */
  alloc_adx ();

/* thread creation and management  */

  if (threaded)
    {
      /* Initialize mutex and condition variable objects */
      pthread_mutexattr_init (&attr);
      pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_ERRORCHECK_NP);
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
		    printf ("Running file '%s' (%d of %d)\n",
			    filenames[i + j], i + j + 1, numfiles);
		  else
		    printf ("Running file '%s'\n", filenames[i]);
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
    printf ("\n");

  /* get ending wallclock time */
  gettimeofday (&wallclock_finished, NULL);

  /* general output */
  fprintf (stdout, "%lu packets seen, %lu TCP packets traced",
	   pnum, tcp_trace_count_outgoing + tcp_trace_count_incoming
	   + tcp_trace_count_local);
  if (do_udp)
    fprintf (stdout, ", %lu UDP packets traced", udp_trace_count);
  fprintf (stdout, "\n");

  /* actual tracefile times */
  etime = elapsed (first_packet, last_packet);
  fprintf (stdout, "trace %s elapsed time: %s\n",
	   (num_files == 1) ? "file" : "files", elapsed2str (etime));
  if (debug > 0)
    {
      fprintf (stdout, "\tfirst packet:  %s\n", ts2ascii (&first_packet));
      fprintf (stdout, "\tlast packet:   %s\n", ts2ascii (&last_packet));
    }
  exit(EXIT_SUCCESS);
#else
  return EXIT_SUCCESS;
#endif //TSTAT_RUNASLIB
}


// MGM
/* Create subdirs into which out files will be put */
void
create_new_outfiles (char *filename)
{
  char tmpstr[200];
  struct stat fbuf;
  char date[50];
  char logfile[200] = "";

  if ((!histo_engine) && (!log_engine) && (!global_histo))
    return;

  if (!basedirspecified)
    {
      /* get the basename from the tracefile */
      if (is_stdin ||
          strcmp(filename, "TSTAT_RUNASLIB") == 0)
	{
	  basenamedir = strdup ("stdin");
	}
      else
	{
	  basenamedir = get_basename (filename);
	}
    }
  if (stat (basenamedir, &fbuf) != 0)
    {
      mkdir (basenamedir, 0775);
    }
  strftime (date, 49, "%H_%M_%d_%b_%Y", localtime (&current_time.tv_sec));


  sprintf (basename, "%s/%s.out", basenamedir, date);

  if (stat (basename, &fbuf) != -1)
    {
      /* remove the previous directory */
      sprintf (tmpstr, "rm -rf %s", basename);
      system (tmpstr);
    }
  mkdir (basename, 0775);

  if (global_histo)
    sprintf (global_data_dir, "%s/GLOBAL", basename);

  if ((!histo_engine) && (!log_engine))
    return;

  if (log_engine)
    {
      /* Open the files for complete and uncomplete connection logging */

      sprintf (logfile, "%s/%s", basename, "log_tcp_complete");
      if (fp_logc != NULL)
	fclose (fp_logc);
      fp_logc = fopen (logfile, "w");
      if (fp_logc == NULL)
	{
	  printf ("Could not open file %s\n", logfile);
	}

      sprintf (logfile, "%s/%s", basename, "log_tcp_nocomplete");
      if (fp_lognc != NULL)
	fclose (fp_lognc);
      fp_lognc = fopen (logfile, "w");
      if (fp_lognc == NULL)
	{
	  printf ("Could not open file %s\n", logfile);
	}
#ifdef RTP_CLASSIFIER
      /* RTP log */

      sprintf (logfile, "%s/%s", basename, "log_mm_complete");
      if (fp_rtp_logc != NULL)
	fclose (fp_rtp_logc);
      fp_rtp_logc = fopen (logfile, "w");
      if (fp_rtp_logc == NULL)
	{
	  printf ("Could not open file %s\n", logfile);
	}
#endif

#ifdef SKYPE_CLASSIFIER
      /* skype log */

      sprintf (logfile, "%s/%s", basename, "log_skype_complete");
      if (fp_skype_logc != NULL)
	fclose (fp_skype_logc);
      fp_skype_logc = fopen (logfile, "w");
      if (fp_skype_logc == NULL)
	{
	  printf ("Could not open file %s\n", logfile);
	}
#endif

#ifdef P2P_CLASSIFIER

      /* UDP log */

      sprintf (logfile, "%s/%s", basename, "log_udp_complete");
      if (fp_udp_logc != NULL)
	fclose (fp_udp_logc);
      fp_udp_logc = fopen (logfile, "w");
      if (fp_udp_logc == NULL)
	{
	  printf ("Could not open file %s\n", logfile);
	}
#endif 

      /* MSN+Yahoo+Jabber log */
#if defined(MSN_CLASSIFIER) || defined(YMSG_CLASSIFIER) || defined(XMPP_CLASSIFIER)
      sprintf (logfile, "%s/%s", basename, "log_chat_complete");
      if (fp_chat_logc != NULL)
	fclose (fp_chat_logc);
      fp_chat_logc = fopen (logfile, "w");
      if (fp_chat_logc == NULL)
	{
	  printf ("Could not open file %s\n", logfile);
	}
      sprintf (logfile, "%s/%s", basename, "log_chat_messages");
      if (fp_chat_log_msg != NULL)
	fclose (fp_chat_log_msg);
      fp_chat_log_msg = fopen (logfile, "w");
      if (fp_chat_log_msg == NULL)
	{
	  printf ("Could not open file %s\n", logfile);
	}
  #ifdef MSN_OTHER_COMMANDS
      sprintf (logfile, "%s/%s", basename, "log_msn_OtherCommands");
      if (fp_msn_log_othercomm != NULL)
	fclose (fp_msn_log_othercomm);
      fp_msn_log_othercomm = fopen (logfile, "w");
      if (fp_msn_log_othercomm == NULL)
	{
	  printf ("Could not open file %s\n", logfile);
	}
  #endif

    //XXX FINAMORE
  dump_create_outdir(basename);

#endif

#ifdef LOG_OOO
      /* MGM start */
      /* Open the files for dup and ooo logging */

      sprintf (logfile, "%s/%s", basename, "dup_ooo");
      if (fp_dup_ooo_log != NULL)
	fclose (fp_dup_ooo_log);
      fp_dup_ooo_log = fopen (logfile, "w");
      if (fp_dup_ooo_log == NULL)
	{
	  printf ("Could not open file %s\n", logfile);
	}
      /* MGM stop */
#endif
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
		        void *plast)
{
  /* another sanity check, only understand ETHERNET right now */

  if (phystype != PHYS_ETHER)
    {
      static int not_ether = 0;

      ++not_ether;
      if (not_ether < 5)
	{
	  fprintf (stderr,
		   "Skipping packet %lu, not an ethernet packet\n", pnum);
	}			/* else, just shut up */
      return 0;
    }

#ifdef SUPPORT_IPV6
  if (PIP_ISV6 (pip))
    {

      //fprintf(stderr,"IPv6 packet \n");
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
	  internal_src = coming_in;
	  internal_dst = !coming_in;
	}
      else
	{
	  internal_src = internal_ip (pip->ip_src);
	  internal_dst = internal_ip (pip->ip_dst);
	}

      /* .a.c. */
      if (internal_src && !internal_dst)
	{
	  L4_bitrate.out[IP_TYPE] += ntohs (pip->ip_len);
	  if (pip->ip_p == IPPROTO_ICMP)
	    L4_bitrate.out[ICMP_TYPE] += ntohs (pip->ip_len);
	  add_histo (ip_protocol_out, pip->ip_p);
	  add_histo (ip_len_out, (float) ntohs (pip->ip_len));
	  add_histo (ip_ttl_out, (float) pip->ip_ttl);
	  add_histo (ip_tos_out, (float) pip->ip_tos);
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
	}
      else if (internal_src && internal_dst)
	{
	  L4_bitrate.loc[IP_TYPE] += ntohs (pip->ip_len);
	  if (pip->ip_p == IPPROTO_ICMP)
	    L4_bitrate.loc[ICMP_TYPE] += ntohs (pip->ip_len);
	  add_histo (ip_protocol_loc, pip->ip_p);
	  add_histo (ip_len_loc, (float) ntohs (pip->ip_len));
	  add_histo (ip_ttl_loc, (float) pip->ip_ttl);
	  add_histo (ip_tos_loc, (float) pip->ip_tos);
	}


      if (adx_engine)
	{
	  add_adx (&(pip->ip_src), SRC_ADX);
	  add_adx (&(pip->ip_dst), DST_ADX);
	}
#ifdef SUPPORT_IPV6
    }
#endif
  /* update global and per-file packet counters */
  ++pnum;			/* global */
  ++(*fpnum);			/* local to this file */
  ++(*pcount);			/* counter per chiudere i pendenti */


  /* the last_time_step is assigned only at the first packet */
  if (pnum == 1)
    last_time_step = last_cleaned = current_time;


  /* check for re-ordered packets */
  if (!ZERO_TIME (&last_packet))
    {
      if (elapsed (last_packet, current_time) < 0)
	{
	  /* out of order */
	  if ((file_count > 1) && ((*fpnum) == 1))
	    {
	      fprintf (stderr, "\
Warning, first packet in file %s comes BEFORE the last packet\n\
in the previous file.  That will likely confuse the program, please\n\
order the files in time if you have trouble\n", filename);
	    }
	  else
	    {
	      static int warned = 0;

	      if (warn_ooo)
		{
		  fprintf (stderr, "\
Warning, packet %ld in file %s comes BEFORE the previous packet\n\
That will likely confuse the program, so be careful!\n", (*fpnum), filename);
		}
	      else if (!warned)
		{
		  fprintf (stderr, "\
Packets in file %s are out of order.\n\
That will likely confuse the program, so be careful!\n", filename);
		}
	      warned = 1;
	    }

	}
    }


  /* install signal handler */
  if ((*fpnum) == 1)
    {
      signal (SIGINT, QuitSig);
      signal (SIGUSR1, Usr1Sig);
    }

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
	    fprintf (stderr, "%s: ", cur_filename);
	  fprintf (stderr, "Tp= %lu Tf=%lu ", (*fpnum), fcount);
	  if (CompIsCompressed ())
	    {
	      frac = location / filesize * 100;
	      if (frac <= 100)
		fprintf (stderr, "~%u%% (compressed)", frac);
	      else
		fprintf (stderr, "~100%% + %u%% (compressed)", frac - 100);
	    }
	  else if (!is_stdin)
	    {
	      location = ftell (stdin);
	      frac = location / filesize * 100;
	      fprintf (stderr, "%u%%", frac);
	    }
	  /* print elapsed time */
	  {
	    double etime = elapsed (first_packet, last_packet);
	    fprintf (stderr, " (%s)", elapsed2str (etime));
	  }
	  /* print number of opened flow */
	  {
	    fprintf (stderr, " Nf(TCP)=%lu Nf(UDP)=%lu", tot_conn_TCP,
		     tot_conn_UDP);
	    fprintf (stderr, " Ntrash=%lu", not_id_p);
	  }

	  /* carriage return (but not newline) */
	  fprintf (stderr, "\r");
	}
      fflush (stderr);
    }
#endif //TSTAT_RUNASLIB

  /* keep track of global times */
  if (ZERO_TIME (&first_packet))
    first_packet = current_time;
  last_packet = current_time;

  return 1;			/*finished ok */
}

void InitAfterFirstPacketReaded(char *filename, int file_count) {
  if ((con_cat == FALSE) || (file_count == 1))
    create_new_outfiles (filename);

  if (con_cat == FALSE)
    {
      // reset bitrate stats
      memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
      memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
      
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
                         long int location)
{
    struct tcphdr *ptcp = NULL;
    tcp_pair *ptp;
    struct udphdr *pudp;
    udp_pair *pup = NULL;
    int dir;

    current_time = *pckt_time;

    //------------------ skip very close pkts 
    //  if (elapsed (last_packet, current_time) <= 0)
    //    continue;
    //  fprintf(stderr,"%f \n", elapsed (last_packet, current_time));


    /* quick sanity check, better be an IPv4/v6 packet */
    if (!PIP_ISV4 (pip) && !PIP_ISV6 (pip))
    {
        static Bool warned = FALSE;

        if (!warned)
        {
            fprintf (stderr, "Warning: saw at least one non-ip packet\n");
            warned = TRUE;
        }

        if (debug > 1)
#ifdef SUPPORT_IPV6
            fprintf (stderr,
                    "Skipping packet %lu, not an IPv4/v6 packet (version:%d)\n",
                    pnum, pip->ip_v);
#else
        fprintf (stderr,
                "Skipping packet %lu, not an IPv4 packet (version:%d)\n",
                pnum, pip->ip_v);
#endif
        return 0;
    }



    /* Statistics from IP HEADER */
    if (ip_header_stat
            (phystype, pip, fpnum, pcount, file_count, filename, location,
             tlen, plast) == 0)
        return 0;

    if (elapsed (last_time_step, current_time) > MAX_TIME_STEP)
    {
        update_num++;

        if (threaded)
        {
#ifdef DEBUG_THREAD
            printf ("Signaling thread stat dump\n");
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
        /* reset bitrate stats */
        memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
        memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
    }


    /* Statistics from LAYER 4 (TCP/UDP) HEADER */
    /* Statistics from upper-layers are called as:
     *     	proto_analyzer(pip, pproto, PROTOCOL_type, thisdir, dir, plast);
     * from tcp_flow_stat and udp_flow_stat
     */
    if ((ptcp = tcp_header_stat (ptcp, pip, plast)) != NULL)
    {
        ptp = tcp_flow_stat (pip, ptcp, plast, &dir);
        if (ptp == NULL)
            return 0;
        /* Topix: try to guess the upper level protocol */
        /* FindConType: returns the type of connection, 0 if unknown */
        // FindConType (ptp, pip, ptcp, plast, len, dir);

        /* if it wasn't "interesting", we return NULL here */

    }
    else if (do_udp)
    {
        /* look for a UDP header */
        pudp = getudp (pip, &plast);
        if (pudp != NULL)
            pup = udp_flow_stat (pip, pudp, plast);
        else {
            return 0;
        }
    }
    else
    {
        return 0;
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
    /* set ^C back to the default */
    /* (so we can kill the output if needed) */
    {
        sigset_t mask;

        sigemptyset (&mask);
        sigaddset (&mask, SIGINT);

        sigprocmask (SIG_UNBLOCK, &mask, NULL);
        signal (SIGINT, SIG_DFL);
    }

    /* statistics dumping modified for -c option*/
    stat_dumping_old_style ();

    if (con_cat == TRUE && last == FALSE)
    {
        update_num++;

        if (threaded)
        {
#ifdef DEBUG_THREAD
            printf ("Signaling thread stat dump\n");
#endif
            pthread_mutex_lock (&stat_dump_cond_mutex);
            pthread_cond_signal (&stat_dump_cond);
            pthread_mutex_unlock (&stat_dump_cond_mutex);
            pthread_mutex_lock (&stat_dump_mutex);
            pthread_mutex_unlock (&stat_dump_mutex);
        }
        else
            stat_dumping_old_style ();

        last_time_step = current_time;
        /* reset bitrate stats */
        memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
        memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));

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
                printf ("DEB: writing stats for uncomplete traces... ");
            trace_done ();
            if (do_udp)
                udptrace_done ();
            /*DB*/
            /*
               else 
               if (((elapsed (last_skypeprint_time, last_packet) )/1000.0/1000.0) >= 5.0 )
               {
               printf ("\nSono dentro !");
               last_skypeprint_time = last_packet;
               udptrace_part ();
               }
               */
            if (debug > 1)
                printf ("DEB: writing addresses... ");


            /* update average histos */


            /* swap since the frozen ones are printed out */
            swap_adx ();
            swap_histo ();
            if (global_histo)
                print_all_histo (HISTO_PRINT_GLOBAL);

            print_all_histo (HISTO_PRINT_CURRENT);
            print_adx ();

            clear_all_histo ();
        }
    }

#ifndef TSTAT_RUNASLIB
    /* close the input file */
    CompCloseFile(cur_filename);
    get_stats_report(&report);
    //dump_internal_stats(&report, stdout);
    tstat_print_report(&report, stdout);
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
    InitAfterFirstPacketReaded(filename, 1);
#endif
}

// !!!fake function for normal use!!!
int tstat_next_pckt(struct timeval *pckt_time, 
                    void *ip_hdr, 
                    void *last_ip_byte,
                    int tlen) 
{
#ifdef TSTAT_RUNASLIB
    //use some fake parameter
    return ProcessPacket(pckt_time, (struct ip*)ip_hdr, last_ip_byte, tlen, 
                         PHYS_ETHER, &fpnum, &pcount, 1, cur_filename, 0);
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
  if (FileIsStdin (filename))
    {
      filesize = 1;
      is_stdin = TRUE;
    }
  else
    {
      if (stat (filename, &str_stat) != 0)
	{
	  perror ("stat");
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
	    fprintf (stderr, "Capturing using '%s' (%s)\n",
		     file_formats[ETH_LIVE].format_name,
		     file_formats[ETH_LIVE].format_descr);
	  break;
#endif

#ifdef GROK_ERF_LIVE
	case DAG:
	  ppread = (*file_formats[ERF_LIVE].test_func) (dag_dev_list);
	  free (dag_dev_list);
	  if (debug > 0)
	    fprintf (stderr, "Capturing using '%s' (%s)\n",
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
	printf ("NUM_FILE_FORMATS: %d\n", (int) NUM_FILE_FORMATS);
      for (fix = 0; fix < (int) NUM_FILE_FORMATS - NUM_LIVE_FORMATS; ++fix)
	{
	  if (debug > 0)
	    fprintf (stderr, "Checking for file format '%s' (%s)\n",
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
		fprintf (stderr, "File format is '%s' (%s)\n",
			 file_formats[fix].format_name,
			 file_formats[fix].format_descr);
	      break;
	    }
	  else if (debug > 0)
	    {
	      fprintf (stderr, "File format is NOT '%s'\n",
		       file_formats[fix].format_name);
	    }
	}

      /* if we haven't found a reader, then we can't continue */
      if (ppread == NULL)
	{
	  int count = 0;

	  fprintf (stderr, "Unknown input file format\n");
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
		  fprintf (stderr,
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
	  printf ("Trace file size: %lu bytes\n", filesize);
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
  while ((ret != -1)
	 && (current_time.tv_sec == 0 && current_time.tv_usec == 0));

  if (ret == -1)
    {
      fprintf (stderr,
	       "Not even a single packet read (check tcpdump filter)! Aborting...\n");
      exit (1);
    }

    InitAfterFirstPacketReaded(filename, file_count);
/*
  if ((con_cat == FALSE) || (file_count == 1))
    create_new_outfiles (filename);

  if (con_cat == FALSE)
    {
      // reset bitrate stats
      memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
      memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
      
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
                      file_count, cur_filename, location);
//      //------------------ skip very close pkts 
//      //  if (elapsed (last_packet, current_time) <= 0)
//      //    continue;
//      //  fprintf(stderr,"%f \n", elapsed (last_packet, current_time));
//
//
//      /* quick sanity check, better be an IPv4/v6 packet */
//      if (!PIP_ISV4 (pip) && !PIP_ISV6 (pip))
//	{
//	  static Bool warned = FALSE;
//
//	  if (!warned)
//	    {
//	      fprintf (stderr, "Warning: saw at least one non-ip packet\n");
//	      warned = TRUE;
//	    }
//
//	  if (debug > 1)
//#ifdef SUPPORT_IPV6
//	    fprintf (stderr,
//		     "Skipping packet %lu, not an IPv4/v6 packet (version:%d)\n",
//		     pnum, pip->ip_v);
//#else
//	    fprintf (stderr,
//		     "Skipping packet %lu, not an IPv4 packet (version:%d)\n",
//		     pnum, pip->ip_v);
//#endif
//	  continue;
//	}
//
//
//
///* Statistics from IP HEADER */
//      if (ip_header_stat
//	  (phystype, pip, &fpnum, &pcount, file_count, filename, location,
//	   tlen, plast) == 0)
//	continue;
//
//
//
//      if (elapsed (last_time_step, current_time) > MAX_TIME_STEP)
//	{
//	  update_num++;
//
//	  if (threaded)
//	    {
//#ifdef DEBUG_THREAD
//	      printf ("Signaling thread stat dump\n");
//#endif
//	      pthread_mutex_lock (&stat_dump_cond_mutex);
//	      pthread_cond_signal (&stat_dump_cond);
//	      pthread_mutex_unlock (&stat_dump_cond_mutex);
//	      pthread_mutex_lock (&stat_dump_mutex);
//	      pthread_mutex_unlock (&stat_dump_mutex);
//	    }
//	  else
//	    {
//	      stat_dumping_old_style ();
//	    }
//	  last_time_step = current_time;
//          /* reset bitrate stats */
//          memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
//          memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
//	}
//
//
///* Statistics from LAYER 4 (TCP/UDP) HEADER */
///* Statistics from upper-layers are called as:
// *     	proto_analyzer(pip, pproto, PROTOCOL_type, thisdir, dir, plast);
// * from tcp_flow_stat and udp_flow_stat
// */
//      if ((ptcp = tcp_header_stat (ptcp, pip, plast)) != NULL)
//	{
//	  ptp = tcp_flow_stat (pip, ptcp, plast, &dir);
//	  if (ptp == NULL)
//	    continue;
//	  /* Topix: try to guess the upper level protocol */
//	  /* FindConType: returns the type of connection, 0 if unknown */
//	  // FindConType (ptp, pip, ptcp, plast, len, dir);
//
//	  /* if it wasn't "interesting", we return NULL here */
//
//	}
//      else if (do_udp)
//	{
//	  udp_pair *pup;
//	  struct udphdr *pudp;
//
//	  /* look for a UDP header */
//	  pudp = getudp (pip, &plast);
//	  if (pudp != NULL)
//	    pup = udp_flow_stat (pip, pudp, plast);
//	  else {
//	    continue;
//      }
//	}
//      else
//	{
//	  continue;
//	}
//
//      /*
//         however, if we do not have
//         many packets, we'd wait forever
//         // for efficiency, only allow a signal every 1000 packets       
//         // (otherwise the system call overhead will kill us)            
//         if (pnum % 1000 == 0)
//         {
//         sigset_t mask;
//
//         sigemptyset (&mask);
//         sigaddset (&mask, SIGINT);
//
//         sigprocmask (SIG_UNBLOCK, &mask, NULL);
//         // signal can happen EXACTLY HERE, when data structures are consistant 
//         sigprocmask (SIG_BLOCK, &mask, NULL);
//         }
//       */
    }
  while ((ret =
	  (*ppread) (&current_time, &len, &tlen, &phys, &phystype, &pip,
		     &plast)));

  ProcessFileCompleted(last);
//  /* end while == fine file */
//
//  /* set ^C back to the default */
//  /* (so we can kill the output if needed) */
//  {
//    sigset_t mask;
//
//    sigemptyset (&mask);
//    sigaddset (&mask, SIGINT);
//
//    sigprocmask (SIG_UNBLOCK, &mask, NULL);
//    signal (SIGINT, SIG_DFL);
//  }
//  
///* statistics dumping modified for -c option*/
//	stat_dumping_old_style ();
//
//  if (con_cat == TRUE && last == FALSE)
//    {
//      update_num++;
//
//      if (threaded)
//	{
//#ifdef DEBUG_THREAD
//	  printf ("Signaling thread stat dump\n");
//#endif
//	  pthread_mutex_lock (&stat_dump_cond_mutex);
//	  pthread_cond_signal (&stat_dump_cond);
//	  pthread_mutex_unlock (&stat_dump_cond_mutex);
//	  pthread_mutex_lock (&stat_dump_mutex);
//	  pthread_mutex_unlock (&stat_dump_mutex);
//	}
//      else
//	stat_dumping_old_style ();
//
//      last_time_step = current_time;
//      /* reset bitrate stats */
//      memset (&L4_bitrate, 0, sizeof (struct L4_bitrates));
//      memset (&L7_bitrate, 0, sizeof (struct L7_bitrates));
//
//    }
//  else
//    {
///* wait for the stat_dump thread to be idle */
//      if (threaded)
//	pthread_mutex_lock (&stat_dump_cond_mutex);
//      else
//	{
//	  sprintf (curr_data_dir, "%s/LAST", basename);
//	  if (debug > 1)
//	    printf ("DEB: writing stats for uncomplete traces... ");
//	  trace_done ();
//	  if (do_udp)
//	    udptrace_done ();
//	   /*DB*/
//	    /*
//	       else 
//	       if (((elapsed (last_skypeprint_time, last_packet) )/1000.0/1000.0) >= 5.0 )
//	       {
//	       printf ("\nSono dentro !");
//	       last_skypeprint_time = last_packet;
//	       udptrace_part ();
//	       }
//	     */
//	    if (debug > 1)
//	    printf ("DEB: writing addresses... ");
//
//
//	  /* update average histos */
//
//
//	  /* swap since the frozen ones are printed out */
//	  swap_adx ();
//	  swap_histo ();
//	  if (global_histo)
//	    print_all_histo (HISTO_PRINT_GLOBAL);
//
//	  print_all_histo (HISTO_PRINT_CURRENT);
//	  print_adx ();
//
//	  clear_all_histo ();
//	}
//    }
//  /* close the input file */
//  CompCloseFile (filename);
//  get_stats_report(&report);
//  dump_internal_stats (&report, stdout);
}
#endif //TSTAT_RUNASLIB

void
QuitSig (int signum)
{
    tstat_report report;

  printf ("%c\n\n", 7);		/* BELL */
  printf ("Terminating processing early on signal %d\n", signum);
  printf ("Partial result after processing %lu packets:\n\n\n", pnum);

  if (threaded)
    pthread_mutex_lock (&stat_dump_cond_mutex);

  sprintf (curr_data_dir, "%s/LAST", basename);

  if (debug > 1)
    printf ("DEB: writing addresses... ");

  if (debug > 1)
    printf ("DEB: writing stats for uncomplete traces... ");
  trace_done ();
  if (do_udp)
    udptrace_done ();

  if (debug > 1)
    printf ("DEB: writing stats for complete traces... ");

/* update average histos */
  update_fake_histos ();

  /* swap since the frozen ones are printed out */
  swap_histo ();
  swap_adx ();
  if (global_histo)
    print_all_histo (HISTO_PRINT_GLOBAL);
  print_all_histo (HISTO_PRINT_CURRENT);
  print_adx ();

    get_stats_report(&report);
  //dump_internal_stats (&report, stderr);
  tstat_print_report(&report, stderr);
  if (threaded)
    pthread_mutex_unlock (&stat_dump_cond_mutex);
  exit (EXIT_FAILURE);
}


#ifdef MEMDEBUG
void memory_debug ();
#endif
void
Usr1Sig (int signum)
{
    tstat_report report;

  printf ("%c\n\n", 7);		/* BELL */
  printf ("Got a signal USR1\n");
  get_stats_report(&report);
  //dump_internal_stats(&report, stderr);
  tstat_print_report(&report, stderr);
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
        report->tot_adx_hash_count = tot_adx_hash_count;
        report->tot_adx_list_count = tot_adx_list_count;
        report->adx_search_hash_count = adx_search_hash_count;
        report->adx_search_list_count = adx_search_list_count;
        report->wallclock = etime;
        report->pcktspersec = (int) ((double) pnum / (etime / 1000000));
        report->flowspersec = (int) ((double) fcount / (etime / 1000000));
    }
    return report;
}

void
tstat_print_report (tstat_report *rep, FILE *wheref)
//dump_internal_stats (tstat_report *rep, FILE *wheref)
{
    /*
    double etime;
    gettimeofday (&wallclock_temp, NULL);
    etime = elapsed (wallclock_start, wallclock_temp);
    FILE *wheref = err ? stderr : stdout;
    */

    fprintf (wheref, "\n\nDumping internal status variables:\n");
    fprintf (wheref, "total packet analized : %ld\n", rep->pnum);
    fprintf (wheref, "total flows analized : %lu\n", rep->fcount);
    fprintf (wheref, "total TCP flows analized : %lu\n", rep->f_TCP_count);
    fprintf (wheref, "total UDP flows analized : %lu\n", rep->f_UDP_count);
    fprintf (wheref, "total RTP flows analized : %lu\n", rep->f_RTP_count);
    fprintf (wheref, "total RTCP flows analized : %lu\n", rep->f_RTCP_count);
    fprintf (wheref, "total tunneled RTP flows analized : %lu\n", 
            rep->f_RTP_tunneled_TCP_count); /*topix */
    fprintf (wheref, "total iteration spent in the hash search routine : %d\n",
            rep->search_count);
    fprintf (wheref, "total analyzed TCP packet: %ld \n", rep->tcp_packet_count);
    fprintf (wheref, "total analyzed UDP packet: %ld \n", rep->udp_trace_count);

    fprintf (wheref, "total trash TCP packet: %ld \n", rep->not_id_p);
    if (tcp_packet_count != 0)
        fprintf (wheref, "average TCP search length: %f\n", rep->avg_search);
    fprintf (wheref, "Current opened flows: TCP = %ld UDP = %ld\n",
            rep->tot_conn_TCP, rep->tot_conn_UDP);
    fprintf (wheref, "Current flow vector index: %d (%d)\n", 
            rep->num_tcp_pairs, MAX_TCP_PAIRS);
    fprintf (wheref, "Total adx used in hash: %ld \n", rep->tot_adx_hash_count);
    fprintf (wheref, "Total adx used in list: %ld \n", rep->tot_adx_list_count);
    fprintf (wheref, "Total adx hash search: %ld\n", rep->adx_search_hash_count);
    fprintf (wheref, "Total adx list search: %ld\n", rep->adx_search_list_count);
    fprintf (wheref, "elapsed wallclock time: %s\n", elapsed2str(rep->wallclock));
    fprintf (wheref, "%d pkts/sec analyzed\n", rep->pcktspersec);
    fprintf (wheref, "%d flows/sec analyzed\n", rep->flowspersec);

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
      perror ("Malloc failed, fatal\n");
      fprintf (stderr, "\
when memory allocation fails, it's either because:\n\
1) You're out of swap space, talk to your local sysadmin about making more\n\
   (look for system commands 'swap' or 'swapon' for quick fixes)\n\
2) The amount of memory that your OS gives each process is too little\n\
   That's a system configuration issue that you'll need to discuss\n\
   with the system administrator\n\
");
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
      fprintf (stderr,
	       "Realloc failed (%d bytes --> %d bytes), fatal\n",
	       obytes, nbytes);
      perror ("realloc");
      exit (EXIT_FAILURE);
    }
  if (obytes < nbytes)
    {
      memset ((char *) ptr + obytes, 0, nbytes - obytes);	/* BZERO */
    }

  return (ptr);
}


/* convert a buffer to an argc,argv[] pair */
void
StringToArgv (char *buf, int *pargc, char ***pargv)
{
  char **argv;
  int nargs = 0;

  /* discard the original string, use a copy */
  buf = strdup (buf);

  /* (very pessimistically) make the argv array */
  argv = malloc (sizeof (char *) * ((strlen (buf) / 2) + 1));

  /* skip leading blanks */
  while ((*buf != '\00') && (isspace ((int) *buf)))
    {
      if (debug > 10)
	printf ("skipping isspace('%c')\n", *buf);
      ++buf;
    }

  /* break into args */
  for (nargs = 1; *buf != '\00'; ++nargs)
    {
      char *stringend;
      argv[nargs] = buf;

      /* search for separator */
      while ((*buf != '\00') && (!isspace ((int) *buf)))
	{
	  if (debug > 10)
	    printf ("'%c' (%d) is NOT a space\n", *buf, (int) *buf);
	  ++buf;
	}
      stringend = buf;

      /* skip spaces */
      while ((*buf != '\00') && (isspace ((int) *buf)))
	{
	  if (debug > 10)
	    printf ("'%c' (%d) IS a space\n", *buf, (int) *buf);
	  ++buf;
	}

      *stringend = '\00';	/* terminate the previous string */

      if (debug)
	printf ("  argv[%d] = '%s'\n", nargs, argv[nargs]);
    }

  *pargc = nargs;
  *pargv = argv;
}



//===================================================================================
//  skip comment lines and take args from 1st file-line as from cmdline 
//-----------------------------------------------------------------------------------
/*
void
ArgsFromFile (const char *fname, int *_argc, char *_argv[])
{
  char ch, filestr[1024], tmpstr[1024];
  char *str, *str_end;
  int i = 0;
  FILE *f;

  f = fopen (fname, "r");
  if (f == NULL)
    {
      fprintf (stderr, "Cannot parse file <%s>\n", fname);
      exit (1);
    }
  while (!feof (f))
    {
      if ((ch = getc (f)) == EOL)
	continue;

      if (ch == '#')
	{
	  while ((ch = getc (f)) != EOL);
	  continue;

	}
      else
	{
	  if (feof (f))
	    break;
	  ungetc (ch, f);
	}

      if (fgets (tmpstr, 1024, f))
	break;
    }
  fclose (f);
  sprintf (filestr, "tstat %s", tmpstr);
  if (!strncmp (filestr + strlen (filestr) - 1, "\n", 1))
    filestr[strlen (filestr) - 1] = '\0';
  //fprintf(stderr,"%s\n",filestr);

  str = filestr;
  while (*str)
    {
      while (*str == ' ')
	*(str++) = '\0';
      if (*str)
	{
	  str_end = str;
	  while (*str_end && (*str_end != ' '))
	    str_end++;

	  snprintf (tmpstr, str_end - str + 1, "%s", str);
	  if (debug > 2)
	    fprintf (stderr, "ArgsFromFile[%d]=%s\n", i, tmpstr);

	  _argv[i] = strdup (tmpstr);
	  i++;

	  str = str_end;
	}
    }
  *_argc = i;
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
        fprintf(stderr, "'%s' - No such file\n", fname);
        exit(1);
    }

    //init argc/argv
    *pargc = 1;
    argv = malloc(sizeof(char *));
    argv[0] = strdup("tstat");
    
    //debug message
    //fprintf(stderr, "Reading options from %s\n", fname);

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
            //fprintf(stderr, "new option/param: %s\n", word);

            word = strtok(NULL, " \t\n");
        }
    }

    //debug message
    //fprintf(stderr, "Configuration file analized\n");
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
    /* remember the name of the program for errors... */
    progname = (*pargc == 1) ? "tstat" : argv[0];
    char **tmpargv, *fname;
    int i, tot_args;

    if (*pargc == 1)
    {
        fname = (strcmp(argv[0], "tstat") == 0) ? "tstat.conf" : argv[0];
        tmpargv = ArgsFromFile (fname, pargc);
        tot_args = *pargc;
        ParseArgs (pargc, tmpargv);
        //debug messages
        if (debug >= 2) {
            fprintf(stderr, "config: reading options from %s\n", fname);
            for (i = 0; i < tot_args; i++) {
                fprintf(stderr, "config: added option/param: %s\n", tmpargv[i]);
            }
            fprintf(stderr, "config: reading options completed\n");
        }
    }
    else
    {
        ParseArgs (pargc, argv);
    }

    /* make sure we found the files */
    if (filenames == NULL && 
        live_flag == FALSE && 
        dump_all_histo_definition == FALSE)
    {
        BadArg (NULL, "must specify at least one file name\n");
    }
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
#define GROK_LIVE_TCPDUMP_OPT "li:"
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

static void
ParseArgs (int *pargc, char *argv[])
{
  char bayes_dir[128];
  sprintf (bayes_dir, "skype");
  histo_set_conf (NULL);

#ifdef GROK_ERF_LIVE
  int num_dev;
  int dim;
  char *ptr_help;
#endif

    dump_conf_fname[0] = '\0';
  /* parse the args */
  while (1)
    {
      int option_index = 0;
      int c;
      static struct option long_options[] = {
	/* {option_name,has_arg(0=none,1=recquired,2=optional),flag,return_value} */
	/* see man getopt for details                                             */
	{"dag", 2, 0, 1},
	{0, 0, 0, 0}
      };

      c =
	getopt_long (*pargc, argv,
		     GROK_TCPDUMP_OPT GROK_LIVE_TCPDUMP_OPT GROK_DPMI_OPT
		     HAVE_RRDTOOL_OPT SUPPORT_IPV6_OPT
		     "B:N:H:s:T:gpdhtucSLvw21", long_options, &option_index);

      if (c == -1)
	break;

      if (debug > 2)
	fprintf (stderr, "ParseArgs[%d]=%s\n", optind, argv[optind]);

      switch (c)
	{
	case 'N':
	  /* -N file */
	  internal_net_file = strdup (optarg);
	  if (!LoadInternalNets (internal_net_file))
	    {
	      fprintf (stderr, "Error while loading configuration\n");
	      fprintf (stderr, "Could not open %s\n", internal_net_file);
	      exit (1);
	    }
	  net_conf = TRUE;
	  break;
#ifdef SUPPORT_IPV6
	case '6':
	  /* -6file */
	  internal_net_filev6 = strdup (optarg);

	  if (!LoadInternalNetsv6
	      (internal_net_filev6, &internal_net_listv6,
	       &tot_internal_netsv6))
	    {
	      fprintf (stderr,
		       "Error while loading IPv6 configuration file\n");
	      fprintf (stderr, "Could not open %s\n", internal_net_filev6);
	      exit (1);
	    }
	  break;
#endif
	case 'p':
	  threaded = TRUE;
	  break;
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
	  break;
#ifdef GROK_DPMI
	case 'D':
	  {
	    char *dpmi_conf = strdup (optarg);
	    if (!dpmi_parse_config (dpmi_conf))
	      {
		fprintf (stderr, "Error while loading DPMI configuration\n");
		fprintf (stderr, "Could not open %s\n", internal_net_file);
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
	    printf ("Capturing device set to %s\n", dev);
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
	    printf ("basenamedir set to %s\n", basenamedir);
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
		  fprintf (stderr,
			   "RRDTool database path <%s> exists\n", rrdpath);
	      }
	    else
	      {
		mkdir (rrdpath, 0775);
		if (debug)
		  fprintf (stderr,
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
		  fprintf (stderr,
			   "RRDTool configuration file <%s> found (delayed parsing)\n",
			   rrdconf);
		rrdtool_set_conf (rrdconf);
	      }
	    else
	      {
		fprintf (stderr, "Could not open %s\n", rrdconf);
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
      sprintf(dump_conf_fname, "%s", optarg);
      dump_engine = TRUE;
      break;

	case 'S':
	  histo_engine = FALSE;
	  break;
	case 'L':
	  log_engine = FALSE;
	  break;
        case '1':
          log_version = 1;
	  break;
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
		      fprintf (stderr,
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
	      printf ("\n Error in parsing long opt %d\n", option_index);
	      break;
	    }
	  break;

	default:
	  printf ("\n");
	  Help ();
	  exit (EXIT_FAILURE);
	}
    }

  filenames = &argv[optind];
  *pargc -= optind;


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
LoadInternalNets (char *file)
{
  int i;
  FILE *fp;
  char c[50];

  fp = fopen (file, "r");
  if (fp == NULL)
    {
      return 0;
    }

  i = 0;

  while (fgets (c, 20, fp) != NULL)
    {
      inet_aton (c, &(internal_net_list[i]));
      if (fgets (c, 20, fp) != NULL)
	{
	  inet_aton (c, &(internal_net_mask2[i]));
	  internal_net_mask[i] = inet_addr (c);
	}
      else
	{
	  printf ("Cannot parse mask for net %d\n", (i + 1));
	  return 0;
	}
      if (debug)
	{
	  printf ("Adding: %s as internal net ",
		  inet_ntoa (internal_net_list[i]));
	  printf ("with mask %s (%d)\n", inet_ntoa (internal_net_mask2[i]),
		  internal_net_mask[i]);
	}
      i++;
    }
  tot_internal_nets = i;
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

  //printf("Checking %s \n",inet_ntoa(adx));
  for (i = 0; i < tot_internal_nets; i++)
    {
      //printf(" Against: %s \n",inet_ntoa(internal_net_list[i]));
      if ((adx.s_addr & internal_net_mask[i]) == internal_net_list[i].s_addr)
	{
	  //printf("Internal: %s\n",inet_ntoa(adx));
	  return 1;
	}
    }
  //printf("External: %s\n",inet_ntoa(adx));
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
    printf ("Created thread stat_dumping()\n");
  pthread_mutex_lock (&stat_dump_mutex);
  pthread_mutex_lock (&stat_dump_cond_mutex);
  while (1)
    {
      pthread_cond_wait (&stat_dump_cond, &stat_dump_cond_mutex);
#ifdef DEBUG_THREAD
      printf ("\n\nSvegliato thread stats DUMP.\n");
#endif
      swap_adx ();
      /* update average histos */
      update_fake_histos ();

      swap_histo ();
      pthread_mutex_unlock (&stat_dump_mutex);
      usleep (200);

      /* Create the new path in curr_data_dir: its the base dir name plus
         the integrer step we reached so far. From 000 up to 999" */
      sprintf (curr_data_dir, "%s/%03d", basename, step);

      print_all_histo (HISTO_PRINT_CURRENT);	/* print out the data frozen histograms */
      print_adx ();

      clear_all_histo ();	/* then clear them */
      step++;

      /* In case we are processing live streams, create a new dir every
         DIRS steps */
      if (step >= DIRS && is_stdin)
	{
	  create_new_outfiles (NULL);
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
  swap_adx ();
  swap_histo ();
  sprintf (curr_data_dir, "%s/%03d", basename, step);

  // update GLOBAL every hour
  if (global_histo && step && !step % 1200)
    print_all_histo (HISTO_PRINT_GLOBAL);
  print_all_histo (HISTO_PRINT_CURRENT);
  print_adx ();

  clear_all_histo ();


  step++;

  /* In case we are processing live streams, create a new dir every
     DIRS steps */
  if (step >= DIRS && is_stdin)
    {
      create_new_outfiles (NULL);
      step = 0;
    }
}
