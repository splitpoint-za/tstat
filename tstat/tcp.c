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


#include "tstat.h"
#include "tcpL7.h"

/* provided globals  */
extern FILE *fp_logc;
extern FILE *fp_lognc;
extern FILE *fp_rtp_logc;

extern Bool is_stdin;
extern Bool printticks;
extern unsigned long int fcount;
extern unsigned long int f_TCP_count;
/* TOPIX */
extern unsigned long int f_RTP_tunneled_TCP_count;
extern struct L4_bitrates L4_bitrate;
/* end TOPIX */
extern Bool log_engine;
extern int log_version;

/* thread mutex and conditional variables  */
extern pthread_mutex_t ttp_lock_mutex;
extern pthread_mutex_t utp_lock_mutex;
extern pthread_mutex_t flow_close_cond_mutex;
extern pthread_mutex_t flow_close_started_mutex;
extern pthread_cond_t flow_close_cond;
extern pthread_mutex_t stat_dump_mutex;
extern pthread_mutex_t stat_dump_cond_mutex;
extern pthread_cond_t stat_dump_cond;
extern Bool threaded;
extern long int tcp_packet_count;


Bool thread_stats_flag = FALSE;	/* parameter used to make not possible that two
				   istances of the same thread can run at the same time */

/* tcp database stats */
long not_id_p;
int search_count = 0;

int num_tcp_pairs = 0;		/* how many pairs we've allocated */
tcp_pair **ttp = NULL;		/* array of pointers to allocated pairs */
struct tp_list_elem *tp_list_start = NULL;	/* starting point of the linked list */
struct tp_list_elem *tp_list_curr = NULL;	/* current insert point of the linked list */
u_long tcp_trace_count_outgoing = 0;
u_long tcp_trace_count_incoming = 0;
u_long tcp_trace_count_local = 0;


/* local routine definitions */
static tcp_pair **NewTTP_2 (struct ip *, struct tcphdr *);
static ptp_snap **FindTTP (struct ip *, struct tcphdr *, int *);
static void free_tp (tcp_pair * ptp_save);
static int ConnReset (tcp_pair *);
static int ConnComplete (tcp_pair *);
/*
static u_int SynCount (tcp_pair * ptp);
*/
static u_int FinCount (tcp_pair * ptp);

void update_conn_log_mm_v1 (tcp_pair *tcp_save, tcb *pab, tcb *pba);
void update_conn_log_mm_v2 (tcp_pair *tcp_save, tcb *pab, tcb *pba);



#ifdef CHECK_TCP_DUP
Bool
dup_tcp_check (struct ip *pip, struct tcphdr *ptcp, tcb * thisdir)
{
//  static int tot;
  double delta_t = elapsed (thisdir->last_time, current_time);
  if (thisdir->last_ip_id == pip->ip_id &&
      thisdir->last_checksum == ntohs(ptcp->th_sum) && 
      delta_t < MIN_DELTA_T_TCP_DUP_PKT && thisdir->last_len == pip->ip_len)
    {
 //      fprintf (fp_stdout, "dup tcp %d , id = %u ",tot++, pip->ip_id);
 //      fprintf (fp_stdout, "TTL: %d ID: %d Checksum: %d Delta_t: %g\n", 
 //           pip->ip_ttl,pip->ip_id,ntohs(ptcp->th_sum),delta_t);
      thisdir->last_ip_id = pip->ip_id;
      thisdir->last_len = pip->ip_len;
      thisdir->last_checksum = ntohs(ptcp->th_sum);
      return TRUE;
    }
 //   fprintf (fp_stdout, "NOT dup tcp %d\n",tot);
  thisdir->last_ip_id = pip->ip_id;
  thisdir->last_len = pip->ip_len;
  thisdir->last_checksum = ntohs(ptcp->th_sum);
  return FALSE;
}
#endif


void
tcp_header_stat (struct tcphdr *ptcp, struct ip *pip)
{

  /* perform TCP packet analysis */
  if ((!ACK_SET (ptcp) && SYN_SET (ptcp)))
    {
      if (internal_src && !internal_dst)
	{
	  add_histo (tcp_port_synsrc_out, (float) ntohs (ptcp->th_sport));
	  add_histo (tcp_port_syndst_out, (float) ntohs (ptcp->th_dport));
	}
      else if (!internal_src && internal_dst)
	{
	  add_histo (tcp_port_synsrc_in, (float) ntohs (ptcp->th_sport));
	  add_histo (tcp_port_syndst_in, (float) ntohs (ptcp->th_dport));
	}
      else if (internal_src && internal_dst)
	{
	  add_histo (tcp_port_synsrc_loc, (float) ntohs (ptcp->th_sport));
	  add_histo (tcp_port_syndst_loc, (float) ntohs (ptcp->th_dport));
	}
    }

  if (internal_src && !internal_dst)
    {
      L4_bitrate.out[TCP_TYPE] += ntohs (pip->ip_len);
      add_histo (tcp_port_src_out, (float) ntohs (ptcp->th_sport));
      add_histo (tcp_port_dst_out, (float) ntohs (ptcp->th_dport));
    }
  else if (!internal_src && internal_dst)
    {
      L4_bitrate.in[TCP_TYPE] += ntohs (pip->ip_len);
      add_histo (tcp_port_src_in, (float) ntohs (ptcp->th_sport));
      add_histo (tcp_port_dst_in, (float) ntohs (ptcp->th_dport));
    }
  else if (internal_src && internal_dst)
    {
      L4_bitrate.loc[TCP_TYPE] += ntohs (pip->ip_len);
      add_histo (tcp_port_src_loc, (float) ntohs (ptcp->th_sport));
      add_histo (tcp_port_dst_loc, (float) ntohs (ptcp->th_dport));
    }

  return;
}

/*
u_int
SynCount (tcp_pair * ptp)
{
  tcb *pab = &ptp->c2s;
  tcb *pba = &ptp->s2c;

  return (((pab->syn_count >= 1) ? 1 : 0) + ((pba->syn_count >= 1) ? 1 : 0));
}
*/


u_int
FinCount (tcp_pair * ptp)
{
  tcb *pab = &ptp->c2s;
  tcb *pba = &ptp->s2c;

  return (((pab->fin_count >= 1) ? 1 : 0) + ((pba->fin_count >= 1) ? 1 : 0));
}



/* copy the IP addresses and port numbers into an addrblock structure	*/
/* in addition to copying the address, we also create a HASH value	*/
/* which is based on BOTH IP addresses and port numbers.  It allows	*/
/* faster comparisons most of the time					*/
void
CopyAddr (tcp_pair_addrblock * ptpa,
	  struct ip *pip, portnum port1, portnum port2)
{
  ptpa->a_port = port1;
  ptpa->b_port = port2;

  if (PIP_ISV4 (pip))
    {				/* V4 */
      IP_COPYADDR (&ptpa->a_address, *IPV4ADDR2ADDR (&pip->ip_src));
      IP_COPYADDR (&ptpa->b_address, *IPV4ADDR2ADDR (&pip->ip_dst));
      /* fill in the hashed address */
      ptpa->hash = ptpa->a_address.un.ip4.s_addr
	+ ptpa->b_address.un.ip4.s_addr + ptpa->a_port + ptpa->b_port;
    }
#ifdef SUPPORT_IPV6
  else
    {				/* V6 */
      int i;
      struct ipv6 *pip6 = (struct ipv6 *) pip;
      IP_COPYADDR (&ptpa->a_address, *IPV6ADDR2ADDR (&pip6->ip6_saddr));
      IP_COPYADDR (&ptpa->b_address, *IPV6ADDR2ADDR (&pip6->ip6_daddr));
      /* fill in the hashed address */
      ptpa->hash = ptpa->a_port + ptpa->b_port;
      for (i = 0; i < 16; ++i)
	{
	  ptpa->hash += ptpa->a_address.un.ip6.s6_addr[i];
	  ptpa->hash += ptpa->b_address.un.ip6.s6_addr[i];
	}
    }
#endif
}



int
WhichDir (tcp_pair_addrblock * ptpa1, tcp_pair_addrblock * ptpa2)
{

#ifdef BROKEN_COMPILER
  /* sorry for the ugly nested 'if', but a 4-way conjunction broke my */
  /* Optimizer (under 'gcc version cygnus-2.0.2')                     */

  /* same as first packet */
  if (IP_SAMEADDR (ptpa1->a_address, ptpa2->a_address))
    if (IP_SAMEADDR (ptpa1->b_address, ptpa2->b_address))
      if ((ptpa1->a_port == ptpa2->a_port))
	if ((ptpa1->b_port == ptpa2->b_port))
	  return (C2S);

  /* reverse of first packet */
  if (IP_SAMEADDR (ptpa1->a_address, ptpa2->b_address))
    if (IP_SAMEADDR (ptpa1->b_address, ptpa2->a_address))
      if ((ptpa1->a_port == ptpa2->b_port))
	if ((ptpa1->b_port == ptpa2->a_port))
	  return (S2C);
#else /* BROKEN_COMPILER */
  /* same as first packet */
  if (IP_SAMEADDR (ptpa1->a_address, ptpa2->a_address) &&
      IP_SAMEADDR (ptpa1->b_address, ptpa2->b_address) &&
      (ptpa1->a_port == ptpa2->a_port) && (ptpa1->b_port == ptpa2->b_port))
    return (C2S);

  /* reverse of first packet */
  if (IP_SAMEADDR (ptpa1->a_address, ptpa2->b_address) &&
      IP_SAMEADDR (ptpa1->b_address, ptpa2->a_address) &&
      (ptpa1->a_port == ptpa2->b_port) && (ptpa1->b_port == ptpa2->a_port))
    return (S2C);
#endif /* BROKEN_COMPILER */

  /* different connection */
  return (0);
}

int
SameConn (tcp_pair_addrblock * ptpa1, tcp_pair_addrblock * ptpa2, int *pdir)
{
  /* if the hash values are different, they can't be the same */
  if (ptpa1->hash != ptpa2->hash)
    return (0);

  /* OK, they hash the same, are they REALLY the same function */
  *pdir = WhichDir (ptpa1, ptpa2);
  return (*pdir != 0);
}

int
ConnComplete (tcp_pair * ptp)
{
  return (ptp->c2s.closed && ptp->s2c.closed);
}


int
ConnReset (tcp_pair * ptp)
{
  return (ptp->c2s.reset_count + ptp->s2c.reset_count != 0);
}


extern Bool warn_MAX_;
static tcp_pair **
NewTTP_2 (struct ip *pip, struct tcphdr *ptcp)
{
  tcp_pair *ptp;
  int old_new_tcp_pairs = num_tcp_pairs;
  int steps = 0;

  /* look for the next eventually available free block */
  num_tcp_pairs++;
  num_tcp_pairs = num_tcp_pairs % MAX_TCP_PAIRS;
  /* make a new one, if possible */
  while ((num_tcp_pairs != old_new_tcp_pairs) && (ttp[num_tcp_pairs] != NULL)
	 && (steps < LIST_SEARCH_DEPT))
    {
      steps++;
      /* look for the next one */
//         fprintf (fp_stdout, "%d %d\n", num_tcp_pairs, old_new_tcp_pairs);
      num_tcp_pairs++;
      num_tcp_pairs = num_tcp_pairs % MAX_TCP_PAIRS;
    }
  if (ttp[num_tcp_pairs] != NULL)
    {
      if (warn_MAX_)
	{
	  fprintf (fp_stderr, "\n" 
	    "ooopsss: number of simultaneous connection opened is greater then the maximum supported number!\n"
	    "you have to rebuild the source with a larger LIST_SEARCH_DEPT defined!\n"
	    "or possibly with a larger MAX_TCP_PAIRS defined!\n");
	}
      warn_MAX_ = FALSE;
      return (NULL);
    }

  /* create a new TCP pair record and remember where you put it */
  ptp = ttp[num_tcp_pairs] = tp_alloc ();

  /* grab the address from this packet */
  CopyAddr (&ptp->addr_pair,
	    pip, ntohs (ptcp->th_sport), ntohs (ptcp->th_dport));

  ptp->c2s.time.tv_sec = -1;
  ptp->s2c.time.tv_sec = -1;
  /* a.c */
  ptp->s2c.closed = FALSE;
  ptp->c2s.closed = FALSE;

  ptp->c2s.ptp = ptp;
  ptp->s2c.ptp = ptp;

  ptp->c2s.min_jitter = MAXFLOAT;
  ptp->s2c.min_jitter = MAXFLOAT;

  ptp->internal_src = internal_src;
  ptp->internal_dst = internal_dst;

  /* Initialize the state */
  ptp->con_type = 0;
  ptp->state = UNKNOWN_TYPE;
  ptp->p2p_type = 0;
  ptp->p2p_state = UNKNOWN_TYPE;
  ptp->ignore_dpi = FALSE;

  return (&ttp[num_tcp_pairs]);
}

static ptp_snap *
NewPTPH_2 (void)
{
  return (ptph_alloc ());
}


void *
time_out_flow_closing ()
{
  if (debug > 0)
    fprintf (fp_stdout, "Created thread time_out_flow_closing()\n");
  pthread_mutex_lock (&flow_close_started_mutex);
  pthread_mutex_lock (&flow_close_cond_mutex);
  while (1)
    {
      pthread_cond_wait (&flow_close_cond, &flow_close_cond_mutex);
#ifdef DEBUG_THREAD
      fprintf (fp_stdout, "\n\nSvegliato thread FLOW CLOSE\n");
#endif
      pthread_mutex_unlock (&flow_close_started_mutex);

      usleep (200);
      trace_done_periodic ();

      pthread_mutex_lock (&flow_close_started_mutex);
#ifdef DEBUG_THREAD
      fprintf (fp_stdout, "\n\nTerminato thread FLOW CLOSE\n");
#endif
    }
  pthread_exit (NULL);
}



/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/

ptp_snap *ptp_hashtable[HASH_TABLE_SIZE] = { NULL };

static ptp_snap **
FindTTP (struct ip *pip, struct tcphdr *ptcp, int *pdir)
{

  ptp_snap **pptph_head = NULL;
  ptp_snap *ptph;
  ptp_snap *ptph_last;
  static tcp_pair **temp_ttp;

  tcp_pair_addrblock tp_in;
  int dir;
  hash hval;

  int prof_curr_clk;
  struct timeval prof_tm;
  double prof_curr_tm;
  struct tms prof_curr_tms;
  double cpu_sys,cpu_usr;

  /* grab the address from this packet */
  CopyAddr (&tp_in, pip, ntohs (ptcp->th_sport), ntohs (ptcp->th_dport));

  /* grab the hash value (already computed by CopyAddr) */
  hval = tp_in.hash % HASH_TABLE_SIZE;

  ptph_last = NULL;
  pptph_head = &ptp_hashtable[hval];


  for (ptph = *pptph_head; ptph; ptph = ptph->next)
    {
      ++search_count;

      if (SameConn (&tp_in, &ptph->addr_pair, &dir))
	{
	  /* OK, this looks good, suck it into memory */
	  tcp_pair *ptp = ptph->ptp;
	  tcb *thisdir;
	  tcb *otherdir;


	  /* figure out which direction this packet is going */
	  if (dir == C2S)
	    {
	      thisdir = &ptp->c2s;
	      otherdir = &ptp->s2c;
	    }
	  else
	    {
	      thisdir = &ptp->s2c;
	      otherdir = &ptp->c2s;
	    }

	  /* move to head of access list (unless already there) */
	  if (ptph != *pptph_head)
	    {
	      ptph_last->next = ptph->next;	/* unlink */
	      ptph->next = *pptph_head;	/* move to head */
	      *pptph_head = ptph;
	    }
	  *pdir = dir;
	  return (pptph_head);
	}
      ptph_last = ptph;
    }

  /* Didn't find it, make a new one, if possible */

  if (!(SYN_SET (ptcp) && !ACK_SET (ptcp)))
    {
      /* the new connection must begin with a SYN */
      if (debug > 1)
	{
	  fprintf (fp_stdout, 
        "** trash TCP packet: it does not belong to any known flows\n");
	}
      not_id_p++;
      return (NULL);
    }

  if (debug > 1)
    {
      fprintf (fp_stdout, "tracing a new TCP flow\n");
    }

    if (profile_cpu -> flag == HISTO_ON) {
        prof_curr_clk = (int)clock();
        gettimeofday(&prof_tm, NULL);
        prof_curr_tm = time2double(prof_tm)/1e6;
        times(&prof_curr_tms);
        
        
        if (prof_curr_tm - prof_last_tm > PROFILE_IDLE) {
            /* system cpu */
            cpu_sys = 1.0 * (prof_curr_tms.tms_stime - prof_last_tms.tms_stime) / prof_cps /
                  (prof_curr_tm - prof_last_tm) * 100;
            AVE_new_step(prof_tm, &ave_win_sys_cpu, cpu_sys);
            // system + user cpu 
            //cpu = 1.0 * (prof_curr_clk - prof_last_clk) / CLOCKS_PER_SEC / 
            //      (prof_curr_tm - prof_last_tm) * 100;
            //AVE_new_step(prof_tm, &ave_win_usrsys_cpu, cpu);
            cpu_usr = 1.0 * (prof_curr_tms.tms_utime - prof_last_tms.tms_utime) / prof_cps /
                  (prof_curr_tm - prof_last_tm) * 100;
            AVE_new_step(prof_tm, &ave_win_usr_cpu, cpu_usr);
        
            prof_last_tm = prof_curr_tm;
            prof_last_clk = prof_curr_clk; 
            prof_last_tms = prof_curr_tms;
            max_cpu = (max_cpu < (cpu_usr+cpu_sys)) ? cpu_usr+cpu_sys : max_cpu;
            //printf("cpu:%.2f max:%.2f\n", cpu, max_cpu);
        }
    }
    
    

  // we fire it at DOUBLE rate, but actually clean only those > TCP_IDLE_TIME
#ifdef WIPE_TCP_SINGLETONS
  if (elapsed (last_cleaned, current_time) > TCP_SINGLETON_TIME / 2)
#else
  if (elapsed (last_cleaned, current_time) > TCP_IDLE_TIME / 2)
#endif
    {
      if (threaded)
	{
	  pthread_mutex_unlock (&ttp_lock_mutex);
	  pthread_mutex_lock (&flow_close_cond_mutex);
#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "TCP_IDLE_TIME fired: Signaling thread FLOW CLOSE\n");
#endif
	  pthread_cond_signal (&flow_close_cond);
	  pthread_mutex_unlock (&flow_close_cond_mutex);

	  pthread_mutex_lock (&flow_close_started_mutex);
	  pthread_mutex_unlock (&flow_close_started_mutex);
#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "\n\nlocked thread FLOW CLOSE\n");
#endif
	  pthread_mutex_lock (&ttp_lock_mutex);
	}
      else
	trace_done_periodic ();

      last_cleaned = current_time;
    }


  add_histo (L4_flow_number, L4_FLOW_TCP);
  fcount++;
  f_TCP_count++;

  if (threaded)
    {
#ifdef DEBUG_THREAD
      fprintf (fp_stdout, "\n\nTry to lock thread TTP\n");
#endif
      pthread_mutex_lock (&ttp_lock_mutex);
#ifdef DEBUG_THREAD
      fprintf (fp_stdout, "\n\nGot lock thread TTP\n");
#endif
    }

  temp_ttp = NewTTP_2 (pip, ptcp);
  if (temp_ttp == NULL)		/* not enough memory to store the new flow */
    {
      /* the new connection must begin with a SYN */
      if (debug > 0)
	{
	  fprintf (fp_stdout, 
        "** out of memory when creating flows - considering a not_id_p\n");
	}
      not_id_p++;

    /* profile number of missed TCP session */
    if (profile_flows->flag == HISTO_ON)
        AVE_arrival(current_time, &missed_flows_win_TCP);

      return (NULL);
    }
  if (profile_flows->flag == HISTO_ON)
    AVE_arrival(current_time, &active_flows_win_TCP);
  tot_conn_TCP++;
  ptph = NewPTPH_2 ();
  ptph->ttp_ptr = temp_ttp;
  ptph->ptp = *(ptph->ttp_ptr);
  ptph->ptp->id_number = f_TCP_count;

  ptph->addr_pair = ptph->ptp->addr_pair;

  /* put at the head of the access list */
  ptph->next = *pptph_head;
  *pptph_head = ptph;

  *pdir = C2S;


  if (threaded)
    {
      pthread_mutex_unlock (&ttp_lock_mutex);
#ifdef DEBUG_THREAD
      fprintf (fp_stdout, "\n\nUnlocked thread TTP\n");
#endif
    }

  /* return the new ptph */
  return (pptph_head);
}

int
tcp_flow_stat (struct ip * pip, struct tcphdr * ptcp, void *plast, int *dir)
{
  struct tcp_options *ptcpo;
  tcp_pair *ptp_save;
  ptp_snap **ptph_ptr;
  ptp_snap *ptph_save;
  ptp_snap *ptph_tmp;
  int tcp_length;
  int tcp_data_length;
  u_long start;
  u_long end;
  tcb *thisdir;
  tcb *otherdir;
  tcp_pair tp_in;
  Bool retrans;
  Bool ecn_ce = FALSE;
  Bool ecn_echo = FALSE;
  Bool cwr = FALSE;
  int retrans_num_bytes;
  Bool out_order;		/* out of order */
  u_short th_sport;		/* source port */
  u_short th_dport;		/* destination port */
  tcp_seq th_seq;		/* sequence number */
  tcp_seq th_ack;		/* acknowledgement number */
  u_short th_win;		/* window */
  u_long eff_win;		/* window after scaling */
  short ip_len;			/* total length */
  enum t_ack ack_type = NORMAL;	/* how should we draw the ACK */
   /*TOPIX*/ double delta_t = 0;
  /*end TOPIX */

  /* make sure we have enough of the packet */
  if ((unsigned long) ptcp + sizeof (struct tcphdr) - 1 >
      (unsigned long) plast)
    {
      if (warn_printtrunc)
	fprintf (fp_stderr,
		 "TCP packet %lu truncated too short (%ld) to trace, ignored\n",
		 pnum,
		 (unsigned long) ptcp + sizeof (struct tcphdr) -
		 (unsigned long) plast);
      ++ctrunc;
      return (FLOW_STAT_SHORT);
    }


  /* convert interesting fields to local byte order */
  th_seq = ntohl (ptcp->th_seq);
  th_ack = ntohl (ptcp->th_ack);
  th_sport = ntohs (ptcp->th_sport);
  th_dport = ntohs (ptcp->th_dport);
  th_win = ntohs (ptcp->th_win);
  ip_len = gethdrlength (pip, plast) + getpayloadlength (pip, plast);


  /* make sure this is one of the connections we want */
  ptph_ptr = FindTTP (pip, ptcp, dir);

  /* if the connection is not to be analyzed return a NULL */
  if (ptph_ptr == NULL)
    {
      return (FLOW_STAT_NULL);
    }

  ptph_save = (*ptph_ptr);
  ptp_save = ptph_save->ptp;


  if (ptp_save == NULL)
    {
      return (FLOW_STAT_NULL);
    }

  if (internal_src && !internal_dst)
    {
      ++tcp_trace_count_outgoing;
    }
  else if (!internal_src && internal_dst)
    {
      ++tcp_trace_count_incoming;
    }
  else if (internal_src && internal_dst)
    {
      ++tcp_trace_count_local;
    }


  /* do time stats */
  if (ZERO_TIME (&ptp_save->first_time))
    {
      ptp_save->first_time = current_time;
    }
  ptp_save->last_time = current_time;



  /* bug fix:  it's legal to have the same end points reused.  The */
  /* program uses a heuristic of looking at the elapsed time from */
  /* the last packet on the previous instance and the number of FINs */
  /* in the last instance.  If we don't increment the fin_count */
  /* before bailing out in "ignore_pair" below, this heuristic breaks */

  /* figure out which direction this packet is going */
  if (*dir == C2S)
    {
      thisdir = &ptp_save->c2s;
      otherdir = &ptp_save->s2c;
    }
  else
    {
      thisdir = &ptp_save->s2c;
      otherdir = &ptp_save->c2s;
    }

#ifdef CHECK_TCP_DUP
  /* check if this is a dupe udp */
  if (dup_tcp_check (pip, ptcp,thisdir)) {
    return(FLOW_STAT_DUP);
  }
#endif

  /* meta connection stats */
  if (SYN_SET (ptcp))
    ++thisdir->syn_count;
  if (RESET_SET (ptcp))
    ++thisdir->reset_count;
  if (FIN_SET (ptcp))
    {
      ++thisdir->fin_count;
      thisdir->fin_seqno = th_seq;
    }
  /* sanity check - stop tracking this flow if we got a SYN */
  /* from the client, no SYN+ACK from the server */
  /* and this is a data packet from the client */
  /* indeed, if no SYN+ACK has been seen, then this must be an */
  /* half flow... force a false RST message to close this flow */

  if ((*dir == C2S) && (!SYN_SET (ptcp)) && (otherdir->syn_count == 0))
    {
       ptp_save->ignore_dpi = TRUE;
    }

#ifndef LOG_HALFDUPLEX
  if ((*dir == C2S) && (!SYN_SET (ptcp)) && (otherdir->syn_count == 0))
    {
      //fprintf (fp_stdout, "  Closing a half duplex flow\n");
      if (profile_flows->flag == HISTO_ON)
        AVE_departure(current_time, &active_flows_win_TCP);
      tot_conn_TCP--;
      make_conn_stats (ptp_save,
		       (ptp_save->s2c.syn_count > 0
			&& ptp_save->c2s.syn_count > 0));

      /* free up memory for this flow */

      if (threaded)
	{
#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "\n\nRichiesto blocco thread TTP\n");
#endif
	  pthread_mutex_lock (&ttp_lock_mutex);
#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "\n\nOttenuto blocco thread TTP\n");
#endif
	}
      free_tp (ptp_save);

      /* free up the first element of the list pointer by the hash */
      ptph_tmp = ptph_save;
      *(ptph_save->ttp_ptr) = NULL;
      *ptph_ptr = ptph_save->next;
      ptph_release (ptph_tmp);
      if (threaded)
	{
#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "\n\nRichiesto sblocco thread TTP\n");
#endif
	  pthread_mutex_unlock (&ttp_lock_mutex);
#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "\n\nOttenuto sblocco thread TTP\n");
#endif
	}

      return (FLOW_STAT_OK);
    }
#endif

  if ((ACK_SET (ptcp)) &&
      (otherdir->fin_count >= 1) && (th_ack >= (otherdir->fin_seqno + 1)))
    {
      // This is the ACK to the FIN
      otherdir->closed = TRUE;
    }

  if (ACK_SET (ptcp) && otherdir->cwnd_flag)
    {
      add_histo (tcp_cwnd, (otherdir->seq - thisdir->ack));

      /* we already counted this flight-size, then do not 
       * consider it anymore until some new data will be received on the
       * backward direction.
       */
      otherdir->cwnd_flag = 0;
    }

  /* compute the "effective window", which is the advertised window */
  /* with scaling */
  if (ACK_SET (ptcp) || SYN_SET (ptcp))
    {
      eff_win = (u_long) th_win;

      /* N.B., the window_scale stored for the connection DURING 3way */
      /* handshaking is the REQUESTED scale.  It's only valid if both */
      /* sides request scaling.  AFTER we've seen both SYNs, that field */
      /* is reset (above) to contain zero.  Note that if we */
      /* DIDN'T see the SYNs, the windows will be off. */
      if (thisdir->f1323_ws && otherdir->f1323_ws)
	eff_win <<= thisdir->window_scale;
    }
  else
    {
      eff_win = 0;
    }


  /* idle-time stats */
  if (!ZERO_TIME (&thisdir->last_time))
    {
      u_llong itime = elapsed (thisdir->last_time, current_time);
      if (itime > thisdir->idle_max)
	thisdir->idle_max = itime;
      delta_t = (double) itime;
    }
  thisdir->last_time = current_time;


  /* calculate data length */
  tcp_length = getpayloadlength (pip, plast);
  tcp_data_length = tcp_length - (4 * ptcp->th_off);

  /* congestion window 
   * This is a new data segment which enable the cwnd evaluation
   */
  if ((tcp_data_length != 0) || SYN_SET (ptcp) || FIN_SET (ptcp)
      || RESET_SET (ptcp))
    {
      thisdir->cwnd_flag = 1;
    }

  /* calc. data range */
  start = th_seq;
  end = start + tcp_data_length;

  /* record sequence limits */
  if (SYN_SET (ptcp))
    {
      /* error checking - better not change! */
      if ((thisdir->syn_count > 1) && (thisdir->syn != start))
	{
	  /* it changed, that shouldn't happen! */
	  if (warn_printbad_syn_fin_seq)
	    fprintf (fp_stderr,
		     "rexmitted SYN had diff. seqnum! (was %lu, now %lu, etime: %d sec)\n",
		     thisdir->syn, start,
		     (int) (elapsed (ptp_save->first_time, current_time) /
			    1000000));
	  thisdir->bad_behavior = TRUE;
	}
      thisdir->syn = start;
      otherdir->ack = start;
      /* bug fix for Rob Austein <sra@epilogue.com> */
    }
  if (FIN_SET (ptcp))
    {
      /* bug fix, if there's data here too, we need to bump up the FIN */
      /* (psc data file shows example) */
      u_long fin = start + tcp_data_length;
      /* error checking - better not change! */
      if ((thisdir->fin_count > 1) && (thisdir->fin != fin))
	{
	  /* it changed, that shouldn't happen! */
	  if (warn_printbad_syn_fin_seq)
	    fprintf (fp_stderr,
		     "rexmitted FIN had diff. seqnum! (was %lu, now %lu, etime: %d sec)\n",
		     thisdir->fin, fin,
		     (int) (elapsed (ptp_save->first_time, current_time) /
			    1000000));
	  thisdir->bad_behavior = TRUE;
	}
      thisdir->fin = fin;
    }

  /* "ONLY" bug fix - Wed Feb 24, 1999 */
  /* the tcp-splicing heuristic needs "windowend", which was only being */
  /* calculated BELOW the "only" point below.  Move that part of the */
  /* calculation up here! */

  if (ACK_SET (ptcp))
    {
      thisdir->windowend = th_ack + eff_win;
    }
  /* end bugfix */

  /* grab the address from this packet */
  CopyAddr (&tp_in.addr_pair, pip, th_sport, th_dport);


  /* check the options */
  ptcpo = ParseOptions (ptcp, plast);
  if (ptcpo->mss != -1)
    thisdir->mss = ptcpo->mss;
  if (ptcpo->ws != -1)
    {
      thisdir->window_scale = ptcpo->ws;
      thisdir->f1323_ws = TRUE;
    }
  if (ptcpo->tsval != -1)
    {
      thisdir->f1323_ts = TRUE;
    }
  /* NOW, unless BOTH sides asked for window scaling in their SYN     */
  /* segments, we aren't using window scaling */
  if (!SYN_SET (ptcp) && ((!thisdir->f1323_ws) || (!otherdir->f1323_ws)))
    {
      thisdir->window_scale = otherdir->window_scale = 0;
    }

  /* check sacks */
  if (ptcpo->sack_req)
    {
      thisdir->fsack_req = 1;
    }
  if (ptcpo->sack_count > 0)
    {
      ++thisdir->sacks_sent;
    }

  if (*dir == C2S)
    ptp_save->c2s.ip_bytes += ip_len;
  else
    ptp_save->s2c.ip_bytes += ip_len;

  /* do data stats */
  if (tcp_data_length > 0)
    {
      thisdir->data_pkts += 1;
      if (PUSH_SET (ptcp))
	thisdir->data_pkts_push += 1;
      thisdir->data_bytes += tcp_data_length;
      if (tcp_data_length > thisdir->max_seg_size)
	thisdir->max_seg_size = tcp_data_length;
      if ((thisdir->min_seg_size == 0) ||
	  (tcp_data_length < thisdir->min_seg_size))
	thisdir->min_seg_size = tcp_data_length;
      /* record first and last times for data (Mallman) */
      if (ZERO_TIME (&thisdir->first_data_time))
	thisdir->first_data_time = current_time;
      thisdir->last_data_time = current_time;
    }

  /*TTL stats */
  if ((thisdir->ttl_min == 0) || (thisdir->ttl_min > (int) pip->ip_ttl))
    thisdir->ttl_min = (int) pip->ip_ttl;
  if (thisdir->ttl_max < (int) pip->ip_ttl)
    thisdir->ttl_max = (int) pip->ip_ttl;

   /*TOPIX*/ thisdir->ttl_tot += (u_llong) pip->ip_ttl;
   /*TOPIX*/
    /* total packets stats */
    ++ptp_save->packets;
  ++thisdir->packets;

  /* set minimum seq */
  if ((thisdir->min_seq == 0) && (start != 0))
    {
      thisdir->min_seq = start;
    }
  thisdir->max_seq = end;


  /* Kevin Lahey's ECN code */
  /* only works for IPv4 */
  if (PIP_ISV4 (pip))
    {
      ecn_ce = IP_ECT (pip) && IP_CE (pip);
    }
  cwr = CWR_SET (ptcp);
  ecn_echo = ECN_ECHO_SET (ptcp);

  /* do rexmit stats */
  retrans = FALSE;
  out_order = FALSE;
  retrans_num_bytes = 0;
  if (SYN_SET (ptcp) || FIN_SET (ptcp) || tcp_data_length > 0)
    {
      int len = tcp_data_length;
      int retrans;
      if (SYN_SET (ptcp))
	++len;
      if (FIN_SET (ptcp))
	++len;

      retrans = retrans_num_bytes =
	rexmit (thisdir, start, len, &out_order, pip->ip_id);

      /* count anything NOT retransmitted as "unique" */
      /* exclude SYN and FIN */
      if (SYN_SET (ptcp))
	{
	  /* don't count the SYN as data */
	  --len;
	  /* if the SYN was rexmitted, then don't count it */
	  if (thisdir->syn_count > 1)
	    --retrans;
	}
      if (FIN_SET (ptcp))
	{
	  /* don't count the FIN as data */
	  --len;
	  /* if the FIN was rexmitted, then don't count it */
	  if (thisdir->fin_count > 1)
	    --retrans;
	}
      if (retrans < len)
	thisdir->unique_bytes += (len - retrans);

    }
  if (out_order)
    thisdir->out_order_pkts++;

   /*TOPIX*/
    /* delta_t evaluation if packets are data packets */
    if (tcp_data_length > 0)
    {
      double jitter;
      /* delta_t in milliseconds */
      delta_t = delta_t / 1000.0;
      thisdir->sum_delta_t += delta_t;
      thisdir->n_delta_t++;
      jitter = delta_t - thisdir->sum_delta_t / thisdir->n_delta_t;
      if (jitter < 0)
	jitter = -jitter;
      thisdir->sum_jitter += jitter;
      if (thisdir->max_jitter < jitter)
	thisdir->max_jitter = jitter;
      if (thisdir->min_jitter > jitter)
	thisdir->min_jitter = jitter;

    }
  /*end TOPIX */


  /* do rtt stats */
  if (ACK_SET (ptcp))
    {
      ack_type = ack_in (otherdir, th_ack, tcp_data_length);
    }

  /* stats for rexmitted data */
  if (retrans_num_bytes > 0)
    {
      retrans = TRUE;
      thisdir->rexmit_pkts += 1;
      thisdir->rexmit_bytes += retrans_num_bytes;
    }
  else
    {
      thisdir->seq = end;
    }

  /* check for RESET */
  if (RESET_SET (ptcp))
    {

      if (ACK_SET (ptcp))
	++thisdir->ack_pkts;

      if (ConnReset (ptp_save))
	{
	  //fprintf (fp_stdout, "  (new reset)\n");
      if (profile_flows->flag == HISTO_ON)
        AVE_departure(current_time, &active_flows_win_TCP);
	  tot_conn_TCP--;
	  make_conn_stats (ptp_save,
			   (ptp_save->s2c.syn_count > 0
			    && ptp_save->c2s.syn_count > 0));

	  /* free up memory for this flow */

	  if (threaded)
	    {
#ifdef DEBUG_THREAD
	      fprintf (fp_stdout, "\n\nRichiesto blocco thread TTP\n");
#endif
	      pthread_mutex_lock (&ttp_lock_mutex);
#ifdef DEBUG_THREAD
	      fprintf (fp_stdout, "\n\nOttenuto blocco thread TTP\n");
#endif
	    }
	  free_tp (ptp_save);

	  /* free up the first element of the list pointer by the hash */
	  ptph_tmp = ptph_save;
	  *(ptph_save->ttp_ptr) = NULL;
	  *ptph_ptr = ptph_save->next;
	  ptph_release (ptph_tmp);
	  if (threaded)
	    {
#ifdef DEBUG_THREAD
	      fprintf (fp_stdout, "\n\nRichiesto sblocco thread TTP\n");
#endif
	      pthread_mutex_unlock (&ttp_lock_mutex);
#ifdef DEBUG_THREAD
	      fprintf (fp_stdout, "\n\nOttenuto sblocco thread TTP\n");
#endif
	    }
	}

      /* make upper layer protocol analysis and update the classified bitrate */

      proto_analyzer (pip, ptcp, PROTOCOL_TCP, thisdir, *dir, plast);

      if (thisdir != NULL && thisdir->ptp != NULL)
        make_tcpL7_rate_stats(thisdir->ptp, ntohs (pip->ip_len));

      return (FLOW_STAT_OK);
    }


  /* do window stats (include first SYN too!) */
  if (ACK_SET (ptcp) || SYN_SET (ptcp))
    {
      thisdir->win_curr = eff_win;
      if (eff_win > thisdir->win_max)
	thisdir->win_max = eff_win;
      if ((eff_win > 0) &&
	  ((thisdir->win_min == 0) || (eff_win < thisdir->win_min)))
	thisdir->win_min = eff_win;
      thisdir->win_tot += eff_win;
    }

  if (ACK_SET (ptcp))
    {
      seqnum ack = th_ack;
      u_long winend;

      winend = ack + eff_win;

      if (eff_win == 0)
	++thisdir->win_zero_ct;

      ++thisdir->ack_pkts;
      if ((tcp_data_length == 0) &&
	  !SYN_SET (ptcp) && !FIN_SET (ptcp) && !RESET_SET (ptcp))
	{
	  ++thisdir->pureack_pkts;
	}

      thisdir->time = current_time;
      thisdir->ack = ack;

    }

  /* do stats for initial window (first slow start) */
  /* (if there's data in this and we've NEVER seen */
  /*  an ACK coming back from the other side) */
  /* this is for Mark Allman for slow start testing -- Mon Mar 10, 1997 */
  if (!otherdir->data_acked && ACK_SET (ptcp)
      && ((otherdir->syn + 1) != th_ack))
    {
      otherdir->data_acked = TRUE;
    }
  if ((tcp_data_length > 0) && (!thisdir->data_acked))
    {
      if (!retrans)
	{
	  /* don't count it if it was retransmitted */
	  thisdir->initialwin_bytes += tcp_data_length;
	  thisdir->initialwin_segs += 1;
	}
    }

  if (SYN_SET (ptcp) && !ACK_SET (ptcp))
    {
      thisdir->highest_seqno = thisdir->max_seq;
    }

  /* check if this segment is carrying the first data */
  if (thisdir->payload_start_time.tv_sec == 0 &&
      thisdir->payload_start_time.tv_usec == 0 && tcp_data_length != 0)
    {
      thisdir->payload_start_time = current_time;
    }

  /* check if this segment is carrying new or retransmitted data */
  if (tcp_data_length != 0)
    {
      thisdir->payload_end_time = current_time;
    }

  /* do stats for congestion window (estimated) */
  /* estimate the congestion window as the number of outstanding */
  /* un-acked bytes */
  if (!SYN_SET (ptcp) && !out_order && !retrans)
    {
      u_long cwin = end - otherdir->ack;

      if (cwin > thisdir->cwin_max)
	thisdir->cwin_max = cwin;
      if ((cwin > 0) &&
	  ((thisdir->cwin_min == 0) || (cwin < thisdir->cwin_min)))
	thisdir->cwin_min = cwin;
    }

  /* Count TCP messages and track message sizes.
     We split messages on PSH segments 
  */
  if (ACK_SET(ptcp))
   {
     if ( (PUSH_SET(ptcp)||FIN_SET(ptcp)) && 
           thisdir->msg_last_seq < thisdir->seq) 
      {
        u_int curr_msg_size = thisdir->msg_last_seq==0 ? 
	                           thisdir->seq - thisdir->min_seq - 1 :
	                           thisdir->seq - thisdir->msg_last_seq;
	if (thisdir->msg_count<MAX_COUNT_MESSAGES)
          thisdir->msg_size[thisdir->msg_count]= curr_msg_size;
        if (curr_msg_size>0) thisdir->msg_count++;
        thisdir->msg_last_seq = thisdir->seq;
     }

   }

  /* make upper layer protocol analysis and update the classified bitrate */

  proto_analyzer (pip, ptcp, PROTOCOL_TCP, thisdir, *dir, plast);

  if (thisdir != NULL && thisdir->ptp != NULL)
    make_tcpL7_rate_stats(thisdir->ptp, ntohs (pip->ip_len));
  

  /* Check if the connection is completed */

  if (ConnComplete (ptp_save))
    {
      //fprintf (fp_stdout, "  (new complete)\n");
      if (profile_flows->flag == HISTO_ON)
        AVE_departure(current_time, &active_flows_win_TCP);
      tot_conn_TCP--;
      make_conn_stats (ptp_save, TRUE);

      /* free up memory for this flow */

      if (threaded)
	{
#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "\n\nRichiesto blocco thread TTP\n");
#endif
	  pthread_mutex_lock (&ttp_lock_mutex);
#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "\n\nOttenuto blocco thread TTP\n");
#endif
	}
      free_tp (ptp_save);

      /* free up the first element of the list pointedby the hash */
      ptph_tmp = ptph_save;
      *(ptph_save->ttp_ptr) = NULL;

      /* ptph_ptr is the head, pointed by the hash */
      /* recall the this element is the first, as it has been moved by the
         FindTTP() */
      *ptph_ptr = ptph_save->next;
      ptph_release (ptph_tmp);
      if (threaded)
	{
#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "\n\ngoing to Unlock of the TTP thread\n");
#endif
	  pthread_mutex_unlock (&ttp_lock_mutex);
#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "\n\nthread TTP unlocked\n");
#endif
	}
    }
  return (FLOW_STAT_OK);
}

void
print_ttp ()
{
  int p;

  for (p = 0; p < MAX_TCP_PAIRS; p++)
    {
      fprintf (fp_stdout, "[%2d]", p);
      if (ttp[p] != NULL)
	fprintf (fp_stdout, "->[ptp]\n");
      else
	fprintf (fp_stdout, "->[NULL]\n");
    }
}

void
trace_done (void)
{
  tcp_pair *ptp;
  int ix;

  /* complete the "idle time" calculations using NOW */
  for (ix = 0; ix <= num_tcp_pairs; ++ix)
    {
      tcb *thisdir;
      u_llong itime;

      ptp = ttp[ix];

      if (ptp == NULL)		/* already analyzed */
	continue;

      /* if it's CLOSED, skip it - shouldn't ever happen */
      if ((FinCount (ptp) >= 2) || (ConnReset (ptp)))
	continue;

      /* c2s direction */
      thisdir = &ptp->c2s;
      if (!ZERO_TIME (&thisdir->last_time))
	{
	  itime = elapsed (thisdir->last_time, current_time);
	  if (itime > thisdir->idle_max)
	    thisdir->idle_max = itime;
	}


      /* s2c direction */
      thisdir = &ptp->s2c;
      if (!ZERO_TIME (&thisdir->last_time))
	{
	  itime = elapsed (thisdir->last_time, current_time);
	  if (itime > thisdir->idle_max)
	    thisdir->idle_max = itime;
	}
    }

  for (ix = 0; ix <= num_tcp_pairs; ++ix)
    {
      ptp = ttp[ix];
      if (ptp == NULL)		/* already analyzed */
	continue;

      /* do not consider this flow for the stats */
      make_conn_stats (ptp, FALSE);
    }
}

void
trace_done_periodic ()
{
  tcp_pair *ptp;
  udp_pair *pup;
  int ix, dir, j;
  unsigned int cleaned = 0;
  unsigned long init_tot_conn = tot_conn_TCP;
  extern ptp_snap *ptp_hashtable[];

  hash hval;
  ptp_snap *ptph_tmp, *ptph, *ptph_prev;
  ptp_snap **pptph_head = NULL;


  tcb *thisdir;
  u_llong itime;

  /* complete the "idle time" calculations using NOW */
  if (printticks && debug > 1)
    fprintf (fp_stdout, "\nStart cleaning TCP flows\n");
  for (ix = 0; ix < MAX_TCP_PAIRS; ++ix)
    {
      ptp = ttp[ix];

      if ((ptp == NULL))
	continue;

      /* If no packets have been received in the last IDLE_TIME period,
         close the flow */
#ifdef WIPE_TCP_SINGLETONS
      if (( (
             (
	      (ptp->c2s.syn_count>0 && ptp->s2c.syn_count==0)
              ||
	      (ptp->c2s.syn_count==0 && ptp->s2c.syn_count>0)
	     ) 
	     &&
	     (
	      ptp->packets == (ptp->c2s.syn_count+ptp->s2c.syn_count)
	     )
	    )
            && 
	    (elapsed (ptp->last_time, current_time) > TCP_SINGLETON_TIME)
	  )
	  ||
          (elapsed (ptp->last_time, current_time) > TCP_IDLE_TIME))
#else
      if ((elapsed (ptp->last_time, current_time) > TCP_IDLE_TIME))
#endif
	{
	  if (threaded)
	    {
#ifdef DEBUG_THREAD
	      fprintf (fp_stdout, "\n\nTrace_done_periodic trying lock thread TTP\n");
#endif
	      pthread_mutex_lock (&ttp_lock_mutex);
#ifdef DEBUG_THREAD
	      fprintf (fp_stdout, "\n\nTrace_done_periodic got lock thread TTP\n");
#endif
	      if ((ptp == NULL))
		/* someonelse already cleaned this ptp */
		{
		  pthread_mutex_unlock (&ttp_lock_mutex);
		  continue;
		}
#ifdef WIPE_TCP_SINGLETONS
             /* Not sure this is the correct test when managing
	        singletons and normal times together
	     */
	      if ((elapsed (ptp->last_time, current_time) <= TCP_SINGLETON_TIME)
		  || (ptp->last_time.tv_sec == 0
		      && ptp->last_time.tv_usec == 0))
#else
	      if ((elapsed (ptp->last_time, current_time) <= TCP_IDLE_TIME)
		  || (ptp->last_time.tv_sec == 0
		      && ptp->last_time.tv_usec == 0))
#endif
		{
		  /* someonelse already cleaned this ptp */
		  pthread_mutex_unlock (&ttp_lock_mutex);
		  continue;
		}
	    }
	  /* must be cleaned */
	  cleaned++;

	  /* c2s direction */
	  thisdir = &ptp->c2s;
	  if (!ZERO_TIME (&thisdir->last_time))
	    {
	      itime = elapsed (thisdir->last_time, current_time);
	      if (itime > thisdir->idle_max)
		thisdir->idle_max = itime;
	    }


	  /* s2c direction */
	  thisdir = &ptp->s2c;
	  if (!ZERO_TIME (&thisdir->last_time))
	    {
	      itime = elapsed (thisdir->last_time, current_time);
	      if (itime > thisdir->idle_max)
		thisdir->idle_max = itime;
	    }

	  make_conn_stats (ptp, (ptp->s2c.syn_count > 0)
			   && (ptp->c2s.syn_count > 0));
      if (profile_flows->flag == HISTO_ON)
        AVE_departure(current_time, &active_flows_win_TCP);
	  tot_conn_TCP--;

	  /* free up hash element->.. */
	  hval = ptp->addr_pair.hash % HASH_TABLE_SIZE;

	  pptph_head = &ptp_hashtable[hval];
	  j = 0;
	  ptph_prev = *pptph_head;
	  for (ptph = *pptph_head; ptph; ptph = ptph->next)
	    {
	      j++;
	      if (SameConn (&ptp->addr_pair, &ptph->addr_pair, &dir))
		{
		  ptph_tmp = ptph;
		  if (j == 1)
		    {
		      /* it is the top of the list */
		      ptp_hashtable[hval] = ptph->next;
		    }
		  else
		    {
		      /* it is in the middle of the list */
		      ptph_prev->next = ptph->next;
		    }
		  ptph_release (ptph_tmp);
		  break;
		}
	      ptph_prev = ptph;
	    }

	  /* ... and free up the TP. */
	  free_tp (ptp);
	  ttp[ix] = NULL;
	  if (threaded)
	    {
	      pthread_mutex_unlock (&ttp_lock_mutex);
#ifdef DEBUG_THREAD
	      fprintf (fp_stdout, "\n\nTrace_done_periodic released lock thread TTP\n");
#endif
	    }
	}

    }

  if (printticks && debug > 1)
    fprintf (fp_stdout,
	     "\rCleaned %d/(%ld) TCP flows\n", cleaned, init_tot_conn);

  if (do_udp == FALSE)
    return;
 /************ Start cleaning UDP flows *******************/


  if (printticks && debug > 1)
    fprintf (fp_stdout, "Start cleaning UDP flows\n");

  cleaned = 0;
  init_tot_conn = tot_conn_UDP;
  for (ix = 0; ix < MAX_UDP_PAIRS; ++ix)
    {
      pup = utp[ix];

      if ((pup == NULL))
	continue;

      /* If no packets have been received in the last UDP_IDLE_TIME period,
         close the flow */
#ifdef WIPE_UDP_SINGLETONS
      if (( (pup->packets == 1) && 
	    (elapsed (pup->last_time, current_time) > UDP_SINGLETON_TIME)
	  )
	  ||
          (elapsed (pup->last_time, current_time) > UDP_IDLE_TIME))
	close_udp_flow (pup, ix, dir);
#else
      if ((elapsed (pup->last_time, current_time) > UDP_IDLE_TIME))
	close_udp_flow (pup, ix, dir);
#endif

    }
  if (printticks && debug > 1)
    fprintf (fp_stdout,
	     "\rCleaned %d/(%ld) UDP flows\n", cleaned, init_tot_conn);
}

void
trace_init (void)
{
  static Bool initted = FALSE;

  if (initted)
    return;

  initted = TRUE;

  /* create an array to hold any pairs that we might create */
  ttp = (tcp_pair **) MallocZ (MAX_TCP_PAIRS * sizeof (tcp_pair *));

  Minit ();
}


/* get a long (4 byte) option (to avoid address alignment problems) */
static u_long
get_long_opt (void *ptr)
{
  u_long l;
  memcpy (&l, ptr, sizeof (u_long));
  return (l);
}


/* get a short (2 byte) option (to avoid address alignment problems) */
static u_short
get_short_opt (void *ptr)
{
  u_short s;
  memcpy (&s, ptr, sizeof (u_short));
  return (s);
}


struct tcp_options *
ParseOptions (struct tcphdr *ptcp, void *plast)
{
  static struct tcp_options tcpo;
  struct sack_block *psack;
  u_char *pdata;
  u_char *popt;
  u_char *plen;

  popt = (u_char *) ptcp + sizeof (struct tcphdr);
  pdata = (u_char *) ptcp + ptcp->th_off * 4;
  /* init the options structure */
  memset (&tcpo, 0, sizeof (tcpo));
  tcpo.mss = tcpo.ws = tcpo.tsval = tcpo.tsecr = -1;
  tcpo.sack_req = 0;
  tcpo.sack_count = -1;
  tcpo.echo_req = tcpo.echo_repl = -1;
  tcpo.cc = tcpo.ccnew = tcpo.ccecho = -1;

  /* a quick sanity check, the unused (MBZ) bits must BZ! */
  if (warn_printbadmbz)
    {
      if (ptcp->th_x2 != 0)
	{
	  fprintf (fp_stderr,
		   "TCP packet %lu: 4 reserved bits are not zero (0x%01x)\n",
		   pnum, ptcp->th_x2);
	}
      if ((ptcp->th_flags & 0xc0) != 0)
	{
	  fprintf (fp_stderr,
		   "TCP packet %lu: upper flag bits are not zero (0x%02x)\n",
		   pnum, ptcp->th_flags);
	}
    }
  else
    {
      static int warned = 0;
      if (!warned && ((ptcp->th_x2 != 0) || ((ptcp->th_flags & 0xc0) != 0)))
	{
	  warned = 1;
	  fprintf (fp_stderr, "\
TCP packet %lu: reserved bits are not all zero.  \n\
\tFurther warnings disabled, use '-w' for more info\n", pnum);
	}
    }

  /* looks good, now check each option in turn */
  while (popt < pdata)
    {
      plen = popt + 1;
      /* check for truncation error */
      if ((unsigned long) popt >= (unsigned long) plast)
	{
	  if (warn_printtrunc)
	    fprintf (fp_stderr, "\
ParseOptions: packet %lu too short (%lu) to parse remaining options\n", pnum, (unsigned long) popt - (unsigned long) plast + 1);
	  ++ctrunc;
	  break;
	}

#define CHECK_O_LEN(opt) \
	if (*plen == 0) { \
	    if (warn_printtrunc) fprintf (fp_stderr, "\
ParseOptions: packet %lu %s option has length 0, skipping other options\n", \
                                           pnum,opt); \
	    popt = pdata; break;} \
	if ((unsigned long)popt + *plen - 1 > (unsigned long)(plast)) { \
	    if (warn_printtrunc) \
		fprintf (fp_stderr, "\
ParseOptions: packet %lu %s option truncated, skipping other options\n", \
              pnum,opt); \
	    ++ctrunc; \
	    popt = pdata; break;} \


      switch (*popt)
	{
	case TCPOPT_EOL:
	  ++popt;
	  break;
	case TCPOPT_NOP:
	  ++popt;
	  break;
	case TCPOPT_MAXSEG:
	  CHECK_O_LEN ("TCPOPT_MAXSEG");
	  tcpo.mss = ntohs (get_short_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_WS:
	  CHECK_O_LEN ("TCPOPT_WS");
	  tcpo.ws = *((u_char *) (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_TS:
	  CHECK_O_LEN ("TCPOPT_TS");
	  tcpo.tsval = ntohl (get_long_opt (popt + 2));
	  tcpo.tsecr = ntohl (get_long_opt (popt + 6));
	  popt += *plen;
	  break;
	case TCPOPT_ECHO:
	  CHECK_O_LEN ("TCPOPT_ECHO");
	  tcpo.echo_req = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_ECHOREPLY:
	  CHECK_O_LEN ("TCPOPT_ECHOREPLY");
	  tcpo.echo_repl = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_CC:
	  CHECK_O_LEN ("TCPOPT_CC");
	  tcpo.cc = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_CCNEW:
	  CHECK_O_LEN ("TCPOPT_CCNEW");
	  tcpo.ccnew = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_CCECHO:
	  CHECK_O_LEN ("TCPOPT_CCECHO");
	  tcpo.ccecho = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_SACK_PERM:
	  CHECK_O_LEN ("TCPOPT_SACK_PERM");
	  tcpo.sack_req = 1;
	  popt += *plen;
	  break;
	case TCPOPT_SACK:
	  /* see which bytes are acked */
	  CHECK_O_LEN ("TCPOPT_SACK");
	  tcpo.sack_count = 0;
	  psack = (sack_block *) (popt + 2);	/* past the kind and length */
	  popt += *plen;
	  while ((unsigned long) psack < (unsigned long) popt)
	    {
	      struct sack_block *psack_local =
		&tcpo.sacks[(unsigned) tcpo.sack_count];
	      /* warning, possible alignment problem here, so we'll
	         use memcpy() and hope for the best */
	      /* better use -fno-builtin to avoid gcc alignment error
	         in GCC 2.7.2 */
	      memcpy (psack_local, psack, sizeof (sack_block));

	      /* convert to local byte order (Jamshid Mahdavi) */
	      psack_local->sack_left = ntohl (psack_local->sack_left);
	      psack_local->sack_right = ntohl (psack_local->sack_right);

	      ++psack;
	      if ((unsigned long) psack > ((unsigned long) plast + 1))
		{
		  /* this SACK block isn't all here */
		  if (warn_printtrunc)
		    fprintf (fp_stderr, "packet %lu: SACK block truncated\n",
			     pnum);
		  ++ctrunc;
		  break;
		}
	      ++tcpo.sack_count;
	      if (tcpo.sack_count > MAX_SACKS)
		{
		  /* this isn't supposed to be able to happen */
		  fprintf (fp_stderr,
			   "Warning, internal error, too many sacks!!\n");
		  tcpo.sack_count = MAX_SACKS;
		}
	    }
	  break;
	default:
	  if (debug)
	    fprintf (fp_stderr,
		     "Warning, ignoring unknown TCP option 0x%x\n", *popt);
	  CHECK_O_LEN ("TCPOPT_UNKNOWN");

	  /* record it anyway... */
	  if (tcpo.unknown_count < MAX_UNKNOWN)
	    {
	      int ix = tcpo.unknown_count;	/* make lint happy */
	      tcpo.unknowns[ix].unkn_opt = *popt;
	      tcpo.unknowns[ix].unkn_len = *plen;
	    }
	  ++tcpo.unknown_count;

	  popt += *plen;
	  break;
	}
    }

  return (&tcpo);
}


/* given a tcp_pair and a packet, tell me which tcb it is */
struct tcb *
ptp2ptcb (tcp_pair * ptp, struct ip *pip, struct tcphdr *ptcp)
{
  int dir = 0;
  tcp_pair tp_in;

  /* grab the address from this packet */
  CopyAddr (&tp_in.addr_pair, pip,
	    ntohs (ptcp->th_sport), ntohs (ptcp->th_dport));

  /* check the direction */
  if (!SameConn (&tp_in.addr_pair, &ptp->addr_pair, &dir))
    return (NULL);		/* not found, internal error */

  if (dir == C2S)
    return (&ptp->c2s);
  else
    return (&ptp->s2c);
}


/*------------------------------------------------------------------------
 *  cksum  -  Return 16-bit ones complement of 16-bit ones complement sum 
 *------------------------------------------------------------------------
 */
static u_short
cksum (void *pvoid,		/* any alignment is legal */
       int nbytes)
{
  u_char *pchar = pvoid;
  u_long sum = 0;

  while (nbytes >= 2)
    {
      /* can't assume pointer alignment :-( */
      sum += (pchar[0] << 8);
      sum += pchar[1];

      pchar += 2;
      nbytes -= 2;
    }

  /* special check for odd length */
  if (nbytes == 1)
    {
      sum += (pchar[0] << 8);
      /* lower byte is assumed to be 0 */
    }

  sum = (sum >> 16) + (sum & 0xffff);	/* add in carry   */
  sum += (sum >> 16);		/* maybe one more */

  return (sum);
}

/* compute IP checksum */
static u_short
ip_cksum (struct ip *pip, void *plast)
{
  u_short sum;

#ifdef SUPPORT_IPV6
  if (PIP_ISV6 (pip))
    return (0);			/* IPv6 has no header checksum */
#endif
  if (!PIP_ISV4 (pip))
    return (1);			/* I have no idea! */


  /* quick sanity check, if the packet is truncated, pretend it's valid */
  if (plast < (void *) ((char *) pip + pip->ip_hl * 4 - 1))
    {
      return (0);
    }

  /* ... else IPv4 */
  sum = cksum (pip, pip->ip_hl * 4);
  return (sum);
}


/* is the IP checksum valid? */
Bool
ip_cksum_valid (struct ip * pip, void *plast)
{
  u_short sum;

  sum = ip_cksum (pip, plast);

  return ((sum == 0) || (sum == 0xffff));
}


/* compute the TCP checksum */
static u_short
tcp_cksum (struct ip *pip, struct tcphdr *ptcp, void *plast)
{
  u_long sum = 0;
  unsigned tcp_length;

  /* verify version */
  if (!PIP_ISV4 (pip) && !PIP_ISV6 (pip))
    {
      fprintf (fp_stderr, "Internal error, tcp_cksum: neither IPv4 nor IPv6\n");
      exit (-1);
    }


  /* TCP checksum includes: */
  /* - IP source */
  /* - IP dest */
  /* - IP type */
  /* - TCP header length + TCP data length */
  /* - TCP header and data */

  if (PIP_ISV4 (pip))
    {
      /* quick sanity check, if the packet is fragmented,
         pretend it's valid */
      if ((ntohs (pip->ip_off) << 2) != 0)
	{
	  /* both the offset AND the MF bit must be 0 */
	  /* (but we shifted off the DF bit */
	  return (0);
	}

      /* 2 4-byte numbers, next to each other */
      sum += cksum (&pip->ip_src, 4 * 2);

      /* type */
      sum += (u_short) pip->ip_p;

      /* length (TCP header length + TCP data length) */
      tcp_length = ntohs (pip->ip_len) - (4 * pip->ip_hl);
      sum += (u_short) htons (tcp_length);
    }
#ifdef SUPPORT_IPV6
  else
    {				/* if (PIP_ISV6(pip)) */

      static Bool warned = FALSE;

      /* wow, this gets ugly with pseudo headers, sounds like a good
         job for another day :-(  */

      if (!warned)
	{
	  fprintf (fp_stderr, "\nWarning: IPv6 TCP checksums not verified\n\n");
	  warned = TRUE;
	}
      return (0);		/* pretend it's valid */
    }
#endif

  /* quick sanity check, if the packet is truncated, pretend it's valid */
  if (plast < (void *) ((char *) ptcp + tcp_length - 1))
    {
      return (0);
    }


  /* checksum the TCP header and data */
  sum += cksum (ptcp, tcp_length);

  /* roll down into a 16-bit number */
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (u_short) (~sum & 0xffff);
}



/* compute the UDP checksum */
static u_short
udp_cksum (struct ip *pip, struct udphdr *pudp, void *plast)
{
  u_long sum = 0;
  unsigned udp_length;

  /* WARNING -- this routine has not been extensively tested */

  /* verify version */
  if (!PIP_ISV4 (pip) && !PIP_ISV6 (pip))
    {
      fprintf (fp_stderr, "Internal error, udp_cksum: neither IPv4 nor IPv6\n");
      exit (-1);
    }


  /* UDP checksum includes: */
  /* - IP source */
  /* - IP dest */
  /* - IP type */
  /* - UDP length field */
  /* - UDP header and data */

  if (PIP_ISV4 (pip))
    {
      /* 2 4-byte numbers, next to each other */
      sum += cksum (&pip->ip_src, 4 * 2);

      /* type */
      sum += (u_short) pip->ip_p;

      /* UDP length */
      udp_length = ntohs (pudp->uh_ulen);
      sum += pudp->uh_ulen;
    }
#ifdef SUPPORT_IPV6
  else
    {				/* if (PIP_ISV6(pip)) */

      static Bool warned = FALSE;

      /* wow, this gets ugly with pseudo headers, sounds like a good
         job for another day :-(  */

      if (!warned)
	{
	  fprintf (fp_stderr, "\nWarning: IPv6 UDP checksums not verified\n\n");
	  warned = TRUE;
	}
      return (0);		/* pretend it's valid */
    }
#endif

  /* quick sanity check, if the packet is truncated, pretend it's valid */
  if (plast < (void *) ((char *) pudp + udp_length - 1))
    {
      return (0);
    }


  /* checksum the UDP header and data */
  sum += cksum (pudp, udp_length);

  /* roll down into a 16-bit number */
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (u_short) (~sum & 0xffff);
}


/* is the TCP checksum valid? */
Bool
tcp_cksum_valid (struct ip * pip, struct tcphdr * ptcp, void *plast)
{
  return (tcp_cksum (pip, ptcp, plast) == 0);
}


/* is the UDP checksum valid? */
Bool
udp_cksum_valid (struct ip * pip, struct udphdr * pudp, void *plast)
{
  if (ntohs (pudp->uh_sum) == 0)
    {
      /* checksum not used */
      return (1);		/* valid */
    }

  return (udp_cksum (pip, pudp, plast) == 0);
}


void
make_conn_stats (tcp_pair * ptp_save, Bool complete)
{
  tcb *outgoing, *incoming;
  Bool local;
  double etime;
  FILE *fp;
  tcb *pab, *pba;

  /* Statistichs about CHAT flows */
#ifdef MSN_CLASSIFIER
  print_msn_conn_stats(ptp_save);
#endif
#ifdef YMSG_CLASSIFIER
  print_ymsg_conn_stats(ptp_save);
#endif
#ifdef XMPP_CLASSIFIER
  print_jabber_conn_stats(ptp_save);
#endif

  /* Statistics from the plugins */

  /* TCP proto stats should be done only for complete flows 
     This affects only the histograms of L7 TCP flows */
  if (complete)
     make_proto_stat (ptp_save, PROTOCOL_TCP);

  if (complete)
    {
      fp = fp_logc;
    }
  else
    {
      fp = fp_lognc;
    }

  /* TOPIX: connection type statistics */
  if (ptp_save->con_type & RTP_PROTOCOL)
    f_RTP_tunneled_TCP_count++;
  /* end TOPIX */

  pab = &(ptp_save->c2s);
  pba = &(ptp_save->s2c);

  if (ptp_save->internal_src && !ptp_save->internal_dst)
    {
      outgoing = &(ptp_save->c2s);	// c2s out
      incoming = &(ptp_save->s2c);	// s2c in
      local = FALSE;
    }
  else if (ptp_save->internal_dst && !ptp_save->internal_src)
    {
      outgoing = &(ptp_save->s2c);	// s2c out
      incoming = &(ptp_save->c2s);	// c2s in
      local = FALSE;
    }
  else if (ptp_save->internal_src && ptp_save->internal_dst)
    {
      local = TRUE;
      outgoing = &(ptp_save->s2c);	// s2s loc
      incoming = &(ptp_save->c2s);	// c2s loc
    }
  else
    {
      if (warn_IN_OUT)
	{
	  fprintf (fp_stderr, 
        "\nWARN: This flow is neither incoming nor outgoing: src - %s;",
	     HostName (ptp_save->addr_pair.a_address));
	  fprintf (fp_stderr, " dst - %s!\n", HostName (ptp_save->addr_pair.b_address));
	  warn_IN_OUT = FALSE;
	}
#ifndef LOG_UNKNOWN
      return;
#else
/* fool the internal and external definition... */
      outgoing = &(ptp_save->s2c);
      incoming = &(ptp_save->c2s);
      local = FALSE;
#endif
    }




  if (complete)
    {
      /* sack
       *  [1] A<->B  both agree
       *  [2] A ->B  a set
       *  [3] A<- B  b set
       *  [4] not set
       */

      if (ptp_save->c2s.fsack_req && ptp_save->s2c.fsack_req)
	{
	  add_histo (tcp_opts_SACK, 1);
	}
      else if (ptp_save->c2s.fsack_req)
	{
	  add_histo (tcp_opts_SACK, 2);
	}
      else if (ptp_save->s2c.fsack_req)
	{
	  add_histo (tcp_opts_SACK, 3);
	}
      else
	{
	  add_histo (tcp_opts_SACK, 4);
	}

      /* winscale
       *  [1] A<->B  both agree
       *  [2] A ->B  a set
       *  [3] A<- B  b set
       *  [4] not set
       */

      if (ptp_save->c2s.f1323_ws && ptp_save->s2c.f1323_ws)
	{
	  add_histo (tcp_opts_WS, 1);
	}
      else if (ptp_save->c2s.f1323_ws)
	{
	  add_histo (tcp_opts_WS, 2);
	}
      else if (ptp_save->s2c.f1323_ws)
	{
	  add_histo (tcp_opts_WS, 3);
	}
      else
	{
	  add_histo (tcp_opts_WS, 4);
	}


      /* timestamp
       *  [1] A<->B  both agree
       *  [2] A ->B  a set
       *  [3] A<- B  b set
       *  [4] not set
       */

      if (ptp_save->c2s.f1323_ts && ptp_save->s2c.f1323_ts)
	{
	  add_histo (tcp_opts_TS, 1);
	}
      else if (ptp_save->c2s.f1323_ts)
	{
	  add_histo (tcp_opts_TS, 2);
	}
      else if (ptp_save->s2c.f1323_ts)
	{
	  add_histo (tcp_opts_TS, 3);
	}
      else
	{
	  add_histo (tcp_opts_TS, 4);
	}

      /* MSS
       */

      add_histo (tcp_mss_a, ptp_save->c2s.mss);
      add_histo (tcp_mss_b, ptp_save->s2c.mss);

      if ((ptp_save->c2s.mss == 0) || (ptp_save->s2c.mss == 0))
	{
	  add_histo (tcp_mss_used, 536);
	}
      else if (ptp_save->c2s.mss < ptp_save->s2c.mss)
	{
	  add_histo (tcp_mss_used, ptp_save->c2s.mss);
	}
      else
	{
	  add_histo (tcp_mss_used, ptp_save->s2c.mss);
	}

/* flow lenght */
      if (!local)
	{
	  add_histo (tcp_cl_b_s_out, outgoing->data_bytes);
	  add_histo (tcp_cl_b_s_in, incoming->data_bytes);
	  add_histo (tcp_cl_b_l_out, outgoing->data_bytes);
	  add_histo (tcp_cl_b_l_in, incoming->data_bytes);

	  add_histo (tcp_cl_p_out, outgoing->packets);
	  add_histo (tcp_cl_p_in, incoming->packets);
	}
      else
	{
	  add_histo (tcp_cl_b_s_loc, outgoing->data_bytes);
	  add_histo (tcp_cl_b_s_loc, incoming->data_bytes);
	  add_histo (tcp_cl_b_l_loc, outgoing->data_bytes);
	  add_histo (tcp_cl_b_l_loc, incoming->data_bytes);

	  add_histo (tcp_cl_p_loc, outgoing->packets);
	  add_histo (tcp_cl_p_loc, incoming->packets);
	}

      add_histo (tcp_cl_b_s_c2s, ptp_save->c2s.data_bytes);
      add_histo (tcp_cl_b_s_s2c, ptp_save->s2c.data_bytes);
      add_histo (tcp_cl_b_l_c2s, ptp_save->c2s.data_bytes);
      add_histo (tcp_cl_b_l_s2c, ptp_save->s2c.data_bytes);

      add_histo (tcp_cl_p_c2s, ptp_save->c2s.packets);
      add_histo (tcp_cl_p_s2c, ptp_save->s2c.packets);
      /* receiver window */
      add_histo (tcp_win_min, ptp_save->c2s.win_min);
      add_histo (tcp_win_min, ptp_save->s2c.win_min);


      if (ptp_save->c2s.packets)
	{
	  add_histo (tcp_win_avg,
		     (ptp_save->c2s.win_tot / ptp_save->c2s.packets));
	}
      if (ptp_save->s2c.packets)
	{
	  add_histo (tcp_win_avg,
		     (ptp_save->s2c.win_tot / ptp_save->s2c.packets));
	}

      add_histo (tcp_win_max, ptp_save->c2s.win_max);
      add_histo (tcp_win_max, ptp_save->s2c.win_max);

      /* RTT */

      if ((incoming->rtt_count >= 1) && (outgoing->rtt_count >= 1))
	{
	  if (!local)
	    {
	      add_histo (tcp_rtt_avg_out,
			 (Average (outgoing->rtt_sum, outgoing->rtt_count) /
			  1000.0));
	      add_histo (tcp_rtt_avg_in,
			 (Average (incoming->rtt_sum, incoming->rtt_count) /
			  1000.0));

	      /* min */
	      add_histo (tcp_rtt_min_out, (outgoing->rtt_min / 1000.0));
	      add_histo (tcp_rtt_min_in, (incoming->rtt_min / 1000.0));

	      /* max */
	      add_histo (tcp_rtt_max_out, (outgoing->rtt_max / 1000.0));
	      add_histo (tcp_rtt_max_in, (incoming->rtt_max / 1000.0));

	      /* stdev */
	      add_histo (tcp_rtt_stdev_out,
			 (Stdev (outgoing->rtt_sum, outgoing->rtt_sum2,
				 outgoing->rtt_count) / 1000.0));
	      add_histo (tcp_rtt_stdev_in,
			 (Stdev (incoming->rtt_sum, incoming->rtt_sum2,
				 incoming->rtt_count) / 1000.0));

	      /* valid samples */
	      add_histo (tcp_rtt_cnt_out, outgoing->rtt_count);
	      add_histo (tcp_rtt_cnt_in, incoming->rtt_count);
	    }
	  else if (!local)
	    {
	      add_histo (tcp_rtt_avg_loc,
			 (Average (outgoing->rtt_sum, outgoing->rtt_count) /
			  1000.0));
	      add_histo (tcp_rtt_avg_loc,
			 (Average (incoming->rtt_sum, incoming->rtt_count) /
			  1000.0));

	      /* min */
	      add_histo (tcp_rtt_min_loc, (outgoing->rtt_min / 1000.0));
	      add_histo (tcp_rtt_min_loc, (incoming->rtt_min / 1000.0));

	      /* max */
	      add_histo (tcp_rtt_max_loc, (outgoing->rtt_max / 1000.0));
	      add_histo (tcp_rtt_max_loc, (incoming->rtt_max / 1000.0));

	      /* stdev */
	      add_histo (tcp_rtt_stdev_loc,
			 (Stdev (outgoing->rtt_sum, outgoing->rtt_sum2,
				 outgoing->rtt_count) / 1000.0));
	      add_histo (tcp_rtt_stdev_loc,
			 (Stdev (incoming->rtt_sum, incoming->rtt_sum2,
				 incoming->rtt_count) / 1000.0));

	      /* valid samples */
	      add_histo (tcp_rtt_cnt_loc, outgoing->rtt_count);
	      add_histo (tcp_rtt_cnt_loc, incoming->rtt_count);
	    }


	  /* avg */
	  add_histo (tcp_rtt_avg_c2s,
		     (Average (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_count)
		      / 1000.0));
	  add_histo (tcp_rtt_avg_s2c,
		     (Average (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_count)
		      / 1000.0));

	  /* min */
	  add_histo (tcp_rtt_min_c2s, (ptp_save->c2s.rtt_min / 1000.0));
	  add_histo (tcp_rtt_min_s2c, (ptp_save->s2c.rtt_min / 1000.0));

	  /* max */
	  add_histo (tcp_rtt_max_c2s, (ptp_save->c2s.rtt_max / 1000.0));
	  add_histo (tcp_rtt_max_s2c, (ptp_save->s2c.rtt_max / 1000.0));

	  /* stdev */
	  add_histo (tcp_rtt_stdev_c2s,
		     (Stdev (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_sum2,
			     ptp_save->c2s.rtt_count) / 1000.0));
	  add_histo (tcp_rtt_stdev_s2c,
		     (Stdev (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_sum2,
			     ptp_save->s2c.rtt_count) / 1000.0));

	  /* valid samples */
	  add_histo (tcp_rtt_cnt_c2s, ptp_save->c2s.rtt_count);
	  add_histo (tcp_rtt_cnt_s2c, ptp_save->s2c.rtt_count);
	}

      /* Statistichs about duplicates and rtxs */

      if (!local)
	{
	  add_histo (tcp_rtx_RTO_out, outgoing->rtx_RTO);
	  add_histo (tcp_rtx_RTO_in, incoming->rtx_RTO);

	  add_histo (tcp_rtx_FR_out, outgoing->rtx_FR);
	  add_histo (tcp_rtx_FR_in, incoming->rtx_FR);

	  add_histo (tcp_reordering_out, outgoing->reordering);
	  add_histo (tcp_reordering_in, incoming->reordering);

	  add_histo (tcp_net_dup_out, outgoing->net_dup);
	  add_histo (tcp_net_dup_in, incoming->net_dup);

	  add_histo (tcp_unknown_out, outgoing->unknown);
	  add_histo (tcp_unknown_in, incoming->unknown);

	  add_histo (tcp_flow_ctrl_out, outgoing->flow_control);
	  add_histo (tcp_flow_ctrl_in, incoming->flow_control);

	  add_histo (tcp_unnrtx_RTO_out, outgoing->unnecessary_rtx_RTO);
	  add_histo (tcp_unnrtx_RTO_in, incoming->unnecessary_rtx_RTO);

	  add_histo (tcp_unnrtx_FR_out, outgoing->unnecessary_rtx_FR);
	  add_histo (tcp_unnrtx_FR_in, incoming->unnecessary_rtx_FR);
	}
      else
	{
	  add_histo (tcp_rtx_RTO_loc, outgoing->rtx_RTO);
	  add_histo (tcp_rtx_RTO_loc, incoming->rtx_RTO);

	  add_histo (tcp_rtx_FR_loc, outgoing->rtx_FR);
	  add_histo (tcp_rtx_FR_loc, incoming->rtx_FR);

	  add_histo (tcp_reordering_loc, outgoing->reordering);
	  add_histo (tcp_reordering_loc, incoming->reordering);

	  add_histo (tcp_net_dup_loc, outgoing->net_dup);
	  add_histo (tcp_net_dup_loc, incoming->net_dup);

	  add_histo (tcp_unknown_loc, outgoing->unknown);
	  add_histo (tcp_unknown_loc, incoming->unknown);

	  add_histo (tcp_flow_ctrl_loc, outgoing->flow_control);
	  add_histo (tcp_flow_ctrl_loc, incoming->flow_control);

	  add_histo (tcp_unnrtx_RTO_loc, outgoing->unnecessary_rtx_RTO);
	  add_histo (tcp_unnrtx_RTO_loc, incoming->unnecessary_rtx_RTO);

	  add_histo (tcp_unnrtx_FR_loc, outgoing->unnecessary_rtx_FR);
	  add_histo (tcp_unnrtx_FR_loc, incoming->unnecessary_rtx_FR);
	}


      add_histo (tcp_rtx_RTO_c2s, ptp_save->c2s.rtx_RTO);
      add_histo (tcp_rtx_RTO_s2c, ptp_save->s2c.rtx_RTO);

      add_histo (tcp_rtx_FR_c2s, ptp_save->c2s.rtx_FR);
      add_histo (tcp_rtx_FR_s2c, ptp_save->s2c.rtx_FR);

      add_histo (tcp_reordering_c2s, ptp_save->c2s.reordering);
      add_histo (tcp_reordering_s2c, ptp_save->s2c.reordering);

      add_histo (tcp_net_dup_c2s, ptp_save->c2s.net_dup);
      add_histo (tcp_net_dup_s2c, ptp_save->s2c.net_dup);

      add_histo (tcp_unknown_c2s, ptp_save->c2s.unknown);
      add_histo (tcp_unknown_s2c, ptp_save->s2c.unknown);

      add_histo (tcp_flow_ctrl_c2s, ptp_save->c2s.flow_control);
      add_histo (tcp_flow_ctrl_s2c, ptp_save->s2c.flow_control);

      add_histo (tcp_unnrtx_RTO_c2s, ptp_save->c2s.unnecessary_rtx_RTO);
      add_histo (tcp_unnrtx_RTO_s2c, ptp_save->s2c.unnecessary_rtx_RTO);

      add_histo (tcp_unnrtx_FR_c2s, ptp_save->c2s.unnecessary_rtx_FR);
      add_histo (tcp_unnrtx_FR_s2c, ptp_save->s2c.unnecessary_rtx_FR);
    }



  /* connection time and throughput */
  /* from microseconds to ms */
  etime = elapsed (ptp_save->first_time, ptp_save->last_time);
  etime = etime / 1000;

  if (complete)
    {
      double thru = ((double) ptp_save->c2s.unique_bytes /
		     elapsed (ptp_save->first_time,
			      pab->payload_end_time) * 8000.0);
      add_histo (tcp_tot_time, etime);
      /* throughput in kbps */
      if (finite (thru))
	add_histo (tcp_thru_c2s, thru);
      thru = ((double) ptp_save->s2c.unique_bytes /
	      elapsed (ptp_save->first_time, pba->payload_end_time) * 8000.0);
      if (finite (thru))
	add_histo (tcp_thru_s2c, thru);

    }

  /* check if this flow has been abruptly interrupted by the user       */
  /* according to the heuristic defined in                              */
  /* D. Rossi, C. Casetti, M. Mellia                                    */
  /*      User Patience and the Web: a hands-on investigation           */
  /*      IEEE Globecom 2003                                            */
  /*      San Francisco, CA, USA, December 1-5, 2003                    */
  {
    Bool eligible = !(pba->fin_count > 0 || pba->reset_count > 0)
      && pba->unique_bytes > 0 && pab->reset_count > 0;
    double RTT = Average (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_count) +
      Average (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_count);
    Bool Interrupted = eligible &&
      (elapsed (ptp_save->last_time, pba->payload_end_time) < RTT);
    add_histo (tcp_interrupted, Interrupted);
  }

  /*---------------------------------------------------------*/
  /* dump stream properties                                  */
  /* topix                                                   */

  if (ptp_save->con_type & (RTP_PROTOCOL | ICY_PROTOCOL))
    {

      if (!ptp_save->internal_src && ptp_save->internal_dst)
	{
	  add_histo (mm_type_out, ptp_save->con_type);
	  if (ptp_save->con_type & RTP_PROTOCOL)
	    {
	      add_histo (mm_rtp_pt_out, ptp_save->rtp_pt);
	    }
	  add_histo (mm_cl_b_out, pba->unique_bytes);
	  //if(pba->unique_bytes <= SHORT_MM_CL_B)
	  add_histo (mm_cl_b_s_out, pba->unique_bytes);
	  if (pba->packets >= BITRATE_MIN_PKTS)
	    {
	      add_histo (mm_avg_bitrate_out,
			 (pba->unique_bytes >> 7) / (etime / 1000.0));
	    }
	  add_histo (mm_cl_p_out, pba->packets);
	  //if(pba->packets <= SHORT_MM_CL_P)
	  add_histo (mm_cl_p_s_out, pba->packets);
	  add_histo (mm_avg_ipg_out,
		     (pba->sum_delta_t / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_avg_jitter_out,
		     (pba->sum_jitter / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_n_oos_out, pba->out_order_pkts);
	  add_histo (mm_p_oos_out,
		     ((float) pba->out_order_pkts /
		      (float) pba->packets) * 1000);
	  add_histo (mm_tot_time_out, etime / 1000);
	  //if (etime <= SHORT_MM_TOT_TIME)
	  add_histo (mm_tot_time_s_out, etime);
	  add_histo (mm_p_dup_out, (pba->rexmit_pkts * 1000) / pba->packets);
	}
      else if (ptp_save->internal_src && !ptp_save->internal_dst)
	{
	  add_histo (mm_type_in, ptp_save->con_type);
	  if (ptp_save->con_type & RTP_PROTOCOL)
	    {
	      add_histo (mm_rtp_pt_in, ptp_save->rtp_pt);
	    }
	  add_histo (mm_cl_b_in, pba->unique_bytes);
	  //if(pba->unique_bytes <= SHORT_MM_CL_B)
	  add_histo (mm_cl_b_s_in, pba->unique_bytes);
	  if (pba->packets >= BITRATE_MIN_PKTS)
	    {
	      add_histo (mm_avg_bitrate_in,
			 (pba->unique_bytes >> 7) / (etime / 1000.0));
	    }
	  add_histo (mm_cl_p_in, pba->packets);
	  //if(pba->packets <= SHORT_MM_CL_P)
	  add_histo (mm_cl_p_s_in, pba->packets);
	  add_histo (mm_avg_ipg_in,
		     (pba->sum_delta_t / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_avg_jitter_in,
		     (pba->sum_jitter / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_n_oos_in, pba->out_order_pkts);
	  add_histo (mm_p_oos_in,
		     ((float) pba->out_order_pkts /
		      (float) pba->packets) * 1000);
	  add_histo (mm_tot_time_in, etime / 1000);
	  //if (etime <= SHORT_MM_TOT_TIME)
	  add_histo (mm_tot_time_s_in, etime);
	  add_histo (mm_p_dup_in, (pba->rexmit_pkts * 1000) / pba->packets);
	}
      else if (ptp_save->internal_src && ptp_save->internal_dst)
	{
	  add_histo (mm_type_loc, ptp_save->con_type);
	  if (ptp_save->con_type & RTP_PROTOCOL)
	    {
	      add_histo (mm_rtp_pt_loc, ptp_save->rtp_pt);
	    }
	  add_histo (mm_cl_b_loc, pba->unique_bytes);
	  //if(pba->unique_bytes <= SHORT_MM_CL_B)
	  add_histo (mm_cl_b_s_loc, pba->unique_bytes);
	  if (pba->packets >= BITRATE_MIN_PKTS)
	    {
	      add_histo (mm_avg_bitrate_loc,
			 (pba->unique_bytes >> 7) / (etime / 1000.0));
	    }
	  add_histo (mm_cl_p_loc, pba->packets);
	  //if(pba->packets <= SHORT_MM_CL_P)
	  add_histo (mm_cl_p_s_loc, pba->packets);
	  add_histo (mm_avg_ipg_loc,
		     (pba->sum_delta_t / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_avg_jitter_loc,
		     (pba->sum_jitter / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_n_oos_loc, pba->out_order_pkts);
	  add_histo (mm_p_oos_loc,
		     ((float) pba->out_order_pkts /
		      (float) pba->packets) * 1000);
	  add_histo (mm_tot_time_loc, etime / 1000);
	  //if (etime <= SHORT_MM_TOT_TIME)
	  add_histo (mm_tot_time_s_loc, etime);
	  add_histo (mm_p_dup_loc, (pba->rexmit_pkts * 1000) / pba->packets);
	}
      else
	{
	  if (warn_IN_OUT)
	    {
	      fprintf (fp_stderr, 
            "\nWARN: This stream is neither incoming nor outgoing: src - %s;",
		    HostName (ptp_save->addr_pair.a_address));
	      fprintf (fp_stderr, " dst - %s!\n",
		      HostName (ptp_save->addr_pair.b_address));
	      warn_IN_OUT = FALSE;
	    }
#ifdef LOG_UNKNOWN
/* fool the internal and external definition... */
	  add_histo (mm_type_loc, ptp_save->con_type);
	  if (ptp_save->con_type & RTP_PROTOCOL)
	    {
	      add_histo (mm_rtp_pt_loc, ptp_save->rtp_pt);
	    }
	  add_histo (mm_cl_b_loc, pba->unique_bytes);
	  //if(pba->unique_bytes <= SHORT_MM_CL_B)
	  add_histo (mm_cl_b_s_loc, pba->unique_bytes);
	  if (pba->packets >= BITRATE_MIN_PKTS)
	    {
	      add_histo (mm_avg_bitrate_loc,
			 (pba->unique_bytes >> 7) / (etime / 1000.0));
	    }
	  add_histo (mm_cl_p_loc, pba->packets);
	  //if(pba->packets <= SHORT_MM_CL_P)
	  add_histo (mm_cl_p_s_loc, pba->packets);
	  add_histo (mm_avg_ipg_loc,
		     (pba->sum_delta_t / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_avg_jitter_loc,
		     (pba->sum_jitter / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_n_oos_loc, pba->out_order_pkts);
	  add_histo (mm_p_oos_loc,
		     ((float) pba->out_order_pkts /
		      (float) pba->packets) * 1000);
	  add_histo (mm_tot_time_loc, etime / 1000);
	  //if (etime <= SHORT_MM_TOT_TIME)
	  add_histo (mm_tot_time_s_loc, etime);
	  add_histo (mm_p_dup_loc, (pba->rexmit_pkts * 1000) / pba->packets);
#endif
	}
    }
  /* end topix */

  /*---------------------------------------------------------*/
  /* RRDtools                                                */
  if(!log_engine)
	  return;
  if (fp_logc != NULL)
    {
      fprintf (fp, 
	       "%s %s %lu %u %lu %lu %lu %lu %lu %u %u %u %d %d %d %d %d %d %d %d %u %u %u %u %d %lu %lu %u",
	       HostName (ptp_save->addr_pair.a_address),
	       ServiceName (ptp_save->addr_pair.a_port),
	       pab->packets,
	       pab->reset_count, pab->ack_pkts, pab->pureack_pkts,
	       pab->unique_bytes, pab->data_pkts, pab->data_bytes,
	       pab->rexmit_pkts, pab->rexmit_bytes, pab->out_order_pkts,
	       pab->syn_count, pab->fin_count, pab->f1323_ws, pab->f1323_ts,
	       pab->window_scale, pab->fsack_req, pab->sacks_sent, pab->mss,
	       pab->max_seg_size, pab->min_seg_size, pab->win_max,
	       pab->win_min, pab->win_zero_ct, pab->cwin_max, pab->cwin_min,
	       pab->initialwin_bytes);

      fprintf (fp, " %f %f %f %f %u %u %u",
	       (Average (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_count) /
		1000.0),
	       (ptp_save->c2s.rtt_min / 1000.0),
               (ptp_save->c2s.rtt_max / 1000.0),
	       (Stdev (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_sum2,
		      ptp_save->c2s.rtt_count) / 1000.0),
		ptp_save->c2s.rtt_count,
                ptp_save->c2s.ttl_min,
                ptp_save->c2s.ttl_max);

      fprintf (fp, " %u %u %u %u %u %u %u %u",
	       ptp_save->c2s.rtx_RTO,
	       ptp_save->c2s.rtx_FR,
	       ptp_save->c2s.reordering,
	       ptp_save->c2s.net_dup,
	       ptp_save->c2s.unknown,
	       ptp_save->c2s.flow_control,
	       ptp_save->c2s.unnecessary_rtx_RTO,
	       ptp_save->c2s.unnecessary_rtx_FR);
      /* Bad behaviour */
      fprintf (fp, " %d", ptp_save->c2s.bad_behavior);

      fprintf (fp,
	       " %s %s %lu %u %lu %lu %lu %lu %lu %u %u %u %d %d %d %d %d %d %d %d %u %u %u %u %d %lu %lu %u",
	       HostName (ptp_save->addr_pair.b_address),
	       ServiceName (ptp_save->addr_pair.b_port),
	       pba->packets,
	       pba->reset_count,
	       pba->ack_pkts,
	       pba->pureack_pkts,
	       pba->unique_bytes,
	       pba->data_pkts,
	       pba->data_bytes,
	       pba->rexmit_pkts,
	       pba->rexmit_bytes,
	       pba->out_order_pkts,
	       pba->syn_count,
	       pba->fin_count,
	       pba->f1323_ws,
	       pba->f1323_ts,
	       pba->window_scale,
	       pba->fsack_req,
	       pba->sacks_sent,
	       pba->mss,
	       pba->max_seg_size,
	       pba->min_seg_size,
	       pba->win_max,
	       pba->win_min,
	       pba->win_zero_ct,
	       pba->cwin_max, pba->cwin_min, pba->initialwin_bytes);

      fprintf (fp, " %f %f %f %f %u %u %u",
	       (Average (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_count) /
		1000.0),
	       (ptp_save->s2c.rtt_min / 1000.0),
               (ptp_save->s2c.rtt_max / 1000.0),
	       (Stdev (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_sum2,
		      ptp_save->s2c.rtt_count) / 1000.0),
		ptp_save->s2c.rtt_count,
                ptp_save->s2c.ttl_min,
                ptp_save->s2c.ttl_max);

      fprintf (fp, " %u %u %u %u %u %u %u %u",
	       ptp_save->s2c.rtx_RTO,
	       ptp_save->s2c.rtx_FR,
	       ptp_save->s2c.reordering,
	       ptp_save->s2c.net_dup,
	       ptp_save->s2c.unknown,
	       ptp_save->s2c.flow_control,
	       ptp_save->s2c.unnecessary_rtx_RTO,
	       ptp_save->s2c.unnecessary_rtx_FR);
      /* Bad behaviour */
      fprintf (fp, " %d", ptp_save->s2c.bad_behavior);

/* elapsed time */
      fprintf (fp, " %f", etime);

/* first pkt time */
      fprintf (fp, " %f",
	       elapsed (first_packet, ptp_save->first_time) / 1000.0);
/* last pkt time */
      fprintf (fp, " %f",
	       elapsed (first_packet, ptp_save->last_time) / 1000.0);

/* first DATA pkt time */
      fprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pab->payload_start_time) / 1000.0);
      fprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pba->payload_start_time) / 1000.0);

/* last DATA pkt time */
      fprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pab->payload_end_time) / 1000.0);
      fprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pba->payload_end_time) / 1000.0);

      /* printing boolean flag if this is considered internal or not */
      fprintf (fp, " %d", ptp_save->internal_src);

      /* TOPIX: added 97th colon: connection type */
      fprintf (fp, " %d", ptp_save->con_type);

      /* P2P: added 98-99th colon: p2p protocol / p2p message type /  */
      fprintf (fp, " %d %d", ptp_save->p2p_type / 100,
	       ptp_save->p2p_type % 100);

      /* P2P: added 100-103th colon: p2p data mesg. / p2p signalling msg.   */
      /*      currently only for ED2K-TCP - MMM 7/3/08*/
      fprintf (fp, " %d %d %d %d", ptp_save->p2p_data_count,
	       ptp_save->p2p_sig_count,ptp_save->p2p_c2s_count,ptp_save->p2p_c2c_count);

      /* P2P: added 104th colon: p2p chat mesg. count */
      /*      currently only for ED2K-TCP - MMM 5/6/08*/
      fprintf (fp, " %d", ptp_save->p2p_msg_count);

      /* Web2.0: added 105th colon: HTTP content type */
      /* 
         Using http_data+1 so that valid values are > 0, i.e. GET is 1,
         POST is 2, etc.
      */
      fprintf (fp, " %d", ptp_save->con_type & HTTP_PROTOCOL ?
                          ptp_save->http_data + 1 : 0 );

      /* write to log file */
      fprintf (fp, "\n");

   }
   if(!fp_rtp_logc || (((ptp_save->con_type & RTP_PROTOCOL) == 0)
      && ((ptp_save->con_type & ICY_PROTOCOL) == 0)))
      return;
   if(log_version == 1)
      update_conn_log_mm_v1(ptp_save,pab,pba);
   else
      update_conn_log_mm_v2(ptp_save,pab,pba);
}

void
update_conn_log_mm_v1(tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  double etime;

  etime = elapsed (ptp_save->first_time, ptp_save->last_time);

/* A --> B */
  fprintf (fp_rtp_logc, "%d %d %s %s",
	   PROTOCOL_TCP,
	   ptp_save->con_type,
	   HostName (ptp_save->addr_pair.a_address),
	   ServiceName (ptp_save->addr_pair.a_port));

  fprintf (fp_rtp_logc, " %s %s %lu %g %g %g %g %d %d %g %u %u %f %f %lu %g %g %g %u %u %g %g %g %g %u %g %g",
           HostName (ptp_save->addr_pair.b_address), 
	   ServiceName (ptp_save->addr_pair.b_port), 
	   pab->packets,
	   (pab->sum_delta_t / (pab->n_delta_t - 1)),
	   (pab->sum_jitter / (pab->n_delta_t - 1)),
	   pab->max_jitter,
	   pab->min_jitter,
	   ptp_save->internal_src,
	   ptp_save->internal_dst,
	   (double) pab->ttl_tot / (double) pab->packets,
	   pab->ttl_max,
	   pab->ttl_min,
	   (double) ptp_save->first_time.tv_sec + (double) ptp_save->first_time.tv_usec / 1000000.0,
	   etime / 1000.0,	/* [s] */
	   pab->unique_bytes,
	   ((double) (pab->unique_bytes) / (etime / 1000.0)) * 8,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_http) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_rtsp) / 1000.0,
	   pab->out_order_pkts,
	   pab->rexmit_pkts,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_rtp) / 1000.0,
	   (Average (pab->rtt_sum, pab->rtt_count) / 1000.0),
	   pab->rtt_max / 1000.0,
	   pab->rtt_min / 1000.0,
	   pab->rtt_count,
	   pab->rttvar / 1000.0,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_icy) / 1000.0);

/* B --> A */
  fprintf (fp_rtp_logc, " %d %d %s %s",
	   PROTOCOL_TCP,
	   ptp_save->con_type,
	   HostName (ptp_save->addr_pair.b_address),
	   ServiceName (ptp_save->addr_pair.b_port));

  fprintf (fp_rtp_logc, " %s %s %lu %g %g %g %g %d %d %g %u %u %f %f %lu %g %g %g %u %u %g %g %g %g %u %g %g",
           HostName (ptp_save->addr_pair.a_address), 
	   ServiceName (ptp_save->addr_pair.a_port), 
	   pba->packets,
	   (pba->sum_delta_t / (pba->n_delta_t - 1)),
	   (pba->sum_jitter / (pba->n_delta_t - 1)),
	   pba->max_jitter,
	   pba->min_jitter,
	   ptp_save->internal_src,
	   ptp_save->internal_dst,
	   (double) pba->ttl_tot / (double) pba->packets,
	   pba->ttl_max,
	   pba->ttl_min,
	   (double) ptp_save->first_time.tv_sec + (double) ptp_save->first_time.tv_usec / 1000000.0,
	   etime / 1000.0,	/* [s] */
	   pba->unique_bytes,
	   ((double) (pba->unique_bytes) / (etime / 1000.0)) * 8,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_http) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_rtsp) / 1000.0,
	   pba->out_order_pkts,
	   pba->rexmit_pkts,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_rtp) / 1000.0,
	   (Average (pba->rtt_sum, pba->rtt_count) / 1000.0),
	   pba->rtt_max / 1000.0,
	   pba->rtt_min / 1000.0,
	   pba->rtt_count,
	   pba->rttvar / 1000.0,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_icy) / 1000.0);

  fprintf (fp_rtp_logc, "\n");
}

void
update_conn_log_mm_v2(tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  double etime;

  etime = elapsed (ptp_save->first_time, ptp_save->last_time);

/* A --> B */
  fprintf (fp_rtp_logc, "%d %d %s %s %d %lu %g %g %g %g %g %u %u %f %f %lu %g 0 0 %u %u 0 0 0 0 0 0 0 %g %g %g %u 0 %g %g %g %g",
	   PROTOCOL_TCP,
	   ptp_save->con_type,
	   HostName (ptp_save->addr_pair.a_address),
	   ServiceName (ptp_save->addr_pair.a_port),
	   ptp_save->internal_src,
	   pab->packets,
	   (pab->sum_delta_t / (pab->n_delta_t - 1)),
	   (pab->sum_jitter / (pab->n_delta_t - 1)),
	   pab->max_jitter,
	   pab->min_jitter,
	   (double) pab->ttl_tot / (double) pab->packets,
	   pab->ttl_max,
	   pab->ttl_min,
	   (double) ptp_save->first_time.tv_sec + (double) ptp_save->first_time.tv_usec / 1000000.0,
	   etime / 1000.0,	/* [s] */
	   pab->unique_bytes,
	   ((double) (pab->unique_bytes) / (etime / 1000.0)) * 8,
	   pab->out_order_pkts,
	   pab->rexmit_pkts,
	   (Average (pab->rtt_sum, pab->rtt_count) / 1000.0),
	   pab->rtt_max / 1000.0,
	   pab->rtt_min / 1000.0,
	   pab->rtt_count,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_http) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_rtsp) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_rtp) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_icy) / 1000.0);

/* B --> A */
  fprintf (fp_rtp_logc, " %d %s %s %d %lu %g %g %g %g %g %u %u %f %f %lu %g 0 0 %u %u 0 0 0 0 0 0 0 %g %g %g %u 0 %g %g %g %g",
	   ptp_save->con_type,
	   HostName (ptp_save->addr_pair.b_address),
	   ServiceName (ptp_save->addr_pair.b_port),
	   ptp_save->internal_dst,
	   pba->packets,
	   (pba->sum_delta_t / (pba->n_delta_t - 1)),
	   (pba->sum_jitter / (pba->n_delta_t - 1)),
	   pba->max_jitter,
	   pba->min_jitter,
	   (double) pba->ttl_tot / (double) pba->packets,
	   pba->ttl_max,
	   pba->ttl_min,
	   (double) ptp_save->first_time.tv_sec + (double) ptp_save->first_time.tv_usec / 1000000.0,
	   etime / 1000.0,	/* [s] */
	   pba->unique_bytes,
	   ((double) (pba->unique_bytes) / (etime / 1000.0)) * 8,
	   pba->out_order_pkts,
	   pba->rexmit_pkts,
	   (Average (pba->rtt_sum, pba->rtt_count) / 1000.0),
	   pba->rtt_max / 1000.0,
	   pba->rtt_min / 1000.0,
	   pba->rtt_count,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_http) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_rtsp) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_rtp) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_icy) / 1000.0);
  
  fprintf (fp_rtp_logc, "\n");
}

void
free_tp (tcp_pair * ptp_save)
{
  int i;
  /* free up memory for the flow stats */

  /* for each quad then for each segment in each quad... */
  for (i = 0; i < 4; i++)
    {
      if (ptp_save->c2s.ss->pquad[i] != NULL)
	{
	  freequad (&(ptp_save->c2s.ss->pquad[i]));
	}
    }

  for (i = 0; i < 4; i++)
    {
      if (ptp_save->s2c.ss->pquad[i] != NULL)
	{
	  freequad (&(ptp_save->s2c.ss->pquad[i]));
	}
    }

  /* finally free up the ptp */

  tp_release (ptp_save);
  ptp_save = NULL;

}


void
freequad (quadrant ** ppquad)
{
  segment *pseg;
  segment *pseg_next;

  pseg = (*ppquad)->seglist_head;
  while (pseg && pseg->next)
    {
      pseg_next = pseg->next;
      segment_release (pseg);
      pseg = pseg_next;
    }
  if (pseg)
    segment_release (pseg);

  (*ppquad)->no_of_segments = 0;
  quadrant_release (*ppquad);
  *ppquad = NULL;
}
