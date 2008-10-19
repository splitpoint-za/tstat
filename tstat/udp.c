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


#include "tstat.h"


/* Dichiarazione dei mutex per gestione dei thread */
extern pthread_mutex_t utp_lock_mutex;
extern pthread_mutex_t flow_close_started_mutex;
extern pthread_mutex_t flow_close_cond_mutex;
extern pthread_cond_t flow_close_cond;
extern Bool threaded;

extern struct L4_bitrates L4_bitrate;

/* locally global variables */
static int packet_count = 0;
static int search_count = 0;



/* provided globals  */
int num_udp_pairs = -1;		/* how many pairs we've allocated */
u_long udp_trace_count = 0;
udp_pair **utp = NULL;		/* array of pointers to allocated pairs */


/* local routine definitions */
static udp_pair *NewUTP (struct ip *, struct udphdr *);
static udp_pair *FindUTP (struct ip *, struct udphdr *, int *);


extern unsigned long int fcount;
extern Bool warn_MAX_;
extern unsigned long int f_UDP_count;

#ifdef CHECK_UDP_DUP
Bool
dup_udp_check (struct ip *pip, ucb * thisdir, int dir, udp_pair * pup_save)
{
//  static int tot;
  double delta_t = elapsed (thisdir->last_pkt_time, current_time);
  if (thisdir->last_ip_id == pip->ip_id &&
      delta_t < MIN_DELTA_T_UDP_DUP_PKT && thisdir->last_len == pip->ip_len)
    {
//       fprintf (fp_stdout, "dup udp %d , id = %u ",tot++, pip->ip_id);
//       fprintf (fp_stdout, "TTL: %d ID: %d Delta_t: %g\n", 
//          pip->ip_ttl,pip->ip_id,delta_t);
      thisdir->last_ip_id = pip->ip_id;
      thisdir->last_len = pip->ip_len;
      return TRUE;
    }
//    fprintf (fp_stdout, "NOT dup udp %d\n",tot);
  thisdir->last_ip_id = pip->ip_id;
  thisdir->last_len = pip->ip_len;
  return FALSE;
}
#endif

static udp_pair *
NewUTP (struct ip *pip, struct udphdr *pudp)
{
  udp_pair *pup;
  int old_new_udp_pairs = num_udp_pairs;
  int steps = 0;

  /* look for the next eventually available free block */
  num_udp_pairs++;
  num_udp_pairs = num_udp_pairs % MAX_UDP_PAIRS;
  /* make a new one, if possible */
  while ((num_udp_pairs != old_new_udp_pairs) && (utp[num_udp_pairs] != NULL)
	 && (steps < LIST_SEARCH_DEPT))
    {
      steps++;
      /* look for the next one */
//         fprintf (fp_stdout, "%d %d\n", num_udp_pairs, old_new_udp_pairs);
      num_udp_pairs++;
      num_udp_pairs = num_udp_pairs % MAX_UDP_PAIRS;
    }
  if (utp[num_udp_pairs] != NULL)
    {
      if (warn_MAX_)
	{
	  fprintf (fp_stdout, 
        "\nooopsss: number of simultaneous connection opened is greater then the maximum supported number!\n"
	    "you have to rebuild the source with a larger LIST_SEARCH_DEPT defined!\n"
	    "or possibly with a larger 'MAX_UDP_PAIRS' defined!\n");
	}
      warn_MAX_ = FALSE;
      return (NULL);
    }

  /* create a new UDP pair record and remember where you put it */
  pup = utp[num_udp_pairs] = utp_alloc ();

  /* grab the address from this packet */
  CopyAddr (&pup->addr_pair,
	    pip, ntohs (pudp->uh_sport), ntohs (pudp->uh_dport));

  pup->c2s.first_pkt_time.tv_sec = 0;
  pup->s2c.first_pkt_time.tv_sec = 0;

  pup->c2s.last_pkt_time.tv_sec = -1;
  pup->s2c.last_pkt_time.tv_sec = -1;

  pup->c2s.pup = pup;
  pup->s2c.pup = pup;

  pup->internal_src = internal_src;
  pup->internal_dst = internal_dst;

  pup->c2s.type = UDP_UNKNOWN;
  pup->s2c.type = UDP_UNKNOWN;
  return (utp[num_udp_pairs]);
}


udp_pair *pup_hashtable[HASH_TABLE_SIZE] = { NULL };


/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/
// static 
udp_pair *
FindUTP (struct ip * pip, struct udphdr * pudp, int *pdir)
{
  udp_pair **ppup_head = NULL;
  udp_pair *pup;
  udp_pair *pup_last;
  udp_pair tp_in;


  int dir;
  hash hval;

  /* grab the address from this packet */
  CopyAddr (&tp_in.addr_pair, pip,
	    ntohs (pudp->uh_sport), ntohs (pudp->uh_dport));

  /* grab the hash value (already computed by CopyAddr) */
  hval = tp_in.addr_pair.hash % HASH_TABLE_SIZE;


  pup_last = NULL;
  ppup_head = &pup_hashtable[hval];
  for (pup = *ppup_head; pup; pup = pup->next)
    {
      ++search_count;
      if (SameConn (&tp_in.addr_pair, &pup->addr_pair, &dir))
	{
	  /* move to head of access list (unless already there) */
	  if (pup != *ppup_head)
	    {
	      pup_last->next = pup->next;	/* unlink */
	      pup->next = *ppup_head;	/* move to head */
	      *ppup_head = pup;
	    }
	  *pdir = dir;

/*
#ifdef RUNTIME_SKYPE_RESET
	  if (elapsed (pup->first_time, current_time) >
	      SKYPE_UPDATE_DELTA_TIME)
	    {
//            close_udp_flow (pup, -1, dir)
	      memset (&(pup->c2s.skype), 0, sizeof ((pup->c2s.skype)));
	      memset (&(pup->s2c.skype), 0, sizeof ((pup->s2c.skype)));
	      bayes_reset ((pup->c2s.bc_pktsize), BAYES_RESET_ZERO);
	      bayes_reset ((pup->c2s.bc_avgipg), BAYES_RESET_ZERO);

	    }
	  else
#endif
*/
	    return (pup);
	}
      pup_last = pup;
    }

/* if is elapsed an IDLE_TIME from the last cleaning flow operation I will start
a new one */

  // we fire it at DOUBLE rate, but actually clean only those > UDP_IDLE_TIME
  if (elapsed (last_cleaned, current_time) > UDP_IDLE_TIME / 2)
    {
      if (threaded)
	{
	  pthread_mutex_lock (&flow_close_cond_mutex);

#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "Signaling thread FLOW CLOSE\n");
#endif
	  pthread_cond_signal (&flow_close_cond);
	  pthread_mutex_unlock (&flow_close_cond_mutex);

	  pthread_mutex_lock (&flow_close_started_mutex);
	  pthread_mutex_unlock (&flow_close_started_mutex);
#ifdef DEBUG_THREAD
	  fprintf (fp_stdout, "\n\nlocked thread FLOW CLOSE\n");
#endif
	}
      else
	trace_done_periodic ();
      last_cleaned = current_time;
    }

  fcount++;
  f_UDP_count++;
  add_histo (L4_flow_number, L4_FLOW_UDP);

  if (threaded)
    {
#ifdef DEBUG_THREAD_UTP
      fprintf (fp_stdout, "\n\nFindUTP: Try to lock thread UTP\n");
#endif

      pthread_mutex_lock (&utp_lock_mutex);

#ifdef DEBUG_THREAD_UTP
      fprintf (fp_stdout, "\n\nFindUTP: Got lock thread UTP\n");
#endif
    }
  pup = NewUTP (pip, pudp);

  /* put at the head of the access list */
  if (pup)
    {
      tot_conn_UDP++;
      pup->next = *ppup_head;
      *ppup_head = pup;
    }

  *pdir = C2S;

  if (threaded)
    {
      pthread_mutex_unlock (&utp_lock_mutex);

#ifdef DEBUG_THREAD_UTP
      fprintf (fp_stdout, "\n\nFindUTP: Unlocked thread TTP\n");
#endif
    }

  /*Return the new utp */

  return (pup);
}



udp_pair *
udp_flow_stat (struct ip * pip, struct udphdr * pudp, void *plast)
{

  udp_pair *pup_save;
  ucb *thisdir;
  ucb *otherdir;
  udp_pair tp_in;
  int dir;
  u_short uh_sport;		/* source port */
  u_short uh_dport;		/* destination port */
  u_short uh_ulen;		/* data length */

  /* make sure we have enough of the packet */
  if ((unsigned long) pudp + sizeof (struct udphdr) - 1 >
      (unsigned long) plast)
    {
      if (warn_printtrunc)
	fprintf (fp_stderr,
		 "UDP packet %lu truncated too short to trace, ignored\n",
		 pnum);
      ++ctrunc;
      return (NULL);
    }


  /* convert interesting fields to local byte order */
  uh_sport = ntohs (pudp->uh_sport);
  uh_dport = ntohs (pudp->uh_dport);
  uh_ulen = ntohs (pudp->uh_ulen);

  if (internal_src && !internal_dst)
    {
      L4_bitrate.out[UDP_TYPE] += ntohs (pip->ip_len);
      add_histo (udp_port_dst_in, (float) (uh_dport));
    }
  else if (!internal_src && internal_dst)
    {
      L4_bitrate.in[UDP_TYPE] += ntohs (pip->ip_len);
      add_histo (udp_port_dst_out, (float) (uh_dport));
    }
  else if (internal_src && internal_dst)
    {
      L4_bitrate.loc[UDP_TYPE] += ntohs (pip->ip_len);
      add_histo (udp_port_dst_loc, (float) (uh_dport));
    }

  /* stop at this level of analysis */
  ++udp_trace_count;

  /* make sure this is one of the connections we want */
  pup_save = FindUTP (pip, pudp, &dir);

  ++packet_count;

  if (pup_save == NULL)
    {
      return (NULL);
    }

  /* do time stats */
  if (ZERO_TIME (&pup_save->first_time))
    {
      pup_save->first_time = current_time;

    }
  pup_save->last_time = current_time;

  /* grab the address from this packet */
  CopyAddr (&tp_in.addr_pair, pip, uh_sport, uh_dport);

  /* figure out which direction this packet is going */
  if (dir == C2S)
    {
      thisdir = &pup_save->c2s;
      otherdir = &pup_save->s2c;
    }
  else
    {
      thisdir = &pup_save->s2c;
      otherdir = &pup_save->c2s;
    }

#ifdef CHECK_UDP_DUP
  /* check if this is a dupe udp */
  if (dup_udp_check (pip, thisdir, dir, pup_save)) {
    return NULL;
  }
#endif

  if ((thisdir->last_pkt_time.tv_sec) == -1)	/* is the first time I see this flow */
    {
      /* destination port of the flow */
      add_histo (udp_port_flow_dst, (float) (ntohs (pudp->uh_dport)));
      /* flow starting time */
      thisdir->first_pkt_time = current_time;
    }
  thisdir->last_pkt_time = current_time;

  /* do data stats */
  thisdir->data_bytes += uh_ulen - 8;	/* remove the UDP header */


  /* total packets stats */
  ++pup_save->packets;
  ++thisdir->packets;

   /*TOPIX*/
    /*TTL stats */
    if ((thisdir->ttl_min == 0) || (thisdir->ttl_min > (int) pip->ip_ttl))
    thisdir->ttl_min = (int) pip->ip_ttl;
  if (thisdir->ttl_max < (int) pip->ip_ttl)
    thisdir->ttl_max = (int) pip->ip_ttl;
  thisdir->ttl_tot += (u_llong) pip->ip_ttl;
   /*TOPIX*/
    //
    // NOW, this should be called by proto_analyzer...
    //
    //   p_rtp = getrtp (pudp, plast);
    //   if ((p_rtp) != NULL)
    //       rtpdotrace (thisdir, p_rtp, dir, pip);
    // 
    // 
    proto_analyzer (pip, pudp, PROTOCOL_UDP, thisdir, dir, plast);

    //if (thisdir != NULL && thisdir->pup != NULL)
    make_udpL7_rate_stats(thisdir, ntohs(pip->ip_len));

  return (pup_save);
}



void
udptrace_init (void)
{
  static Bool initted = FALSE;

  if (initted)
    return;

  initted = TRUE;

  /* create an array to hold any pairs that we might create */
  utp = (udp_pair **) MallocZ (MAX_UDP_PAIRS * sizeof (udp_pair *));
}

void
udptrace_done (void)
{
  udp_pair *pup;
  int ix;
  int dir;

  for (ix = 0; ix <= num_udp_pairs; ++ix)
    {
      pup = utp[ix];
      if (pup == NULL)		/* already analized */
	continue;
      /* consider this udp connection */
      if (!con_cat) {
          //flush histos and call the garbage colletor
          //Note: close_udp_flow() calls make_udp_conn_stats()
          close_udp_flow(pup, ix, &dir);
      }
      else
        //only flush histos
        make_udp_conn_stats (pup, TRUE);
    }
}

void
make_udp_conn_stats (udp_pair * pup_save, Bool complete)
{
  double etime;

  if (complete)
    {
      if (pup_save->internal_src && !pup_save->internal_dst)
	{
	  add_histo (udp_cl_b_s_out, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_s_in, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_l_out, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_l_in, pup_save->s2c.data_bytes);

	  add_histo (udp_cl_p_out, pup_save->c2s.packets);
	  add_histo (udp_cl_p_in, pup_save->s2c.packets);
	}
      else if (!pup_save->internal_src && pup_save->internal_dst)
	{
	  add_histo (udp_cl_b_s_out, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_s_in, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_l_out, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_l_in, pup_save->c2s.data_bytes);

	  add_histo (udp_cl_p_out, pup_save->s2c.packets);
	  add_histo (udp_cl_p_in, pup_save->c2s.packets);
	}
      else if (pup_save->internal_src && pup_save->internal_dst)
	{
	  add_histo (udp_cl_b_s_loc, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_s_loc, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_l_loc, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_l_loc, pup_save->c2s.data_bytes);

	  add_histo (udp_cl_p_loc, pup_save->s2c.packets);
	  add_histo (udp_cl_p_loc, pup_save->c2s.packets);

	}
      else
	{
	  if (warn_IN_OUT)
	    {
	      fprintf (fp_stdout, 
            "\nWARN: This udp flow is neither incoming nor outgoing: src - %s;",
		    HostName (pup_save->addr_pair.a_address));
	      fprintf (fp_stdout, " dst - %s!\n",
		      HostName (pup_save->addr_pair.b_address));
	      warn_IN_OUT = FALSE;
	    }
#ifndef LOG_UNKNOWN
	  return;
#endif
#ifdef LOG_UNKNOWN
/* fool the internal and external definition... */
	  add_histo (udp_cl_b_s_loc, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_s_loc, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_l_loc, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_l_loc, pup_save->c2s.data_bytes);

	  add_histo (udp_cl_p_loc, pup_save->s2c.packets);
	  add_histo (udp_cl_p_loc, pup_save->c2s.packets);
#endif
	}
    }

  /* Statistics using plugins */

  make_proto_stat (pup_save, PROTOCOL_UDP);

  /* connection time */
  /* from microseconds to ms */
  etime = elapsed (pup_save->first_time, pup_save->last_time);
  etime = etime / 1000;
  add_histo (udp_tot_time, etime);
}



void
close_udp_flow (udp_pair * pup, int ix, int dir)
{

  extern udp_pair *pup_hashtable[];
  udp_pair **ppuph_head = NULL;
  udp_pair *puph_tmp, *puph, *puph_prev;
  unsigned int cleaned = 0;
  hash hval;
  int j;



  if (threaded)
    {
#ifdef DEBUG_THREAD_UTP
      fprintf (fp_stdout, "\n\nTrace_done_periodic: trying lock thread UTP\n");
#endif
      pthread_mutex_lock (&utp_lock_mutex);
#ifdef DEBUG_THREAD_UTP
      fprintf (fp_stdout, "\n\nTrace_done_periodic: got lock thread UTP\n");
#endif
      if ((pup == NULL))
	/* someonelse already cleaned this pup */
	{
	  pthread_mutex_unlock (&utp_lock_mutex);
	  return;
	}
      if ((elapsed (pup->last_time, current_time) <= UDP_IDLE_TIME)
	  || (pup->last_time.tv_sec == 0 && pup->last_time.tv_usec == 0))
	{
	  /* someonelse already cleaned this pup */
	  pthread_mutex_unlock (&utp_lock_mutex);
	  return;
	}
    }
  /* must be cleaned */
  cleaned++;

  /* Consider this flow for statistic collections */
  make_udp_conn_stats (pup, TRUE);
  tot_conn_UDP--;

  /* free up hash element->.. */
  hval = pup->addr_pair.hash % HASH_TABLE_SIZE;

  ppuph_head = &pup_hashtable[hval];
  j = 0;
  puph_prev = *ppuph_head;
  for (puph = *ppuph_head; puph; puph = puph->next)
    {
      j++;
      if (SameConn (&pup->addr_pair, &puph->addr_pair, &dir))
	{
	  puph_tmp = puph;
	  if (j == 1)
	    {
	      /* it is the top of the list */
	      pup_hashtable[hval] = puph->next;
	    }
	  else
	    {
	      /* it is in the middle of the list */
	      puph_prev->next = puph->next;
	    }
	  utp_release (puph_tmp);
	  break;
	}
      puph_prev = puph;
    }

  if (ix == -1)			/* I should look for the correct ix value */
    {
      for (ix = 0; ix < MAX_UDP_PAIRS; ++ix)
	{
	  //      pup = utp[ix];

	  if ((utp[ix] == NULL))
	    continue;

	  /* If no packets have been received in the last UDP_IDLE_TIME period,
	     close the flow */
	  if (SameConn (&pup->addr_pair, &utp[ix]->addr_pair, &dir))
	    {
	      break;
	    }
	}
    }

  utp[ix] = NULL;

  if (threaded)
    {
      pthread_mutex_unlock (&utp_lock_mutex);
#ifdef DEBUG_THREAD_UTP
      fprintf (fp_stdout, "\n\nTrace_done_periodic: released lock thread UTP\n");
#endif
    }

}
