/*
 *
 * Copyright (c) 2006
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
 *              http://http://www.tlc-networks.polito.it/index.html
 *		mellia@mail.tlc.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/


#include "tstat.h"

/* define SKYPE_DEBUG if you want to see all identified pkts */
//#define SKYPE_DEBUG

FILE *fp_skype_mode;
extern FILE *fp_skype_logc;
extern FILE *fp_bayes_logc;
extern Bool log_engine;
extern Bool bayes_engine;
extern struct L4_bitrates L4_bitrate;
extern struct L7_bitrates L7_bitrate;

void
skype_init ()
{
  /* nothing to do so far */
}


/******** function used to convert bayes configuration FEATURE string into 
	  a numerical valueto speedup the code execution	**********/

int
skype_feat2code (char *str)
{

#define SKYPE_FEAT_PKTSIZE 0
  if (!strcmp (str, "PKTSIZE"))
    return SKYPE_FEAT_PKTSIZE;

#define SKYPE_FEAT_MAXDELPKTSIZE 1
  if (!strcmp (str, "MAXDELPKTSIZE"))
    return SKYPE_FEAT_MAXDELPKTSIZE;

#define SKYPE_FEAT_AVGIPG 2
  if (!strcmp (str, "AVGIPG"))
    return SKYPE_FEAT_AVGIPG;

#define SKYPE_FEAT_PKTRATE 3
  if (!strcmp (str, "PKTRATE"))
    return SKYPE_FEAT_PKTRATE;

#define SKYPE_FEAT_BITRATE 4
  if (!strcmp (str, "BITRATE"))
    return SKYPE_FEAT_BITRATE;

#define SKYPE_FEAT_AVGPKT 5
  if (!strcmp (str, "AVGPKT"))
    return SKYPE_FEAT_AVGPKT;

#define SKYPE_FEAT_UNKNOWN -1
  return SKYPE_FEAT_UNKNOWN;
}






/******** function used to find the skype packet starting point **********/


void
update_randomness (random_stat * random, void *hdr, skype_hdr * pskype,
		   void *plast, int tproto, int payload_len)
{
  int i, j;
  int random_bits;
  int valid_blocks;
  u_int32_t *ppayload = NULL;

/* 
we use the chi square test, forming nibbles of N_RANDOM_BIT bits
and checkg the uniformity of the distribution.
for each random bits, update the frequency */

  if (tproto == PROTOCOL_UDP)
    {
      udphdr *pudp;
      pudp = (udphdr *) hdr;

      ppayload = ((u_int32_t *) pudp) + 2 /* 32bit*2 for udp header */ ;
    }
  else if (tproto == PROTOCOL_TCP)
    {
      tcphdr *ptcp;
      ptcp = (tcphdr *) hdr;

      ppayload = ((u_int32_t *) ptcp) + (u_int32_t) (ptcp->th_off);
    }
  valid_blocks = (payload_len > ((int) plast - (int) ppayload + 1)
		  ? ((int) plast - (int) ppayload + 1)
		  : payload_len) * 8 / N_RANDOM_BIT;

  i = 0;
  do
    {
      for (j = 0; j < (sizeof (u_int32_t) * 8 / N_RANDOM_BIT) && (i < N_BLOCK); j++)	/* number of shift in the word */
	{
	  if (i <= valid_blocks)
	    {
	      random_bits = (*ppayload >> N_RANDOM_BIT * j) & RND_MASK;
	    }
	  else			/* real data, no padding */
	    {
	      random_bits = 0;
	    }
	  random->rnd_bit_histo[random_bits][i]++;
	  i++;
	}
      ppayload++;		/* go to the next word */
    }
  while (i < N_BLOCK);
  random->rnd_n_samples++;	/* Number of valid packets */
}


void
update_delta_t (deltaT_stat * stat)
{
  if (stat->last_time.tv_usec == 0 && stat->last_time.tv_usec == 0)
    stat->last_time = current_time;
  else
    {
      stat->sum += elapsed (stat->last_time, current_time) / 1000;
      stat->n++;
      stat->last_time = current_time;
    }
}

double
get_average_delta_t (deltaT_stat * stat)
{
  if (stat->n)
    return (stat->sum / stat->n);
  else
    return -1.0;
}


struct skype_hdr *
getSkype (struct udphdr *pudp, int tproto, void *pdir, void *plast)
{

  void *theheader;

  theheader = ((char *) pudp + 8);
  if ((u_long) theheader + (sizeof (struct skype_hdr)) - 1 > (u_long) plast)
    {
      /* part of the header is missing */
      return (NULL);
    }
  return (struct skype_hdr *) theheader;
}

void
print_skype (struct ip *pip, void *pproto, void *plast)
{
  unsigned char *theheader = ((unsigned char *) pproto + 8);
  int i;

  printf ("%s\t", inet_ntoa (pip->ip_src));
  printf ("%s\t", inet_ntoa (pip->ip_dst));
  printf ("%3d ", (ntohs ((pip)->ip_len) - 28));
  for (i = 0; i < 11; i++, theheader++)
    {
      /* we have headers of this packet */
      if (theheader <= (unsigned char *) plast)
	printf ("%2X ", *theheader);
      else
	printf ("xx ");
    }

  theheader = ((unsigned char *) pproto + 8);
  for (i = 0; i < 11; i++, theheader++)
    {
      /* we have headers of this packet */
      if (theheader <= (unsigned char *) plast)
	printf ("%3d ", *theheader);
      else
	printf ("xxx ");
    }
  printf ("\n");
}



void
skype_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
		 int dir, void *hdr, void *plast)
{
  skype_hdr *pskype = (struct skype_hdr *) hdr;
  int type;
  int payload_len;
  tcphdr *ptcp;
  ptcp = (tcphdr *) hdr;



  type = (tproto == PROTOCOL_UDP) ?
    is_skype_pkt (pip, pproto, pdir, pskype, plast) : NOT_SKYPE;

  if (tproto == PROTOCOL_UDP)
    {
      payload_len = ntohs (((struct udphdr *) pproto)->uh_ulen) - 8;
      ((ucb *) pdir)->skype.pkt_type_num[type]++;
      update_delta_t (&((ucb *) pdir)->skype.stat[type]);
      update_randomness (&((ucb *) pdir)->skype.random, pproto, pskype, plast,
			 tproto, payload_len);
#ifdef RUNTIME_SKYPE
      float etime_s =
	(elapsed (((ucb *) pdir)->skype.LastSkypePrint_time, current_time));

      if (etime_s > SKYPE_UPDATE_DELTA_TIME)
	if ((((ucb *) pdir)->packets - ((ucb *) pdir)->lastnumpkt) > 10)
	  //if ((&((ucb *) pdir)->skype)->pkt_type_num[TOTAL_SKYPE_KNOWN_TYPE] > 10)
	  {
	    //  printf (" %.2f ", etime_s);
	    ((ucb *) pdir)->skype.LastSkypePrint_time = current_time;
	    //((ucb *) pdir)->lastnumpkt = ((ucb *) pdir)->packets;
	    skype_conn_stats (&(((ucb *) pdir)->pup->c2s), C2S, PROTOCOL_UDP);
	    skype_conn_stats (&(((ucb *) pdir)->pup->s2c), S2C, PROTOCOL_UDP);
	  }


#endif
    }
  else
    {				/* tproto == PROTOCOL_TCP */


      payload_len =
	getpayloadlength (pip, plast) - ((tcphdr *) pproto)->th_off * 4;

      if (payload_len > 0)	/* skip pure ack and signalling */
	update_randomness (&((tcb *) pdir)->skype.random, pproto, pskype,
			   plast, tproto, payload_len);

    }

//===================================================================================
//  bayes classification
#define SKYPE_WINDOW_SIZE 30.0

  if (bayes_engine)
    {
      struct bayes_classifier *bc_pktsize = (tproto == PROTOCOL_UDP) ?
	((ucb *) pdir)->bc_pktsize : ((tcb *) pdir)->bc_pktsize;

      struct bayes_classifier *bc_avgipg = (tproto == PROTOCOL_UDP) ?
	((ucb *) pdir)->bc_avgipg : ((tcb *) pdir)->bc_avgipg;

      struct skype_stat *sk = (tproto == PROTOCOL_UDP) ?
	&((ucb *) pdir)->skype : &((tcb *) pdir)->skype;

      int pktsize, avgipg;
      Bool full_window = FALSE, is_1st_packet = FALSE;

      // 
      // non windowed 
      // 
      // 
      // or windowed ?                                                                                
      // 


      switch (tproto)
	{
	case PROTOCOL_UDP:
	  pktsize = UDP_PAYLOAD_LEN (pip);
	  if (((ucb *) pdir)->packets == 1)
	    {
	      sk->win.start = current_time;
	      is_1st_packet = TRUE;
	    }
	  break;

	case PROTOCOL_TCP:
	  pktsize =
	    getpayloadlength (pip, plast) - (4 * ((tcphdr *) pproto)->th_off);
	  /* avoid to consider TCP ACK */
	  if (pktsize == 0)
	    return;
	  if (((tcb *) pdir)->data_pkts == 1)
	    {
	      sk->win.start = current_time;
	      is_1st_packet = TRUE;
	    }
//       printf(" %d ",(4*ptcp->th_off));
	  break;
	default:
	  perror ("skype_flow_stat: fatal - you should never stop here!!\n");
	  exit (1);
	}

      //printf(" %d ", pktsize); 



      // update the number of pure video packets
      // CHECK DARIO
      if (((pktsize >= 400 && pktsize <= 490)
	   || (pktsize >= 800 && pktsize <= 980)) && tproto == PROTOCOL_UDP)
	{
	  sk->video_pkts++;
	  full_window = FALSE;
	}
      else
	{
	  sk->audiovideo_pkts++;
	  full_window = !(sk->audiovideo_pkts % ((int) SKYPE_WINDOW_SIZE));
	}

      // update window size      
      sk->win.bytes += pktsize;
      sk->win.pktsize_max =
	sk->win.pktsize_max > pktsize ? sk->win.pktsize_max : pktsize;
      sk->win.pktsize_min =
	sk->win.pktsize_min < pktsize ? sk->win.pktsize_min : pktsize;

      if (full_window && !is_1st_packet)
	{
	  avgipg =
	    (int) (elapsed (sk->win.start, current_time) / 1000.0 /
		   SKYPE_WINDOW_SIZE);

	  // reset the window
	  sk->win.pktsize_max = -1;
	  sk->win.pktsize_min = 65535;
	  sk->win.start = current_time;
	  sk->win.bytes = 0;

	  bayes_sample (bc_avgipg, avgipg);
	}

      // rougly filter video packets for UDP protocol only
      if ((pktsize < 400 && tproto == PROTOCOL_UDP) || tproto == PROTOCOL_TCP)
	bayes_sample (bc_pktsize, pktsize);
    }

// bayes END
//===================================================================================



#ifdef SKYPE_DEBUG
  switch (type)
    {
    case SKYPE_NAK:
      printf ("%4llu NAK\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);
      break;

    case SKYPE_FUN2:
      printf ("%4llu FUN2\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);
      break;

    case SKYPE_FUN3:
      printf ("%4llu FUN3\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);
      break;

    case SKYPE_E2E_DATA:
      printf ("%4llu E2E_DATA\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);
      break;

    case SKYPE_OUT_DATA:
      printf ("%4llu OUT_DATA\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);

      break;

    case NOT_SKYPE:
      printf ("%4llu UNKNOWN\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);
    default:
      ;

    }
#endif
}


int
is_skypeOUT_pkt (struct ip *pip, struct udphdr *pudp, void *pdir,
		 struct skype_hdr *pskype, void *plast)
{

  /* the length was 29bytes */
  /* this might be an OUT DATA PKT */
  /* should see one every 20ms */

  void *theheader = ((char *) pudp + 8);	/* skip udp header */
  ucb *thisdir = (ucb *) pdir;

  if ((thisdir->skype.OUT_data_block == 0) &&
      ((u_long) theheader + (sizeof (struct skype_OUT)) - 1 <=
       (u_long) plast))
    {
      /* we have all the identifier block, copy it for future use */
      thisdir->skype.OUT_data_block = ((struct skype_OUT *) theheader)->block;
      return NOT_SKYPE;
    }

  if (thisdir->skype.OUT_data_block == ((struct skype_OUT *)
					theheader)->block)
    {
      return SKYPE_OUT_DATA;
    }
  else
    {
      /* we have a new the identifier block, copy it for future use */
      thisdir->skype.OUT_data_block = ((struct skype_OUT *) theheader)->block;
      return NOT_SKYPE;
    }



  return NOT_SKYPE;
}



Bool
is_skype_pkt (struct ip * pip, struct udphdr * pudp, void *pdir,
	      struct skype_hdr * pskype, void *plast)
{


  if (is_skypeOUT_pkt (pip, pudp, pdir, pskype, plast) == SKYPE_OUT_DATA)
    return SKYPE_OUT_DATA;



  if (((pskype->func & 0x8f) == 0x07) &&	/* is function 7  */
      (UDP_PAYLOAD_LEN (pip) == 11))	/* the length was 11bytes */
    {
      /* this is a NAK, used as quick STUN like hack to find my real IP
         in case a NAT is going to be traversed */

      return SKYPE_NAK;
    }

  if ((pskype->func & 0x8f) == 0x02)	/* is function 2  */
    {
      /* this is a FUN2 msg. It is sent several time, with different length
         is usually the first packet, whose len is 28 */

      return SKYPE_FUN2;
    }

  if ((pskype->func & 0x8f) == 0x03)	/* is function 3  */
    {
      /* this is a FUN3 msg. It is sent several time, usually after receiving
         a NAK packet */

      return SKYPE_FUN3;
    }


  if ((pskype->func & 0x8f) == 0x0d)	/* is function 13  */
    {
      if (UDP_PAYLOAD_LEN (pip) > 4)
	{
	  /* this might be a voice sample */
	  /* should see one every DeltaT ms */
	  return SKYPE_E2E_DATA;
	}
      else
	{
	  /* this might be a data keep alive */
	  return SKYPE_FUN3;
	}

    }

  return NOT_SKYPE;
}



/******** function to update the skype stats *********/

/* this will be called by the plugin */
void
make_skype_conn_stats (void *thisflow, int tproto)
{
  /* Statistichs about SKYPE flows */

  skype_conn_stats (thisflow, C2S, tproto);
  skype_conn_stats (thisflow, S2C, tproto);

}

void
skype_conn_stats (void *thisdir, int dir, int tproto)
{
  struct skype_stat *pskype;
  int i;
  int tot_skype = 0;
  struct ucb *thisUdir;
  struct tcb *thisTdir;

  switch (tproto)
    {
    case PROTOCOL_UDP:
      if (dir == C2S)
	{
	  thisUdir = &(((udp_pair *) thisdir)->c2s);
	  thisTdir = NULL;
	  pskype = &thisUdir->skype;
	}
      else
	{
	  thisUdir = &(((udp_pair *) thisdir)->s2c);
	  thisTdir = NULL;
	  pskype = &thisUdir->skype;
	}
      break;
    case PROTOCOL_TCP:
      if (dir == C2S)
	{
	  thisTdir = &(((tcp_pair *) thisdir)->c2s);
	  thisUdir = NULL;
	  pskype = &thisTdir->skype;
	}
      else
	{
	  thisTdir = &(((tcp_pair *) thisdir)->s2c);
	  thisUdir = NULL;
	  pskype = &thisTdir->skype;
	}
      break;
    default:
      perror ("skype_conn_stats: fatal - you should never stop here!!\n");
      exit (1);
    }

  if (!log_engine || fp_skype_logc == NULL)
    return;


  /* first check if there is at least a skype pkt */

  tot_skype = 0;
  for (i = 1; i < TOTAL_SKYPE_KNOWN_TYPE; i++)
    tot_skype += pskype->pkt_type_num[i];

  // Skip only very short flows
  //  if ( tot_skype  < MIN_SKYPE_PKTS)

  switch (tproto)
    {
    case PROTOCOL_UDP:
      if (thisUdir->packets < MIN_SKYPE_PKTS)
	return;
      break;

    case PROTOCOL_TCP:
      if ((&thisTdir->skype)->random.rnd_n_samples < MIN_SKYPE_PKTS_TCP)
	return;
      break;
    }

  /* log only SKYPE or unknown traffic */

  if (tproto != PROTOCOL_UDP)
      return;

  switch (thisUdir->type)
  {
      case RTP:
      case RTCP:
      case P2P_DC:
      case P2P_GNU:
      case P2P_KAZAA:
      case P2P_BT:
      case P2P_JOOST:
      case P2P_PPLIVE:
      case P2P_SOPCAST:
      case P2P_TVANTS:
          break;

      case SKYPE_E2E:
      case SKYPE_OUT:
      case SKYPE_SIG:
          printf ("skype.c: No idea how I get there !\n");
          exit (1);
          break;

      case FIRST_RTP:
      case FIRST_RTCP:
      case P2P_EDK:  /* Skype could be matched by generic Emule/Kad rules */
      case P2P_KAD:
      case P2P_KADU:
      case UDP_UNKNOWN:
      default:

          if ((pskype->pkt_type_num[SKYPE_E2E_DATA] > MIN_SKYPE_E2E_NUM) &&
                  ((double) pskype->pkt_type_num[SKYPE_E2E_DATA] * 100.0 /
                   (double) thisUdir->packets > MIN_SKYPE_E2E_PERC))
          {
              thisUdir->type = SKYPE_E2E;

          }
          else if ((pskype->pkt_type_num[SKYPE_OUT_DATA] > MIN_SKYPE_OUT_NUM)
                  && ((double) pskype->pkt_type_num[SKYPE_OUT_DATA] * 100.0 /
                      (double) thisUdir->packets > MIN_SKYPE_OUT_PERC))
          {
              thisUdir->type = SKYPE_OUT;
              /*    if (dir == S2C) {
                    if (strcmp(ServiceName(pup->addr_pair.a_port),"12340")==0)  {

                    thisUdir->type = SKYPE_OUT;
                    }
                    }
                    else 
                    if (strcmp(ServiceName(pup->addr_pair.b_port),"12340")==0)  {

                    thisUdir->type = SKYPE_OUT;
                    } */
          }
          else if (thisUdir->packets
                  && (tot_skype * 100 / thisUdir->packets > MIN_SKYPE_PERC))
          {
              thisUdir->type = SKYPE_SIG;

          }
          else
          {
              if (thisUdir->type==FIRST_RTP || thisUdir->type==FIRST_RTCP)
              {
                  thisUdir->type = UDP_UNKNOWN;
              }
          }

          #ifdef ONELINE_LOG_FORMAT
            if (dir == C2S)
              return;
          #endif
          if (tproto == PROTOCOL_UDP)
          {
              print_skype_conn_stats_UDP (thisUdir, dir);	/* thisUdir */
          }
          else
          {
              print_skype_conn_stats_TCP (thisTdir, dir);	/* thisTdir */
          }
          break;

  }
}


void
print_skype_conn_stats_UDP (void *thisdir, int dir)
{
  int i, j, CSFT = -1;
  int C2S_is_Skype = 0;
  struct ucb *thisUdir;
  char logline[400];
  struct skype_stat *pskype;
  struct sudp_pair *pup;
  double chi_square[N_BLOCK];
  double expected_num;
  Bool video_present;
  thisUdir = (ucb *) thisdir;
  pup = thisUdir->pup;
  pskype = &thisUdir->skype;
  double minCHI_E2O_HDR, maxCHI_E2E_HDR, minCHI_E2E_HDR, maxCHI_PAY;


  if (bayes_engine)
    {
      if (pup->s2c.bc_pktsize->mean_max_belief == 0)
	{
	  pup->s2c.bc_pktsize->mean_max_belief = MIN_TH_VALID_PERC;
	  pup->s2c.bc_pktsize->argmax = -1;
	}
      if (pup->c2s.bc_pktsize->mean_max_belief == 0)
	{
	  pup->c2s.bc_pktsize->mean_max_belief = MIN_TH_VALID_PERC;
	  pup->c2s.bc_pktsize->argmax = -1;
	}

      if (pup->s2c.bc_avgipg->mean_max_belief == 0)
	{
	  pup->s2c.bc_avgipg->mean_max_belief = MIN_TH_VALID_PERC;
	  pup->s2c.bc_avgipg->argmax = -1;
	}
      if (pup->c2s.bc_avgipg->mean_max_belief == 0)
	{
	  pup->c2s.bc_avgipg->mean_max_belief = MIN_TH_VALID_PERC;
	  pup->c2s.bc_avgipg->argmax = -1;
	}
    }

  // was video present? yes if video only pkts are larger than 10%

  video_present =
    (100 * pskype->video_pkts / (pskype->audiovideo_pkts + 1) >
     10) ? TRUE : FALSE;

#ifdef ONELINE_LOG_FORMAT
  thisUdir = &(pup->c2s);
  pskype = &thisUdir->skype;
  
  //     #   Field Meaning
  //    --------------------------------------
  //     1   Client IP Address
  //     2   Client Port
  //     3   Internal address (0=no, 1=yes)

  sprintf (logline, "%s %s %d",
	   HostName (pup->addr_pair.a_address),
	   ServiceName (pup->addr_pair.a_port), pup->internal_src);


  //     4   Flow Size [Bytes]
  sprintf (logline, "%s %llu", logline, thisUdir->data_bytes);

  //     5   No. of Total flow packets
  //     6   No. of End-2-End  packets
  //     7   No. of Skypeout   packets
  //     8   No. of Signaling  packets
  //     9   No. of Unknown    packets
  //    10   No. of audio or audio+video packets
  //    11   No. of video only   packets
  sprintf (logline,
	   "%s %lld %d %d %d %d %d %d",
	   logline,
	   thisUdir->packets,
	   pskype->pkt_type_num[SKYPE_E2E_DATA],
	   pskype->pkt_type_num[SKYPE_OUT_DATA],
	   pskype->pkt_type_num[SKYPE_NAK] +
	   pskype->pkt_type_num[SKYPE_FUN2] +
	   pskype->pkt_type_num[SKYPE_FUN3],
	   pskype->pkt_type_num[NOT_SKYPE],
	   pskype->audiovideo_pkts, pskype->video_pkts);

  //    12   Average Pktsize
  //    13   Packet Size: Max Mean Belief

  Bool b_pktsize = 0;

  if (bayes_engine)
    {
      sprintf (logline,
	       "%s %f %.3f",
	       logline,
	       (double) thisUdir->data_bytes / (double) thisUdir->packets,
	       pup->c2s.bc_pktsize->mean_max_belief);

      b_pktsize = (pup->c2s.bc_pktsize->mean_max_belief >=
		   pup->c2s.bc_pktsize->settings->avg_threshold);
    }


  //    14   Average Inter-packet Gap
  //    15   Average IPG: Max Mean Belief

  Bool b_avgipg = 0;


  if (bayes_engine)
    {

      sprintf (logline,
	       "%s %f %.3f",
	       logline,
	       (double) elapsed (pup->first_time,
				 pup->last_time) / 1000.0 /
	       (double) thisUdir->packets,
	       pup->c2s.bc_avgipg->mean_max_belief);

      b_avgipg = (pup->c2s.bc_avgipg->mean_max_belief >=
		  pup->c2s.bc_avgipg->settings->avg_threshold);
    }

//    16  Chi-square: min E2O Header
//    17  Chi-square: max E2E Header
//    18  Chi-square: min E2E Header
//    19  Chi-square: max Payload

  /* evaluate the chi_square as
     (x_i - E_i)^2
     sum -----------
     E_i
   */

  /* start with the skype hdr of e2e messages */
  expected_num = (double) thisUdir->packets * E2E_EXPECTED_PROB;

  for (j = 0; j < N_BLOCK; j++)
    {
      chi_square[j] = 0.0;
      for (i = 0; i < N_RANDOM_BIT_VALUES; i++)
	{
	  chi_square[j] +=
	    (pskype->random.rnd_bit_histo[i][j] - expected_num) *
	    (pskype->random.rnd_bit_histo[i][j] - expected_num);
	}
      chi_square[j] /= expected_num;
    }
  maxCHI_E2E_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    {
      if (i == 4 || i == 5)	/* 5 e 6 CHI deterministico */
	i = 6;			/* salta non calcola il max */
      if (maxCHI_E2E_HDR < chi_square[i])
	maxCHI_E2E_HDR = chi_square[i];
    }
  minCHI_E2E_HDR = chi_square[4];	/* 5 e 6 CHI deterministico */
  if (minCHI_E2E_HDR > chi_square[5])	/* calcola il min tra i due */
    minCHI_E2E_HDR = chi_square[5];

  maxCHI_PAY = chi_square[8];
  for (i = 9; i < N_BLOCK; i++)
    if (maxCHI_PAY < chi_square[i])
      maxCHI_PAY = chi_square[i];

  minCHI_E2O_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    if (minCHI_E2O_HDR > chi_square[i])
      minCHI_E2O_HDR = chi_square[i];

  sprintf (logline,
	   "%s %.3f %.3f %.3f %.3f", logline,
	   minCHI_E2O_HDR, maxCHI_E2E_HDR, minCHI_E2E_HDR, maxCHI_PAY);


  //    20   Deterministic Flow Type
  //    21   Bayesian Flow Type
  //    22   Chi-square Flow Type
  //    23   Video present flag (0=no, 1=yes)

  if (minCHI_E2O_HDR >= 150 && maxCHI_PAY < 150)
    CSFT = L7_FLOW_SKYPE_E2O;	/* SKYPE E2O */
  else
    {
      if (maxCHI_E2E_HDR < 150 && chi_square[4] >= 150
	  && chi_square[5] >= 100 && maxCHI_PAY < 150)
	CSFT = L7_FLOW_SKYPE_E2E;	/* SKYPE E2E */
      else
	CSFT = NOT_SKYPE;
    }

  sprintf (logline,
	   "%s %d %d %d %d",
	   logline,
	   thisUdir->type,
	   b_avgipg && b_pktsize ? 1 :
	   (!b_avgipg && !b_pktsize) ? 0 :
	   (!b_avgipg && b_pktsize) ? -1 :
	   (b_avgipg && !b_pktsize) ? -2 : -255, CSFT, video_present);

  if ((thisUdir->type == SKYPE_E2E || thisUdir->type == SKYPE_OUT)
      && (b_avgipg && b_pktsize) && CSFT != NOT_SKYPE)
    C2S_is_Skype = 1;

/* add this flow to the skype one */
  if (b_avgipg && b_pktsize && CSFT != NOT_SKYPE)
    {
      pskype->skype_type = CSFT;
      switch ((in_out_loc (pup->internal_src, pup->internal_dst, dir)))
	{
	case OUT_FLOW:
	  switch (CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2E);
	      L7_bitrate.out[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2O);
	      L7_bitrate.out[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      break;
	    }
	  break;

	case IN_FLOW:
	  switch (CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2E);
	      L7_bitrate.in[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2O);
	      L7_bitrate.in[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      break;
	    }
	  break;
	case LOC_FLOW:
	  switch (CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2E);
	      L7_bitrate.loc[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2O);
	      L7_bitrate.loc[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      break;
	    }
	  break;
	}
    }

/*S2C*/

  thisUdir = &(pup->s2c);
  pskype = &thisUdir->skype;


  // was video present? yes if video only pkts are larger than 10%

  video_present =
    (100 * pskype->video_pkts / (pskype->audiovideo_pkts + 1) >
     10) ? TRUE : FALSE;

  //     #   Field Meaning
  //    --------------------------------------
  //    24   Server IP Address
  //    25   Server Port
  //    26   Internal address (0=no, 1=yes)

  sprintf (logline, "%s %s %s %d", logline,
	   HostName (pup->addr_pair.b_address),
	   ServiceName (pup->addr_pair.b_port), pup->internal_dst);

  //    27    Flow Size [Bytes]
  sprintf (logline, "%s %llu", logline, thisUdir->data_bytes);

  //    28   No. of Total flow packets
  //    29   No. of End-2-End  packets
  //    30   No. of Skypeout   packets
  //    31   No. of Signaling  packets
  //    32   No. of Unknown    packets
  //    33   No. of audio or audio+video packets
  //    34   No. of video only   packets
  sprintf (logline,
	   "%s %lld %d %d %d %d %d %d",
	   logline,
	   thisUdir->packets,
	   pskype->pkt_type_num[SKYPE_E2E_DATA],
	   pskype->pkt_type_num[SKYPE_OUT_DATA],
	   pskype->pkt_type_num[SKYPE_NAK] +
	   pskype->pkt_type_num[SKYPE_FUN2] +
	   pskype->pkt_type_num[SKYPE_FUN3],
	   pskype->pkt_type_num[NOT_SKYPE],
	   pskype->audiovideo_pkts, pskype->video_pkts);

  //    35   Average Pktsize
  //    36   Packet Size: Max Mean Belief

  b_pktsize = 0;

  if (bayes_engine)
    {
      sprintf (logline,
	       "%s %f %.3f",
	       logline,
	       (double) thisUdir->data_bytes / (double) thisUdir->packets,
	       pup->s2c.bc_pktsize->mean_max_belief);

      b_pktsize = (pup->s2c.bc_pktsize->mean_max_belief >=
		   pup->s2c.bc_pktsize->settings->avg_threshold);

    }


  //    37   Average Inter-packet Gap
  //    38   Average IPG: Max Mean Belief

  b_avgipg = 0;


  if (bayes_engine)
    {
      sprintf (logline,
	       "%s %f %.3f",
	       logline,
	       (double) elapsed (pup->first_time,
				 pup->last_time) / 1000.0 /
	       (double) thisUdir->packets,
	       pup->s2c.bc_avgipg->mean_max_belief);

      b_avgipg = (pup->s2c.bc_avgipg->mean_max_belief >=
		  pup->s2c.bc_avgipg->settings->avg_threshold);

    }

  //    39  Chi-square: min E2O Header
  //    40  Chi-square: max E2E Header
  //    41  Chi-square: min E2E Header
  //    42  Chi-square: max Payload

  /* evaluate the chi_square as
     (x_i - E_i)^2
     sum -----------
     E_i
   */

  /* start with the skype hdr of e2e messages */
  expected_num = (double) thisUdir->packets * E2E_EXPECTED_PROB;

  for (j = 0; j < N_BLOCK; j++)
    {
      chi_square[j] = 0.0;
      for (i = 0; i < N_RANDOM_BIT_VALUES; i++)
	{
	  chi_square[j] +=
	    (pskype->random.rnd_bit_histo[i][j] - expected_num) *
	    (pskype->random.rnd_bit_histo[i][j] - expected_num);
	}
      chi_square[j] /= expected_num;
    }
  maxCHI_E2E_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    {
      if (i == 4 || i == 5)	/* 5 e 6 CHI deterministico */
	i = 6;			/* salta non calcola il max */
      if (maxCHI_E2E_HDR < chi_square[i])
	maxCHI_E2E_HDR = chi_square[i];
    }
  minCHI_E2E_HDR = chi_square[4];	/* 5 e 6 CHI deterministico */
  if (minCHI_E2E_HDR > chi_square[5])	/* calcola il min tra i due */
    minCHI_E2E_HDR = chi_square[5];

  maxCHI_PAY = chi_square[8];
  for (i = 9; i < N_BLOCK; i++)
    if (maxCHI_PAY < chi_square[i])
      maxCHI_PAY = chi_square[i];

  minCHI_E2O_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    if (minCHI_E2O_HDR > chi_square[i])
      minCHI_E2O_HDR = chi_square[i];

  sprintf (logline,
	   "%s %.3f %.3f %.3f %.3f", logline,
	   minCHI_E2O_HDR, maxCHI_E2E_HDR, minCHI_E2E_HDR, maxCHI_PAY);


  //    43   Deterministic Flow Type
  //    44   Bayesian Flow Type
  //    45   Chi-square Flow Type
  //    46   Video present flag (0=no, 1=yes)

  if (minCHI_E2O_HDR >= 150 && maxCHI_PAY < 150)
    CSFT = L7_FLOW_SKYPE_E2O;	/* SKYPE E2O */
  else
    {
      if (maxCHI_E2E_HDR < 150 && chi_square[4] >= 150
	  && chi_square[5] >= 100 && maxCHI_PAY < 150)
	CSFT = L7_FLOW_SKYPE_E2E;	/* SKYPE E2E */
      else
	CSFT = NOT_SKYPE;
    }

  sprintf (logline,
	   "%s %d %d %d %d",
	   logline,
	   thisUdir->type,
	   b_avgipg && b_pktsize ? 1 :
	   (!b_avgipg && !b_pktsize) ? 0 :
	   (!b_avgipg && b_pktsize) ? -1 :
	   (b_avgipg && !b_pktsize) ? -2 : -255, CSFT, video_present);


  //    47   Flow Start Time [in Unix time]
  //    48   Flow Elapsed Time [s]

  sprintf (logline,
	   "%s %f %.3f",
	   logline,
	   1e-6 * time2double (pup->first_time),
	   elapsed (pup->first_time, pup->last_time) / 1000.0 / 1000.0);

  /* log flow if at least one of two dir is SKYPE */
  if (C2S_is_Skype || (
      (thisUdir->type == SKYPE_E2E || thisUdir->type == SKYPE_OUT)
	    && (b_avgipg && b_pktsize) && CSFT != NOT_SKYPE))

    fprintf (fp_skype_logc, "%s U\n", logline);

#else
  //     
  //     #   Field Meaning
  //    --------------------------------------
  //     1   Source Address
  //     2   Source Port
  //     3   Destination Address
  //     4   Destination Port

  if (dir == S2C)
    {
      sprintf (logline, "%s %s ",
	       HostName (pup->addr_pair.b_address),
	       ServiceName (pup->addr_pair.b_port));
      sprintf (logline, "%s %s %s ", logline,
	       HostName (pup->addr_pair.a_address),
	       ServiceName (pup->addr_pair.a_port));
    }
  else
    {
      sprintf (logline, "%s %s ",
	       HostName (pup->addr_pair.a_address),
	       ServiceName (pup->addr_pair.a_port));
      sprintf (logline, "%s %s %s ", logline,
	       HostName (pup->addr_pair.b_address),
	       ServiceName (pup->addr_pair.b_port));
    }




  //     5   Flow Start Time
  //     6   Flow End Time
  //     7   Flow Size [Bytes]
  sprintf (logline,
	   "%s %.2f %.2f %llu",
	   logline,
	   elapsed (first_packet, pup->first_time) / 1000.0 / 1000.0,
	   elapsed (first_packet, pup->last_time) / 1000.0 / 1000.0,
	   thisUdir->data_bytes);



  //     8   No. of Total flow packets
  //     9   No. of End-2-End  packets
  //    10   No. of Skypeout   packets
  //    11   No. of Signaling  packets
  //    12   No. of Unknown    packets
  //    13   No. of audio or audio+video  packets
  //    14   No. of video only packets
  sprintf (logline,
	   "%s %lld %d %d %d %d",
	   logline,
	   thisUdir->packets,
	   pskype->pkt_type_num[SKYPE_E2E_DATA],
	   pskype->pkt_type_num[SKYPE_OUT_DATA],
	   pskype->pkt_type_num[SKYPE_NAK] +
	   pskype->pkt_type_num[SKYPE_FUN2] +
	   pskype->pkt_type_num[SKYPE_FUN3],
	   pskype->pkt_type_num[NOT_SKYPE],
	   pskype->audiovideo_pkts, pskype->video_pkts);



  //    15   Average Pktsize
  //    16   Packet Size: Max Mean Belief
  //    17   Packet Size: Validity Percentage
  //    18   Packet Size: Above Threshold Percentage
  //    19   Packet Size: Codec type (Argmax)
  Bool b_pktsize;

  if (bayes_engine)
    {
      if (dir == S2C)
	{
	  sprintf (logline,
		   "%s %f %.3f %.3f %.3f %d",
		   logline,
		   (double) thisUdir->data_bytes / (double) thisUdir->packets,
		   pup->s2c.bc_pktsize->mean_max_belief,
		   pup->s2c.bc_pktsize->valid_percentage,
		   pup->s2c.bc_pktsize->aboveth_percentage,
		   pup->s2c.bc_pktsize->argmax);

	  b_pktsize = (pup->s2c.bc_pktsize->mean_max_belief >=
		       pup->s2c.bc_pktsize->settings->avg_threshold);


	}
      else
	{
	  sprintf (logline,
		   "%s %f %.3f %.3f %.3f %d",
		   logline,
		   (double) thisUdir->data_bytes / (double) thisUdir->packets,
		   pup->c2s.bc_pktsize->mean_max_belief,
		   pup->c2s.bc_pktsize->valid_percentage,
		   pup->c2s.bc_pktsize->aboveth_percentage,
		   pup->c2s.bc_pktsize->argmax);

	  b_pktsize = (pup->c2s.bc_pktsize->mean_max_belief >=
		       pup->c2s.bc_pktsize->settings->avg_threshold);
	}
    }

  //    20   Average Inter-packet Gap
  //    21   Average Inter-packet Gap (End-2-end)
  //    22   Average Inter-packet Gap (Skypeout)
  //    23   Average IPG: Max Mean Belief
  //    24   Average IPG: Validity Percentage
  //    25   Average IPG: Above Threshold Percentage
  //    26   Average IPG: Codec type (Argmax)
  Bool b_avgipg;

#define SKYPE_DELTA(x)  ((x==-1000.0) ? -1.0 : x)

  if (bayes_engine)
    {
      if (dir == S2C)
	{
	  sprintf (logline,
		   "%s %f %f %f %.3f %.3f %.3f %d",
		   logline,
		   (double) elapsed (pup->first_time,
				     pup->last_time) / 1000.0 /
		   (double) thisUdir->packets,
		   SKYPE_DELTA (get_average_delta_t
				(&pskype->stat[SKYPE_E2E_DATA])),
		   SKYPE_DELTA (get_average_delta_t
				(&pskype->stat[SKYPE_OUT_DATA])),
		   pup->s2c.bc_avgipg->mean_max_belief,
		   pup->s2c.bc_avgipg->valid_percentage,
		   pup->s2c.bc_avgipg->aboveth_percentage,
		   pup->s2c.bc_avgipg->argmax);

	  b_avgipg = (pup->s2c.bc_avgipg->mean_max_belief >=
		      pup->s2c.bc_avgipg->settings->avg_threshold);

	}
      else
	{
	  sprintf (logline,
		   "%s %f %f %f %.3f %.3f %.3f %d",
		   logline,
		   (double) elapsed (pup->first_time,
				     pup->last_time) / 1000.0 /
		   (double) thisUdir->packets,
		   SKYPE_DELTA (get_average_delta_t
				(&pskype->stat[SKYPE_E2E_DATA])),
		   SKYPE_DELTA (get_average_delta_t
				(&pskype->stat[SKYPE_OUT_DATA])),
		   pup->c2s.bc_avgipg->mean_max_belief,
		   pup->c2s.bc_avgipg->valid_percentage,
		   pup->c2s.bc_avgipg->aboveth_percentage,
		   pup->c2s.bc_avgipg->argmax);

	  b_avgipg = (pup->c2s.bc_avgipg->mean_max_belief >=
		      pup->c2s.bc_avgipg->settings->avg_threshold);
	}
    }

  //    27   Deterministic Flow Type
  //    28   Bayesian Flow Type

  sprintf (logline,
	   "%s %d %d",
	   logline,
	   thisUdir->type,
	   b_avgipg && b_pktsize ? 1 :
	   (!b_avgipg && !b_pktsize) ? 0 :
	   (!b_avgipg && b_pktsize) ? -1 :
	   (b_avgipg && !b_pktsize) ? -2 : -255);


  fprintf (fp_skype_logc, "%s", logline);

  //    29->44   Chi-square values

  /* evaluate the chi_square as
     (x_i - E_i)^2
     sum -----------
     E_i
   */

  /* start with the skype hdr of e2e messages */
  expected_num = (double) thisUdir->packets * E2E_EXPECTED_PROB;

  for (j = 0; j < N_BLOCK; j++)
    {
      chi_square[j] = 0;
      for (i = 0; i < N_RANDOM_BIT_VALUES; i++)
	{
	  chi_square[j] +=
	    (pskype->random.rnd_bit_histo[i][j] - expected_num) *
	    (pskype->random.rnd_bit_histo[i][j] - expected_num);
	}
      chi_square[j] /= expected_num;
      fprintf (fp_skype_logc, " %.3f", chi_square[j]);
    }

  fprintf (fp_skype_logc, "\n");

#endif

/* add this flow to the skype one */
  if (b_avgipg && b_pktsize && CSFT != NOT_SKYPE)
    {
      pskype->skype_type = CSFT;
      switch ((in_out_loc (pup->internal_src, pup->internal_dst, dir)))
	{
	case OUT_FLOW:
	  switch (CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2E);
	      L7_bitrate.out[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2O);
	      L7_bitrate.out[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      break;
	    }
	  break;

	case IN_FLOW:
	  switch (CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2E);
	      L7_bitrate.in[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2O);
	      L7_bitrate.in[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      break;
	    }
	  break;
	case LOC_FLOW:
	  switch (CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2E);
	      L7_bitrate.loc[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2O);
	      L7_bitrate.loc[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      break;
	    }
	  break;
	}
    }
}

void
print_skype_conn_stats_TCP (void *thisdir, int dir)
{

  double chi_square[N_BLOCK];
  double expected_num;
  int i, j, CSFT = -1;
  int C2S_is_Skype = 0;
  struct tcb *thisTdir;
  char logline[300] = "";
  Bool video_present;

  struct skype_stat *pskype;
  struct stcp_pair *ptp;
  thisTdir = (tcb *) thisdir;
  ptp = thisTdir->ptp;
  pskype = &thisTdir->skype;
  float maxCHI_HDR, maxCHI_PAY;

  if (bayes_engine)
    {
      if (ptp->s2c.bc_pktsize->mean_max_belief == 0)
	{
	  ptp->s2c.bc_pktsize->mean_max_belief = MIN_TH_VALID_PERC;
	  ptp->s2c.bc_pktsize->argmax = -1;
	}
      if (ptp->c2s.bc_pktsize->mean_max_belief == 0)
	{
	  ptp->c2s.bc_pktsize->mean_max_belief = MIN_TH_VALID_PERC;
	  ptp->c2s.bc_pktsize->argmax = -1;
	}

      if (ptp->s2c.bc_avgipg->mean_max_belief == 0)
	{
	  ptp->s2c.bc_avgipg->mean_max_belief = MIN_TH_VALID_PERC;
	  ptp->s2c.bc_avgipg->argmax = -1;
	}
      if (ptp->c2s.bc_avgipg->mean_max_belief == 0)
	{
	  ptp->c2s.bc_avgipg->mean_max_belief = MIN_TH_VALID_PERC;
	  ptp->c2s.bc_avgipg->argmax = -1;
	}
    }
  // was video present? yes if video only pkts are larger than 10%

  video_present =
    (100 * pskype->video_pkts / (pskype->audiovideo_pkts + 1) >
     10) ? TRUE : FALSE;

#ifdef ONELINE_LOG_FORMAT
  thisTdir = &(ptp->c2s);
  pskype = &thisTdir->skype;
  
  //     #   Field Meaning
  //    --------------------------------------
  //     1   Client IP Address
  //     2   Client Port
  //     3   Internal address (0=no, 1=yes)

  sprintf (logline, "%s %s %d",
	   HostName (ptp->addr_pair.a_address),
	   ServiceName (ptp->addr_pair.a_port), ptp->internal_src);

  //     4   Flow Size [Bytes]

  sprintf (logline, "%s %lu", logline, thisTdir->unique_bytes);

  //     5   No. of Total flow packets
  //     6   No. of Total audio or audio+video packets
  //     7   No. of Total video only packets

  sprintf (logline, "%s %ld %d %d", logline, thisTdir->packets,
	   pskype->audiovideo_pkts, pskype->video_pkts);

  //     8   Average Pktsize
  //     9   Packet Size: Max Mean Belief

  Bool b_pktsize = 0;

  if (bayes_engine)
    {

      sprintf (logline,
	       "%s %f %.3f",
	       logline,
	       (double) thisTdir->unique_bytes / (double)
	       thisTdir->data_pkts, ptp->c2s.bc_pktsize->mean_max_belief);

      b_pktsize = (ptp->c2s.bc_pktsize->mean_max_belief >=
		   ptp->c2s.bc_pktsize->settings->avg_threshold);

    }


  //    10   Average Inter-packet Gap
  //    11   Average IPG: Max Mean Belief

  Bool b_avgipg = 0;

  if (bayes_engine)
    {
      sprintf (logline,
	       "%s %f %.3f",
	       logline,
	       (double) elapsed (ptp->first_time,
				 ptp->last_time) / 1000.0 /
	       (double) thisTdir->data_pkts,
	       ptp->c2s.bc_avgipg->mean_max_belief);

      b_avgipg = (ptp->c2s.bc_avgipg->mean_max_belief >=
		  ptp->c2s.bc_avgipg->settings->avg_threshold);

    }


//    12  Chi-square: max Header
//    13  Chi-square: max Payload

  /* evaluate the chi_square as
     (x_i - E_i)^2
     sum -----------
     E_i
   */

  /* do the same for payload bytes after the 4th bytes */
  expected_num = (double) pskype->random.rnd_n_samples * OUT_EXPECTED_PROB;
//  expected_num = (double)thisTdir->packets*E2E_EXPECTED_PROB;

  for (j = 0; j < N_BLOCK; j++)
    {
      chi_square[j] = 0.0;
      for (i = 0; i < N_RANDOM_BIT_VALUES; i++)
	{
	  chi_square[j] +=
	    (pskype->random.rnd_bit_histo[i][j] - expected_num) *
	    (pskype->random.rnd_bit_histo[i][j] - expected_num);
	}
      chi_square[j] /= expected_num;
    }

  maxCHI_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    {
      if (maxCHI_HDR < chi_square[i])
	maxCHI_HDR = chi_square[i];
    }

  maxCHI_PAY = chi_square[8];
  for (i = 9; i < N_BLOCK; i++)
    {
      if (maxCHI_PAY < chi_square[i])
	maxCHI_PAY = chi_square[i];
    }

  sprintf (logline, "%s %.3f %.3f", logline, maxCHI_HDR, maxCHI_PAY);


  //    16   Bayesian Flow Type
  //    17   Chi-square Flow Type
  //    18   Video present flag (0=no, 1=yes)

  if (maxCHI_HDR < 150 && maxCHI_PAY < 150)
    CSFT = L7_FLOW_SKYPE_TCP;	/* SKYPE senza distinzione E2E/E2O */
  else
    CSFT = NOT_SKYPE;

  sprintf (logline,
	   "%s %d %d %d",
	   logline,
	   b_avgipg && b_pktsize ? 1 :
	   (!b_avgipg && !b_pktsize) ? 0 :
	   (!b_avgipg && b_pktsize) ? -1 :
	   (b_avgipg && !b_pktsize) ? -2 : -255, CSFT, video_present);

  if ((b_avgipg && b_pktsize) && CSFT != NOT_SKYPE)
    C2S_is_Skype = 1;

/* add this flow to the skype one */
/* decide if it is entering or going out */

  if (b_avgipg && b_pktsize && CSFT != NOT_SKYPE)
    {
      /* this is a Skype flow -> set the TCP flow type as well */
      ptp->con_type |= SKYPE_PROTOCOL;
      pskype->skype_type = CSFT;

      switch ((in_out_loc (ptp->internal_src, ptp->internal_dst, dir)))
	{
	case OUT_FLOW:
	  L7_bitrate.out[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	case IN_FLOW:
	  L7_bitrate.out[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	case LOC_FLOW:
	  L7_bitrate.out[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	}
    }

/*S2C*/
  thisTdir = &(ptp->s2c);
  pskype = &thisTdir->skype;

  // was video present? yes if video only pkts are larger than 10%

  video_present =
    (100 * pskype->video_pkts / (pskype->audiovideo_pkts + 1) >
     10) ? TRUE : FALSE;

  //     #   Field Meaning
  //    --------------------------------------
  //    14   Server IP Address
  //    15   Server Port
  //    16   Internal address (0=no, 1=yes)

  sprintf (logline, "%s %s %s %d", logline,
	   HostName (ptp->addr_pair.b_address),
	   ServiceName (ptp->addr_pair.b_port), ptp->internal_dst);

  //    17   Flow Size [Bytes]

  sprintf (logline, "%s %lu", logline, thisTdir->unique_bytes);

  //    18   No. of Total flow packets
  //    19   No. of Total audio or audio+video packets
  //    20   No. of Total video only packets

  sprintf (logline, "%s %ld %d %d", logline, thisTdir->packets,
	   pskype->audiovideo_pkts, pskype->video_pkts);

  //    21   Average Pktsize
  //    22   Packet Size: Max Mean Belief

  b_pktsize = 0;

  if (bayes_engine)
    {
      sprintf (logline,
	       "%s %f %.3f",
	       logline,
	       (double) thisTdir->unique_bytes / (double)
	       thisTdir->data_pkts, ptp->s2c.bc_pktsize->mean_max_belief);

      b_pktsize = (ptp->s2c.bc_pktsize->mean_max_belief >=
		   ptp->s2c.bc_pktsize->settings->avg_threshold);

    }

  //    23   Average Inter-packet Gap
  //    24   Average IPG: Max Mean Belief

  b_avgipg = 0;

  if (bayes_engine)
    {
      sprintf (logline,
	       "%s %f %.3f",
	       logline,
	       (double) elapsed (ptp->first_time,
				 ptp->last_time) / 1000.0 /
	       (double) thisTdir->packets,
	       ptp->s2c.bc_avgipg->mean_max_belief);

      b_avgipg = (ptp->s2c.bc_avgipg->mean_max_belief >=
		  ptp->s2c.bc_avgipg->settings->avg_threshold);
    }


  //    25  Chi-square: max Header
  //    26  Chi-square: max Payload

  /* evaluate the chi_square as
     (x_i - E_i)^2
     sum -----------
     E_i
   */

  /* do the same for payload bytes after the 4th bytes */
  expected_num = (double) pskype->random.rnd_n_samples * OUT_EXPECTED_PROB;
//  expected_num = (double)thisTdir->packets*E2E_EXPECTED_PROB;


  for (j = 0; j < N_BLOCK; j++)
    {
      chi_square[j] = 0.0;
      for (i = 0; i < N_RANDOM_BIT_VALUES; i++)
	{
	  chi_square[j] +=
	    (pskype->random.rnd_bit_histo[i][j] - expected_num) *
	    (pskype->random.rnd_bit_histo[i][j] - expected_num);
	}
      chi_square[j] /= expected_num;
    }

  maxCHI_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    {
      if (maxCHI_HDR < chi_square[i])
	maxCHI_HDR = chi_square[i];
    }

  maxCHI_PAY = chi_square[8];
  for (i = 9; i < N_BLOCK; i++)
    {
      if (maxCHI_PAY < chi_square[i])
	maxCHI_PAY = chi_square[i];
    }

  sprintf (logline, "%s %.3f %.3f", logline, maxCHI_HDR, maxCHI_PAY);


  //    27   Bayesian Flow Type
  //    28   Chi-square Flow Type
  //    29   Video present flag (0=no, 1=yes)

  if (maxCHI_HDR < 150 && maxCHI_PAY < 150)
    CSFT = L7_FLOW_SKYPE_TCP;	/* SKYPE senza distinzione E2E/E2O */
  else
    CSFT = NOT_SKYPE;

  sprintf (logline,
	   "%s %d %d %d",
	   logline,
	   b_avgipg && b_pktsize ? 1 :
	   (!b_avgipg && !b_pktsize) ? 0 :
	   (!b_avgipg && b_pktsize) ? -1 :
	   (b_avgipg && !b_pktsize) ? -2 : -255, CSFT, video_present);

  //    30   Flow Start Time [in Unix time]
  //    31   Flow Elapsed Time [s]

  sprintf (logline, "%s %f %.3f", logline,
	   1e-6 * time2double (ptp->first_time),
	   elapsed (ptp->first_time, ptp->last_time) / 1000.0 / 1000.0);

  /* log flow if at least one of two dir is SKYPE */
  if (C2S_is_Skype || ((b_avgipg && b_pktsize) && CSFT != NOT_SKYPE))

    fprintf (fp_skype_logc, "%s T\n", logline);


#else
  //     #   Field Meaning
  //    --------------------------------------
  //     1   Source Address
  //     2   Source Port
  //     3   Destination Address
  //     4   Destination Port



  if (dir == S2C)
    {
      sprintf (logline, "%s %s ",
	       HostName (ptp->addr_pair.b_address),
	       ServiceName (ptp->addr_pair.b_port));
      sprintf (logline, "%s %s %s ", logline,
	       HostName (ptp->addr_pair.a_address),
	       ServiceName (ptp->addr_pair.a_port));
    }
  else
    {
      sprintf (logline, "%s %s ",
	       HostName (ptp->addr_pair.a_address),
	       ServiceName (ptp->addr_pair.a_port));
      sprintf (logline, "%s %s %s ", logline,
	       HostName (ptp->addr_pair.b_address),
	       ServiceName (ptp->addr_pair.b_port));
    }

  //     5   Flow Start Time
  //     6   Flow End Time
  //     7   Flow Size [Bytes]
  sprintf (logline,
	   "%s %.2f %.2f %lu",
	   logline,
	   elapsed (first_packet, ptp->first_time) / 1000.0 / 1000.0,
	   elapsed (first_packet, ptp->last_time) / 1000.0 / 1000.0,
	   thisTdir->unique_bytes);


  //     8   No. of Total flow packets
  //     9   No. of Total flow packets - audio or audio+video
  //     10  No. of Total flow packets - video only

  sprintf (logline, "%s %lu", logline, thisTdir->packets);


  //    11   Average Pktsize
  //    12   Packet Size: Max Mean Belief
  //    13   Packet Size: Validity Percentage
  //    14   Packet Size: Above Threshold Percentage
  //    15   Packet Size: Codec type (Argmax)

  Bool b_pktsize;

  if (bayes_engine)
    {
      if (dir == S2C)
	{
	  sprintf (logline,
		   "%s %f %.3f %.3f %.3f %d",
		   logline,
		   (double) thisTdir->unique_bytes / (double)
		   thisTdir->data_pkts,
		   ptp->s2c.bc_pktsize->mean_max_belief,
		   ptp->s2c.bc_pktsize->valid_percentage,
		   ptp->s2c.bc_pktsize->aboveth_percentage,
		   ptp->s2c.bc_pktsize->argmax);

	  b_pktsize = (ptp->s2c.bc_pktsize->mean_max_belief >=
		       ptp->s2c.bc_pktsize->settings->avg_threshold);

	}
      else
	{
	  sprintf (logline,
		   "%s %f %.3f %.3f %.3f %d",
		   logline,
		   (double) thisTdir->unique_bytes / (double)
		   thisTdir->data_pkts,
		   ptp->c2s.bc_pktsize->mean_max_belief,
		   ptp->c2s.bc_pktsize->valid_percentage,
		   ptp->c2s.bc_pktsize->aboveth_percentage,
		   ptp->c2s.bc_pktsize->argmax);

	  b_pktsize = (ptp->c2s.bc_pktsize->mean_max_belief >=
		       ptp->c2s.bc_pktsize->settings->avg_threshold);
	}
    }

  //    16   Average Inter-packet Gap
  //    17   Average IPG: Max Mean Belief
  //    18   Average IPG: Validity Percentage
  //    19   Average IPG: Above Threshold Percentage
  //    20   Average IPG: Codec type (Argmax)

  Bool b_avgipg;


  if (bayes_engine)
    {
      if (dir == S2C)
	{
	  sprintf (logline,
		   "%s %f %.3f %.3f %.3f %d",
		   logline,
		   (double) elapsed (ptp->first_time,
				     ptp->last_time) / 1000.0 /
		   (double) thisTdir->data_pkts,
		   ptp->s2c.bc_avgipg->mean_max_belief,
		   ptp->s2c.bc_avgipg->valid_percentage,
		   ptp->s2c.bc_avgipg->aboveth_percentage,
		   ptp->s2c.bc_avgipg->argmax);

	  b_avgipg = (ptp->s2c.bc_avgipg->mean_max_belief >=
		      ptp->s2c.bc_avgipg->settings->avg_threshold);

	}
      else
	{
	  sprintf (logline,
		   "%s %f %.3f %.3f %.3f %d",
		   logline,
		   (double) elapsed (ptp->first_time,
				     ptp->last_time) / 1000.0 /
		   (double) thisTdir->data_pkts,
		   ptp->c2s.bc_avgipg->mean_max_belief,
		   ptp->c2s.bc_avgipg->valid_percentage,
		   ptp->c2s.bc_avgipg->aboveth_percentage,
		   ptp->c2s.bc_avgipg->argmax);

	  b_avgipg = (ptp->c2s.bc_avgipg->mean_max_belief >=
		      ptp->c2s.bc_avgipg->settings->avg_threshold);
	}
    }

  //    21   Bayesian Flow Type

  sprintf (logline,
	   "%s %d",
	   logline,
	   b_avgipg && b_pktsize ? 1 :
	   (!b_avgipg && !b_pktsize) ? 0 :
	   (!b_avgipg && b_pktsize) ? -1 :
	   (b_avgipg && !b_pktsize) ? -2 : -255);

  /* do the same for payload bytes after the 4th bytes */
  expected_num = (double) pskype->random.rnd_n_samples * OUT_EXPECTED_PROB;
//  expected_num = (double)thisTdir->packets*E2E_EXPECTED_PROB;

  //    22->36   Chi-square values

  for (j = 0; j < N_BLOCK; j++)
    {
      chi_square[j] = 0.0;
      for (i = 0; i < N_RANDOM_BIT_VALUES; i++)
	{
	  chi_square[j] +=
	    (pskype->random.rnd_bit_histo[i][j] - expected_num) *
	    (pskype->random.rnd_bit_histo[i][j] - expected_num);
	}

      chi_square[j] /= expected_num;

      sprintf (logline, "%s %.3f", logline, chi_square[j]);
    }

  /*   36   Random samples for the Chi-square evaluation

     sprintf (logline, "%s %d", logline, pskype->random.rnd_n_samples);

   */

  /* discard flow when all are negative */
  if (b_avgipg || b_pktsize || CSFT != 0)
    fprintf (fp_skype_logc, "%s\n", logline);
#endif

/* add this flow to the skype one */
/* decide if it is entering or going out */

  if (b_avgipg && b_pktsize && CSFT != NOT_SKYPE)
    {
      /* this is a Skype flow -> set the TCP flow type as well */
      ptp->con_type |= SKYPE_PROTOCOL;
      pskype->skype_type = CSFT;

      switch ((in_out_loc (ptp->internal_src, ptp->internal_dst, dir)))
	{
	case OUT_FLOW:
	  L7_bitrate.out[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	case IN_FLOW:
	  L7_bitrate.out[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	case LOC_FLOW:
	  L7_bitrate.out[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	}
    }
}
