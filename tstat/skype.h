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
 *              http://http://www.tlc-networks.polito.it/index.html
 *		mellia@mail.tlc.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/

#define ONELINE_LOG_FORMAT


#define NOT_SKYPE 0
#define SKYPE_NAK 1
#define SKYPE_FUN2 2
#define SKYPE_FUN3 3
#define SKYPE_E2E_DATA 4
#define SKYPE_OUT_DATA 5
#define TOTAL_SKYPE_KNOWN_TYPE 6

#define UDP_PAYLOAD_LEN(p) ((ntohs ((p)->ip_len) - ((p)->ip_hl * 4) - 8))

#define MIN_SKYPE_PKTS 10	/* only flows with at least MIN_SKYPE_PKTS 
				   will be logged into the 
				   log_skype_complete log */

#define MIN_SKYPE_PKTS_TCP 50	/* only TCP flows with at least MIN_SKYPE_PKTS_TCP 
				   will be logged into the 
				   log_skype_complete log */

#define MIN_TH_VALID_PERC -100	/* Setta il valore minimo della percentuale di validita`
				   nel caso in cui il classificatore baesiano non
				   viene aggiornato */


#define MIN_SKYPE_PERC 90	/* only flows with at least MIN_SKYPE_PERC
				   of packets marked as skype packets
				   will be logged marked as skype flows
				   (either skype_isac or skypeout */

#define MIN_SKYPE_OUT_NUM 100
#define MIN_SKYPE_OUT_PERC 90	/* only flows with at least MIN_SKYPE_OUT_PERC and
				   MIN_SKYPE_OUT_NUM of packets marked as SKYPE_OUT 
				   packets with respect to all packets will be marked 
				   as SKYPE_OUT flows */

#define MIN_SKYPE_E2E_NUM 100
#define MIN_SKYPE_E2E_PERC 90	/* only flows with at least MIN_SKYPE_E2E_PERC and
				   MIN_SKYPE_E2E_NUM of packets marked as SKYPE_E2E 
				   packets with respect to all packets will be marked 
				   as SKYPE_E2E flows */

/* number of bits to be randomly checked 
we use the chi square test, forming nibbles of N_RANDOM_BIT bits
and checkg the uniformity of the distribution.

 1  2   4 5    7 8   10 11  13 14   16       1 2 3 4 5 6 7 8
+-+------+------+------+------+------+      ----------------+
| |      |      |      |      |      |      | |     |       |   
|X| X X X| X X X| X X X| X X X| X X X|      |F|X X X|F F F F|   
| |      |      |      |      |      |      | |     |       |   
+-+------+------+------+------+------+      +---------------+
F are bits of the FUNC field -> defined values
X are random bits
consider blocks of 32 bits
*/

#define RANDOM_MASK_LEN 64	/* Number of bits to test */
#define N_RANDOM_BIT 4		/* In origine 3 */
#define N_RANDOM_BIT_VALUES 16	/* 2^N_RANDOM_BIT */
#define N_BLOCK  16		/* (RANDOM_MASK_LEN/N_RANDOM_BIT) Number of nibbles */
#define RND_MASK (N_RANDOM_BIT_VALUES - 1)
#define E2E_EXPECTED_PROB (1.0/(N_RANDOM_BIT_VALUES))

#define OUT_EXPECTED_PROB (1.0/(N_RANDOM_BIT_VALUES))

//#define RUNTIME_SKYPE_RESET /* to enable runtime classification and flow closing */
//#define RUNTIME_SKYPE       /* to enable runtime classification only */
#define SKYPE_UPDATE_DELTA_TIME 5000000	/* time between two updates in a runtime
					   classification [us] */

struct skype_hdr
{
  u_int16_t id;			/* Identifier */
  u_int8_t func;		/* function */
};
typedef struct skype_hdr skype_hdr;

struct skype_NAK
{
  u_int16_t id;			/* Identifier */
  u_int8_t func;		/* function */
/* to avoid alignament problem use u_int8_t */
//    struct in_addr saddr;  /* IP addr of the client */
//    struct in_addr daddr;  /* IP addr of the server */
  u_int8_t saddr[4];		/* IP addr of the client */
  u_int8_t daddr[4];		/* IP addr of the server ?!?! */
};
typedef struct skype_NAK skype_NAK;

struct skype_OUT
{
  u_int32_t block;		/* 4 bytes of Identifier */
};
typedef struct skype_OUT skype_OUT;



void print_skype_conn_stats_UDP (void *thisdir, int dir);
void print_skype_conn_stats_TCP (void *thisdir, int dir);
void skype_conn_stats (void *thisdir, int dir, int tproto);
void skype_init ();
