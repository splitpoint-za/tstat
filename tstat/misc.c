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

#include <stdio.h>
#include "tstat.h"

/* Miscellanea */

#define MODULE  2147483647
#define A       16807
#define LASTXN  127773
#define UPTOMOD -2836
#define RATIO   0.46566128e-9	/* 1/MODULE */


/*        
**  Function  : long rnd32(long seed) 
**  Return    : the updated value of 'seed'.
**  Remarks   : congruential generator of pseudorandom sequences of numbers
**              uniformly distributed between 1 and 2147483646, using the 
**              congruential relation: Xn+1 = 16807 * Xn  mod  2147483647 . 
**              The input to the routine is the integer Xn, while the returned 
**              integer is the number Xn+1.
*/
inline long
rnd32 (long *seed)
{
  long times, rest, prod1, prod2;

  times = *seed / LASTXN;
  rest = *seed - times * LASTXN;
  prod1 = times * UPTOMOD;
  prod2 = rest * A;
  *seed = prod1 + prod2;
  if (*seed < 0)
    *seed = *seed + MODULE;
  return *seed;
}


/*
**  Function  : double uniform(double a, double b, long seed)
**  Return    : a value uniformly distributed between 'a' and 'b'
*/

double
uniform (double a, double b, long *seed)
{
  double u;
  *seed = rnd32 (seed);
  u = (*seed) * RATIO;
  u = a + u * (b - a);
  return (int) floor (u);
}


/* Function to estimate the average of an birth and death process n(t) */

#define DEBUG_AVERAGE 2

void
AVE_init (win_stat * stat, char *name, timeval tc)
{

  stat->tot = 0;
  stat->n = 0;
  stat->t = tc;
  stat->t0 = tc;
  strcpy (stat->name, name);
}

void
AVE_arrival (timeval tc, win_stat * stat)
{

  stat->tot += elapsed (stat->t, tc) / 1000.0 * stat->n;
  stat->n++;
  if (debug > DEBUG_AVERAGE)
    fprintf (fp_stdout, 
        "new arrival %s: n:%d - tot: %f (elapsed = %f)\n", 
        stat->name, stat->n, stat->tot, elapsed (stat->t, tc));
  stat->t = tc;

}

void
AVE_departure (timeval tc, win_stat * stat)
{

  stat->tot += elapsed (stat->t, tc) / 1000.0 * stat->n;
  stat->n--;
  if (debug > DEBUG_AVERAGE)
    fprintf (fp_stdout,
        "new departure %s: n:%d - tot: %f (elapsed = %f)\n", 
        stat->name, stat->n, stat->tot, elapsed (stat->t, tc));
  stat->t = tc;
}

double
AVE_get_stat (timeval tc, win_stat * stat)
{
  stat->tot += elapsed (stat->t, tc) / 1000.0 * stat->n;
  double avg = stat->tot / elapsed (stat->t0, tc) * 1000;
  if (debug > DEBUG_AVERAGE)
    fprintf (fp_stdout,
        "new stat %s: n:%d - tot: %f (elapsed = %f) AVG: %f\n",
	    stat->name, stat->n, stat->tot, elapsed (stat->t, tc), avg);
  stat->tot = 0;
  stat->t = tc;
  stat->t0 = tc;
  return avg;
}

int in_out_loc(int internal_src, int internal_dst, int dir)
{
   if(internal_src && !internal_dst)
   {
     if(dir == C2S)
        return OUT_FLOW;
     else
        return IN_FLOW;
   } else
   if(!internal_src && internal_dst)
   {
     if(dir == C2S)
        return IN_FLOW;
     else
        return OUT_FLOW;
   } else
      if(internal_src && internal_dst)
   {
        return LOC_FLOW;
   } else
    return EXT_FLOW;
}
