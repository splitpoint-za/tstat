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


/* 
 * print.c -- packet printing routines
 */

#include "tstat.h"
#include <time.h>


/* Unix format: "Fri Sep 13 00:00:00 1986\n" */
/*			   1         2          */
/*		 012345678901234567890123456789 */
char *
ts2ascii (struct timeval *ptime)
{
  static char buf[30];
  struct tm *ptm;
  char *now;
  int decimal;

  if (ZERO_TIME (ptime))
    return ("        <the epoch>       ");

  ptm = localtime (&ptime->tv_sec);
  now = asctime (ptm);

  /* splice in the microseconds */
  now[19] = '\00';
  /*    decimal = (ptime->tv_usec + 50) / 100; *//* for 4 digits */
  decimal = ptime->tv_usec;	/* for 6 digits */

  now[24] = '\00';		/* nuke the newline */
  sprintf (buf, "%s.%06d %s", now, decimal, &now[20]);

  return (buf);
}

/* same as ts2ascii, but leave the year on */
char *
ts2ascii_date (struct timeval *ptime)
{
  static char buf[30];
  struct tm *ptm;
  char *now;
  int decimal;

  if (ZERO_TIME (ptime))
    return ("        <the epoch>       ");

  ptm = localtime (&ptime->tv_sec);
  now = asctime (ptm);
  now[24] = '\00';

  /*    decimal = (ptime->tv_usec + 50) / 100; *//* for 4 digits */
  decimal = ptime->tv_usec;	/* for 6 digits */
  sprintf (buf, "%s.%06d", now, decimal);

  return (buf);
}
