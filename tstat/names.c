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
 * name.c -- name binding stuff
 * 
 * Author:	Shawn Ostermann
 * Date:	Tue Nov  1, 1994
 */

#include "tstat.h"


/* local routines */


char *
ServiceName (portnum port)
{
  static char port_buf[6];

  sprintf (port_buf, "%hu", port);
  return (port_buf);
}


/* turn an ipaddr into a printable format */
/* N.B. - result comes from static memory, save it before calling back! */
char *
HostAddr (ipaddr ipaddress)
{
  char *adr;

#ifdef SUPPORT_IPV6
  if (ADDR_ISV6 (&ipaddress))
    {
      static char adrv6[INET6_ADDRSTRLEN];
      my_inet_ntop (AF_INET6, (char *) ipaddress.un.ip6.s6_addr,
		    adrv6, INET6_ADDRSTRLEN);
      adr = adrv6;
    }
  else
#endif
    adr = inet_ntoa (ipaddress.un.ip4);

  return (adr);
}



char *
HostName (ipaddr ipaddress)
{
  char *adr;

  adr = HostAddr (ipaddress);
  return (adr);
}
