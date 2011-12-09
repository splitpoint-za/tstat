/*
 *
 * Copyright (c) 2001-2008
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

#ifndef _VIDEOL7_H_
#define _VIDEOL7_H_

#include <sys/types.h>

/* Number of maximum packets inspected
 * in order to classify a flow as video   */
#define MAX_HTTP_STREAMING_DEPTH 5

#define HINIBBLE(b) (((b) >> 4) & 0x0F)
#define LONIBBLE(b) ((b) & 0x0F)

/* Keyword definitions for fast compare */
/* considering both byte orders         */

#if(BYTE_ORDER == BIG_ENDIAN)

/*Flash header*/
#define FLV  		0x464C5601UL

/* MP4 header */
#define MP4  		0x00000018UL

#else

/*Flash header*/
#define FLV  		0x01564C46UL

/* MP4 header */
#define MP4  		0x18000000UL
#define M4A  		0x20000000UL
#define MP4_YT  	0x1C000000UL

/* MP4-MOOF header */
#define MP4_MOOF_1  0x80000000UL
#define MP4_MOOF_2  0x0000014AUL

/* AVI header */
#define AVI  		0x46464952UL

/* WEBM header */
#define WEBM  		0xA3DF451AUL

/* ASF header */
#define WMV_1  		0x75B22630UL
#define WMV_2  		0xAA00D9A6UL
#define WMV_3  		0x01AD4D24UL

/* MPEG header */
#define MPEG  		0xB3010000UL

#endif
/* end Keyword definitions */

#endif
