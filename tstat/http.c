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

#include "tstat.h"
#include "http.h"
#include "tcpL7.h"
#include <regex.h>

#define get_u8(X,O)   (*(tt_uint8  *)(X + O))
#define get_u16(X,O)  (*(tt_uint16 *)(X + O))
#define get_u32(X,O)  (*(tt_uint32 *)(X + O))

#define HTTP_BUFFER_SIZE 1520

char *http_patterns[12];
regex_t http_re[12];
regmatch_t re_res[3];
char http_url[1600];
char http_method[10];
char http_host[200];
char http_ua[200];
char http_ctype[200];
char http_clen[200];
char http_referer[1600];
char http_response[5];
char http_range[200];
char http_server[200];

extern FILE *fp_http_logc;

void init_http_patterns()
{
  int i;
  
  http_patterns[0] = "^([A-Z]+) ([^[:cntrl:][:space:]]+) ";
  http_patterns[1] = "Host: ([^[:cntrl:][:space:]]+)";
  http_patterns[2] = "Referer: ([^[:cntrl:][:space:]]+)";
  http_patterns[3] = "User-Agent: ([^[:cntrl:]]+)";
  http_patterns[4] = "Content-Type: ([^[:cntrl:]]+)";
  http_patterns[5] = "Content-Length: ([^[:cntrl:]]+)";
  http_patterns[6] = "Content-Range: ([^[:cntrl:]]+)";
  http_patterns[7] = "Server: ([^[:cntrl:]]+)";
  http_patterns[8] = "Location: ([^[:cntrl:][:space:]]+)";
  /* Very long path in truncated packet */
  http_patterns[9] = "^([A-Z]+) ([^[:cntrl:][:space:]]+)"; 

  for (i=0;i<10;i++)
   {
     regcomp(&http_re[i],http_patterns[i],REG_EXTENDED);
   }

}


void http_init()
{
  /* nothing to do so far */
  init_http_patterns();
}

void *
gethttp(struct udphdr *pudp, int tproto, void *pdir, void *plast)
{
  /* just pass the complete packet and let the tcpL7_flow_stat decide */

  return (void *) pudp;
}

void http_flow_stat(struct ip *pip, void *pproto, int tproto, void *pdir,
		int dir, void *hdr, void *plast)
{
  tcp_pair *ptp;

  void *pdata; /*start of payload */
  int data_length, payload_len;
  tcb *tcp_stats;
  char *last_payload_char;

  tcphdr *ptcp;
  ptcp = (tcphdr *) hdr;

  if (tproto == PROTOCOL_UDP) {
  	  return;
  }

  ptp = ((tcb *) pdir)->ptp;

  if (ptp == NULL)
  	  return;

  /* Content of the old FindConType function */

  pdata = (char *) ptcp + ptcp->th_off * 4;
  payload_len = getpayloadlength(pip, plast) - ptcp->th_off * 4;
  data_length = (char *) plast - (char *) pdata + 1;

  if (data_length <= 0 || payload_len == 0)
    return;

  if (dir == C2S)
    tcp_stats = &(ptp->c2s);
  else
    tcp_stats = &(ptp->s2c);

  if ((char *) pdata + 4 > (char *) plast)
    return;

  char *base = (char *)pdata;

  switch (*((u_int32_t *) pdata)) 
   {
     case GET:
     case POST:
     case HEAD:
       if (dir == C2S)
        { 

  	  last_payload_char =  *((char *)(pdata + data_length));
  	  *(char *)(pdata + data_length) = '\0';

	  if (regexec(&http_re[0],base,(size_t) 3,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;

              memcpy(http_method,base+re_res[1].rm_so,
               (msize<9?msize:9));
               http_method[msize<9?msize:9]='\0';

             msize = re_res[2].rm_eo-re_res[2].rm_so;

              memcpy(http_url,base+re_res[2].rm_so,
               (msize<1599?msize:1599));
               http_url[msize<1599?msize:1599]='\0';
	       
	     base += re_res[2].rm_eo;
	    }
	  else if (regexec(&http_re[9],base,(size_t) 3,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;

              memcpy(http_method,base+re_res[1].rm_so,
               (msize<9?msize:9));
               http_method[msize<9?msize:9]='\0';

             msize = re_res[2].rm_eo-re_res[2].rm_so;

              memcpy(http_url,base+re_res[2].rm_so,
               (msize<1599?msize:1599));
               http_url[msize<1599?msize:1599]='\0';
	    }
          else
	   {
	     strcpy(http_method,"-");
	     strcpy(http_url,"-");
	   }

	  if (regexec(&http_re[1],base,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;

              memcpy(http_host,base+re_res[1].rm_so,
               (msize<199?msize:199));
               http_host[msize<199?msize:199]='\0';
	    }
          else
	   {
	     strcpy(http_host,"-");
	   }

	  if (regexec(&http_re[2],base,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;

              memcpy(http_referer,base+re_res[1].rm_so,
               (msize<1599?msize:1599));
               http_referer[msize<1599?msize:1599]='\0';
	    }
          else
	   {
	     strcpy(http_referer,"-");
	   }

	  if (regexec(&http_re[3],base,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;

              memcpy(http_ua,base+re_res[1].rm_so,
               (msize<199?msize:199));
               http_ua[msize<199?msize:199]='\0';
	    }
          else
	   {
	     strcpy(http_ua,"-");
	   }


         *(char *)(pdata + data_length) = last_payload_char;

         if (fp_http_logc != NULL && LOG_IS_ENABLED(LOG_HTTP_COMPLETE) )
	  {
            wfprintf (fp_http_logc,"%s\t%s",HostName(ptp->addr_pair.a_address),
                                    ServiceName(ptp->addr_pair.a_port));
            wfprintf (fp_http_logc,"\t%s\t%s",HostName(ptp->addr_pair.b_address),
                                    ServiceName(ptp->addr_pair.b_port));
				    
            wfprintf (fp_http_logc,"\t%f",time2double(current_time)/1e6);
            wfprintf (fp_http_logc,"\t%s\t%s",http_method,http_host);

            wfprintf (fp_http_logc,"\t%s\t%s\t%s",http_url,http_referer,http_ua);

            wfprintf(fp_http_logc,"\n");
	  }

          if (0)
          {
           int ii;
           printf ("%s %s",HostName(ptp->addr_pair.a_address),
                                    ServiceName(ptp->addr_pair.a_port));
           printf (" %s %s ",HostName(ptp->addr_pair.b_address),
                                    ServiceName(ptp->addr_pair.b_port));
           //printf ("%d ",ptp->http_data);
           for (ii=0;ii<data_length;ii++)
            {
              printf ("%c",isprint(*(char *)(pdata+ii))?*(char *)(pdata+ii):'.');
            }
           printf("\n");
          }

	}
       break;
     case HTTP:
       if (dir == S2C)
        { 
  	  last_payload_char =  *((char *)(pdata + data_length));
  	  *(char *)(pdata + data_length) = '\0';

          if ((char *) pdata + 13 <= (char *) plast)
	    {
              memcpy(http_response,(char *) pdata+9,3);
	      http_response[3]='\0';
            }
          else
	    {
              strcpy(http_response,"-");
	    }

	  if (regexec(&http_re[4],base,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;

              memcpy(http_ctype,base+re_res[1].rm_so,
               (msize<199?msize:199));
               http_ctype[msize<199?msize:199]='\0';
	    }
          else
	   {
	     strcpy(http_ctype,"-");
	   }

	  if (regexec(&http_re[5],base,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;

              memcpy(http_clen,base+re_res[1].rm_so,
               (msize<199?msize:199));
               http_clen[msize<199?msize:199]='\0';
	    }
          else
	   {
	     strcpy(http_clen,"-");
	   }

	  if (regexec(&http_re[6],base,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;

              memcpy(http_range,base+re_res[1].rm_so,
               (msize<199?msize:199));
               http_range[msize<199?msize:199]='\0';
	    }
          else
	   {
	     strcpy(http_range,"-");
	   }

	  if (regexec(&http_re[7],base,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;

              memcpy(http_server,base+re_res[1].rm_so,
               (msize<199?msize:199));
               http_server[msize<199?msize:199]='\0';
	    }
          else
	   {
	     strcpy(http_server,"-");
	   }

	  if (regexec(&http_re[8],base,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;

              memcpy(http_url,base+re_res[1].rm_so,
               (msize<1599?msize:1599));
               http_url[msize<1599?msize:1599]='\0';
	    }
          else
	   {
	     strcpy(http_url,"-");
	   }

         *(char *)(pdata + data_length) = last_payload_char;

         if (fp_http_logc != NULL && LOG_IS_ENABLED(LOG_HTTP_COMPLETE) )
	  {
            wfprintf (fp_http_logc,"%s\t%s",HostName(ptp->addr_pair.a_address),
                                    ServiceName(ptp->addr_pair.a_port));
            wfprintf (fp_http_logc,"\t%s\t%s",HostName(ptp->addr_pair.b_address),
                                    ServiceName(ptp->addr_pair.b_port));
				    
            wfprintf (fp_http_logc,"\t%f",time2double(current_time)/1e6);
            wfprintf (fp_http_logc,"\t%s\t%s\t%s\t%s","HTTP",http_response,http_clen,http_ctype);
            wfprintf (fp_http_logc,"\t%s\t%s\t%s",http_server,http_range,http_url);

            wfprintf(fp_http_logc,"\n");
	  }

          if (0)
          {
           int ii;
           printf ("%s %s",HostName(ptp->addr_pair.a_address),
                                    ServiceName(ptp->addr_pair.a_port));
           printf (" %s %s ",HostName(ptp->addr_pair.b_address),
                                    ServiceName(ptp->addr_pair.b_port));
           //printf ("%d ",ptp->http_data);
           for (ii=0;ii<data_length;ii++)
            {
              printf ("%c",isprint(*(char *)(pdata+ii))?*(char *)(pdata+ii):'.');
            }
           printf("\n");
          }

	}
       break;
     default:
       // if (ptp->packets > MAX_UNKNOWN_PACKETS)
       //   ptp->streaming.state = IGNORE_FURTHER_PACKETS;
       break;
   }

  // if (ptp->packets > MAX_PACKETS_CON)
  //  ptp->streaming.state = IGNORE_FURTHER_PACKETS;


  return;
}

void make_http_conn_stats(void *thisflow, int tproto)
{
  return;
}
