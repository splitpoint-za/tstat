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

#ifdef LOG_DNS

#include <ldns/ldns.h>
#include "tstat.h"

#define UDP_HDR_SZ 8
#define MAX_STR_DNS 256

extern FILE *fp_dns_logc;

// Utility function prototype
char replace_char (char *s, char find, char replace);
inline char * pkt_rcode2str(ldns_pkt_rcode rcode);
inline char * rr_class2str(ldns_rr_class rcode);
inline char * rr_type2str(ldns_rr_type rcode);

void *
check_dns(struct udphdr *pudp, int tproto, void *pdir, void *plast)
{
  /* just pass the complete packet and let the  */
  return (void *) pudp;
}



void dns_flow_stat(struct ip *pip, void *pproto, int tproto, void *pdir,
		int dir, void *hdr, void *plast)
{
  
  ldns_pkt * pkt;
  ldns_rr * rr;
  int i;
  int pkt_id;
  int is_query;
  ldns_pkt_rcode rcode;
  ucb * thisdir;
  ldns_rr_list* rr_list;
  char * type;
  struct sudp_pair *pup;

  if (fp_dns_logc == NULL || !(LOG_IS_ENABLED(LOG_DNS_COMPLETE)))
    return;

  // Find UDP control block
  thisdir = (ucb *) pdir;
  pup = thisdir->pup;

  // Check it is a well formed DNS packet
  ldns_status ret = ldns_wire2pkt ( &pkt, (const uint8_t *) hdr + UDP_HDR_SZ , getpayloadlength(pip, plast) - UDP_HDR_SZ  ) ;
  if (ret == LDNS_STATUS_OK)
  {

    // Check if it is Request or Response and parse Packet Fields
    if ( ldns_pkt_qr (pkt ) == 1 )
    {
      is_query=0;
      type="RESP";
      rr_list =  ldns_pkt_answer (pkt ) ;
      rcode = ldns_pkt_get_rcode (pkt);
    } 
    else
    {
      is_query=1;
      rr_list =  ldns_pkt_question (pkt ) ;
      type = "REQ";
    }

    // <pkt_id> contains transaction ID 
    pkt_id = ldns_pkt_id (pkt);

    // <tuple_str_src> contains L3 and L4 information for Source
    char tuple_str_src [MAX_STR_DNS]; 
    if (pup->crypto_src==FALSE)
      sprintf (tuple_str_src, "%s %s", HostName (pup->addr_pair.a_address), ServiceName (pup->addr_pair.a_port));
    else
      sprintf (tuple_str_src, "%s %s", HostNameEncrypted (pup->addr_pair.a_address), ServiceName (pup->addr_pair.a_port));

    // <tuple_str_dst> contains L3 and L4 information for Destination        
    char tuple_str_dst [MAX_STR_DNS]; 
    if (pup->crypto_dst==FALSE)
      sprintf (tuple_str_dst,"%s %s", HostName (pup->addr_pair.b_address), ServiceName (pup->addr_pair.b_port));
    else
      sprintf (tuple_str_dst, "%s %s", HostNameEncrypted (pup->addr_pair.b_address), ServiceName (pup->addr_pair.b_port));

    // Find Client and Server -- Must invert when finding spurious responses
    char * client_str=tuple_str_src;
    char * server_str=tuple_str_dst;
    if (is_query == 0 && &(pup->c2s) == thisdir)
    {
      client_str= tuple_str_dst;
      server_str= tuple_str_src;
    }

    // Check if it is an <error response> and, in case, print Error code and eventual question
    if ( is_query==0 && rcode != LDNS_RCODE_NOERROR )
    { 
      char * type = "RESP_ERR";
      char * rcode_str = pkt_rcode2str(rcode);
      char question [MAX_STR_DNS];
      char * class_str =	"-";
      char * type_str =	"-";

      // Search eventual Question
      ldns_rr_list * rr_list_question =  ldns_pkt_question (pkt ) ;
      strcpy ( question, "--");
      if (ldns_rr_list_rr_count (rr_list_question) > 0)
      {

        // Copy the Owner of the first question
        rr = ldns_rr_list_rr(rr_list_question, 0);
        ldns_rdf* rdf = ldns_rr_owner(rr);
        memcpy(question,rdf->_data,rdf->_size );
        question[rdf->_size]=0;

        //Find and replace the label counts with '.'
        int index=0;
        while (index < rdf->_size)
        {
          int tmp_len=question[index];
          question[index]='.';
          index += (tmp_len+1);
        }

        // Get class and type
        class_str =	rr_class2str(ldns_rr_get_class (rr));
        type_str =	rr_type2str (ldns_rr_get_type (rr));

      }
      wfprintf (fp_dns_logc,"%s %s %f %s %d %s - %s %s %s\n",client_str,server_str,time2double(current_time)/1e3, 
                type,pkt_id,question+1,class_str,type_str,rcode_str);
    }
    // If Query has no error
    else{
      // Iterate over RRs and print a log line for each one
      for(i = 0; i < ldns_rr_list_rr_count(rr_list); i++)
      {
        // It is a query
        if (is_query==1)
        {
          char question [MAX_STR_DNS];
          rr = ldns_rr_list_rr(rr_list, i);
          ldns_rdf* rdf = ldns_rr_owner(rr);

          // Find the Owner of the question
          memcpy(question,rdf->_data,rdf->_size );
          question[rdf->_size]=0;
          
          //Find and replace the label counts with '.'
          int index=0;
          while (index < rdf->_size)
          {
            int tmp_len=question[index];
            question[index]='.';
            index += (tmp_len+1);
          }
          // Get class and type
          char * class_str =	rr_class2str(ldns_rr_get_class (rr));
          char * type_str =	rr_type2str (ldns_rr_get_type (rr));

          wfprintf (fp_dns_logc,"%s %s %f %s %d %s - %s %s -\n", client_str, server_str, time2double(current_time)/1e3, 
                    type, pkt_id, question+1,class_str,type_str); 

        }
        // It is a response
        else
        {

          rr = ldns_rr_list_rr(rr_list, i);

          // <rr_str> contains DNS information
          char * rr_str = ldns_rr2str(rr);
          replace_char (rr_str, '\t', ' ');

          wfprintf (fp_dns_logc,"%s %s %f %s %d %s", client_str, server_str, time2double(current_time)/1e3, type, pkt_id, rr_str);
          free (rr_str);
        }
      }
    }

    // Free the RR list
    ldns_rr_list_deep_free(rr_list);
    //ldns_pkt_free(pkt);
  }

}

// Utility Function to replace Char with Tab
inline char replace_char (char *s, char find, char replace) {
    while (*s != 0) {
        if (*s == find)
        *s = replace;
        s++;
    }
    return s;
}

// Utility Function to get string representation of error codes
inline char * pkt_rcode2str(ldns_pkt_rcode rcode)
{
  switch (rcode) {
    case 0:
        return ("NO_ERROR");
        break;
    case 1:
        return ( "FORMERR");
        break;
    case 2:
        return ( "SERVFAIL");
        break;
    case 3:
        return ( "NXDOMAIN");
        break;
    case 4:
        return ( "NOTIMPL");
        break;
    case 5:
        return ( "REFUSED");
        break;
    case 6:
        return ("YXDOMAIN");
        break;
    case 7:
        return ("YXRRSET");
        break;
    case 8:
        return ( "NXRRSET");
        break;
    case 9:
        return ( "NOTAUTH");
        break;
    case 10:
        return ("NOTZONE");
        break;
    default:
        return ( "UNKNOWN-ERROR");
  break;
  }
}

// Utility Function to get string representation of error codes
inline char * rr_class2str(ldns_rr_class rcode)
{
  switch (rcode) 
  {
      case LDNS_RR_CLASS_IN:
          return ( "IN");
          break;
      case LDNS_RR_CLASS_CH:
          return (  "CH");
          break;
      case LDNS_RR_CLASS_HS:
          return ( "HS");
          break;
      case LDNS_RR_CLASS_NONE:
          return ( "NONE");
          break;
      case LDNS_RR_CLASS_ANY:
          return ( "ANY");
          break;
      default:
          return ( "OTHER");
          break;
  }
}

inline char * rr_type2str(ldns_rr_type rcode)
{
  switch (rcode) {
      case LDNS_RR_TYPE_HINFO:
          return ( "HINFO");
          break;
      case LDNS_RR_TYPE_SSHFP:
          return ( "SSHFP");
          break;
      case LDNS_RR_TYPE_GPOS:
          return ( "GPOS");
          break;
      case LDNS_RR_TYPE_LOC:
          return ( "LOC");
          break;
      case LDNS_RR_TYPE_DNSKEY:
          return ( "DNSKEY");
          break;
#ifdef LDNS_RR_TYPE_NSEC3PARAM
      case LDNS_RR_TYPE_NSEC3PARAM:
          return ( "NSEC3PARAM");
          break;
#endif /* LDNS_RR_TYPE_NSEC3PARAM */
      case LDNS_RR_TYPE_NSEC3:
          return ( "NSEC3");
          break;
      case LDNS_RR_TYPE_NSEC:
          return ( "NSEC");
          break;
      case LDNS_RR_TYPE_RRSIG:
          return ( "RRSIG");
          break;
      case LDNS_RR_TYPE_DS:
          return ( "DS");
          break;
      case LDNS_RR_TYPE_PTR:
          return ( "PTR");
          break;
      case LDNS_RR_TYPE_A:
          return ( "A");
          break;
      case LDNS_RR_TYPE_AAAA:
          return ( "AAAA");
          break;
      case LDNS_RR_TYPE_CNAME:
          return ( "CNAME");
          break;
      case LDNS_RR_TYPE_DNAME:
          return ( "DNAME");
          break;
      case LDNS_RR_TYPE_NAPTR:
          return ( "NAPTR");
          break;
      case LDNS_RR_TYPE_RP:
          return ( "RP");
          break;
      case LDNS_RR_TYPE_SRV:
          return ( "SRV");
          break;
      case LDNS_RR_TYPE_TXT:
          return ( "TXT");
          break;
      case LDNS_RR_TYPE_SPF:
          return ( "SPF");
          break;
      case LDNS_RR_TYPE_SOA:
          return ( "SOA");
          break;
      case LDNS_RR_TYPE_NS:
          return ( "NS");
          break;
      case LDNS_RR_TYPE_MX:
          return ( "MX");
          break;
      default:
          return ( "OTHER");
          break;
  }
}


#endif //LOG_DNS

