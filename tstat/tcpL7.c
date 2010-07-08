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
#include "tcpL7.h"
#include "msn.h"
#include "ymsg.h"
#include "jabber.h"
#include "p2p.h"

#ifdef YOUTUBE_DETAILS
#include <regex.h>
#endif

int map_flow_type(tcp_pair *thisflow);

extern struct L4_bitrates L4_bitrate;
extern struct L7_bitrates L7_bitrate;
extern struct L7_bitrates L7_udp_bitrate;
extern struct HTTP_bitrates HTTP_bitrate;
extern struct WEB_bitrates WEB_bitrate;

#ifdef YOUTUBE_DETAILS
extern void init_web_patterns();

extern char yt_id[20];
extern int yt_seek;
#endif

void
tcpL7_init ()
{
  /* nothing to do so far */
#ifdef YOUTUBE_DETAILS
   init_web_patterns();
#endif
}

void *
gettcpL7 (struct udphdr *pudp, int tproto, void *pdir, void *plast)
{
  /* just pass the complete packet and let the tcpL7_flow_stat decide */

  return (void *) pudp;
}

Bool ssl_client_check(tcp_pair *ptp, void *pdata, int payload_len)
{
  int record_length;
  if (  *(char *)pdata == 0x16 && 
      *(char *)(pdata + 1) == 0x03 && 
    ( *(char *)(pdata + 2) >= 0x00 && *(char *)(pdata + 2) <= 0x03 ) && 
    ( *(char *)(pdata + 3) >= 0x00 && *(char *)(pdata + 3) <= 0x39 ) &&
      *(char *)(pdata + 5) == 0x01
     )
   { 
     /* Match SSL 3 - TLS 1.x Handshake Client HELLO */
      ptp->state = SSL_HANDSHAKE;
      return TRUE;
   }
  else if (  *(char *)(pdata + 2) == 0x01 &&
             *(char *)(pdata + 3) == 0x03 &&
           ( *(char *)(pdata + 4) >= 0x00 && *(char *)(pdata + 4) <= 0x03 )
          ) 
   { 
     /* Match SSL 2.0 Handshake CLient HELLO */
      record_length = ((*(char *)pdata & 0x7f) << 8) | (*(char *)(pdata + 1));
      if (record_length == payload_len-2)
        { 
	  ptp->state = SSL_HANDSHAKE;
          return TRUE;
	}
   }
  return FALSE;
}

Bool ssl_server_check(void *pdata)
{
  if (  *(char *)pdata == 0x16 && 
        *(char *)(pdata + 1) == 0x03 && 
      ( *(char *)(pdata + 2) >= 0x00 && *(char *)(pdata + 2) <= 0x03 ) && 
      ( *(char *)(pdata + 3) >= 0x00 && *(char *)(pdata + 3) <= 0x39 ) &&
        *(char *)(pdata + 5) == 0x02
     )
   { 
     /* Match SSL 3 - TLS 1.x Handshake Server HELLO */
      return TRUE;
   }
  return FALSE;
}

Bool ssh_header_check(void *pdata)
{
  if (( *(char *)(pdata + 4) == 0x31 || *(char *)(pdata + 4) == 0x32 ) && 
        *(char *)(pdata + 5) == 0x2E && 
      ( *(char *)(pdata + 6) >= 0x30 && *(char *)(pdata + 6) <= 0x39 )
     )
   { 
     /* Match SSH 2.x/1.x Handshake */
      return TRUE;
   }
  return FALSE;
}

Bool is_imap_tag(void *pdata)
{
  int i;
  char c;

  /* Identify the IMAP tag with pattern /^.+[0-9A-Za-z] /
    (space after either a digit or a letter) in the first 6 chars.
     General tag identification not possible, since it can be
     any alphanumeric unique string
  */
  
  for (i=1;i<6;i++)
   {
     if ( *(char *)(pdata + i) == 0x20 )
       {
         c = *(char *)(pdata + i-1 );
	 if ( (c>=0x30 && c<=0x39) ||    /* digit */
	      (c>=0x61 && c<=0x7a) ||    /* lowercase letter */
	      (c>=0x41 && c<=0x5a) )     /* uppercase letter */
	   return TRUE;   
       }  
   }
  return FALSE;
}

void rtmp_handshake_check(tcp_pair *ptp, void *pdata, int payload_len, int dir)
{
  char c;
  
  /* Check first byte of the first data segment in both directions...*/

  if (ptp->state_rtmp_c2s_seen==1 && ptp->state_rtmp_s2c_seen==1)
    return;
    
  c = *(char *)pdata; /* First byte in the payload: 
                         must be 0x03 (unencrypted), 0x06 (encrypted) 
                         or 0x08 (further encrypted)
		      */ 
    
  if (dir == C2S && ptp->state_rtmp_c2s_seen==0)
    { 
      ptp->state_rtmp_c2s_seen=1;
      if ( c == 0x03 || c==0x06 || c==0x08 )
         ptp->state_rtmp_c2s_hand=1;
    }

  if (dir == S2C && ptp->state_rtmp_s2c_seen==0)
    { 
      ptp->state_rtmp_s2c_seen=1;
      if ( c == 0x03 || c==0x06 || c==0x08 )
        ptp->state_rtmp_s2c_hand=1;
    }
    
  if ( ptp->state_rtmp_c2s_hand == 1 && ptp->state_rtmp_s2c_hand == 1)
    ptp->con_type |= RTMP_PROTOCOL;

  return;
}

void ed2k_obfuscate_check(tcp_pair *ptp,int payload_len)
{
/* Identification of sequences of messages through the packet size
   information (and only if the packet has the PSH/ACK flags set):
     11 -> 83 -> 55 => SecureID with key exchange 
     11 -> 55       => SecureID without key exchange
     22 -> 18       => Upload queue management
      6 -> 46	  => Accept-upload/Request Parts
*/	

  switch(payload_len)
   {
     case 11:
       ptp->state_11=1;
       break;
     case 83:
       if (ptp->state_11==1)
     	  ptp->state_11_83=1;
       break;
     case 55:
       if (ptp->state_11_83==1)
     	 { 
     	   ptp->state_11_83_55=1;
     	   ptp->con_type |= OBF_PROTOCOL;
	 }
       else if (ptp->state_11==1)
     	 { 
     	   ptp->state_11_55=1; 
     	   ptp->con_type |= OBF_PROTOCOL;
     	 }
       break;

     case 22:
       ptp->state_22=1;
       break;
     case 18:
       if (ptp->state_22==1)
     	 {
     	   ptp->state_22_18=1;
     	   ptp->con_type |= OBF_PROTOCOL;
     	 }  
       break;

     case 6:
       ptp->state_6=1;
       break;
     case 46:
       if (ptp->state_6==1)
     	{
     	  ptp->state_6_46=1;
     	  ptp->con_type |= OBF_PROTOCOL;
     	}
       break;
     default:
       break;
   }
}

void mse_protocol_check(tcp_pair *ptp)
{
/* Identification of BitTorrent Message Stream Encryption protocol
   At the handshake, the (concurrent) handshake between A<->B is
    A -> B between 96 and 608 bytes
    B -> A between 96 and 608 bytes
   Data entropy is high (>ENTROPY_THRESHOLD for both the high and the low
   nibbles)
   Due to the protocol behavior, messages are overlapped and fragmented 
   randomly, so we must check the cumulative size of consecutive packets
*/	
 int length_test;

 if (ptp->c2s.msg_count==0 || ptp->s2c.msg_count==0)
   return;
   
 length_test = FALSE;
 
 if (ptp->c2s.msg_size[0]>=96 && ptp->c2s.msg_size[0]<=608)
  {
    if ((ptp->s2c.msg_size[0]>=96 && ptp->s2c.msg_size[0]<=608)||
        ((ptp->s2c.msg_size[0]+ptp->s2c.msg_size[1])>=96 && 
           (ptp->s2c.msg_size[0]+ptp->s2c.msg_size[1])<=608))
     {
       length_test = TRUE;
     }
  }
 else if ((ptp->c2s.msg_size[0]+ptp->c2s.msg_size[1])>=96 && 
          (ptp->c2s.msg_size[0]+ptp->c2s.msg_size[1])<=608)
  {
    if ((ptp->s2c.msg_size[0]>=96 && ptp->s2c.msg_size[0]<=608)||
        ((ptp->s2c.msg_size[0]+ptp->s2c.msg_size[1])>=96 && 
         (ptp->s2c.msg_size[0]+ptp->s2c.msg_size[1])<=608))
     {
       length_test = TRUE;
     }
  }
     
  if (length_test == TRUE && ptp->entropy_h>ENTROPY_THRESHOLD && 
                             ptp->entropy_l>ENTROPY_THRESHOLD )
    if (ptp->con_type==UNKNOWN_PROTOCOL)
      /* Don't overwrite existing classification with MSE/PE */
      ptp->con_type |= MSE_PROTOCOL; 

 return;
 
}


#ifdef MSN_CLASSIFIER
void msn_s2c_state_update(tcp_pair *ptp, int state,int http_tunneling, void *pdata, void *plast)
{
  char MSNP_ver[8] = "?\0";
  char *pMSNP_ver;

  if (http_tunneling == 1)
   {
     ptp->s2c.msn.POST_count = ptp->c2s.msn.POST_count = 1;
     ptp->s2c.msn.MFT = ptp->c2s.msn.MFT = MSN_HTTP_TUNNELING;
   }
   
  switch (state)
   {
     case VER:
        ptp->con_type |= MSN_PROTOCOL;
	ptp->con_type &= ~OBF_PROTOCOL;
	ptp->con_type &= ~MSE_PROTOCOL;
        ptp->state = MSN_VER_S2C;
        ptp->s2c.msn.MSN_VER_count = 1;
	
	   /* try to find MSN Protocol version negoziated */
	if ((char *) pdata + 13 <= (char *) plast)
	 {
	   pMSNP_ver = (char *) pdata + 6;
	   sscanf ((char *) (pMSNP_ver), "%7s", MSNP_ver);

       	   strncpy (ptp->s2c.msn.MSNPversion, MSNP_ver,7);
	   strncpy (ptp->c2s.msn.MSNPversion, MSNP_ver,7);
	 }
	break;
     case USR:
        ptp->con_type |= MSN_PROTOCOL;
	ptp->con_type &= ~OBF_PROTOCOL;
	ptp->con_type &= ~MSE_PROTOCOL;
        ptp->state = MSN_USR_S2C;
        ptp->s2c.msn.MSN_USR_count = 1;
	break;
     case ANS:
        ptp->con_type |= MSN_PROTOCOL;
	ptp->con_type &= ~OBF_PROTOCOL;
	ptp->con_type &= ~MSE_PROTOCOL;
        ptp->state = MSN_ANS_COMMAND;
        ptp->s2c.msn.MSN_ANS_count = 1;
	break;
     case IRO:
        ptp->con_type |= MSN_PROTOCOL;
	ptp->con_type &= ~OBF_PROTOCOL;
	ptp->con_type &= ~MSE_PROTOCOL;
        ptp->state = MSN_IRO_COMMAND;
        ptp->s2c.msn.MSN_IRO_count = 1;
        break;
     default:
        break;
   }
}
#endif

void compute_nibbles (struct ip *pip, void *pproto, int tproto, void *pdir,
	       int dir, void *hdr, void *plast)
{
/* Compute information entropy over high and low nibbles (4 bits)
   of the available payload. Only the first four payload packets are
   considered. 
*/
  void *pdata;			/*start of payload */
  tcp_pair *ptp;
  int data_length, payload_len;
  int i;
  char c;
  char c1,c2;
  double log2=log(2);
  double probi;

  tcphdr *ptcp;
  ptcp = (tcphdr *) hdr;

  if (tproto == PROTOCOL_UDP)
    {
       return;
    }

  ptp = ((tcb *) pdir)->ptp;

  if (ptp == NULL)
    return;

  if (ptp->nibble_packet_count>=4)
   return;

  pdata = (char *) ptcp + ptcp->th_off * 4;
  payload_len = getpayloadlength (pip, plast) - ptcp->th_off * 4;
  data_length = (char *) plast - (char *) pdata + 1;

  if (data_length <= 0 || payload_len == 0)
    return;

  for (i=0;i<data_length;i++)
   {
     c = *(char *)(pdata+i);

     c1 = c & 0x0f;
     c2 = (c>>4)&0x0f;

     ptp->nibbles_l[(int)c1]++;
     ptp->nibble_l_count++;
     ptp->nibbles_h[(int)c2]++;
     ptp->nibble_h_count++;
   }
   ptp->nibble_packet_count++;

   ptp->entropy_h = 0.0;
   if (ptp->nibble_h_count>0)
    {
      for (i=0; i<16;i++)
      {
        if (ptp->nibbles_h[i]==0) continue;
        probi = ptp->nibbles_h[i]*1.0/ptp->nibble_h_count;
        ptp->entropy_h += (-1.0)*probi*log(probi)/log2;
      }
    }

   ptp->entropy_l = 0.0;
   if (ptp->nibble_l_count>0)
    {
      for (i=0; i<16;i++)
      {
        if (ptp->nibbles_l[i]==0) continue;
        probi = ptp->nibbles_l[i]*1.0/ptp->nibble_l_count;
        ptp->entropy_l += (-1.0)*probi*log(probi)/log2;
      }
    }

  return;
}

void
tcpL7_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
	       int dir, void *hdr, void *plast)
{
  tcp_pair *ptp;

  void *pdata;			/*start of payload */
  int data_length, payload_len;
  tcb *tcp_stats;
  struct rtphdr *prtp;

  tcphdr *ptcp;
  ptcp = (tcphdr *) hdr;

  if (tproto == PROTOCOL_UDP)
    {
       return;
    }

  ptp = ((tcb *) pdir)->ptp;

  if (ptp!=NULL)
   {
     compute_nibbles(pip,pproto,tproto,pdir,dir,hdr,plast);
   }

  if (ptp == NULL || ptp->state == IGNORE_FURTHER_PACKETS)
    return;

/* Content of the old FindConType function */
 
  pdata = (char *) ptcp + ptcp->th_off * 4;
  payload_len = getpayloadlength (pip, plast) - ptcp->th_off * 4;
  data_length = (char *) plast - (char *) pdata + 1;

  if (data_length <= 0 || payload_len == 0)
    return;

  if (ACK_SET(ptcp) && PUSH_SET(ptcp))
    ed2k_obfuscate_check(ptp,payload_len);

  rtmp_handshake_check(ptp,pdata,payload_len,dir);

  mse_protocol_check(ptp);
  
  if (dir == C2S)
    tcp_stats = &(ptp->c2s);
  else
    tcp_stats = &(ptp->s2c);

  switch (ptp->state)
   {
     case UNKNOWN_TYPE:
        if ((char *) pdata + 4 > (char *) plast)
	  return;
	switch (*((u_int32_t *) pdata))
	 {
            case GET:
	      if (dir == C2S)
	        {
	          tcp_stats->u_protocols.f_http = current_time;
	          ptp->state = HTTP_COMMAND;
                  ptp->http_data = HTTP_GET;
#ifdef YOUTUBE_DETAILS
                  strcpy(ptp->http_ytid,"--");
		  strcpy(yt_id,"--");
		  yt_seek = 0;
#endif

                  ptp->http_data = classify_http_get(pdata,data_length);
#ifdef YOUTUBE_DETAILS
                  if (ptp->http_data==HTTP_YOUTUBE_VIDEO ||
		      ptp->http_data==HTTP_YOUTUBE_SITE )
                   {
                     strncpy(ptp->http_ytid,yt_id,19);
			  ptp->http_ytseek=yt_seek; 
                   }
#endif
	        }
	      break;
	    case POST:
	      if (dir == C2S)
	        {
	          tcp_stats->u_protocols.f_http = current_time;
	          ptp->state = HTTP_COMMAND;
		  ptp->http_data = HTTP_POST;
#ifdef YOUTUBE_DETAILS
                  strcpy(ptp->http_ytid,"--");
		  strcpy(yt_id,"--");
		  yt_seek = 0;
#endif
                  ptp->http_data = classify_http_post(pdata,data_length);
	        }
	      break;
	    case HEAD:
	      if (dir == C2S)
	        {
	          tcp_stats->u_protocols.f_http = current_time;
	          ptp->state = HTTP_COMMAND;
	        }
	      break;
#ifdef YMSG_CLASSIFIER		/* Yahoo! Messenger */
	   case YMSG:
	     ptp->state = YMSGP;
	     ptp->con_type |= YMSG_PROTOCOL;
	     ptp->con_type &= ~OBF_PROTOCOL;
	     ptp->con_type &= ~MSE_PROTOCOL;

	      /* try to find Yahoo! Messenger Protocol version */

	     if ((char *) pdata + 5 > (char *) plast)
	         return;

#if(BYTE_ORDER == BIG_ENDIAN)
	     ptp->s2c.ymsg.YMSGPversion = ptp->c2s.ymsg.YMSGPversion =
	         *((u_int16_t *) (pdata + 4));
#else
	     ptp->s2c.ymsg.YMSGPversion = ptp->c2s.ymsg.YMSGPversion =
	         *((u_int16_t *) (pdata + 5));
#endif
	     break;
#endif
#ifdef XMPP_CLASSIFIER		/* Jabber - Google Talk */
	   case XMPP_SMELL:
	     ptp->state = XMPP;
	     ptp->con_type |= XMPP_PROTOCOL;
	     ptp->con_type &= ~OBF_PROTOCOL;
	     ptp->con_type &= ~MSE_PROTOCOL;
	     break;
#endif
#ifdef MSN_CLASSIFIER
	    case VER:		/* start connection with DS or NS */
	      if (dir == C2S)
	        {
 	          ptp->c2s.msn.login = current_time;
	          ptp->c2s.msn.MSN_VER_count = 1;
	          ptp->state = MSN_VER_C2S;
		 }
	      else
	        {
	          msn_s2c_state_update(ptp,VER,0,pdata,plast);
		}
	      break;

	    case USR:		/* start connection with SB to enstablish a chat session */
	      if (dir == C2S)
	        {
	          ptp->c2s.msn.start_chat = current_time;
	          ptp->c2s.msn.MSN_USR_count = 1;
	          ptp->state = MSN_USR_C2S;
		}
	      else
	        {
	          msn_s2c_state_update(ptp,USR,0,pdata,plast);
		}
	      break;

	    case ANS:		/* start connection with SB to accept a chat session */
	      if (dir == C2S)
	        {
	          ptp->c2s.msn.start_chat = current_time;
	          ptp->c2s.msn.MSN_ANS_count = 1;
	          ptp->state = MSN_ANS_COMMAND;
		}
	      else
	        {
	          msn_s2c_state_update(ptp,ANS,0,pdata,plast);
		}
	      break;

	    case IRO:		/* start connection with SB to accept a chat session */
	      if (dir == C2S)
	        {
	          ptp->c2s.msn.MSN_IRO_count = 1;
	          ptp->state = MSN_IRO_COMMAND;
		}
	      else
	        {
	          msn_s2c_state_update(ptp,IRO,0,pdata,plast);
		}
	      break;
#endif
#ifdef RTSP_CLASSIFIER
            case DESC:
	      if ((dir == C2S) && ((char *) pdata + 8 <= (char *) plast))
               {
	         switch (*((u_int64_t *) pdata))
	          {
	            case DESCRIBE:
	              tcp_stats->u_protocols.f_rtsp = current_time;
	              ptp->state = RTSP_COMMAND;
	              break;
	            default:
	              break;
		  }
	       }
	      break;
#endif

            case SMTP_220:
              /* A SMTP dialog is open by the server with the "220 xxxx"
	         message 
	      */
	      if (dir == S2C)
	        {
	          ptp->state = SMTP_OPENING;
	        }
	      break;

            case POP_OK:
            case POP_ERR:
              /* A POP3 dialog is open by the server with the "+OK xxxx"
	         message. We consider also the "-ERR xxx" message, even if
		 it not probable that a server uses it to start the dialog
	      */
	      if (dir == S2C)
	        {
	          ptp->state = POP3_OPENING;
	        }
	      break;

            case IMAP_OK:
              /* An IMAP dialog is open by the server with the "*OK xxxx"
	         message 
	      */
	      if (dir == S2C)
	        {
	          ptp->state = IMAP_OPENING;
	        }
	      break;

            case SSH_HEADER: 
              /* SSH Server handshake SSH-[1-2].[0-9]
	         message 
	      */
	      if (dir == S2C &&
	         ((char *) pdata + 7 <= (char *) plast) &&
	          ssh_header_check(pdata)
	          )
	        {
	          ptp->state = SSH_SERVER;
	        }
	      break;

           default:
             if ( dir==C2S && 
	         ((char *) pdata + 6 <= (char *) plast) &&
	          ssl_client_check(ptp,pdata,payload_len) )
	        break;

	     if (ptp->packets > MAX_UNKNOWN_PACKETS)
	         ptp->state = IGNORE_FURTHER_PACKETS;
	     break;
	 }
	break;
     case SMTP_OPENING:
        if (dir == C2S && ((char *) pdata + 4 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
	      /*
                Possible commands are HELO and EHLO
	      */
	      case SMTP_HELO:
	      case SMTP_EHLO:
	      case SMTP_helo:
	      case SMTP_ehlo:
	        ptp->con_type |= SMTP_PROTOCOL;
	        ptp->con_type &= ~OBF_PROTOCOL;
   	        ptp->con_type &= ~MSE_PROTOCOL;
	        ptp->state = IGNORE_FURTHER_PACKETS;
	        break;
	      default:
	        break;
	    }
	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;
     case POP3_OPENING:
        if (dir == C2S && ((char *) pdata + 4 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
	      /*
	        At the opening we are in Authentication state, so
		the possible commands are USER, APOP and QUIT
	      */
	      case POP_USER:
	      case POP_QUIT:
              case POP_APOP:
	        ptp->con_type |= POP3_PROTOCOL;
	        ptp->con_type &= ~OBF_PROTOCOL;
  	        ptp->con_type &= ~MSE_PROTOCOL;
	        ptp->state = IGNORE_FURTHER_PACKETS;
	        break;
	      default:
	        break;
	    }
	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;
     case IMAP_OPENING:
        if (dir == C2S && ((char *) pdata + 6 <= (char *) plast))
	 {
             if (is_imap_tag(pdata))
	     {
	        ptp->state = IMAP_COMMAND;
		break;
	     }

	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;
     case IMAP_COMMAND:
        if (dir == S2C && ((char *) pdata + 6 <= (char *) plast))
	 {
	   /* 
	     Answer to a possible IMAP command starts either with '* '
	     or with an IMAP tag 
	   */
           if ( ( ( *(char *)(pdata) == 0x2a ) && 
                    *(char *)(pdata + 1) == 0x20 ) || 
		is_imap_tag(pdata)
              )
	     {
	        ptp->con_type |= IMAP_PROTOCOL;
	        ptp->con_type &= ~OBF_PROTOCOL;
	        ptp->con_type &= ~MSE_PROTOCOL;
	        ptp->state = IGNORE_FURTHER_PACKETS;
		break;
	     }

	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;
     case HTTP_COMMAND:
        if (dir == S2C && ((char *) pdata + 4 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
	      case HTTP:
	        tcp_stats->u_protocols.f_http = current_time;
	        ptp->con_type |= HTTP_PROTOCOL;
	        ptp->con_type &= ~OBF_PROTOCOL;
	        ptp->con_type &= ~MSE_PROTOCOL;
	        ptp->state = HTTP_RESPONSE;
	        break;
	      case ICY:
	        tcp_stats->u_protocols.f_icy = current_time;
	        ptp->con_type |= ICY_PROTOCOL;
	        ptp->con_type &= ~OBF_PROTOCOL;
	        ptp->con_type &= ~MSE_PROTOCOL;
	        ptp->state = IGNORE_FURTHER_PACKETS;
	        break;
#ifdef MSN_CLASSIFIER
	      case VER:		/* start connection with DS or NS */
	        msn_s2c_state_update(ptp,VER,1,pdata,plast);
	        break;

	      case USR:		/* start connection with SB to enstablish a chat session */
	        msn_s2c_state_update(ptp,USR,1,pdata,plast);
	        break;

	      case ANS:		/* start connection with SB to accept a chat session */
	        msn_s2c_state_update(ptp,ANS,1,pdata,plast);
	        break;

	      case IRO:		/* start connection with SB to accept a chat session */
	        msn_s2c_state_update(ptp,IRO,1,pdata,plast);
	        break;
#endif
	      default:
	        break;
	    }

	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	    
	 }
	break;
     case HTTP_RESPONSE:
        if (dir == S2C && ((char *) pdata + 4 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
#ifdef MSN_CLASSIFIER
	      case VER:		/* start connection with DS or NS */
	        msn_s2c_state_update(ptp,VER,1,pdata,plast);
	        break;

	      case USR:		/* start connection with SB to enstablish a chat session */
	        msn_s2c_state_update(ptp,USR,1,pdata,plast);
	        break;

	      case ANS:		/* start connection with SB to accept a chat session */
	        msn_s2c_state_update(ptp,ANS,1,pdata,plast);
	        break;

	      case IRO:		/* start connection with SB to accept a chat session */
	        msn_s2c_state_update(ptp,IRO,1,pdata,plast);
	        break;
#endif
	      default:
#ifdef RTSP_CLASSIFIER
	      /* convert the snap in a null-terminated string to use strstr */
	        *((char *) plast) = '\0';
	        if (strstr ((char *) pdata, "RTSP"))
	         {
	           tcp_stats->u_protocols.f_rtsp = current_time;
	           ptp->state = RTSP_RESPONSE;
 	           ptp->con_type |= RTSP_PROTOCOL;
	           ptp->con_type &= ~OBF_PROTOCOL;
	           ptp->con_type &= ~MSE_PROTOCOL;
	         }
#endif
	        break;
	    }

	  if (ptp->packets > MAX_HTTP_RESPONSE_PACKETS)
	    ptp->state = IGNORE_FURTHER_PACKETS;
         }
        else if (dir == C2S && ((char *) pdata + 4 <= (char *) plast))
	 {
           enum http_content new_http_data;
           /* Apply the Web2.0 rules for further commands in 
	      not yet classified HTTP flows
	   */
	   switch (*((u_int32_t *) pdata))
	    {
              case GET:
                if (ptp->http_data==HTTP_GET || ptp->http_data==HTTP_POST)
	         {
#ifdef YOUTUBE_DETAILS
		  strcpy(yt_id,"--");
#endif
                   new_http_data = classify_http_get(pdata,data_length);
                   /* Only update previous classification if new one
		      is specific */
		   if ( new_http_data != HTTP_GET && new_http_data != HTTP_POST)
		     { 
		       ptp->http_data = new_http_data;
#ifdef YOUTUBE_DETAILS
                       if (ptp->http_data==HTTP_YOUTUBE_VIDEO ||
		           ptp->http_data==HTTP_YOUTUBE_SITE )
                        {
                          strncpy(ptp->http_ytid,yt_id,19);
			  ptp->http_ytseek=yt_seek; 
                        }
#endif			
	             }
                 }
	        break;
              case POST:
                if (ptp->http_data==HTTP_GET || ptp->http_data==HTTP_POST)
	         {
#ifdef YOUTUBE_DETAILS
		  strcpy(yt_id,"--");
#endif
                   new_http_data = classify_http_post(pdata,data_length);
                   /* Only update previous classification if new one
		      is specific */
		   if ( new_http_data != HTTP_GET && new_http_data != HTTP_POST)
		    { 
		      ptp->http_data = new_http_data;
#ifdef YOUTUBE_DETAILS
                      if (ptp->http_data==HTTP_YOUTUBE_VIDEO ||
		          ptp->http_data==HTTP_YOUTUBE_SITE )
                       {
                         strncpy(ptp->http_ytid,yt_id,19); 
			  ptp->http_ytseek=yt_seek; 
                       }
#endif
		    }
                 }
	        break;
	      default:
	        break;
	    }
	   if (ptp->packets > MAX_HTTP_RESPONSE_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }

        break;
#ifdef RTSP_CLASSIFIER
     case RTSP_COMMAND:
        if (dir == S2C && ((char *) pdata + 4 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
	      case RTSP:
	        tcp_stats->u_protocols.f_rtsp = current_time;
	        ptp->state = RTSP_RESPONSE;
	        ptp->con_type |= RTSP_PROTOCOL;
	        ptp->con_type &= ~OBF_PROTOCOL;
	        ptp->con_type &= ~MSE_PROTOCOL;
	        break;
	      default:
	        break;
            }
	   if (ptp->packets > MAX_RTSP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;
     case RTSP_RESPONSE:
#ifdef RTP_CLASSIFIER
        if (dir == S2C && ((char *) pdata + 1 <= (char *) plast))
	 {
	   if (*(char *) pdata == RTP_MAGICNUMBER)
	    {
	      prtp = pdata + 4;

	      if ((u_long) prtp + (sizeof (struct rtphdr)) - 1 >
		  (u_long) plast)
		ptp->rtp_pt = UNKNOWN_RTP_PAYLOAD_TYPE;
	      else
		ptp->rtp_pt = prtp->pt;

	      tcp_stats->u_protocols.f_rtp = current_time;

	      ptp->state = IGNORE_FURTHER_PACKETS;
	      ptp->con_type |= RTP_PROTOCOL;
	      ptp->con_type &= ~OBF_PROTOCOL;
	      ptp->con_type &= ~MSE_PROTOCOL;
	    }
	 }
#endif
	if (ptp->packets > MAX_RTSP_RESPONSE_PACKETS)
	  ptp->state = IGNORE_FURTHER_PACKETS;
        break;
#endif
#ifdef YMSG_CLASSIFIER		/* Yahoo! Messenger */
     case YMSGP:
	FindConTypeYmsg (ptp, pip, ptcp, plast, dir);
	classify_ymsg_flow (ptp, dir);
	return;
#endif
#ifdef XMPP_CLASSIFIER		/* Jabber - Google Talk */
     case XMPP:
	FindConTypeJabber (ptp, pip, ptcp, plast, dir);
	classify_jabber_flow (ptp, dir);
	return;
#endif
#ifdef MSN_CLASSIFIER
     case MSN_VER_S2C:
     case MSN_USR_S2C:
     case MSN_IRO_COMMAND:
	FindConTypeMsn (ptp, pip, ptcp, plast, dir);
	classify_msn_flow (ptp, dir);
	return;
     case MSN_VER_C2S:
     case MSN_USR_C2S:
     case MSN_ANS_COMMAND:
      /* These cases were not explicited stated in the spaghetti version */
        if (dir == S2C && ((char *) pdata + 4 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
	      case VER:		/* start connection with DS or NS */
	        msn_s2c_state_update(ptp,VER,0,pdata,plast);
		break;

	      case USR:		/* start connection with SB to enstablish a chat session */
	        msn_s2c_state_update(ptp,USR,0,pdata,plast);
	        break;

	      case ANS:		/* start connection with SB to accept a chat session */
	        msn_s2c_state_update(ptp,ANS,0,pdata,plast);
	        break;

	      case IRO:		/* start connection with SB to accept a chat session */
	        msn_s2c_state_update(ptp,IRO,0,pdata,plast);
	        break;
	      default:
	        break;
	    }
	 }
	break;
#endif     
     case SSL_HANDSHAKE:
        if (dir == S2C && ((char *) pdata + 6 <= (char *) plast) &&
	    ssl_server_check(pdata) )
	  {
	    ptp->con_type |= SSL_PROTOCOL;
	    ptp->con_type &= ~OBF_PROTOCOL;
	    ptp->con_type &= ~MSE_PROTOCOL;
	    ptp->state = IGNORE_FURTHER_PACKETS;
	  }
         else
	  {
            if (ptp->packets > MAX_SSL_HANDSHAKE_PACKETS )
	     { 
	       /* Reset SSL State */
	       ptp->state = UNKNOWN_TYPE;
	     }
	  }  
        break;

     case SSH_SERVER:
        if (dir == C2S && ((char *) pdata + 7 <= (char *) plast))
	 {
	   switch (*((u_int32_t *) pdata))
	    {
	      case SSH_HEADER:
	        if (ssh_header_check(pdata))
		 {
	           ptp->con_type |= SSH_PROTOCOL;
	           ptp->con_type &= ~OBF_PROTOCOL;
	           ptp->con_type &= ~MSE_PROTOCOL;
	           ptp->state = IGNORE_FURTHER_PACKETS;
		 }
	        break;
	      default:
	        break;
	    }
	   if (ptp->packets > MAX_HTTP_COMMAND_PACKETS)
	     ptp->state = IGNORE_FURTHER_PACKETS;
	 }
        break;

     default:
	break;
   }

  if (ptp->packets > MAX_PACKETS_CON)
     ptp->state = IGNORE_FURTHER_PACKETS;

  return; 
}

void
make_tcpL7_conn_stats (void *thisflow, int tproto)
{
   int type;
   tcp_pair * ptp = (tcp_pair *)thisflow;

   type = map_flow_type(ptp);
   
        switch ((in_out_loc(ptp->internal_src, ptp->internal_dst, C2S)))
	{
	case OUT_FLOW:
	  add_histo (L7_TCP_num_out, type);
	  if (type==L7_FLOW_HTTP)
	   {
 	     add_histo (L7_HTTP_num_out, ptp->http_data);
 	     add_histo (L7_WEB_num_out, map_http_to_web(ptp->http_data));
	   }
	  break;
	case IN_FLOW:
	  add_histo (L7_TCP_num_in, type);
	  if (type==L7_FLOW_HTTP)
	   {
 	     add_histo (L7_HTTP_num_in, ptp->http_data);
 	     add_histo (L7_WEB_num_in, map_http_to_web(ptp->http_data));
	   }
	  break;
	case LOC_FLOW:
	  add_histo (L7_TCP_num_loc, type);
	  if (type==L7_FLOW_HTTP)
	   {
 	     add_histo (L7_HTTP_num_loc, ptp->http_data);
 	     add_histo (L7_WEB_num_loc, map_http_to_web(ptp->http_data));
	   }
	  break;
	}
return;
}


/* 
   Map the classification to fit the HISTO labels
   from the bitmask of the tcpL7 classifier and the eventual
   p2p and skype detailed classifier map them to the histo definition
   (from tstat.h)
*/

int map_flow_type(tcp_pair *thisflow)
{
   int type=L7_FLOW_UNKNOWN;


   /* MSE (lowest priority) */
   if(thisflow->con_type & MSE_PROTOCOL)
   {
      type = L7_FLOW_MSE;
   }

   /* OBF (penultimate lowest priority) */
   if(thisflow->con_type & OBF_PROTOCOL)
   {
      type = L7_FLOW_OBF;
   }

   /* RTMP  */
   if(thisflow->con_type & RTMP_PROTOCOL)
   {
     if (thisflow->c2s.msg_count>0 && thisflow->s2c.msg_count>0)
       {
         if (thisflow->c2s.msg_size[0]==1537 &&
             ( thisflow->s2c.msg_size[0]==3073 || 
	       thisflow->s2c.msg_size[0]==1537) ) 
           type = L7_FLOW_RTMP;
         else
          /* If con_type was set to RTMP_PROTOCOL, I already 
	     have seen the first 2 messages and if the size are wrong, the
	     flow will never be RTMP
	  */
            thisflow->con_type &= ~RTMP_PROTOCOL;
       }
   }

   /* HTTP */
   if(thisflow->con_type & HTTP_PROTOCOL)
   {
      type = L7_FLOW_HTTP;
   }

   /* RTSP */
   if(thisflow->con_type & RTSP_PROTOCOL)
   {
      type = L7_FLOW_RTSP;
   }

   /* RTP */
   if(thisflow->con_type & RTP_PROTOCOL)
   {
      type = L7_FLOW_RTP;
   }

   /* ICY */
   if(thisflow->con_type & ICY_PROTOCOL)
   {
      type = L7_FLOW_ICY;
   }

   /* RTCP */
   if(thisflow->con_type & RTCP_PROTOCOL)
   {
      type = L7_FLOW_RTCP;
   }

   /* MSN */
   if(thisflow->con_type & MSN_PROTOCOL)
   {
      type = L7_FLOW_MSN;
   }

   /* YMSG */
   if(thisflow->con_type & YMSG_PROTOCOL)
   {
      type = L7_FLOW_YMSG;
   }

   /* XMPP */
   if(thisflow->con_type & XMPP_PROTOCOL)
   {
      type = L7_FLOW_XMPP;
   }

   /* SMTP */
   if(thisflow->con_type & SMTP_PROTOCOL)
   {
      type = L7_FLOW_SMTP;
   }

   /* POP3 */
   if(thisflow->con_type & POP3_PROTOCOL)
   {
      type = L7_FLOW_POP3;
   }

   /* IMAP */
   if(thisflow->con_type & IMAP_PROTOCOL)
   {
      type = L7_FLOW_IMAP;
   }

   /* SSL */
   if(thisflow->con_type & SSL_PROTOCOL)
   {
      type = L7_FLOW_SSL;
   }

   /* SSH */
   if(thisflow->con_type & SSH_PROTOCOL)
   {
      type = L7_FLOW_SSH;
   }

   /* P2P */
   if(thisflow->con_type & P2P_PROTOCOL)
   {
      type = TCP_p2p_to_L7type(thisflow);
   }

   /* SKYPE */
   if(thisflow->con_type & SKYPE_PROTOCOL)
   {
      type = L7_FLOW_SKYPE_TCP;
   }
   return type;
}

void
make_tcpL7_rate_stats (tcp_pair *thisflow, int len)
{
   int type;
   type = map_flow_type(thisflow);

   /* skype bitrate is managed by skype.c since classification is done 
      at flow end */
      
   if (type==L7_FLOW_SKYPE_E2E ||
       type==L7_FLOW_SKYPE_E2O ||
       type==L7_FLOW_SKYPE_TCP)
       return;
       
   if (internal_src && !internal_dst)
    {
       L7_bitrate.out[type] += len;
      if (type==L7_FLOW_HTTP)
       {
	 HTTP_bitrate.out[thisflow->http_data] += len;
	 WEB_bitrate.out[map_http_to_web(thisflow->http_data)] += len;
       }
    }
  else if (!internal_src && internal_dst)
    {
       L7_bitrate.in[type] += len;
      if (type==L7_FLOW_HTTP)
       {
	 HTTP_bitrate.in[thisflow->http_data] += len;
	 WEB_bitrate.in[map_http_to_web(thisflow->http_data)] += len;
       }
    }
  else if (internal_src && internal_dst)
    {
       L7_bitrate.loc[type] += len;
      if (type==L7_FLOW_HTTP)
       {
	 HTTP_bitrate.loc[thisflow->http_data] += len;
	 WEB_bitrate.loc[map_http_to_web(thisflow->http_data)] += len;
       }
    }

  return;
}

void
make_udpL7_rate_stats (ucb * thisflow, int len)
{
   int type;
   type = UDP_p2p_to_L7type(thisflow);

   /* skype bitrate is managed by skype.c since classification is done 
      at flow end */
   if (type==L7_FLOW_SKYPE_E2E ||
       type==L7_FLOW_SKYPE_E2O ||
       type==L7_FLOW_SKYPE_TCP) /* SKYPE_SIG is not counted in skype.c */
       return;
      
   if (internal_src && !internal_dst)
    {
       L7_udp_bitrate.out[type] += len;
    }
  else if (!internal_src && internal_dst)
    {
       L7_udp_bitrate.in[type] += len;
    }
  else if (internal_src && internal_dst)
    {
       L7_udp_bitrate.loc[type] += len;
    }

  return;
}

