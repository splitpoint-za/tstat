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

enum http_content classify_flickr(char *base, int available_data)
{
  char c;
  int i;
  int status1,status2;

  status1=0;
  status2=0;
  i = 3;
  while (i<6)
   {
     c = *(char *)(base + i );
     if (c=='/') 
      {
	status2=1;
	break;
      }
     if (!isdigit(c)) 
      {
	status1=1;
	break;
      }
     i++;
   }
  if (status1==0 && status2==1)
   {
     int digit_count = 0;
     status1=0;
     status2=0;
     i++;
     while (i < 20)
      {
	c = *(char *)(base + i );
	if (c=='_') 
	 {
	   status2=1;
	   break;
	 }
	if (!isdigit(c)) 
	 {
	   status1=1;
	   break;
	 }
        digit_count++;
	i++;
      }
     if (status1==0 && status2==1 && digit_count>8)
      {
	status1=0;
	i++;
	digit_count = 0;
        while (digit_count<10 && i < available_data)
	 {
	   c = *(char *)(base + i );
	   if (!isxdigit(c)) 
	    {
	      status1=1;
	      break;
	    }
	   i++;
	   digit_count++;
	 }
	if (status1==0 && digit_count==10)
	  return HTTP_FLICKR;
      }
   }
  return HTTP_GET;
}

enum http_content classify_social(char *base, int available_data)
{
  char c;
  int i;
  int status1;

  status1=0;
  i = 3;
  while (i<16)
   {
     c = *(char *)(base + i );
     if (c!='/' && !isdigit(c)) 
      {
	status1=1;
	break;
      }
     i++;
   }
  if (status1==1)
   {
     if ((memcmp(base + i,"thumb/",
     	    ((available_data - i ) < 6 ? available_data - i : 6)) == 0)
     	 || (memcmp(base + i,"other/",
     	    ((available_data - i ) < 6 ? available_data - i : 6)) == 0)
     	 || (memcmp(base + i,"main/",
     	    ((available_data - i ) < 5 ? available_data - i : 5)) == 0)
     	)
     return HTTP_SOCIAL;
   }

  return HTTP_GET;
}


enum http_content classify_http_get(void *pdata,int data_length)
{
  char *base = (char *)pdata+4;
  int available_data = data_length - 4 ;

  char c;
  int i;
  int status1,status2;
  
  if (available_data < 1)
    return HTTP_GET;

  if (*base != 0x2f)
    return HTTP_GET;

  switch (*(base+1))
   {
     case 'A':
       if (memcmp(base, "/ADSAdClient",
               ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_ADV;
       break;
     case 'a':
       if (memcmp(base, "/ads3/flyers/",
        	      ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/album.php?",
        	      ( available_data < 11 ? available_data : 11)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/apps/application.php",
        	     ( available_data < 21 ? available_data : 21)) == 0)
          return HTTP_FACEBOOK;
       else if (memcmp(base, "/adj/",
        	     ( available_data < 5 ? available_data : 5)) == 0)
          return HTTP_ADV;
       else if (memcmp(base, "/ajax_boxes/last_photos",
        	     ( available_data < 23 ? available_data : 23)) == 0)
          return HTTP_SOCIAL;
       else if ( available_data > 10 && (memcmp(base, "/ajax/",6) == 0) )
         {
	   switch (*(base+6))
	    {
	      case 'a':
                if (memcmp(base + 6, "apps/usage_update.php",
        	      ((available_data - 6) < 21 ? available_data - 6 : 21)) == 0)
                  return HTTP_FACEBOOK;
	        break;

	      case 'b':
                if (memcmp(base + 6, "browse_history.php",
        	      ((available_data - 6) < 18 ? available_data - 6 : 18)) == 0)
                  return HTTP_FACEBOOK;
	        break;

	      case 'c':
           	if (memcmp(base + 6, "chat/",
        		   ((available_data - 6) < 5 ? available_data - 6 : 5)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "composer/",
        		   ((available_data - 6) < 9 ? available_data - 6 : 9)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "ct.php?",
        		   ((available_data - 6) < 7 ? available_data - 6 : 7)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 'f':
           	if (memcmp(base + 6, "f2.php?",
        		   ((available_data - 6) < 7 ? available_data - 6 : 7)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "feed/",
        		   ((available_data - 6) < 5 ? available_data - 6 : 5)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "f.php?",
        		   ((available_data - 6) < 6 ? available_data - 6 : 6)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 'i':
	      	if (memcmp (base + 6, "intent.php",
	      		   ((available_data - 6) < 10 ? available_data - 6 : 10)) == 0)
	      	  return HTTP_FACEBOOK;
	        break;

	      case 'l':
           	if (memcmp(base + 6, "like/participants.php",
        		   ((available_data - 6) < 21 ? available_data - 6 : 21)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 'n':
           	if (memcmp(base + 6, "nectar.php",
        		   ((available_data - 6) < 10 ? available_data - 6 : 10)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "notes_upload_ajax.php",
        		   ((available_data - 6) < 21 ? available_data - 6 : 21)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 'p':
           	if (memcmp(base + 6, "presence/",
        		   ((available_data - 6) < 9 ? available_data - 6 : 9)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "profile/",
        		   ((available_data - 6) < 8 ? available_data - 6 : 8)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 'r':
           	if (memcmp(base + 6, "recent_pics.php",
        		   ((available_data - 6) < 15 ? available_data - 6 : 15)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 's':
           	if (memcmp(base + 6, "share_dialog.php",
        		   ((available_data - 6) < 16 ? available_data - 6 : 16)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "stream/profile.php",
        		   ((available_data - 6) < 18 ? available_data - 6 : 18)) == 0)
           	  return HTTP_FACEBOOK;
	   	     break;

	      case 't':
                if (memcmp(base + 6, "typeahead_",
                	   ((available_data - 6) < 10 ? available_data - 6 : 10)) == 0)
                  return HTTP_FACEBOOK;
	        break;

	      case 'v':
           	if (memcmp(base + 6, "video/",
        		   ((available_data - 6) < 6 ? available_data - 6 : 6)) == 0)
           	  return HTTP_FACEBOOK;
	        break;
	      default:
	        break;
	    }
         }
       else if ( available_data > 19 && (memcmp(base, "/albums_list/",13) == 0) )
         {
	   if ( isdigit(*(char *)(base + 13 )) &&
	        isdigit(*(char *)(base + 14 )) &&
	        isdigit(*(char *)(base + 15 )) &&
	        isdigit(*(char *)(base + 16 )) &&
	        isdigit(*(char *)(base + 17 )) &&
	        isdigit(*(char *)(base + 18 ))
              )
             return HTTP_SOCIAL;
	 }
       break;

     case 'b':
       if (memcmp(base, "/blog/ajax_",
        	     ( available_data < 11 ? available_data : 11)) == 0)
          return HTTP_SOCIAL;
       break;

     case 'c':
      /* */
       if (memcmp(base, "/cgi-bin/m?ci=",
        	       ( available_data < 14 ? available_data : 14)) == 0)
         return HTTP_ADV;
       else if (memcmp(base, "/cgi-bin/m?rnd=",
        	       ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_ADV;
       else if (memcmp(base, "/cgi-bin/count?cid=",
        	       ( available_data < 19 ? available_data : 19)) == 0)
         return HTTP_ADV;
       else if (memcmp(base, "/cgi-bin/count?url=",
        	       ( available_data < 19 ? available_data : 19)) == 0)
         return HTTP_ADV;
       else if (memcmp(base, "/cgi-bin/count?rnd=",
        	       ( available_data < 19 ? available_data : 19)) == 0)
         return HTTP_ADV;
       else if (memcmp(base, "/cbk?output=",
               ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/connect.php/",
               ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/connect/connect.php",
               ( available_data < 20 ? available_data : 20)) == 0)
         return HTTP_FACEBOOK;
       else if (available_data > 30 && memcmp(base, "/common/image/",14)==0 )
         {
	   if ( 
                memcmp(base + 14, "albums/",7)==0 || 
                memcmp(base + 14, "card/",5)==0 || 
	        memcmp(base + 14, "clearbox/",9)==0 || 
                memcmp(base + 14, "emoticons/",10)==0 || 
                memcmp(base + 14, "facelift/",9)==0 || 
                memcmp(base + 14, "flash/",6)==0 || 
                memcmp(base + 14, "icon_",5)==0 || 
                memcmp(base + 14, "logo_",5)==0 ||
                memcmp(base + 14, "share/",6)==0  
              )
           return HTTP_SOCIAL;
	 }
       /* */
       break;

     case 'd':
       if ( available_data > 46 && (memcmp(base, "/dl/",4) == 0) &&
                (*(char *)(base + 36 ))=='/' &&
		(*(char *)(base + 45 ))=='/' )
         /* matching '/dl/[a-zA-Z0-9]{32}/[a-zA-Z0-9]{8}/" */
	 /* mostly video downloads, seldom file downloads */
          return HTTP_FLASHVIDEO;
       break;

     case 'e':
       if (memcmp(base, "/editapps.php",
        	     ( available_data < 13 ? available_data : 13)) == 0)
          return HTTP_FACEBOOK;
       else if (memcmp(base, "/editnote.php",
        	     ( available_data < 13 ? available_data : 13)) == 0)
          return HTTP_FACEBOOK;
       else if (memcmp(base, "/extern/login_status.php",
        	     ( available_data < 24 ? available_data : 24)) == 0)
          return HTTP_FACEBOOK;
       else if (memcmp(base, "/e4/flv/",
        	     ( available_data < 8 ? available_data : 8)) == 0)
          return HTTP_FLASHVIDEO;
       break;

     case 'f':
       if (memcmp(base, "/friends/",
               ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_FACEBOOK;
       else if ( available_data > 27 && (memcmp(base, "/friends_online_list/",21) == 0) )
         {
	   if ( isdigit(*(char *)(base + 21 )) &&
	        isdigit(*(char *)(base + 22 )) &&
	        isdigit(*(char *)(base + 23 )) &&
	        isdigit(*(char *)(base + 24 )) &&
	        isdigit(*(char *)(base + 25 )) &&
	        isdigit(*(char *)(base + 26 ))
              )
             return HTTP_SOCIAL;
	 }
       else if ( available_data > 20 && (memcmp(base, "/friends_list/",14) == 0) )
         {
	   if ( isdigit(*(char *)(base + 14 )) &&
	        isdigit(*(char *)(base + 15 )) &&
	        isdigit(*(char *)(base + 16 )) &&
	        isdigit(*(char *)(base + 17 )) &&
	        isdigit(*(char *)(base + 18 )) &&
	        isdigit(*(char *)(base + 19 ))
              )
             return HTTP_SOCIAL;
	 }
       else if ( available_data > 38 && (memcmp(base, "/flv/",5) == 0) )
         {
	   if ( (*(char *)(base + 37 ))=='/' )
             return HTTP_FLASHVIDEO;
	 }
       else if (available_data>15 && (memcmp(base, "/files/",7) ==0) )
        {
     	  status1=0;
     	  status2=0;
     	  i = 7;
     	  while (i<available_data)
     	   {
     	     c = *(char *)(base + i );
	     if (c=='/')
	        break;
             if (!isdigit(c)) status1=1;
     	     if (!isxdigit(c)) 
     	      {
     		status2=1;
     		break;
     	      }
     	     i++;
     	   }
     	  if (i>15 && status2==0 && status1==1)
            return HTTP_MEGAUPLOAD;	     

          status1=0;
          for (i=0;i<8;i++)		     
           {				     
             c = *(char *)(base + 7 + i );
             if (!isdigit(c)) status1=1;
           }				     
          if (status1==0)		     
            return HTTP_RAPIDSHARE;	     
        }
       break;

     case 'g':
       if (memcmp(base, "/generate_204?ip=",
                  ( available_data < 17 ? available_data : 17)) == 0)
          return HTTP_YOUTUBE_VIDEO;
       else if (memcmp (base, "/generate_204?id=",
                  ( available_data < 17 ? available_data : 17)) == 0)
          return HTTP_GOOGLEVIDEO;
       else if (memcmp(base, "/group.php?",
               ( available_data < 11 ? available_data : 11)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/groups.php?",
               ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_FACEBOOK;
       else if ( available_data > 23 && (memcmp(base, "/get/",5) == 0) &&
                (*(char *)(base + 13 ))=='/')
         {
          status1=0;
          for (i=5;i<13;i++)		     
           {				     
             c = *(char *)(base + i );
             if (!isalnum(c)) status1=1;
           }				     
          if (status1==0)
	   {
	     if ((*(char *)(base + 22 ))=='/')
               return HTTP_HOTFILE;
	     else
               return HTTP_STORAGE;
	   }
	 }
       else if ( available_data >21 && memcmp(base, "/gadgets/",9)==0 )
         {
	   if (
                memcmp(base + 9 , "concat?", 7)==0 || 
                memcmp(base + 9 , "ifr?", 4)==0 || 
                memcmp(base + 9 , "js/rpc?", 7)==0 || 
                memcmp(base + 9 , "makeRequest", 11)==0 || 
                memcmp(base + 9 , "proxy?", 6)==0  
	      )
            return HTTP_SOCIAL;
	 }
       else if ( available_data > 25 && (memcmp(base, "/gallery/",9) == 0) )
         {
     	  status1=0;
     	  status2=0;
     	  i = 9;
     	  while (i<24)
     	   {
     	     c = *(char *)(base + i );
	     if (c=='/')
               status1=1;
     	     if (!isdigit(c) && c!='/') 
     	      {
     		break;
     	      }
	     status2 = isdigit(c) ? 1 : 0 ; 
     	     i++;
     	   }
     	  if ( c==' ' && status2==1 && status1==1)
            return HTTP_SOCIAL;
	 }
       break;

     case 'h':
       if (memcmp(base, "/home.php?ref=",
               ( available_data < 14 ? available_data : 14)) == 0)
         return HTTP_FACEBOOK;
       break;

     case 'i':
       if (available_data > 31 && (memcmp(base, "/i/",3) == 0) )
        {
	  if (memcmp(base + 26, "1.jpg",5) == 0)
           return HTTP_YOUTUBE_SITE;
	}
       else if (memcmp(base, "/iframe/10?r=",
               ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK;
       break;

     case 'j':
       if (memcmp(base, "/js/api_lib/v0.4/",
               ( available_data < 17 ? available_data : 17)) == 0)
         return HTTP_FACEBOOK;
       break;

     case 'k':
       if (memcmp(base, "/kh/v=",
               ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_GMAPS;
       break;

     case 'm':
       if (memcmp(base, "/maps/gen_",
               ( available_data < 10 ? available_data : 10)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/maps/vp?",
               ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/maps/l?",
               ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/maps/trends?",
               ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/mapslt?lyrs=",
               ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/mapslt/ft?lyrs=",
               ( available_data < 16 ? available_data : 16)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/might_know/listJSON/",
               ( available_data < 21 ? available_data : 21)) == 0)
         return HTTP_SOCIAL;
       break;
       
     case 'M':
       if (memcmp(base, "/Movies/nexos/MPEG2/",
               ( available_data < 20 ? available_data : 20)) == 0)
         return HTTP_VOD;
       break;

     case 'n':
       if (memcmp(base, "/notifications.php",
               ( available_data < 18 ? available_data : 18)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/new_messages_json/top/",
               ( available_data < 23 ? available_data : 23)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/new_messages_get_mail/",
               ( available_data < 23 ? available_data : 23)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/nktalk/",
        	      ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'o':
       if ( available_data > 19 && (memcmp(base, "/online_list/",13) == 0) )
         {
	   if ( isdigit(*(char *)(base + 13 )) &&
	        isdigit(*(char *)(base + 14 )) &&
	        isdigit(*(char *)(base + 15 )) &&
	        isdigit(*(char *)(base + 16 )) &&
	        isdigit(*(char *)(base + 17 )) &&
	        isdigit(*(char *)(base + 18 ))
              )
             return HTTP_SOCIAL;
	 }
       else if ( available_data > 14 && (memcmp(base, "/object",7) == 0) )
     	{
     	  status1=0;
     	  i = 7;
     	  while (i<14)
     	   {
     	     c = *(char *)(base + i );
     	     if (!isdigit(c) && c!='/') 
     	      {
     		status1=1;
     		break;
     	      }
     	     i++;
     	   }
     	  if (status1==0)
     	    return HTTP_FACEBOOK;
     	}		 
       break;

     case 'p':
      if (memcmp(base, "/pagead/",
        	    ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_ADV;
      else if (memcmp(base, "/photo.php?pid=",
        	    ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_FACEBOOK;
      else if (memcmp(base, "/photo_search.php?",
        	    ( available_data < 18 ? available_data : 18)) == 0)
         return HTTP_FACEBOOK;
      else if (memcmp(base, "/posted.php?",
        	    ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/profile.php?id=",
        	       ( available_data < 16 ? available_data : 16)) == 0)
         return HTTP_FACEBOOK;
       else if ( available_data >22 && memcmp(base, "/pages/",7)==0 )
         {
	   if (
                memcmp(base + 7 , "activity/", 9)==0 || 
                memcmp(base + 7 , "application/", 12)==0 || 
                memcmp(base + 7 , "community/", 10)==0 || 
                memcmp(base + 7 , "image/", 6)==0 || 
                memcmp(base + 7 , "listing/", 8)==0 || 
                memcmp(base + 7 , "main/", 5)==0 || 
                memcmp(base + 7 , "message/", 8)==0 || 
                memcmp(base + 7 , "micrologin/", 11)==0 || 
                memcmp(base + 7 , "misc/", 5)==0 || 
                memcmp(base + 7 , "share/", 6)==0 || 
                memcmp(base + 7 , "timeline/", 9)==0 || 
                memcmp(base + 7 , "user/", 5)==0 
	      )
            return HTTP_SOCIAL;
	 }
       else if ( available_data >16 && memcmp(base, "/poczta/",8)==0 )
         {
	   if (
		isdigit( *(char *)(base + 8 )) ||
                memcmp(base + 8 , "choose", 6)==0 ||
                memcmp(base + 8 , "compose", 7)==0 || 
                memcmp(base + 8 , "inbox", 5)==0 || 
                memcmp(base + 8 , "outbox", 6)==0 || 
                memcmp(base + 8 , "null", 4)==0 || 
                memcmp(base + 8 , "trash", 5)==0
	      )
            return HTTP_SOCIAL;
	 }
       else if (available_data > 14 && (memcmp(base, "/profile",8) == 0))
        {
          status1=0;
          i = 8;
          while (i<14)
           {
             c = *(char *)(base + i );
             if (!isdigit(c) && c!='/') 
              {
        	status1=1;
        	break;
              }
             i++;
           }
          if (status1==0)
            return HTTP_FACEBOOK;
        }		 
       else if ( available_data >26 && memcmp(base, "/profile/",9)==0 )
         {
	   if (
                memcmp(base + 9 , "edit ", 5)==0 ||
                memcmp(base + 9 , "advanced", 8)==0 || 
                memcmp(base + 9 , "black_list", 10)==0 || 
                memcmp(base + 9 , "card", 4)==0 || 
                memcmp(base + 9 , "gallery", 7)==0 || 
                memcmp(base + 9 , "null", 4)==0 || 
                memcmp(base + 9 , "preference", 10)==0 || 
                memcmp(base + 9 , "privacy_settings", 16)==0 || 
                memcmp(base + 9 , "ratings", 7)==0 || 
                memcmp(base + 9 , "sledzik", 7)==0
	      )
            return HTTP_SOCIAL;
	 }
       break;

     case 'R':
       if ( available_data > 23 && (memcmp(base, "/RealMedia/ads/",15) == 0) )
        {
	   switch (*(base+15))
	    {
              case 'a':
                if (memcmp(base + 15, "adstream",
                      ((available_data - 15) < 8 ? available_data - 15 : 8)) == 0)
                  return HTTP_ADV;
	        break;
              case 'C':
                if (memcmp(base + 15, "Creatives",
                      ((available_data - 15) < 9 ? available_data - 15 : 9)) == 0)
                  return HTTP_ADV;
	        break;
              case 'c':
                if (memcmp(base + 15, "cap.cgi",
                      ((available_data - 15) < 7 ? available_data - 15 : 7)) == 0)
                  return HTTP_ADV;
                else if (memcmp(base + 15, "click_lx.ads",
                      ((available_data - 15) < 12 ? available_data - 15 : 12)) == 0)
                  return HTTP_ADV;
	        break;
	      default:
	        break;
	    }
	}
       break;

     case 'r':
       if (memcmp(base, "/reqs.php?",
               ( available_data < 10 ? available_data : 10)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/restserver.php",
        	      ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/rsrc.php/",
               ( available_data < 10 ? available_data : 10)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/rest/person/",
        	    ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_SOCIAL;
       break;

     case 's':
       if (memcmp(base, "/safe_image.php?d=",
        	       ( available_data < 18 ? available_data : 18)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/s.php?",
        	    ( available_data < 7 ? available_data : 7)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/static/v0.4/",
        	    ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/search/pages/",
        	    ( available_data < 14 ? available_data : 14)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/school/",
        	    ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/sledzik/",
        	    ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/storage/gifts/",
        	    ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/storage/smileys/",
        	    ( available_data < 17 ? available_data : 17)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/style/",
        	    ( available_data < 7 ? available_data : 7)) == 0)
        {
	  status1=0;
	  i = 7;
          while (i<available_data-5)
           {
             c = *(char *)(base + i );
             if (c==':') 
              {
        	status1=1;
        	break;
              }
             i++;
           }
          if (status1==1)
           {
	     if ( isxdigit(*(char *)(base + i + 1)) &&
	          isxdigit(*(char *)(base + i + 2)) &&
	          isxdigit(*(char *)(base + i + 3)) &&
	          isxdigit(*(char *)(base + i + 4)) &&
		  (*(char *)(base + i + 5)) == ' '
		 )
             return HTTP_SOCIAL;
	   }
        }
       else if (memcmp(base, "/script/",
        	    ( available_data < 8 ? available_data : 8)) == 0)
        {
	  status1=0;
	  i = 8;
          while (i<available_data-5)
           {
             c = *(char *)(base + i );
             if (c==':') 
              {
        	status1=1;
        	break;
              }
             i++;
           }
          if (status1==1)
           {
	     if ( isxdigit(*(char *)(base + i + 1)) &&
	          isxdigit(*(char *)(base + i + 2)) &&
	          isxdigit(*(char *)(base + i + 3)) &&
	          isxdigit(*(char *)(base + i + 4)) &&
		  (*(char *)(base + i + 5)) == ' '
		 )
             return HTTP_SOCIAL;
	   }
        }
       break;

     case 'u':
       if (available_data > 33 && (memcmp(base, "/u/",3) == 0) )
        {
	  if (memcmp(base + 26, "watch_",6) == 0)
           return HTTP_YOUTUBE_SITE;
	}
       break;

     case 'v':
       if (memcmp(base, "/videoplayback?ip=",
                  ( available_data < 18 ? available_data : 18)) == 0)
          return HTTP_YOUTUBE_VIDEO;
       else if (memcmp (base, "/videoplayback?id=",
                  ( available_data < 18 ? available_data : 18)) == 0)
          return HTTP_GOOGLEVIDEO;
       else if (memcmp(base, "/vimeo/v/",
                  ( available_data < 9 ? available_data : 9)) == 0)
          return HTTP_VIMEO;
       else if (memcmp(base, "/videos/flv/",
                  ( available_data < 12 ? available_data : 12)) == 0)
          return HTTP_FLASHVIDEO;
       else if (memcmp(base, "/vt/v=",
               ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/vt/lyrs=",
               ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_GMAPS;
       else if (available_data > 29 && (memcmp(base, "/vi/",4) == 0) )
        {
	  if (memcmp(base + 16, "default.jpg",11) == 0 ||
              memcmp(base + 16, "hqdefault.jpg",13) == 0 ||
              memcmp(base + 16, "0.jpg",5) == 0 ||
              memcmp(base + 16, "1.jpg",5) == 0 ||
              memcmp(base + 16, "2.jpg",5) == 0 ||
              memcmp(base + 16, "3.jpg",5) == 0 
	      )
           return HTTP_YOUTUBE_SITE;
	}
       else if (available_data > 15 && (memcmp(base, "/v/",3) == 0) )
        {
          c = *(char *)(base + 14);
	  if (c==' ' || c== '&')
	     return HTTP_YOUTUBE_SITE;
	}
       else if (available_data > 12 && (memcmp(base, "/v",2) == 0) )
   	{
          status1=0;
   	  i = 2;
   	  while (i<12)
   	   {
   	     c = *(char *)(base + i );
    	     if (!isdigit(c) && c!='/')
   	      {
   		status1=1;
   		break;
   	      }
   	     i++;
   	   }
   	  if (status1==0)
   	    return HTTP_FACEBOOK;
   	}		 
       break;

     case 'w':
       if (memcmp(base, "/w/index.php?title=",
        	      ( available_data < 19 ? available_data : 19)) == 0)
         return HTTP_WIKI;
       else if (memcmp(base, "/wiki/",
        	       ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_WIKI;
       else if (memcmp(base, "/wikipedia/",
        	       ( available_data < 11 ? available_data : 11)) == 0)
         return HTTP_WIKI;
       else if (memcmp(base, "/www/app_full_proxy.php?app=",
        	       ( available_data < 28 ? available_data : 28)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/watch?v=",
        	       ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_YOUTUBE_SITE;
       else if (memcmp(base, "/watch#!v=",
        	       ( available_data < 10 ? available_data : 10)) == 0)
         return HTTP_YOUTUBE_SITE;
       else if (memcmp(base, "/watched_events ",
        	       ( available_data < 16 ? available_data : 16)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'x':
       if (available_data>16 && (memcmp(base, "/x/", 3) == 0))
        {
          status1=0;
          status2=0;
  	  i = 3;
  	  
	  while (i<14)
  	   {
  	     c = *(char *)(base + i );
  	     if (c=='/') 
  	      {
  	     	status2=1;
  	     	break;
  	      }
  	     if (!isdigit(c)) 
  	      {
  	     	status1=1;
  	     	break;
  	      }
  	     i++;
  	   }
  	 if (status1==0 && status2==1)
  	   {
  	     if ((memcmp(base + i,"/false/p_",
     	     	    ((available_data - i ) < 9 ? available_data - i : 9)) == 0)
  	     	 || (memcmp(base + i,"/true/p_",
     	     	    ((available_data - i ) < 8 ? available_data - i : 8)) == 0)
  	     	)
  	     return HTTP_FACEBOOK;
  	   }
     	 }
       break;

     case 'y':
       if ( available_data > 10 && (memcmp(base, "/yt/",4) == 0) )
        {
	   switch (*(base+4))
	    {
              case 'c':
                if (memcmp(base + 4, "cssbin/",
                      ((available_data - 4) < 7 ? available_data - 4 : 7)) == 0)
                  return HTTP_YOUTUBE_SITE;
	        break;
              case 'f':
                if (memcmp(base + 4, "favicon",
                      ((available_data - 4) < 7 ? available_data - 4 : 7)) == 0)
                  return HTTP_YOUTUBE_SITE;
	        break;
              case 'i':
                if (memcmp(base + 4, "img/",
                      ((available_data - 4) < 4 ? available_data - 4 : 4)) == 0)
                  return HTTP_YOUTUBE_SITE;
	        break;
              case 'j':
                if (memcmp(base + 4, "js/",
                      ((available_data - 4) < 3 ? available_data - 4 : 3)) == 0)
                  return HTTP_YOUTUBE_SITE;
                else if (memcmp(base + 4, "jsbin/",
                      ((available_data - 4) < 6 ? available_data - 4 : 6)) == 0)
                  return HTTP_YOUTUBE_SITE;
	        break;
              case 's':
                if (memcmp(base + 4, "swf/",
                      ((available_data - 4) < 4 ? available_data - 4 : 4)) == 0)
                  return HTTP_YOUTUBE_SITE;
	        break;
	      default:
	        break;
	    }
	}
       break;

     case '_':
       if (memcmp(base, "/_videos_t4vn",
        	      ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FLASHVIDEO;
       else if (memcmp(base, "/_thumbs/",
        	      ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_FLASHVIDEO;
       break;

     case '4':
       if (memcmp(base, "/467f9bca32b1989",
        	      ( available_data < 16 ? available_data : 16)) == 0)
         return HTTP_FLASHVIDEO;
	 /* no break here to fall back to the other rules for digits */
     case '0':
       if (available_data > 12 &&  memcmp(base+5, "/club/", 6)==0)
         return HTTP_SOCIAL;
       else if (available_data > 12 &&  memcmp(base+5, "/user/", 6)==0)
         return HTTP_SOCIAL;
       else if (available_data > 15 &&  memcmp(base+5, "/listing/", 9)==0)
         return HTTP_SOCIAL;
	 /* no break here to fall back to the other rules for digits */
     case '1':
     case '2':
     case '3':
     case '5':
     case '6':
     case '7':
     case '8':
     case '9':
       if (available_data>25)
        {
  	  c = *(char *)(base + 2 );
          if (!isdigit(c))
	    break;

          if (classify_flickr(base,available_data)==HTTP_FLICKR)
	    return HTTP_FLICKR;
	  else if (classify_social(base,available_data)==HTTP_SOCIAL)
	    return HTTP_SOCIAL;
	}
       break;
     
     default:
       break;
   }

  if ( available_data > 14 && 
           (memcmp(base + 6, "-ak-",4) == 0 ||
            memcmp(base + 7, "-ak-",4) == 0 ||
	    memcmp(base + 8, "-ak-",4) == 0))
    return HTTP_FACEBOOK;
  else if ( available_data > 36 &&
           *(char *)(base + 12) == 'g' &&
           *(char *)(base + 13) == '/' &&
           *(char *)(base + 25) == '/'
	  )
    {
      /* Possible Mediafire.com matching ' /[^/_]{11}g/[^/ ]{11}/'
         or better ' /[^/_]{11}g/[^/ ]{11}/[^/]+ ' */

      status1=0;
      status2=0;
      
      for (i=1;i<12;i++)
       {
         c = *(char *)(base + i );
	 if (c=='/' || c=='_')
	  {
	    status1=1;
	    break;
	  }
       }      

      if (status1==0) 
       {      
      	 for (i=14;i<25;i++)
      	  {
      	    c = *(char *)(base + i );
	    if (c=='/' || c==' ')
	     {
	       status2=1;
	       break;
	     }
      	  }	 
      
      	 if (status2==0)
	  {
      	    status1 = 0;
      	    status2 = 0;
      	    for (i=26; i< available_data; i++)
      	     {
      	       c = *(char *)(base + i );
      	       if (c=='/')
	    	{
	    	  status1=1;
	    	  break;
	    	}
	       if (c==' ')
	    	{
	    	  status2=1;
	    	  break;
	    	}
	     }
      	    if (status1==0 && (status2==1 || i==available_data))
      	     {
	       return HTTP_MEDIAFIRE;
	     }
	  }
       }
    }
        

  return HTTP_GET;

}

enum http_content classify_http_post(void *pdata,int data_length)
{
  char *base = (char *)pdata+5;
  int available_data = data_length - 5 ;

  char c;
  int i;
  int status1;
  
  if (available_data < 1)
    return HTTP_POST;

  if (*base != 0x2f)
    return HTTP_POST;

  switch (*(base+1))
   {
     case 'a':
       if (memcmp(base, "/ajax/presence/",
        	      ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/ajax/chat/",
        	      ( available_data < 11 ? available_data : 11)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/ajax/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/accept/",
        	      ( available_data < 8 ? available_data : 8)) == 0)
        {
          status1=0;
          for (i=8;i<13;i++)		     
           {				     
             c = *(char *)(base + i );
             if (!isdigit(c)) status1=1;
           }				     
          if (status1==0)		     
            return HTTP_SOCIAL;
        }
       break;

     case 'c':
       if (memcmp(base, "/close/",
        	      ( available_data < 7 ? available_data : 7)) == 0)
         return HTTP_RTMPT;
       else if (memcmp(base, "/current/flashservices/",
        	      ( available_data < 23 ? available_data : 23)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/cbk?output=",
               ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_GMAPS;
       break;

     case 'C':
       if (memcmp(base, "/CLOSE/",
        	      ( available_data < 7 ? available_data : 7)) == 0)
         return HTTP_RTMPT;
       break;

     case 'f':
       if (memcmp(base, "/fbml/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/flashservices/gateway.php",
        	      ( available_data < 26 ? available_data : 26)) == 0)
            /* Facebook Farmville (but sometimes also xvideos.com) */
         return HTTP_FACEBOOK;
       else if (available_data>15 && (memcmp(base, "/files/",7) ==0) )
        {
          status1=0;
          for (i=0;i<8;i++)		     
           {				     
             c = *(char *)(base + 7 + i );
             if (!isdigit(c)) status1=1;
           }				     
          if (status1==0)		     
            return HTTP_RAPIDSHARE;	     
        }
       break;

     case 'g':
       if (memcmp(base, "/gateway/gateway.dll?Action=",
        	      ( available_data < 28 ? available_data : 28)) == 0)
         return HTTP_MSN;
       else if (memcmp(base, "/gateway/gateway.dll?SessionID=",
        	      ( available_data < 31 ? available_data : 31)) == 0)
         return HTTP_MSN;
       else if (memcmp(base, "/gadgets/makeRequest ",
               ( available_data < 21 ? available_data : 21)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'h':
       if (memcmp(base, "/http-bind ",
        	      ( available_data < 11 ? available_data : 11)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'i':
       if (memcmp(base, "/idle/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       else if (memcmp(base, "/invite/",
        	      ( available_data < 8 ? available_data : 8)) == 0)
        {
          status1=0;
          for (i=8;i<13;i++)		     
           {				     
             c = *(char *)(base + i );
             if (!isdigit(c)) status1=1;
           }				     
          if (status1==0)		     
            return HTTP_SOCIAL;
        }
       break;
     case 'I':
       if (memcmp(base, "/IDLE/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       break;

     case 'm':
       if (memcmp(base, "/might_know/unwanted/",
        	      ( available_data < 21 ? available_data : 21)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'n':
       if (memcmp(base, "/nktalk/",
        	      ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'o':
       if (memcmp(base, "/open/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       break;
     case 'O':
       if (memcmp(base, "/OPEN/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       break;

     case 'p':
       if (memcmp(base, "/pins/friends ",
        	      ( available_data < 14 ? available_data : 14)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/pins/get ",
        	      ( available_data < 10 ? available_data : 10)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/poczta/",
        	      ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       else if ( available_data >26 && memcmp(base, "/profile/",9)==0 )
         {
	   if (
		isdigit( *(char *)(base + 9 )) ||
                memcmp(base + 9 , "privacy_settings", 16)==0 || 
                memcmp(base + 9 , "edit ", 5)==0 || 
                memcmp(base + 9 , "black_list", 10)==0 
	      )
            return HTTP_SOCIAL;
	 }
       else if ( available_data >22 && memcmp(base, "/pages/",7)==0 )
         {
	   if (
                memcmp(base + 7 , "activity/", 9)==0 || 
                memcmp(base + 7 , "application/", 12)==0 || 
                memcmp(base + 7 , "community/", 10)==0 || 
                memcmp(base + 7 , "image/", 6)==0 || 
                memcmp(base + 7 , "listing/", 8)==0 || 
                memcmp(base + 7 , "main/", 5)==0 || 
                memcmp(base + 7 , "message/", 8)==0 || 
                memcmp(base + 7 , "micrologin/", 11)==0 || 
                memcmp(base + 7 , "misc/", 5)==0 || 
                memcmp(base + 7 , "share/", 6)==0 || 
                memcmp(base + 7 , "timeline/", 9)==0 || 
                memcmp(base + 7 , "user/", 5)==0 
	      )
            return HTTP_SOCIAL;
	 }
       break;

     case 'r':
       if (memcmp(base, "/restserver.php",
        	      ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/reject/",
        	    ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/rendering_measurement",
        	    ( available_data < 22 ? available_data : 22)) == 0)
         return HTTP_SOCIAL;
       break;

     case 's':
       if (memcmp(base, "/send/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       else if (memcmp(base, "/social/rpc?st=",
        	      ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/sledzik/",
        	    ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/school/",
        	    ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       break;
     case 'S':
       if (memcmp(base, "/SEND/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       break;

     case 'u':
       if (memcmp(base, "/url_validator",
        	      ( available_data < 14 ? available_data : 14)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'w':
       if (memcmp(base, "/watched_events/",
        	      ( available_data < 16 ? available_data : 16)) == 0)
         return HTTP_SOCIAL;
       break;

     default:
       break;
   }

  return HTTP_POST;

}

enum web_category map_http_to_web(enum http_content http_type)
{
  switch(http_type)
   {
     case HTTP_GET:
       return WEB_GET;

     case HTTP_POST:
       return WEB_POST;

     case HTTP_MSN:
     case HTTP_RTMPT:
     case HTTP_FACEBOOK:
     case HTTP_SOCIAL:
       return WEB_SOCIAL;
       
     case HTTP_YOUTUBE_VIDEO:
       return WEB_YOUTUBE;

     case HTTP_GOOGLEVIDEO:
     case HTTP_VIMEO:
     case HTTP_VOD:
     case HTTP_FLASHVIDEO:
       return WEB_VIDEO;

     case HTTP_RAPIDSHARE:
     case HTTP_MEGAUPLOAD:
     case HTTP_MEDIAFIRE:
     case HTTP_HOTFILE:
     case HTTP_STORAGE:
       return WEB_STORAGE;

     case HTTP_WIKI:
     case HTTP_ADV:
     case HTTP_FLICKR:
     case HTTP_GMAPS:
     case HTTP_YOUTUBE_SITE:
       return WEB_OTHER;

     default:
       return WEB_OTHER;   
   }
  
}