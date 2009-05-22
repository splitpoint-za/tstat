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
 * For bug report and other information please visit Tstat site:
 * http://tstat.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/

#include <stdio.h>
#include "tstat.h"

extern Bool histo_engine;
extern Bool adx_engine;

struct adx **adx_index_first;
struct adx **adx_index_second;
struct adx **adx_index_current;

/*
 * Manages all the addresses hit count  
*/

long int tot_adx_hash_count, tot_adx_list_count, adx_search_hash_count,
  adx_search_list_count;


/* internal prototype */

/* real code */

void
alloc_adx ()
{
  adx_index_first =
    (struct adx **) MMmalloc (sizeof (struct adx *) * MAX_ADX_SLOTS,
			      "alloc_adx");
  adx_index_second =
    (struct adx **) MMmalloc (sizeof (struct adx *) * MAX_ADX_SLOTS,
			      "alloc_adx");
  adx_index_current = adx_index_first;
}

int
add_adx (struct in_addr *adx, int dest, int bytes)
{
  unsigned pos;
  struct adx *temp_adx, *ptr_adx, *prev_ptr_adx;
  unsigned long seed;

//  if (adx_engine == FALSE)
//    return 0;

  seed = (adx->s_addr & ADDR_MASK);
  adx_search_hash_count++;
  pos = (seed % MAX_ADX_SLOTS);

  if (adx_index_current[pos] == NULL)
    {
      tot_adx_hash_count++;
      adx_search_list_count++;
      /* Insert the first */
      temp_adx = (struct adx *) MMmalloc (sizeof (struct adx), "add_adx");
      temp_adx->next = NULL;
      temp_adx->ip.s_addr = seed;
      if (dest == SRC_ADX)
	{
	  temp_adx->src_hits = 1;
	  temp_adx->dst_hits = 0;
	  temp_adx->src_bytes = bytes;
	  temp_adx->dst_bytes = 0;
	}
      else
	{
	  temp_adx->src_hits = 0;
	  temp_adx->dst_hits = 1;
	  temp_adx->src_bytes = 0;
	  temp_adx->dst_bytes = bytes;
	}
      adx_index_current[pos] = temp_adx;
      return 1;
    }

  /* look for it in the list */
  ptr_adx = adx_index_current[pos];
  while (ptr_adx != NULL)
    {
      adx_search_list_count++;
      if (ptr_adx->ip.s_addr == seed || ptr_adx->ip.s_addr == 0L)
	{
	  ptr_adx->ip.s_addr = seed;
	  if (dest == SRC_ADX)
	   {
	    ptr_adx->src_hits++;
	    ptr_adx->src_bytes+=bytes;
	   }
	  else
           {
	    ptr_adx->dst_hits++;
	    ptr_adx->dst_bytes+=bytes;
	   }
	  return 1;
	}
      prev_ptr_adx = ptr_adx;
      ptr_adx = ptr_adx->next;
    }

  /* ... or put it in last position */
  tot_adx_list_count++;
  temp_adx = (struct adx *) MMmalloc (sizeof (struct adx), "add_adx");
  temp_adx->next = NULL;
  temp_adx->ip.s_addr = seed;
  if (dest == SRC_ADX)
    {
      temp_adx->src_hits = 1;
      temp_adx->dst_hits = 0;
      temp_adx->src_bytes = bytes;
      temp_adx->dst_bytes = 0;
    }
  else
    {
      temp_adx->src_hits = 0;
      temp_adx->dst_hits = 1;
      temp_adx->src_bytes = 0;
      temp_adx->dst_bytes = bytes;
    }
  prev_ptr_adx->next = temp_adx;
  return 1;
}

int
print_adx ()
{
  int i;
  struct adx *tmp_adx;
  struct stat fbuf;
  FILE *fp;
  char filename[200];
  struct adx **adx_index;
  adx_index = adx_index_frozen;

  if (histo_engine == FALSE || adx_engine == FALSE)
    return 1;

  /* check directory */
  if (stat (curr_data_dir, &fbuf) == -1)
    {
      fprintf (fp_stdout, "Creating output dir %s\n", curr_data_dir);
      mkdir (curr_data_dir, 0775);

    }


  /*print addresses */
  sprintf (filename, "%s/%s", curr_data_dir, "addresses");
  fp = fopen (filename, "w");

  if (fp == NULL)
    {
      fprintf (fp_stdout, "Could not open file %s\n", filename);
      return 0;
    }

  fprintf (fp, "#Number of packets per subnet (%d.%d.%d.%d NETMASK) \n",
	   ADDR_MASK & 0x000000ff,
	   (ADDR_MASK & 0x0000ff00) >> 8,
	   (ADDR_MASK & 0x00ff0000) >> 16, (ADDR_MASK & 0xff000000) >> 24);
  fprintf (fp, "#Subnet IP \tsrc_hits \tdst_hits \tsrc_bytes \tdst_bytes\n");
  for (i = 0; i < MAX_ADX_SLOTS; i++)
    {
      tmp_adx = adx_index[i];
      if (tmp_adx != NULL)
	{
	  if ((tmp_adx->src_hits != 0) || (tmp_adx->dst_hits != 0))
	    {
	      while ((tmp_adx != NULL)
		     && (tmp_adx->src_hits != 0 || tmp_adx->dst_hits != 0))
		{
		  fprintf (fp, "%s\t%ld\t%ld\t%ld\t%ld\n", inet_ntoa (tmp_adx->ip),
			   tmp_adx->src_hits, tmp_adx->dst_hits,
                           tmp_adx->src_bytes, tmp_adx->dst_bytes);
		  tmp_adx->src_hits = 0;
		  tmp_adx->dst_hits = 0;
		  tmp_adx->src_bytes = 0;
		  tmp_adx->dst_bytes = 0;
		  tmp_adx->ip.s_addr = 0L;
		  tmp_adx = tmp_adx->next;
		}
	    }
	}

    }
  fprintf (fp, "\n");
  fclose (fp);
  /* exit with a clean code */
  return (1);
}

void
swap_adx ()
{
  if (adx_index_first == adx_index_current)
    adx_index_current = adx_index_second;
  else
    adx_index_current = adx_index_first;

}
