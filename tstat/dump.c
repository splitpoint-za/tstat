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
#include "tstat.h"
#include "dump.h"
#include "tcpdump.h"
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>



/* Note: 
 * is NOT possible to use libpcap writing functions because 
 * they use opaque structures that are availables only compiling
 * library sources. To bypass the problem, files are generated
 * using fwrite() and respecting pcap file format deduced from 
 * library sources.
 */

#define DUMP_UDP_COMPLETE LAST_UDP_PROTOCOL
#define DUMP_TCP_COMPLETE LAST_UDP_PROTOCOL + 1
#define DUMP_PROTOS       DUMP_TCP_COMPLETE + 1

//60min = 60 * 60 * 1000000usec
#define DUMP_WINDOW_SIZE 3600000000UL

#define DUMP_DIR_BASENAME "traces"
#define DUMP_LOG_FNAME "log.txt"

struct dump_file {
    FILE            *fp;
    char            *protoname;
    struct timeval  lasttime;
    Bool            enabled;
    int             type;
    int             seq_num;
};
struct dump_file proto2dump[DUMP_PROTOS];

static char dump_filename[200];
static struct ether_header eth_header;
static char outdir[100];
static char *log_basedir;
static FILE *fp_log;
static timeval timestamp;
static Bool dump_enabled = FALSE;
static int dir_counter = 0;

int search_dump_file(char *protoname, struct dump_file *proto2dump) {
    int i = 0;
    for (i = 0; i < DUMP_PROTOS; i++) {
        if (proto2dump[i].protoname[0] != '\0' &&
            strcmp(protoname, proto2dump[i].protoname) == 0)
            break;
    }
    return ((i == DUMP_PROTOS) ? -1 : i);
}


FILE * new_dump_file(char * protoname, int sequence_number) {
    FILE *fp;
    struct pcap_file_header hdr;

    sprintf(dump_filename, "%s/%s%02d.pcap", 
        outdir, protoname, sequence_number);     
    fp = fopen(dump_filename, "w");
    if (fp == NULL) {
        fprintf(fp_stderr, "dump engine: unable to create '%s'\n", dump_filename);
        exit(1);
    }

    // this code comes from libpcap sources!!!
    // (TCPDUMP_MAGIC is defined in tcpdump.h)
    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;	            /* fake info */
    hdr.snaplen = 1000000;	        /* fake info */
    hdr.linktype = PCAP_DLT_EN10MB;	/* always Ethernet (10Mb) */
    hdr.sigfigs = 0;                /* fake info */
    fwrite((char *) &hdr, sizeof(hdr), 1, fp);
    
    return fp; 
}

//only for debug purpose
/*
void print_proto2dump(void) {
    int i, find;
    find = 0;
    for (i = 0; i < UDP_DPI_PROTOCOL; i++) {
        if (udp_dump_protos[i].enabled) {
            find = 1;
            fprintf(fp_stdout, "protoname: %s\n", udp_dump_protos[i].protoname);
        }
    }

    if (!find) {
        fprintf(fp_stdout, "no protocol dump enabled\n");
    }
}
*/

void dump_reset_dump_file(struct dump_file *proto2dump, int type, char *protoname) {
    proto2dump[type].fp = NULL;
    proto2dump[type].protoname = protoname;
    proto2dump[type].lasttime.tv_sec = -1;
    proto2dump[type].lasttime.tv_usec = -1;
    proto2dump[type].enabled = FALSE;
    proto2dump[type].type = type;
    proto2dump[type].seq_num = 0;
}

void dump_parse_ini_arg(char *param_name, int param_value) {
    int pos;

    //syntax check
    if (param_value != 0 && param_value != 1) {
        fprintf(fp_log, "dump engine: '%s = %d' syntax error in config file\n", 
            param_name, param_value);
        exit(1);
    }

    //check protocol name 
    pos = search_dump_file(param_name, proto2dump);
    if (pos == -1) {
        fprintf(fp_stderr, "dump engine err: '%s' - not valid command \n", param_name);
        exit(1);
    }
    if (debug)
        fprintf(fp_stderr, "dump engine: enabling dump for %s\n", 
            proto2dump[pos].protoname);
    proto2dump[pos].enabled = (param_value == 0) ? FALSE : TRUE;
    dump_enabled |= param_value;
}

// this function is called the first time by the plugin system; 
// after by the dump_restart() every time the runtime configuration file is modified
void dump_init(void) {
    int i;

    dump_enabled = FALSE;
    timestamp.tv_sec = -1;
    timestamp.tv_usec = -1;
    /* UDP dump protocols 
     * for semplicity we use a vector with as long as the number of classes
     * identified by the DPI. Among these there are some useless classes
     * (FIRST_RTP for example) so we REALLY register in the vector only 
     * a subset of the complete list of classes. 
     * */
    for (i = 0; i < DUMP_PROTOS; i++) {
        dump_reset_dump_file(proto2dump, i, "");
    }
    dump_reset_dump_file(proto2dump, UDP_UNKNOWN, "udp_unknown");
    dump_reset_dump_file(proto2dump, RTP, "udp_rtp");
    dump_reset_dump_file(proto2dump, RTCP, "udp_rtcp");
    dump_reset_dump_file(proto2dump, P2P_EDK, "udp_edk");
    dump_reset_dump_file(proto2dump, P2P_KAD, "udp_kad");
    dump_reset_dump_file(proto2dump, P2P_KADU, "udp_kadu");
    dump_reset_dump_file(proto2dump, P2P_GNU, "udp_gnutella");
    dump_reset_dump_file(proto2dump, P2P_BT, "udp_bittorrent");
    dump_reset_dump_file(proto2dump, P2P_DC, "udp_dc");
    dump_reset_dump_file(proto2dump, P2P_KAZAA, "udp_kazaa");
    dump_reset_dump_file(proto2dump, P2P_JOOST, "udp_joost");
    dump_reset_dump_file(proto2dump, P2P_PPLIVE, "udp_pplive");
    dump_reset_dump_file(proto2dump, P2P_SOPCAST, "udp_sopcast");
    dump_reset_dump_file(proto2dump, P2P_TVANTS, "udp_tvants");
    dump_reset_dump_file(proto2dump, DUMP_UDP_COMPLETE, "udp_complete");
    dump_reset_dump_file(proto2dump, DUMP_TCP_COMPLETE, "tcp_complete");
}

void dump_packet(FILE *fp,
                 void *pip, 
                 void *plast)
{
    struct pcap_pkthdr phdr;

    // create a pcap packet header (adding size of bogus ethernet header)
    phdr.ts.tv_sec = current_time.tv_sec;
    phdr.ts.tv_usec = current_time.tv_usec;
    phdr.caplen = (char *) plast - (char *) pip + 1;
    phdr.caplen += sizeof(struct ether_header); /* add in the ether header */
    phdr.len = sizeof(struct ether_header) + ntohs (PIP_LEN (pip));	
    if (fp == NULL) {
        printf("AAAA\n");
    }
    fwrite(&phdr, sizeof(struct pcap_pkthdr), 1, fp);

    // write a (bogus) ethernet header
    memset(&eth_header, 0, sizeof(struct ether_header));
    eth_header.ether_type = htons (ETHERTYPE_IP);
    fwrite (&eth_header, sizeof(struct ether_header), 1, fp);

    // write the IP/TCP parts
    fwrite(pip, phdr.caplen - sizeof(struct ether_header), 1, fp);
}

void dump_to_file(struct dump_file *dump_file, 
                  void *pip, 
                  void *plast)
{
    //open a new dump file
    if (dump_file->lasttime.tv_sec == -1 &&
        dump_file->lasttime.tv_usec == -1) {
        dump_file->fp = new_dump_file(dump_file->protoname, dump_file->seq_num);
    }
    else if (elapsed(current_time, dump_file->lasttime) >= DUMP_WINDOW_SIZE) {
        fflush(dump_file->fp);
        fclose(dump_file->fp);
        dump_file->seq_num++;
        dump_file->fp = new_dump_file(dump_file->protoname, dump_file->seq_num);
    }
    //update timestamp
    dump_file->lasttime.tv_sec = current_time.tv_sec;
    dump_file->lasttime.tv_usec = current_time.tv_usec;
    //dump current packet
    dump_packet(dump_file->fp, pip, plast);

    if (timestamp.tv_sec == -1) {
        fprintf(fp_log, "dump start: %s", Timestamp());
    }
    timestamp = current_time;
}

void dump_flow_stat (struct ip *pip, 
                     void *pproto, 
                     int tproto, 
                     void *pdir,
	                 int dir, 
                     void *hdr, 
                     void *plast) 
{
    if (!dump_enabled)
        return;

    if (tproto == PROTOCOL_TCP) {
        if (proto2dump[DUMP_TCP_COMPLETE].enabled)
            dump_to_file(&proto2dump[DUMP_TCP_COMPLETE], pip, plast);
    }
    else {
        //dump to a DPI file
        if (proto2dump[((ucb *)pdir)->type].enabled) {
            dump_to_file(&proto2dump[((ucb *)pdir)->type], pip, plast);
        }
        //dumo to unknown
        else if (proto2dump[UDP_UNKNOWN].enabled) {
            dump_to_file(&proto2dump[UDP_UNKNOWN], pip, plast);
        }
        //dump to a complete file
        if (proto2dump[DUMP_UDP_COMPLETE].enabled)
            dump_to_file(&proto2dump[DUMP_UDP_COMPLETE], pip, plast);
    }
}

void dump_flush(Bool trace_completed) {
    int i;

    if (!dump_enabled)
        return;
    
    if (trace_completed && !con_cat)
        dir_counter = 0;

    //flush traces files
    for (i = 0; i < DUMP_PROTOS; i++) {
        if (proto2dump[i].enabled && proto2dump[i].fp) {
            fflush(proto2dump[i].fp);
            fclose(proto2dump[i].fp);
            proto2dump[i].fp = NULL;
            proto2dump[i].lasttime.tv_sec = -1;
            proto2dump[i].lasttime.tv_usec = -1;
        }
    }

    //write messages to log file
    if (timestamp.tv_sec != -1) {
        fprintf(fp_log, "dump stop: %s\n"
            "---\n"
            "enabled protocols:\n"
            "---\n", ctime(&timestamp.tv_sec));
        for (i = 0; i <  DUMP_PROTOS; i++) {
            if (proto2dump[i].enabled)
                fprintf(fp_log, "%s\n", proto2dump[i].protoname);
        }
        fprintf(fp_log, "---\n");
    }
    fclose(fp_log);
}

void dump_create_outdir(char * basedir) {
    int tot;
    char *fname;

    if (!dump_enabled)
        return;

    log_basedir = basedir;

    tot = strlen(basedir) + strlen(DUMP_DIR_BASENAME) + 4;
    if (tot > (sizeof(outdir) / sizeof(char))) {
        fprintf(fp_stderr, "dump engine err: directory name too long!!!");
        exit(1);
    }
    sprintf(outdir, "%s/%s%02d", basedir, DUMP_DIR_BASENAME, dir_counter);

    if (mkdir(outdir, 0777) != 0) {
        fprintf(fp_stderr, "dump engine err: error creating '%s'\n", outdir);
        exit(1);
    }
    fprintf(fp_stdout, "Creating output dir %s\n", outdir);

    tot += strlen(DUMP_LOG_FNAME);
    fname = malloc(sizeof(char) * tot + 1);
    sprintf(fname, "%s/%s", outdir, DUMP_LOG_FNAME);
    fp_log = fopen(fname, "w");
    if (fp_log == NULL) {
        fprintf(fp_stderr, "dump engine: error creating '%s'\n", fname);
        exit(1);
    }
    free(fname);

    dir_counter++;
}
