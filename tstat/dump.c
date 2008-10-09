#include "tstat.h"
#include "dump.h"
#include "tcpdump.h"
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define BUF_SIZE 50


/* Note: 
 * is NOT possible to use libpcap writing functions because 
 * they use opaque structures that are availables only compiling
 * library sources. To bypass the problem, files are generated
 * using fwrite() and respecting pcap file format deducted from 
 * library sources.
 */

#define UDP_DPI_PROTOCOLS LAST_UDP_PROTOCOL + 1
//60min = 60 * 60 * 1000000usec
#define DPI_DUMP_IDLE 3600000000

typedef struct {
    FILE            *fp;
    char            *protoname;
    struct timeval  lasttime;
    Bool            enabled;
    int             type;
    int             seq_num;
} dpi_file;
dpi_file udp_dpi_files[UDP_DPI_PROTOCOLS];

dpi_file fp_prova;

static char dump_filename[200];
static struct ether_header eth_header;
static char outdir[100];

char * readline(FILE *fp) {
    static char *buf = NULL;
    static int buf_size = 0;
    static int next_pos = 0;
    char *tmp, curr_c;

    if (buf == NULL) {
        buf = malloc(BUF_SIZE * sizeof(char));
        buf_size = BUF_SIZE;
        next_pos = 0;
    }

    while (1) {
        if (next_pos + 1 == buf_size) {
            buf_size += BUF_SIZE;
            //printf("resize: %d\n", buf_size);
            tmp = malloc(buf_size * sizeof(char));
            strcpy(tmp, buf);
            free(buf);
            buf = tmp;
        }

        curr_c = fgetc(fp);
        if (feof(fp)) {
            buf[next_pos] = '\0';
            break;
        }

        buf[next_pos] = curr_c;
        buf[next_pos + 1] = '\0';
        //printf("buf:%s\n", buf);
        next_pos++;
        if (curr_c == '\n')
            break;
    }
    next_pos = 0;
    if (buf[0] == '\0')
        return NULL;
    return buf;
}

int search_dpi_file(char *protoname, dpi_file *dpi_files) {
    int i = 0;
    //printf("\nsearch:\n");
    for (i = 0; i < UDP_DPI_PROTOCOLS; i++) {
        //printf("%lp %s\n", &udp_dpi_files[i], udp_dpi_files[i].protoname);
        if (dpi_files[i].protoname[0] != '\0' &&
            strcmp(protoname, dpi_files[i].protoname) == 0)
            break;
    }
    return ((i == UDP_DPI_PROTOCOLS) ? -1 : i);
}


FILE * new_dump_file(char * protoname, int sequence_number) {
    FILE *fp;
    struct pcap_file_header hdr;

    sprintf(dump_filename, "%s/%s.pcap%d", 
        outdir, protoname, sequence_number);     
    fp = fopen(dump_filename, "w");
    if (fp == NULL) {
        fprintf(stderr, "unable to create '%s'\n", dump_filename);
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
        if (udp_dpi_files[i].enabled) {
            find = 1;
            printf("protoname: %s\n", udp_dpi_files[i].protoname);
        }
    }

    if (!find) {
        printf("no protocol dump enabled\n");
    }
}
*/

void dump_reset_dpifile(dpi_file *dpi_files, int type, char *protoname) {
    dpi_files[type].fp = NULL;
    dpi_files[type].protoname = protoname;
    dpi_files[type].lasttime.tv_sec = -1;
    dpi_files[type].lasttime.tv_usec = -1;
    dpi_files[type].enabled = FALSE;
    dpi_files[type].type = type;
    dpi_files[type].seq_num = 0;
}



void dump_init(void) {
    char *line;
    int pos;
    FILE *fp;
    Bool udp_section;
    char *word;
    dpi_file *dpi_files;
    int i;

    /* UDP dump protocols 
     * for semplicity we use a vector with as long as the number of classes
     * identified by the DPI. Among these there are some useless classes
     * (FIRST_RTP for example) so we REALLY register in the vector only 
     * a subset of the complete list of classes. 
     * */
    for (i = 0; i < UDP_DPI_PROTOCOLS; i++) {
        dump_reset_dpifile(udp_dpi_files, i, "");
    }
    dump_reset_dpifile(udp_dpi_files, UDP_UNKNOWN, "unknown");
    dump_reset_dpifile(udp_dpi_files, RTP, "rtp");
    dump_reset_dpifile(udp_dpi_files, RTCP, "rtcp");
    dump_reset_dpifile(udp_dpi_files, P2P_EDK, "edk");
    dump_reset_dpifile(udp_dpi_files, P2P_KAD, "kad");
    dump_reset_dpifile(udp_dpi_files, P2P_KADU, "kadu");
    dump_reset_dpifile(udp_dpi_files, P2P_GNU, "gnutella");
    dump_reset_dpifile(udp_dpi_files, P2P_BT, "bittorrent");
    dump_reset_dpifile(udp_dpi_files, P2P_DC, "dc");
    dump_reset_dpifile(udp_dpi_files, P2P_KAZAA, "kazaa");
    dump_reset_dpifile(udp_dpi_files, P2P_JOOST, "joost");
    dump_reset_dpifile(udp_dpi_files, P2P_PPLIVE, "pplive");
    dump_reset_dpifile(udp_dpi_files, P2P_SOPCAST, "sopcast");
    dump_reset_dpifile(udp_dpi_files, P2P_TVANTS, "tvants");
    dump_reset_dpifile(udp_dpi_files, LAST_UDP_PROTOCOL, "complete");

    fp = fopen(dump_conf_fname, "r");
    if (!fp) {
        fprintf(stderr, "dump engine err: %s - No such file\n", dump_conf_fname);
        exit(1);
    }

    udp_section = FALSE;
    while (1) {
        line = readline(fp);
        if (line == NULL)
            break;

        word = strtok(line, " \t\n");
        while(word != NULL) {
            //skip comments and void lines
            if (word[0] == '#' || word[0] == '\0')
                break;
           
            // check protocols section (udp or tcp?)
            if (word[0] == '[') { 
                if (strcmp(word, "[udp]") == 0) {
                    udp_section = TRUE;
                    dpi_files = udp_dpi_files;
                }
                /*
                else if (strcmp(word, "[tcp]") == 0) {
                    udp_section = FALSE;
                    //dpi_files = tcp_dump_cmds;
                }
                */
                else {
                    fprintf(stderr, "dump engine err: %s - not valid section\n", word);
                    exit(1);
                }
            }
            else {
                pos = search_dpi_file(word, dpi_files);
                if (pos == -1) {
                    fprintf(stderr, "dump engine err: %s - not valid command \n", word);
                    exit(1);
                }
                if (debug)
                    fprintf(stderr, "dump: enabling dump for (%s) %s\n",
                        ((udp_section == TRUE) ? "udp" : "tcp"),
                        dpi_files[pos].protoname);
                dpi_files[pos].enabled = TRUE;
            }

            word = strtok(NULL, " \t\n");
        }
    }

/*
    // reset vector
    for (i = 0; i < UDP_DPI_PROTOCOLS; i++) {
        udp_dpi_files[i].protoname = NULL;
        udp_dpi_files[i].lasttime.tv_sec = -1;
        udp_dpi_files[i].lasttime.tv_usec = -1;
        udp_dpi_files[i].enabled = FALSE;
        udp_dpi_files[i].type = i;
        udp_dpi_files[i].seq_num = 0;
    }

    // to enable/disable dump for protocols
    // uncomment/comment protocol registration
//    register_proto2dump(RTP, "rtp");
//    register_proto2dump(RTCP, "rtcp");
//    register_proto2dump(P2P_EDK, "edk");
//    register_proto2dump(P2P_KAD, "kad");
//    register_proto2dump(P2P_KADU, "kadu");
//    register_proto2dump(P2P_GNU, "gnutella");
//    register_proto2dump(P2P_BT, "bittorrent");
//    register_proto2dump(P2P_DC, "dc");
//    register_proto2dump(P2P_KAZAA, "kazaa");
//    register_proto2dump(P2P_JOOST, "joost");
    register_proto2dump(P2P_PPLIVE, "pplive");
    register_proto2dump(P2P_SOPCAST, "sopcast");
    register_proto2dump(P2P_TVANTS, "tvants");

//skype subtypes are currently useless because 
//traffic is identified only when the flow is closing
//so we can't dump any packet
//    register_proto2dump(SKYPE_E2E, "skypee2e");
//    register_proto2dump(SKYPE_OUT, "skypeout");
//    register_proto2dump(SKYPE_SIG, "skypesig");

//    register_proto2dump(UDP_UNKNOW, "udp_unknow");
//    register_proto2dump(LAST_UDP_PROTOCOL, "udp_complete");
    register_proto2dump(UDP_DPI_COMPLEMENT, "complement");
*/
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
    fwrite(&phdr, sizeof(struct pcap_pkthdr), 1, fp);

    // write a (bogus) ethernet header
    memset(&eth_header, 0, sizeof(struct ether_header));
    eth_header.ether_type = htons (ETHERTYPE_IP);
    fwrite (&eth_header, sizeof(struct ether_header), 1, fp);

    // write the IP/TCP parts
    fwrite(pip, phdr.caplen - sizeof(struct ether_header), 1, fp);
}

void dump_to_file(dpi_file *dpi_file, 
                  void *pip, 
                  void *plast)
{
    //open a new dump file
    if (dpi_file->lasttime.tv_sec == -1 &&
        dpi_file->lasttime.tv_usec == -1) {
        dpi_file->fp = new_dump_file(dpi_file->protoname, dpi_file->seq_num);
    }
    else if (elapsed(current_time, dpi_file->lasttime) >= DPI_DUMP_IDLE) {
        fflush(dpi_file->fp);
        fclose(dpi_file->fp);
        dpi_file->seq_num++;
        dpi_file->fp = new_dump_file(dpi_file->protoname, dpi_file->seq_num);
    }
    //update timestamp
    dpi_file->lasttime.tv_sec = current_time.tv_sec;
    dpi_file->lasttime.tv_usec = current_time.tv_usec;
    //dump current packet
    dump_packet(dpi_file->fp, pip, plast);
}

void dump_flow_stat (struct ip *pip, 
                     void *pproto, 
                     int tproto, 
                     void *pdir,
	                 int dir, 
                     void *hdr, 
                     void *plast) 
{
    //Bool dumped;
    if (tproto != PROTOCOL_UDP)
        return;
    
    //dump to a DPI file
    if (udp_dpi_files[((ucb *)pdir)->type].enabled) {
        dump_to_file(&udp_dpi_files[((ucb *)pdir)->type], pip, plast);
    }
    //dumo to unknown
    else if (udp_dpi_files[UDP_UNKNOWN].enabled) {
        dump_to_file(&udp_dpi_files[UDP_UNKNOWN], pip, plast);
    }
    
    //dump to a complete file
    if (udp_dpi_files[LAST_UDP_PROTOCOL].enabled)
        dump_to_file(&udp_dpi_files[LAST_UDP_PROTOCOL], pip, plast);
}

void dump_flush(void) {
    int i;
    for (i = 0; i < UDP_DPI_PROTOCOLS; i++) {
        if (udp_dpi_files[i].enabled && udp_dpi_files[i].fp) {
            fflush(udp_dpi_files[i].fp);
            fclose(udp_dpi_files[i].fp);
        }
    }
}

void dump_create_outdir(char * basedir) {
    if (strlen(basedir) + strlen("/dump") > (sizeof(outdir) / sizeof(char))) {
        fprintf(stderr, "dump engine err: directory name too long!!!");
        exit(1);
    }
    strcpy(outdir, basedir);
    strcat(outdir, "/traces");
    if (mkdir(outdir, 0777) != 0) {
        fprintf(stderr, "dump engine err: error creating '%s'\n", outdir);
        exit(1);
    }
}
