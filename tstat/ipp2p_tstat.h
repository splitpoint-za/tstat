/*
This code is derived from IPP2P, an extension to iptables to identify P2P 
traffic, written by Eicke Friedrich and Klaus Degner <ipp2p@ipp2p.org>
Original code available at http://ipp2p.org/
*/

#ifndef __IPT_IPP2P_H

#define __IPT_IPP2P_H
#define IPP2P_VERSION "0.8.2"

struct ipt_p2p_info {
    int cmd;
    int debug;
};

#endif //__IPT_IPP2P_H

#define SHORT_HAND_IPP2P	1	/* --ipp2p switch */
//#define SHORT_HAND_DATA               4 /* --ipp2p-data switch*/
#define SHORT_HAND_NONE		5	/* no short hand */

#define IPP2P_EDK           (1 << 1)
#define IPP2P_DATA_KAZAA    (1 << 2)
#define IPP2P_DATA_EDK      (1 << 3)
#define IPP2P_DATA_DC       (1 << 4)
#define IPP2P_DC            (1 << 5)
#define IPP2P_DATA_GNU      (1 << 6)
#define IPP2P_GNU           (1 << 7)
#define IPP2P_KAZAA         (1 << 8)
#define IPP2P_BIT           (1 << 9)
#define IPP2P_APPLE         (1 << 10)
#define IPP2P_SOUL          (1 << 11)
#define IPP2P_WINMX         (1 << 12)
#define IPP2P_ARES          (1 << 13)
#define IPP2P_MUTE          (1 << 14)
#define IPP2P_WASTE         (1 << 15)
#define IPP2P_XDCC          (1 << 16)
#define IPP2P_KAD           (1 << 17)
#define IPP2P_KADU          (1 << 18)
#define IPP2P_PPLIVE		(1 << 19)
#define IPP2P_SOPCAST		(1 << 20)
#define IPP2P_TVANTS		(1 << 21)
#define IPP2P_DNS		(1 << 22)
#define IPP2P_PPSTREAM          (1 << 23)
#define IPP2P_TEREDO		(1 << 24)

int search_all_edk (const unsigned char *, const int, int);
int search_kazaa (const unsigned char *, const int, int);
int search_edk (const unsigned char *, const int, int);
int search_dc (const unsigned char *, const int, int);
int search_all_dc (const unsigned char *, const int, int);
int search_gnu (const unsigned char *, const int, int);
int search_all_gnu (const unsigned char *, const int, int);
int search_all_kazaa (const unsigned char *, const int, int);
int search_bittorrent (const unsigned char *, const int, int);
int search_apple (const unsigned char *, const int, int);
int search_soul (const unsigned char *, const int, int);
int search_winmx (const unsigned char *, const int, int);
int search_ares (const unsigned char *, const int, int);
int search_mute (const unsigned char *, const int, int);
int search_waste (const unsigned char *, const int, int);
int search_xdcc (const unsigned char *, const int, int);

int udp_search_kazaa (unsigned char *, const int, int);
int udp_search_bit (unsigned char *, const int, int);
int udp_search_gnu (unsigned char *, const int, int);
int udp_search_edk (unsigned char *, const int, int);
int udp_search_directconnect (unsigned char *, const int, int);
int udp_search_pplive (unsigned char *, const int, int);
int udp_search_sopcast (unsigned char *, const int, int);
int udp_search_tvants (unsigned char *, const int, int);
int udp_search_dns (unsigned char *, const int, int);
int udp_search_ppstream (unsigned char *, const int, int);
int udp_search_teredo (unsigned char *, const int, int);

struct udpmatch
{
  int command;
  int short_hand;		/*for functions included in short hands */
  int packet_len;
  int (*function_name) (unsigned char *, const int, int);
};

struct tcpmatch
{
  int command;
  int short_hand;		/*for functions included in short hands */
  int packet_len;
  int (*function_name) (const unsigned char *, const int, int);
};
