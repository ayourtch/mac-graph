/*
#
# Graph the L2 flows into a format for the visualization with graphviz
#
# Written by Andrew Yourtchenko (ayourtch@gmail.com)
#
*/

#include <stdio.h>
#include <pcap.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include "lua.h"
#include "lualib.h"
#include "lapi.h"
#include "lstate.h"
#include "lauxlib.h"


#define UINT4 unsigned long
#define PROTO_LIST(x) x

lua_State *L;

#pragma pack(1)
typedef struct {
    char ether_dst[6];
    char ether_src[6];
    short ether_type;
    short vlan;
} ether_hdr_t;

unsigned char orig_mac[6];
unsigned char new_mac[6];


pcap_t *pcap_in;
pcap_dumper_t *pcap_out;
pcap_dumper_t *pcap_out2;
int total_packets = 0;

void print_mac(char *target, char *pc) {
  int i;
  char hex[] = "0123456789ABCDEF";
  for(i=0;i<6;i++) {
    *target++ = hex[0xF & (pc[i] >> 4)];
    *target++ = hex[0xF & pc[i]];
    if((i == 1) || (i == 3) ) {
      *target++ = '.';
    }
  }
  *target++ = 0;
}

void push_mac(lua_State *L, char *mac) {
    char hex[] = "0123456789ABCDEF";
    char buf[100];
    char hsrp_mac[] = "\x00\x00\x0c\x07\xac";
    char *bp = buf;
    strcpy(bp, "");
    if(memcmp(mac,hsrp_mac,5) == 0) {
      print_mac(bp, mac);
      bp += strlen(bp);
      strcat(bp, " (hsrp_");
      bp += strlen(bp);
      sprintf(bp, "%d", 0xff & ((unsigned int)mac[5]));
      bp += strlen(bp);
      strcat(bp, ")");
    } else { 
      //strcat(bp, "m_");
      //bp += strlen(bp);
      print_mac(bp, mac);
    }
    lua_pushstring(L, buf);
}

static void dump_packet(u_char *user, const struct pcap_pkthdr *h, 
	const u_char *pc)
{
    ether_hdr_t *e;
    int ret;
    u_char *pc1 = (u_char *)pc;
    e = (ether_hdr_t *)pc;
    u_char c1, c2;

    lua_getglobal(L, "record");
    push_mac(L, e->ether_src);
    lua_pushboolean(L, (e->ether_src[0] & 1));
    push_mac(L, e->ether_dst);
    lua_pushboolean(L, (e->ether_dst[0] & 1));
    if(htons(e->ether_type) == 0x8100) {
      lua_pushnumber(L, htons(e->vlan) & 0xfff);
    } else {
      lua_pushnumber(L, htons(e->ether_type));
    }

    if (lua_pcall(L, 5, 0, 0) != 0) {
      fprintf(stderr,"%s\n",lua_tostring(L,-1));
      return;
    }
}

static int scan_mac(char *pc, unsigned char *mac)
{
  char hex[]="0123456789abcdef";
  int mac_idx = 0;
  unsigned char c1, c2;
  char *hc;

  while(*pc && (mac_idx < 6)) {
    hc = strchr(hex, tolower(*pc));
    if(hc) {
      c1 = hc - hex;
      pc++;
      // fprintf(stderr, "c1: %d\n", c1);
      if(*pc) {
        hc = strchr(hex, tolower(*pc));
        if(hc) {
          c2 = hc - hex;
          // fprintf(stderr, "c2: %d\n", c2);
          mac[mac_idx++] = c1*16 + c2;
          pc++;
        } else {
          fprintf(stderr, "expected hex char, seen: %c!\n", *pc);
        } 
      } else {
        fprintf(stderr, "odd number of hex characters!\n", *pc);
      }
    } else {
      pc++;
    }
  }
  if (mac_idx < 6) {
    fprintf(stderr, "Expected 6 bytes, got only %d\n", mac_idx);
    return 0;
  } else {
    return 1;
  }
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char outfile[8192];
    int done = 0;
    int chunk = 0;

    char opt;
    if (argc < 2) {
      printf("Usage: %s <pcap> lib.lua\n", argv[0]);
      exit(1);
    }

    pcap_in = pcap_open_offline(argv[1], errbuf);
    

    if (pcap_in == NULL) {
	printf("Libpcap error opening infile: %s\n", errbuf);
	exit(1);
    } 
    L = lua_open();
    luaL_openlibs(L); 
    if(luaL_dofile(L, argv[2])!=0) {
      fprintf(stderr,"%s\n",lua_tostring(L,-1));
      return;
    }


    total_packets = 0;
    pcap_loop(pcap_in, 0, dump_packet, NULL);
    lua_getglobal(L, "printall");
    if (lua_pcall(L, 0, 0, 0) != 0) {
      fprintf(stderr,"%s\n",lua_tostring(L,-1));
      return;
    }
}
