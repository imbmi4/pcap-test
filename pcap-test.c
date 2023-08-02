#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/ip.h> // for struct ip

void usage() {
   printf("syntax: pcap-test <interface>\n");
   printf("sample: pcap-test wlan0\n");
}

#define ETHER_ADDR_LEN 6
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

#define IP_ADDR_LEN 4

struct libnet_ipv4_hdr {
    u_int8_t ip_vhl;         /* version << 4 | header length >> 2 */
    u_int8_t ip_tos;         /* type of service */
    u_int16_t ip_len;        /* total length */
    u_int16_t ip_id;         /* identification */
    u_int16_t ip_off;        /* fragment offset field */
    u_int8_t ip_ttl;         /* time to live */
    u_int8_t ip_p;           /* protocol */
    u_int16_t ip_sum;        /* checksum */
    struct in_addr ip_src;   /* source IP address */
    struct in_addr ip_dst;   /* destination IP address */
};

typedef struct {
   char* dev_;
} Param;

Param param = {
   .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
   if (argc != 2) {
      usage();
      return false;
   }
   param->dev_ = argv[1];
   return true;
}

void print_mac(uint8_t *m){
   printf("%02x-%02x-%02x-%02x-%02x-%02x",m[0],m[1],m[2],m[3],m[4],m[5]);
}

void print_ip(struct in_addr ip){
   printf("%s", inet_ntoa(ip));
}

int main(int argc, char* argv[]) {
   if (!parse(&param, argc, argv))
      return -1;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
   if (pcap == NULL) {
      fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);

      return -1;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
   if (pcap == NULL) {
      fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
      return -1;
   }

   while (true) {
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(pcap, &header, &packet);
      if (res == 0) continue;
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
         break;
      }
      printf("%u bytes captured\n", header->caplen);
      struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*) packet;
      printf("smac : ");
      print_mac(eth_hdr -> ether_shost);
      printf("\n");
      printf("dmac : ");
      print_mac(eth_hdr -> ether_dhost);
      printf("\n");
      if(ntohs(eth_hdr -> ether_type) != 0x0800)
         continue;

      // Move to the IP header
      const u_char* ip_packet = packet + sizeof(struct libnet_ethernet_hdr);
      struct ip* ip_hdr = (struct ip*)ip_packet;
      printf("src ip : ");
      print_ip(ip_hdr->ip_src);
      printf("\n");
      printf("dst ip : ");
      print_ip(ip_hdr->ip_dst);
      printf("\n");
      printf("--------------------\n");
   }

   pcap_close(pcap);
}
