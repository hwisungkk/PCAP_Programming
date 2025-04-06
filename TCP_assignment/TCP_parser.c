#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // IP Packet
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); //ethheader 크기만큼

        if (ip->iph_protocol != IPPROTO_TCP) return; // protocol ID가 Only TCP가 아니면 return. 

        int ip_header_len = ip->iph_ihl * 4; // ip header의 길이

        struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len); // ip + ip header의 길이의 위치가 tcp header 시작임.
        int tcp_header_len = TH_OFF(tcp) * 4; // tcp header의 길이, my_header.h의 TH_OFF 매크로 함수로 구할 수 있음

        // 전체 헤더 길이 계산
        int total_header_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;

        // message size 계산: IP 전체 길이 - IP header - TCP header
        // int message_size = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;  ## 보안적으로 조작한 패킷을 보내는 문제가 있을 수 있다고 해서 아래로 변경
        int message_size = header->caplen - total_header_size; // header -> caplen : 실제 캡처된 바이트 수

        // message 위치 계산
        const u_char *message = packet + total_header_size;

        printf("\n==== TCP Packet Information ====\n\n");
        printf("---Ethernet Header---\n");
        printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

        printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        printf("---IP Header---\n");
        printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));
        printf("---TCP Header---\n");
        printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
        printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

        if (message_size > 0) {
            printf("--------------\n");
            int max = message_size > 100 ? 100 : message_size;
            printf("Message (%d bytes):\n", message_size); //최대 100byte 출력
            for (int i = 0; i < max; i++) {
                printf("%c", message[i]);  // 그냥 출력
            }
            printf("\n");
            if(message_size>100)printf("!message는 최대 100글자까지 출력됩니다.!\n");
        }
    }
}

// sniff_imporved.c의 main 함수
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp"; // tcp로 변경
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf); // 사용자의 환경

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}