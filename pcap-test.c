#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#include <unistd.h>
#endif

#pragma pack(push, 1)
// 이더넷 헤더 (14바이트)
typedef struct {
	u_char  dst_mac[6];
	u_char  src_mac[6];
	u_short eth_type;
} eth_hdr_t;

// IPv4 헤더
typedef struct {
	u_char  ver_ihl;
	u_char  tos;
	u_short tot_len;
	u_short id;
	u_short frag_off;
	u_char  ttl;
	u_char  protocol;
	u_short checksum;
	u_int   src_ip;
	u_int   dst_ip;
} ip_hdr_t;

// TCP 헤더
typedef struct {
	u_short src_port;
	u_short dst_port;
	u_int   seq;
	u_int   ack;
	u_char  data_offset;
	u_char  flags;
	u_short window;
	u_short checksum;
	u_short urg_ptr;
} tcp_hdr_t;

// UDP 헤더
typedef struct {
	u_short src_port;
	u_short dst_port;
	u_short len;
	u_short checksum;
} udp_hdr_t;
#pragma pack(pop)

#define DUMP_BYTES 16

void usage() {
	fprintf(stderr, "syntax: ./pcap-test <interface>\n");
	fprintf(stderr, "sample: ./pcap-test eth0\n\n");
}

// 사용 가능한 인터페이스 출력
void list_interfaces() {
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "pcap_findalldevs error: %s\n", errbuf);
		return;
	}
	fprintf(stderr, "Available interfaces:\n");
	for (pcap_if_t* dev = alldevs; dev; dev = dev->next) {
		fprintf(stderr, "  - %s", dev->name);
		if (dev->description) fprintf(stderr, " (%s)", dev->description);
		fprintf(stderr, "\n");
	}
	pcap_freealldevs(alldevs);
}

// MAC 주소 출력
void print_mac(const u_char* mac) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// IP 주소 출력
void print_ip(u_int ip) {
	struct in_addr addr = { ip };
	printf("%s", inet_ntoa(addr));
}

// 콜백: 패킷 캡처 시마다 호출
void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* p) {
	// 타임스탬프
	char timestr[64];
	time_t sec = h->ts.tv_sec;
	struct tm* lt = localtime(&sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", lt);
	printf("\n[%s.%06ld] %u bytes captured\n",
		   timestr, h->ts.tv_usec, h->caplen);

	const u_char* ptr = p;

	// 이더넷 파싱
	eth_hdr_t* eth = (eth_hdr_t*)ptr;
	printf("Ether: ");
	print_mac(eth->src_mac);
	printf(" -> ");
	print_mac(eth->dst_mac);
	printf(" | Type: 0x%04X\n", ntohs(eth->eth_type));
	ptr += sizeof(eth_hdr_t);

	// IPv4 패킷만
	if (ntohs(eth->eth_type) == 0x0800) {
		ip_hdr_t* ip = (ip_hdr_t*)ptr;
		int ihl = (ip->ver_ihl & 0x0F) * 4;
		printf("IPv4: ");
		print_ip(ip->src_ip);
		printf(" -> ");
		print_ip(ip->dst_ip);
		printf(" | TTL: %u | Proto: %u\n", ip->ttl, ip->protocol);
		ptr += ihl;

		// TCP
		if (ip->protocol == IPPROTO_TCP) {
			tcp_hdr_t* tcp = (tcp_hdr_t*)ptr;
			int doff = ((tcp->data_offset & 0xF0) >> 4) * 4;
			printf("TCP: %u -> %u | Seq: %u | Ack: %u\n",
				   ntohs(tcp->src_port), ntohs(tcp->dst_port),
				   ntohl(tcp->seq), ntohl(tcp->ack));
			ptr += doff;
		}
		// UDP
		else if (ip->protocol == IPPROTO_UDP) {
			udp_hdr_t* udp = (udp_hdr_t*)ptr;
			printf("UDP: %u -> %u | Len: %u\n",
				   ntohs(udp->src_port), ntohs(udp->dst_port), ntohs(udp->len));
			ptr += sizeof(udp_hdr_t);
		}
	}

	// 헥사 덤프
	int dump_len = h->caplen < DUMP_BYTES ? h->caplen : DUMP_BYTES;
	printf("Hex Dump (%d bytes): ", dump_len);
	for (int i = 0; i < dump_len; i++) {
		printf("%02X ", p[i]);
	}
	printf("\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		list_interfaces();
		return 1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (!handle) {
		fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
		return 1;
	}

	printf("Listening on %s... (Ctrl+C to stop)\n", dev);
	if (pcap_loop(handle, -1, packet_handler, NULL) < 0) {
		fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
	}

	pcap_close(handle);
	return 0;
}
