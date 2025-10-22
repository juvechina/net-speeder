#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <netinet/ip6.h>
#include <unistd.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 65535

#ifdef COOKED
	#define ETHERNET_H_LEN 16
#else
	#define ETHERNET_H_LEN 14
#endif

#define SPECIAL_TTL 88
#define SPECIAL_HOP_LIMIT 88
#define DEFAULT_MULTIPLIER 1

typedef struct {
	libnet_t *libnet_handler;
	int raw_sock_v6;
	int multiplier;  // 发包倍数
} handler_context;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_usage(void);

pcap_t *net_speeder_pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf)
{
	pcap_t *p;
	int status;

	p = pcap_create(device, errbuf);
	if (p == NULL)
		return (NULL);
	status = pcap_set_snaplen(p, snaplen);
	if (status < 0)
		goto fail;
	status = pcap_set_promisc(p, promisc);
	if (status < 0)
		goto fail;
	status = pcap_set_timeout(p, to_ms);
	if (status < 0)
		goto fail;
	status = pcap_set_immediate_mode(p, 1);
	if (status < 0)
		goto fail;
	
	status = pcap_activate(p);
	if (status < 0)
		goto fail;
	return (p);
fail:
	if (status == PCAP_ERROR)
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %.*s", device,
		    PCAP_ERRBUF_SIZE - 3, pcap_geterr(p));
	else if (status == PCAP_ERROR_NO_SUCH_DEVICE ||
	    status == PCAP_ERROR_PERM_DENIED ||
	    status == PCAP_ERROR_PROMISC_PERM_DENIED)
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s (%.*s)", device,
		    pcap_statustostr(status), PCAP_ERRBUF_SIZE - 6, pcap_geterr(p));
	else
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", device,
		    pcap_statustostr(status));
	pcap_close(p);
	return (NULL);
}

/*
 * print help text
 */
void print_usage(void) {
	printf("Usage: %s [interface] [\"filter rule\"] [multiplier]\n", "net_speeder");
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("    filter       Rules to filter packets (\"ip\" for IPv4, \"ip6\" for IPv6).\n");
	printf("    multiplier   Number of times to send each packet (default: 1).\n");
	printf("\n");
	printf("Examples:\n");
	printf("    ./net_speeder eth0 \"ip\" 2\n");
	printf("    ./net_speeder eth0 \"ip6\" 3\n");
	printf("    ./net_speeder eth0 \"ip or ip6\" 2\n");
	printf("    ./net_speeder eth0 \"ip\" (default multiplier: 1)\n");
	printf("\n");
}

/* Calculate IPv6 pseudo-header checksum */
uint16_t calculate_ipv6_checksum(struct ip6_hdr *ip6, uint8_t protocol, void *payload, uint16_t payload_len)
{
	uint32_t sum = 0;
	uint16_t *ptr;
	int i;

	/* IPv6 pseudo-header: source address (16 bytes) */
	ptr = (uint16_t *)&ip6->ip6_src;
	for (i = 0; i < 8; i++) {
		sum += ntohs(ptr[i]);
	}

	/* IPv6 pseudo-header: destination address (16 bytes) */
	ptr = (uint16_t *)&ip6->ip6_dst;
	for (i = 0; i < 8; i++) {
		sum += ntohs(ptr[i]);
	}

	/* IPv6 pseudo-header: upper-layer packet length */
	sum += payload_len;

	/* IPv6 pseudo-header: next header (protocol) */
	sum += protocol;

	/* Add payload data */
	ptr = (uint16_t *)payload;
	for (i = 0; i < payload_len / 2; i++) {
		sum += ntohs(ptr[i]);
	}

	/* Handle odd byte */
	if (payload_len & 1) {
		sum += (((uint8_t *)payload)[payload_len - 1]) << 8;
	}

	/* Fold 32-bit sum to 16 bits */
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return (uint16_t)~sum;
}

void handle_ipv4_packet(handler_context *ctx, const struct pcap_pkthdr *header, const u_char *packet) {
	struct libnet_ipv4_hdr *ip;
	
	ip = (struct libnet_ipv4_hdr*)(packet + ETHERNET_H_LEN);

	if(ip->ip_ttl != SPECIAL_TTL) {
		ip->ip_ttl = SPECIAL_TTL;
		ip->ip_sum = 0;
		
		if(ip->ip_p == IPPROTO_TCP) {
			struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)((u_int8_t *)ip + ip->ip_hl * 4);
			tcp->th_sum = 0;
			libnet_do_checksum(ctx->libnet_handler, (u_int8_t *)ip, IPPROTO_TCP, ntohs(ip->ip_len) - ip->ip_hl * 4);
		} else if(ip->ip_p == IPPROTO_UDP) {
			struct libnet_udp_hdr *udp = (struct libnet_udp_hdr *)((u_int8_t *)ip + ip->ip_hl * 4);
			udp->uh_sum = 0;
			libnet_do_checksum(ctx->libnet_handler, (u_int8_t *)ip, IPPROTO_UDP, ntohs(ip->ip_len) - ip->ip_hl * 4);
		}
		
		// 根据倍数发送多次
		for(int i = 0; i < ctx->multiplier; i++) {
			int len_written = libnet_adv_write_raw_ipv4(ctx->libnet_handler, (u_int8_t *)ip, ntohs(ip->ip_len));
			if(len_written < 0) {
				printf("IPv4 packet len:[%d] actual write:[%d] attempt:[%d/%d]\n", 
				       ntohs(ip->ip_len), len_written, i+1, ctx->multiplier);
				printf("err msg:[%s]\n", libnet_geterror(ctx->libnet_handler));
				break;  // 如果发送失败，不再继续
			}
		}
	}
}

void handle_ipv6_packet(handler_context *ctx, const struct pcap_pkthdr *header, const u_char *packet) {
	struct ip6_hdr *ip6;
	struct sockaddr_in6 dst_addr;
	
	ip6 = (struct ip6_hdr*)(packet + ETHERNET_H_LEN);

	if(ip6->ip6_hlim != SPECIAL_HOP_LIMIT) {
		ip6->ip6_hlim = SPECIAL_HOP_LIMIT;
		
		uint16_t payload_len = ntohs(ip6->ip6_plen);
		uint8_t next_header = ip6->ip6_nxt;
		void *payload = (u_int8_t *)ip6 + sizeof(struct ip6_hdr);
		
		if(next_header == IPPROTO_TCP) {
			struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)payload;
			tcp->th_sum = 0;
			tcp->th_sum = htons(calculate_ipv6_checksum(ip6, IPPROTO_TCP, payload, payload_len));
		} else if(next_header == IPPROTO_UDP) {
			struct libnet_udp_hdr *udp = (struct libnet_udp_hdr *)payload;
			udp->uh_sum = 0;
			udp->uh_sum = htons(calculate_ipv6_checksum(ip6, IPPROTO_UDP, payload, payload_len));
		}
		
		int total_len = sizeof(struct ip6_hdr) + payload_len;
		
		/* Setup destination address */
		memset(&dst_addr, 0, sizeof(dst_addr));
		dst_addr.sin6_family = AF_INET6;
		memcpy(&dst_addr.sin6_addr, &ip6->ip6_dst, sizeof(struct in6_addr));
		
		// 根据倍数发送多次
		for(int i = 0; i < ctx->multiplier; i++) {
			int len_written = sendto(ctx->raw_sock_v6, ip6, total_len, 0,
			                         (struct sockaddr *)&dst_addr, sizeof(dst_addr));
			
			if(len_written < 0) {
				printf("IPv6 packet len:[%d] actual write:[%d] attempt:[%d/%d]\n", 
				       total_len, len_written, i+1, ctx->multiplier);
				printf("err msg:[%s]\n", strerror(errno));
				break;  // 如果发送失败，不再继续
			}
		}
	}
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;
	count++;
	
	handler_context *ctx = (handler_context *)args;
	
	/* Determine IP version by examining the first nibble */
	const u_char *ip_packet = packet + ETHERNET_H_LEN;
	uint8_t version = (ip_packet[0] >> 4) & 0x0F;
	
	if(version == 4) {
		handle_ipv4_packet(ctx, header, packet);
	} else if(version == 6) {
		handle_ipv6_packet(ctx, header, packet);
	}
	
	return;
}

libnet_t* start_libnet(char *dev) {
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *libnet_handler = libnet_init(LIBNET_RAW4_ADV, dev, errbuf);

	if(NULL == libnet_handler) {
		printf("libnet_init: error %s\n", errbuf);
	}
	return libnet_handler;
}

int create_raw_socket_v6() {
	int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if(sock < 0) {
		printf("create raw socket v6 failed: %s\n", strerror(errno));
		return -1;
	}
	
	/* Enable manual header inclusion */
	int on = 1;
	if(setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof(on)) < 0) {
		printf("setsockopt IPV6_HDRINCL failed: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	
	return sock;
}

int main(int argc, char **argv) {
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	char *filter_rule = NULL;
	struct bpf_program fp;
	bpf_u_int32 net, mask;
	
	handler_context ctx;
	ctx.multiplier = DEFAULT_MULTIPLIER;

	// 支持 2 个或 3 个参数
	if (argc >= 3 && argc <= 4) {
		dev = argv[1];
		filter_rule = argv[2];
		
		// 如果提供了第三个参数，解析为倍数
		if (argc == 4) {
			ctx.multiplier = atoi(argv[3]);
			if (ctx.multiplier < 1 || ctx.multiplier > 100) {
				printf("Error: multiplier must be between 1 and 100\n");
				print_usage();
				return -1;
			}
		}
		
		printf("Device: %s\n", dev);
		printf("Filter rule: %s\n", filter_rule);
		printf("Packet multiplier: %dx\n", ctx.multiplier);
	} else {
		print_usage();	
		return -1;
	}
	
	printf("ethernet header len:[%d](14:normal, 16:cooked)\n", ETHERNET_H_LEN);

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		printf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	printf("init pcap\n");
	
	handle = net_speeder_pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
	if(handle == NULL) {
		printf("net_speeder_pcap_open_live dev:[%s] err:[%s]\n", dev, errbuf);
		printf("init pcap failed\n");
		return -1;
	}

	printf("init libnet for IPv4\n");
	ctx.libnet_handler = start_libnet(dev);
	if(NULL == ctx.libnet_handler) {
		printf("init libnet failed\n");
		return -1;
	}
	
	printf("init raw socket for IPv6\n");
	ctx.raw_sock_v6 = create_raw_socket_v6();
	if(ctx.raw_sock_v6 < 0) {
		printf("init raw socket v6 failed\n");
		return -1;
	}

	if (pcap_compile(handle, &fp, filter_rule, 0, net) == -1) {
		printf("filter rule err:[%s][%s]\n", filter_rule, pcap_geterr(handle));
		return -1;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("set filter failed:[%s][%s]\n", filter_rule, pcap_geterr(handle));
		return -1;
	}

	printf("Started capturing packets...\n");
	
	while(1) {
		pcap_loop(handle, 1, got_packet, (u_char *)&ctx);
	}

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	libnet_destroy(ctx.libnet_handler);
	close(ctx.raw_sock_v6);
	return 0;
}
