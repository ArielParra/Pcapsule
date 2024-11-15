#include <iostream>
#include <iomanip>

#include <cstdlib>
#include <cstring>

#include <pcap/pcap.h>		 // inet_ntoa
#include <netinet/ip_icmp.h> // icmp_header
#include <netinet/tcp.h>	 // tcp_header
#include <netinet/udp.h>	 // udp_header
// #include <netinet/ip.h>
// #include <netinet/in.h>

int link_hdr_length = 0;

void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packetd_ptr)
{
	// packetd_ptr is pointing to the datalink header
	packetd_ptr += link_hdr_length;
	struct ip *ip_hdr = (struct ip *)packetd_ptr;

	// inet_ntoa() writes it's result to an address and returns this address,
	// but subsequent calls to inet_ntoa() will also write to the same address,
	// so we need to copy the result to a buffer.
	char packet_srcip[INET_ADDRSTRLEN]; // source ip address
	char packet_dstip[INET_ADDRSTRLEN]; // destination ip address

	std::snprintf(packet_srcip, INET_ADDRSTRLEN, "%s", inet_ntoa(ip_hdr->ip_src));
	std::snprintf(packet_dstip, INET_ADDRSTRLEN, "%s", inet_ntoa(ip_hdr->ip_dst));

	int packet_id = ntohs(ip_hdr->ip_id),	// identification
		packet_ttl = ip_hdr->ip_ttl,		// Time To Live
		packet_tos = ip_hdr->ip_tos,		// Type Of Service
		packet_len = ntohs(ip_hdr->ip_len), // header length + data length
		packet_hlen = ip_hdr->ip_hl;		// header length

	std::cout
		//<< "******************************************************************************\n"
		<< std::dec << "ID: " << std::setw(5) << packet_id << " | "
		<< "SRC: " << std::setw(15) << packet_srcip << " | "
		<< "DST: " << std::setw(15) << packet_dstip << " | "
		<< "TOS: 0x" << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << packet_tos << " | "
		<< std::dec << std::setfill(' ') // reset fill for decimal output
		<< "TTL: " << std::setw(3) << packet_ttl << " | ";

	packetd_ptr += (4 * packet_hlen);
	int protocol_type = ip_hdr->ip_p;

	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	struct icmp *icmp_header;
	int src_port, dst_port;

	std::cout << "PROTO: " << std::setw(4);
	switch (protocol_type)
	{
	case IPPROTO_TCP:
	{
		tcp_header = (struct tcphdr *)packetd_ptr;
		src_port = ntohs(tcp_header->th_sport);
		dst_port = ntohs(tcp_header->th_dport);
		std::cout << "TCP"
				  << " | FLAGS: " << (tcp_header->th_flags & TH_SYN ? 'S' : '-')
				  << "/" << (tcp_header->th_flags & TH_ACK ? 'A' : '-')
				  << "/" << (tcp_header->th_flags & TH_URG ? 'U' : '-')
				  << " | SPORT: " << std::setw(5) << src_port
				  << " | DPORT: " << std::setw(5) << dst_port;
		break;
	}
	case IPPROTO_UDP:
	{
		udp_header = (struct udphdr *)packetd_ptr;
		src_port = ntohs(udp_header->uh_sport);
		dst_port = ntohs(udp_header->uh_dport);
		std::cout << "UDP"
				  << " | SPORT: " << std::setw(5) << src_port
				  << " | DPORT: " << std::setw(5) << dst_port;
		break;
	}
	case IPPROTO_ICMP:
	{
		icmp_header = (struct icmp *)packetd_ptr;
		int icmp_type = icmp_header->icmp_type;
		int icmp_type_code = icmp_header->icmp_code;
		std::cout << "ICMP"
				  << " | TYPE: " << std::setw(3) << icmp_type
				  << " | CODE: " << std::setw(3) << icmp_type_code;
		break;
	}
	default:
		std::cout << "---"; // UNKOWN
		break;
	}
	std::cout << " |\n";
}

int main(int argc, char const *argv[])
{

	char error_buffer[PCAP_ERRBUF_SIZE];
	
	const char device[] = "wlp4s0";

	int packets_count = 10; // quantity of capture packages

	//								device, snap length,promiscuous mode, buffer timeout in ms,argument to callback
	pcap_t *capdev = pcap_open_live(device, BUFSIZ, 0, -1, error_buffer);

	if (capdev == nullptr)
	{
		std::cerr << "ERROR: pcap_open_live() " << error_buffer;
		return 1;
	}

	///*
	//Filter expressions consists of qualifiers followed by primitives, For example :
	//host www.duckduckgo.com , port 1337 , src port 80
	//using: $ping -c4 www.duckduckgo.com
	struct bpf_program bpf;
	bpf_u_int32 netmask;
	char filters[] = "host www.duckduckgo.com";

	if (pcap_compile(capdev, &bpf, filters, 0, netmask) == PCAP_ERROR)
	{
		std::cerr << "ERROR: pcap_compile() " << pcap_geterr(capdev);
	}
	if (pcap_setfilter(capdev, &bpf))
	{
		std::cerr << "ERROR: pcap_setfilter() " << pcap_geterr(capdev);
	}
	//*/

	int link_hdr_type = pcap_datalink(capdev); // frame header

	switch (link_hdr_type)
	{
	// Loopback (lo)
	case DLT_NULL:
		link_hdr_length = 4;
		break;
	// Ethernet, IEEE 802.3
	case DLT_EN10MB:
		link_hdr_length = 14;
		break;
	// WLAN, IEEE 802.11
	case DLT_IEEE802_11:
		link_hdr_length = 24;
		break;
	default:
		link_hdr_length = 0;
	}

	if (pcap_loop(capdev, packets_count, call_me, (u_char *)nullptr)) // pcap_loop() passes packet data to the callback function
	{
		std::cerr << "ERROR: pcap_loop() failed!\n";
		return 1;
	}

	return 0;
}
