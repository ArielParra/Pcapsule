#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

#include <cstdlib>			 // exit()
#include <pcap/pcap.h>		 // inet_ntoa
#include <netinet/ip_icmp.h> // icmp_header
#include <netinet/tcp.h>	 // tcp_header
#include <netinet/udp.h>	 // udp_header

#define DEFAULT_PACKET_COUNT 10

void headerLooker(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packetd_ptr)
{
	int link_hdr_length = *(int *)user;
	// packetd_ptr is pointing to the datalink header
	packetd_ptr += link_hdr_length;
	struct ip *ip_hdr = reinterpret_cast<struct ip *>(const_cast<u_char *>(packetd_ptr));

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
				  << " | TYPE: " << std::setw(6) << icmp_type
				  << " | CODE: " << std::setw(6) << icmp_type_code;
		break;
	}
	default:
		std::cout << "---"; // UNKOWN
		break;
	}
	std::cout << " |\n";
}

void displayUsage()
{
	return std::cout
			   << "Usage: ./pcapsule -i <interface> [-n <num_packets>] [-f <filter_expression>] [-h]\n"
			   << "Options:\n"
			   << "  -i <interface>       Specify the network interface to capture packets on.\n"
			   << "  -n <num_packets>     Specify the number of packets to capture (default: 10).\n"
			   << "  -f <filter>          Specify the BPF filter expression to use.\n"
			   << "  -h                   Show this help message.",
		   void();
}

void handleOptions(int argc, const char *argv[], std::string &device_name, int &packets_count, std::string &filter_expression)
{
	// Convert argv to vector of strings for easier handling
	std::vector<std::string> arguments(argv, argv + argc);

	for (int i = 1; i < argc; ++i)
	{
		if (arguments[i] == "-i")
		{
			if (i + 1 < argc)
			{
				device_name = arguments[++i];
			}
			else
			{
				std::cerr << "ERROR: Missing argument for -i option.\n";
				displayUsage();
				exit(1);
			}
		}
		else if (arguments[i] == "-n")
		{
			if (i + 1 < argc)
			{
				try
				{
					packets_count = std::stoi(arguments[++i]);
				}
				catch (const std::out_of_range &e)
				{
					std::cerr << "ERROR: Input number is out of range";
					exit(1);
				}
				catch (const std::invalid_argument &e)
				{
					std::cerr << "ERROR: Invalid input";
					exit(1);
				}
				if (packets_count < 0)
				{
					std::cerr << "ERROR: Input number cannot be negative";
					exit(1);
				}
			}
			else
			{
				std::cerr << "ERROR: Missing argument for -n option.\n";
				displayUsage();
				exit(1);
			}
		}
		else if (arguments[i] == "-f")
		{
			for (++i; i < argc && arguments[i][0] != '-'; ++i)
			{
				if (!filter_expression.empty())
					filter_expression += " ";
				filter_expression += arguments[i];
			}
			--i; // Step back to avoid skipping next option
		}
		else if (arguments[i] == "-h")
		{
			displayUsage();
			exit(1);
		}
		else
		{
			// std::cerr << "ERROR: Unknown option " << argList[i] << "\n";
			displayUsage();
			exit(1);
		}
	}

	return;
}

void selectDeviceName(char *error_buffer, std::string &device_name)
{

	pcap_if_t *alldevsp;
	if (pcap_findalldevs(&alldevsp, error_buffer))
	{
		std::cerr << "ERROR: pcap_findalldevs() -> " << error_buffer;
		exit(1);
	}
	std::vector<std::string> devs;
	std::cout << "\nAvailable Devices are :\n";
	int count = 1;
	for (pcap_if_t *dev = alldevsp; dev != nullptr; dev = dev->next)
	{
		std::cout << count << ". " << dev->name << " - " << (dev->description ? dev->description : "No description") << "\n";
		if (dev->name != nullptr)
		{
			devs.push_back(dev->name);
		}
		++count;
	}
	pcap_freealldevs(alldevsp);
	int device_number;

	std::cout << "Enter the number of the device you want to sniff: ";
	std::cin >> device_number;

	// validation
	if (device_number > 0 && device_number <= devs.size())
	{
		device_name = devs[device_number - 1];
		std::cout << "You selected: " << device_name << "\n";
	}
	else
	{
		std::cerr << "Invalid selection. Please choose a number between 1 and " << devs.size() << ".\n";
		exit(1);
	}
}

int main(int argc, const char *argv[])
{
	std::string device_name = "";
	std::string filter_expression = "";
	int packets_count = DEFAULT_PACKET_COUNT; // Default packet count

	handleOptions(argc, argv, device_name, packets_count, filter_expression);

	char error_buffer[PCAP_ERRBUF_SIZE];

	if (device_name.empty())
		selectDeviceName(error_buffer, device_name);

	// Open the capture device: 	device, snap length,promiscuous mode, buffer timeout in ms,argument to callback
	pcap_t *capdev = pcap_open_live(device_name.c_str(), BUFSIZ, 0, -1, error_buffer);

	if (capdev == nullptr)
	{
		std::cerr << "ERROR: pcap_open_live() -> " << error_buffer;
		return 1;
	}

	// Apply filter if so
	if (!filter_expression.empty())
	{
		std::cout << "Waiting for \"" << filter_expression << "\" packets...\n";
		struct bpf_program bpf;
		bpf_u_int32 netmask;
		if (pcap_compile(capdev, &bpf, filter_expression.c_str(), 0, netmask) == PCAP_ERROR)
		{
			std::cerr << "ERROR: pcap_compile() -> " << pcap_geterr(capdev);
			return 1;
		}
		if (pcap_setfilter(capdev, &bpf) == PCAP_ERROR)
		{
			std::cerr << "ERROR: pcap_setfilter() -> " << pcap_geterr(capdev);
			return 1;
		}
	}
	int link_hdr_type = pcap_datalink(capdev); // frame header
	int link_hdr_length = 0;

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

	if (pcap_loop(capdev, packets_count, headerLooker, (u_char *)&link_hdr_length)) // pcap_loop() passes packet data to the callback function
	{
		std::cerr << "ERROR: pcap_loop() -> " << pcap_geterr(capdev);
		return 1;
	}

	return 0;
}
