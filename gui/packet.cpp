#include <string>
#include <vector>

struct Ethernet_Header
{
    std::string source;
    std::string destiny;
    int protocol;
};
struct IP_Header
{
    int version;
    int header_length; //  DWORDS or  Bytes
    int total_length;  // Bytes(Size of Packet)
    int id;
    int ttl;
    int tos; // type of service
    int checksum;
    std::string protocol;
    std::string source;
    std::string destiny;
    std::vector<u_char> header_data;
};

struct TCP_Header
{
    int source_port;
    int destination_port;
    int sequence_number;
    int acknowledge_number;
    int header_length;
    int urgent_flag;
    int Acknowledgement_flag;
    int push_flag;
    int reset_flag;
    int synchronise_flag;
    int finish_flag;
    int window;
    int checksum;
    int urgent_pointer;
    std::vector<u_char> header_data;
    std::vector<u_char> data_payload;
};

struct UDP_Header
{
    int source_port;
    int destination_port;
    int length;
    int checksum;
    std::vector<u_char> header_data;
    std::vector<u_char> data_payload;
};

struct ICMP_Header
{
    std::string type; //(TTL Expired) or (ICMP Echo Reply)
    int code;
    int checksum;
    std::vector<u_char> header_data;
    std::vector<u_char> data_payload;
};

struct Packet
{
    Ethernet_Header eth_hdr;
    IP_Header ip_hdr;
    TCP_Header tcp_hdr;
    UDP_Header udp_hdr;
    ICMP_Header icmp_hdr;
};