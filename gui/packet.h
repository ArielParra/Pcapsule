#ifndef PACKET_H
#define PACKET_H
#include <string>
#include <vector>
#if defined(_WIN32)
// To avoid conflicting windows.h symbols with raylib, some flags are defined
// WARNING: Those flags avoid inclusion of some Win32 headers that could be required
// by user at some point and won't be included...
//-------------------------------------------------------------------------------------

// If defined, the following flags inhibit definition of the indicated items.
#define NOGDICAPMASKS     // CC_*, LC_*, PC_*, CP_*, TC_*, RC_
#define NOVIRTUALKEYCODES // VK_*
#define NOWINMESSAGES     // WM_*, EM_*, LB_*, CB_*
#define NOWINSTYLES       // WS_*, CS_*, ES_*, LBS_*, SBS_*, CBS_*
#define NOSYSMETRICS      // SM_*
#define NOMENUS           // MF_*
#define NOICONS           // IDI_*
#define NOKEYSTATES       // MK_*
#define NOSYSCOMMANDS     // SC_*
#define NORASTEROPS       // Binary and Tertiary raster ops
#define NOSHOWWINDOW      // SW_*
#define OEMRESOURCE       // OEM Resource values
#define NOATOM            // Atom Manager routines
#define NOCLIPBOARD       // Clipboard routines
#define NOCOLOR           // Screen colors
#define NOCTLMGR          // Control and Dialog routines
#define NODRAWTEXT        // DrawText() and DT_*
#define NOGDI             // All GDI defines and routines
#define NOKERNEL          // All KERNEL defines and routines
#define NOUSER            // All USER defines and routines
//#define NONLS             // All NLS defines and routines
#define NOMB              // MB_* and MessageBox()
#define NOMEMMGR          // GMEM_*, LMEM_*, GHND, LHND, associated routines
#define NOMETAFILE        // typedef METAFILEPICT
#define NOMSG             // typedef MSG and associated routines
#define NOOPENFILE        // OpenFile(), OemToAnsi, AnsiToOem, and OF_*
#define NOSCROLL          // SB_* and scrolling routines
#define NOSERVICE         // All Service Controller routines, SERVICE_ equates, etc.
#define NOSOUND           // Sound driver routines
#define NOTEXTMETRIC      // typedef TEXTMETRIC and associated routines
#define NOWH              // SetWindowsHook and WH_*
#define NOWINOFFSETS      // GWL_*, GCL_*, associated routines
#define NOCOMM            // COMM driver routines
#define NOKANJI           // Kanji support stuff.
#define NOHELP            // Help engine interface.
#define NOPROFILER        // Profiler interface.
#define NODEFERWINDOWPOS  // DeferWindowPos routines
#define NOMCX             // Modem Configuration Extensions

// Type required before windows.h inclusion
typedef struct tagMSG *LPMSG;
#include <ws2tcpip.h>
#include <windows.h>
#undef PlaySound
#undef NOMINMAX


// Type required by some unused function...
typedef struct tagBITMAPINFOHEADER {
  DWORD biSize;
  LONG  biWidth;
  LONG  biHeight;
  WORD  biPlanes;
  WORD  biBitCount;
  DWORD biCompression;
  DWORD biSizeImage;
  LONG  biXPelsPerMeter;
  LONG  biYPelsPerMeter;
  DWORD biClrUsed;
  DWORD biClrImportant;
} BITMAPINFOHEADER, *PBITMAPINFOHEADER;

#include <objbase.h>
#include <mmreg.h>
#include <mmsystem.h>

// Some required types defined for MSVC/TinyC compiler
#if defined(_MSC_VER) || defined(__TINYC__)
    #include "propidl.h"
#endif
#endif

#ifdef _WIN32
#include <pcap/pcap.h>  // inet_ntoa

    #include <cstdint>
    #pragma comment(lib, "wpcap.lib")
    #pragma comment(lib, "ws2_32.lib")
   struct ether_header {
        uint8_t ether_dhost[6]; // Destination MAC address
        uint8_t ether_shost[6]; // Source MAC address
        uint16_t ether_type;    // Ethernet type (protocol)
    };
    // IP header
    struct ip {
        uint8_t ip_hl : 4;       // Header length
        uint8_t ip_v : 4;        // Version
        uint8_t ip_tos;          // Type of service
        uint16_t ip_len;         // Total length
        uint16_t ip_id;          // Identification
        uint16_t ip_off;         // Fragment offset field
        uint8_t ip_ttl;          // Time to live
        uint8_t ip_p;            // Protocol
        uint16_t ip_sum;         // Checksum
        struct in_addr ip_src;   // Source address
        struct in_addr ip_dst;   // Destination address
    };

    // TCP header
    struct tcphdr {
        uint16_t th_sport; // Source port
        uint16_t th_dport; // Destination port
        uint32_t th_seq;   // Sequence number
        uint32_t th_ack;   // Acknowledgment number
        uint8_t th_off : 4, th_x2 : 4; // Data offset
        uint8_t th_flags; // Flags
        uint16_t th_win;  // Window
        uint16_t th_sum;  // Checksum
        uint16_t th_urp;  // Urgent pointer
    };
    struct udphdr {
        uint16_t uh_sport; // Source port
        uint16_t uh_dport; // Destination port
        uint16_t uh_ulen;   // Length
        uint16_t uh_sum;   // Checksum
    };

    struct icmphdr {
        uint8_t type;      // Message type
        uint8_t code;      // Type subcode
        uint16_t checksum; // Checksum
        uint16_t id;       // Identifier
        uint16_t seq;      // Sequence number
    };
    struct icmp {
        uint8_t icmp_type;      // Message type
        uint8_t icmp_code;      // Type subcode
        uint16_t icmp_cksum; // Checksum
        uint16_t id;       // Identifier
        uint16_t seq;      // Sequence number
    };
#else
    #include <netinet/ip_icmp.h> // ICMP header
    #include <netinet/tcp.h>     // TCP header
    #include <netinet/udp.h>     // UDP header
    #include <netinet/if_ether.h> // Ethernet header
#endif

// Ethernet Header structure
struct Ethernet_Header {
    std::string source;
    std::string destiny;
    int protocol;
};

// IP Header structure
struct IP_Header {
    int version;
    int header_length; // DWORDS or Bytes
    int total_length;  // Bytes (Size of Packet)
    int id;
    int ttl;
    int tos;           // Type of service
    int checksum;
    std::string protocol;
    std::string source;
    std::string destiny;
    std::vector<u_char> header_data;
};

// TCP Header structure
struct TCP_Header {
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

// UDP Header structure
struct UDP_Header {
    int source_port;
    int destination_port;
    int length;
    int checksum;
    std::vector<u_char> header_data;
    std::vector<u_char> data_payload;
};

// ICMP Header structure
struct ICMP_Header {
    std::string type;  // TTL Expired or ICMP Echo Reply
    int code;
    int checksum;
    std::vector<u_char> header_data;
    std::vector<u_char> data_payload;
};

// Combined Packet structure
struct Packet {
    Ethernet_Header eth_hdr;
    IP_Header ip_hdr;
    TCP_Header tcp_hdr;
    UDP_Header udp_hdr;
    ICMP_Header icmp_hdr;
};


#endif // PACKET_H