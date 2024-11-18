#include "raylib.h"
#include <vector>
#include <iostream>
#include <string>
#include <utility>
#include <pcap/pcap.h>       // inet_ntoa
#include <netinet/ip_icmp.h> // icmp_header
#include <netinet/tcp.h>     // tcp_header
#include <netinet/udp.h>     // udp_header
#include <netinet/if_ether.h>
#include <fstream>
#include "packet.cpp"

// Función para mostrar popup de error

void showErrorPopup(const std::string &errorMessage)
{
    int screenWidth = GetScreenWidth();
    int screenHeight = GetScreenHeight();

    // Base resolution for scaling
    const float baseWidth = 800.0f;
    const float baseHeight = 600.0f;

    const int basePopupWidth = 600;
    const int baseTextX = 120;
    const int baseTextY = 260;
    const int baseLineHeight = 20;
    const int baseButtonX = 340;
    const int baseButtonY = 340;
    const int baseButtonWidth = 120;
    const int baseButtonHeight = 40;

    while (!WindowShouldClose())
    {
        float scaleX = screenWidth / baseWidth;
        float scaleY = screenHeight / baseHeight;

        int popupWidth = basePopupWidth * scaleX;
        int popupHeight = 200 * scaleY;
        int popupX = (screenWidth - popupWidth) / 2;
        int popupY = (screenHeight - popupHeight) / 2;

        int textX = popupX + 20 * scaleX;
        int textY = popupY + 60 * scaleY;
        int lineHeight = baseLineHeight * scaleY;

        int buttonX = popupX + (popupWidth - baseButtonWidth * scaleX) / 2;
        int buttonY = popupY + popupHeight - baseButtonHeight * scaleY - 20 * scaleY;
        int buttonWidth = baseButtonWidth * scaleX;
        int buttonHeight = baseButtonHeight * scaleY;

        int textMaxWidth = popupWidth - 40 * scaleX; // Leave padding
        std::vector<std::string> wrappedText;

        // Function to wrap text
        auto wrapText = [](const std::string &text, int maxWidth, int fontSize) -> std::vector<std::string>
        {
            std::vector<std::string> lines;
            std::string line;
            for (size_t i = 0; i < text.size(); ++i)
            {
                line += text[i];
                if (MeasureText(line.c_str(), fontSize) > maxWidth || text[i] == '\n')
                {
                    if (text[i] != ' ' && text[i] != '\n')
                    {
                        size_t lastSpace = line.find_last_of(' ');
                        if (lastSpace != std::string::npos)
                        {
                            lines.push_back(line.substr(0, lastSpace));
                            line = line.substr(lastSpace + 1);
                        }
                        else
                        {
                            lines.push_back(line);
                            line.clear();
                        }
                    }
                    else
                    {
                        lines.push_back(line);
                        line.clear();
                    }
                }
            }
            if (!line.empty())
                lines.push_back(line);
            return lines;
        };

        // Rewrap text if resized
        wrappedText = wrapText(errorMessage, textMaxWidth, scaleY * 18);

        BeginDrawing();
        ClearBackground(DARKGRAY);

        // Draw popup background
        DrawRectangle(popupX, popupY, popupWidth, popupHeight, RAYWHITE);

        // Draw error title
        DrawText("Error:", textX, popupY + 20 * scaleY, scaleY * 20, RED);

        // Draw wrapped text
        int currentY = textY;
        for (const auto &line : wrappedText)
        {
            DrawText(line.c_str(), textX, currentY, scaleY * 18, BLACK);
            currentY += lineHeight;
        }

        // Draw Close button
        DrawRectangle(buttonX, buttonY, buttonWidth, buttonHeight, LIGHTGRAY);
        DrawText("Close", buttonX + buttonWidth / 4, buttonY + buttonHeight / 4, scaleY * 20, BLACK);

        if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
        {
            Vector2 mousePosition = GetMousePosition();
            if (mousePosition.x >= buttonX && mousePosition.x <= buttonX + buttonWidth &&
                mousePosition.y >= buttonY && mousePosition.y <= buttonY + buttonHeight)
            {
                break;
            }
        }

        // Handle resizing
        if (IsWindowResized())
        {
            screenWidth = GetScreenWidth();
            screenHeight = GetScreenHeight();
        }

        EndDrawing();
    }
}

std::vector<std::pair<std::string, std::string>> getDevices()
{
    std::vector<std::pair<std::string, std::string>> devices;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, error_buffer))
    {
        showErrorPopup("ERROR: pcap_findalldevs() -> " + std::string(error_buffer));
    }

    for (pcap_if_t *dev = alldevs; dev; dev = dev->next)
    {
        std::string description = dev->description ? dev->description : "No description";
        devices.emplace_back(dev->name, description);
    }

    pcap_freealldevs(alldevs);
    return devices;
}




//Le falta arreglar varias cosas
void DrawPacketData(const u_char *data, int size, float x, float y, float scaleX, float scaleY, Color color)
{
    const int lineLength = 16; // Bytes per line
    char hexLine[48 + 1];      // 16 bytes * 3 chars each ("XX ") + null terminator
    char asciiLine[lineLength + 1]; // 16 chars + null terminator
    int hexOffset = 0;          // Hex part's character offset
    int asciiOffset = 0;        // ASCII part's character offset

    float hexX = x * scaleX;  // Starting position for hex
    float asciiX = (x + 400) * scaleX; // Starting position for ASCII, 400 units to the right

    for (int i = 0; i < size; i++)
    {
        // Add hexadecimal representation to hexLine
        snprintf(&hexLine[hexOffset], 4, "%02X ", data[i]);
        hexOffset += 3;

        // Add ASCII or dot representation to asciiLine
        if (data[i] >= 32 && data[i] <= 128) // Printable range
            asciiLine[asciiOffset] = (char)data[i];
        else
            asciiLine[asciiOffset] = '.';
        asciiOffset++;

        // End of line or last byte
        if ((i + 1) % lineLength == 0 || i == size - 1)
        {
            // Null-terminate the lines
            hexLine[hexOffset] = '\0';
            asciiLine[asciiOffset] = '\0';

            // Draw hex part
            DrawText(hexLine, hexX, y * scaleY, 18 * scaleY, color);

            // Draw ASCII part aligned with hex
            DrawText(asciiLine, asciiX, y * scaleY, 18 * scaleY, color);

            // Move to next line
            y += 20 * scaleY;

            // Reset offsets
            hexOffset = 0;
            asciiOffset = 0;
        }
    }
}

void showPacketInfoWindow(const Packet &packet)
{
    int screenWidth = GetScreenWidth();
    int screenHeight = GetScreenHeight();

    // Base resolution for scaling
    const float baseWidth = 800.0f;
    const float baseHeight = 600.0f;

    while (!WindowShouldClose())
    {
        float scaleX = screenWidth / baseWidth;
        float scaleY = screenHeight / baseHeight;

        BeginDrawing();
        ClearBackground(LIGHTGRAY);

        // Title
        DrawText("Packet Details", 20 * scaleX, 20 * scaleY, 24 * scaleY, DARKGRAY);

        float yOffset = 60 * scaleY; // Vertical spacing offset

        // Display Ethernet Header
        DrawText(TextFormat("Ethernet Source: %s", packet.eth_hdr.source.c_str()),
                 20 * scaleX, yOffset, 18 * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Ethernet Destination: %s", packet.eth_hdr.destiny.c_str()),
                 20 * scaleX, yOffset, 18 * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Ethernet Protocol: %i", packet.eth_hdr.protocol),
                 20 * scaleX, yOffset, 18 * scaleY, BLACK);
        yOffset += 30 * scaleY;

    // Draw IP Header Data
          DrawText("IP Header:", 20 * scaleX, yOffset, 20 * scaleY, DARKGRAY);
        yOffset += 30 * scaleY;

        DrawText(TextFormat("Version: %i", packet.ip_hdr.version), 
                 20 * scaleX, yOffset, 18 * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Header Length: %i", packet.ip_hdr.header_length), 
                 20 * scaleX, yOffset, 18 * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Total Length: %i", packet.ip_hdr.total_length), 
                 20 * scaleX, yOffset, 18 * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Checksum: %i", packet.ip_hdr.checksum), 
                 20 * scaleX, yOffset, 18 * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Protocol: %s", packet.ip_hdr.protocol.c_str()), 
                 20 * scaleX, yOffset, 18 * scaleY, BLACK);
        yOffset += 20 * scaleY;
        DrawText("IP Header Data:", 20 * scaleX, yOffset, 18 * scaleY, BLACK);
        yOffset += 20 * scaleY;
        DrawPacketData(packet.ip_hdr.header_data.data(), packet.ip_hdr.header_data.size(),
                       20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
        yOffset += (packet.ip_hdr.header_data.size() / 16 + 1) * 20 * scaleY;

        // Display protocol-specific details
        if (packet.ip_hdr.protocol == "TCP")
        {
            DrawText("TCP Header:", 20 * scaleX, yOffset, 20 * scaleY, DARKGRAY);
            yOffset += 30 * scaleY;

            DrawText(TextFormat("Source Port: %i", packet.tcp_hdr.source_port),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Destination Port: %i", packet.tcp_hdr.destination_port),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Sequence Number: %i", packet.tcp_hdr.sequence_number),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Acknowledgement Number: %i", packet.tcp_hdr.acknowledge_number),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Header Length: %i", packet.tcp_hdr.header_length),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            // Draw TCP Header Data
            DrawText("TCP Header Data:", 20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.tcp_hdr.header_data.data(), packet.tcp_hdr.header_data.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.tcp_hdr.header_data.size() / 16 + 1) * 20 * scaleY;

            // Draw TCP Payload Data
            DrawText("TCP Payload Data:", 20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.tcp_hdr.data_payload.data(), packet.tcp_hdr.data_payload.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.tcp_hdr.data_payload.size() / 16 + 1) * 20 * scaleY;
        }
        else if (packet.ip_hdr.protocol == "UDP")
        {
            DrawText("UDP Header:", 20 * scaleX, yOffset, 20 * scaleY, DARKGRAY);
            yOffset += 30 * scaleY;

            DrawText(TextFormat("Source Port: %i", packet.udp_hdr.source_port),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Destination Port: %i", packet.udp_hdr.destination_port),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Length: %i", packet.udp_hdr.length),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Checksum: %i", packet.udp_hdr.checksum),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            // Draw UDP Header Data
            DrawText("UDP Header Data:", 20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.udp_hdr.header_data.data(), packet.udp_hdr.header_data.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.udp_hdr.header_data.size() / 16 + 1) * 20 * scaleY;

            // Draw UDP Payload Data
            DrawText("UDP Payload Data:", 20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.udp_hdr.data_payload.data(), packet.udp_hdr.data_payload.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.udp_hdr.data_payload.size() / 16 + 1) * 20 * scaleY;
        }
        else if (packet.ip_hdr.protocol == "ICMP")
        {
            DrawText("ICMP Header:", 20 * scaleX, yOffset, 20 * scaleY, DARKGRAY);
            yOffset += 30 * scaleY;

            DrawText(TextFormat("Type: %s", packet.icmp_hdr.type.c_str()),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Code: %i", packet.icmp_hdr.code),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Checksum: %i", packet.icmp_hdr.checksum),
                    20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;

            // Draw ICMP Header Data
            DrawText("ICMP Header Data:", 20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.icmp_hdr.header_data.data(), packet.icmp_hdr.header_data.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.icmp_hdr.header_data.size() / 16 + 1) * 20 * scaleY;

            // Draw ICMP Payload Data
            DrawText("ICMP Payload Data:", 20 * scaleX, yOffset, 18 * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.icmp_hdr.data_payload.data(), packet.icmp_hdr.data_payload.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.icmp_hdr.data_payload.size() / 16 + 1) * 20 * scaleY;
        }

            // Exit on ESC
            if (IsKeyPressed(KEY_ESCAPE))
            {
                break;
            }

            // Handle resizing
            if (IsWindowResized())
            {
                screenWidth = GetScreenWidth();
                screenHeight = GetScreenHeight();
            }

        EndDrawing();
    }
}

Packet processPacket(const u_char *packet_ptr, int link_hdr_length)
{
    Packet packet_info;

    // Parse Ethernet Header
    const ether_header *eth_hdr = reinterpret_cast<const ether_header *>(packet_ptr);
    packet_info.eth_hdr.source = TextFormat("%02X:%02X:%02X:%02X:%02X:%02X",
                                            eth_hdr->ether_shost[0],
                                            eth_hdr->ether_shost[1],
                                            eth_hdr->ether_shost[2],
                                            eth_hdr->ether_shost[3],
                                            eth_hdr->ether_shost[4],
                                            eth_hdr->ether_shost[5]);

    packet_info.eth_hdr.destiny = TextFormat("%02X:%02X:%02X:%02X:%02X:%02X",
                                             eth_hdr->ether_dhost[0],
                                             eth_hdr->ether_dhost[1],
                                             eth_hdr->ether_dhost[2],
                                             eth_hdr->ether_dhost[3],
                                             eth_hdr->ether_dhost[4],
                                             eth_hdr->ether_dhost[5]);
    packet_info.eth_hdr.protocol = ntohs(eth_hdr->ether_type);

    // Parse IP Header
    const u_char *current_ptr = packet_ptr + link_hdr_length; // Move past Ethernet header
    const ip *ip_hdr = reinterpret_cast<const ip *>(current_ptr);

    if (!ip_hdr)
    {
        return packet_info;
    }

    packet_info.ip_hdr.version = ip_hdr->ip_v;
    packet_info.ip_hdr.header_length = ip_hdr->ip_hl * 4; // IP header length in bytes
    packet_info.ip_hdr.total_length = ntohs(ip_hdr->ip_len);
    packet_info.ip_hdr.id = ntohs(ip_hdr->ip_id);
    packet_info.ip_hdr.source = inet_ntoa(ip_hdr->ip_src);
    packet_info.ip_hdr.destiny = inet_ntoa(ip_hdr->ip_dst);
    packet_info.ip_hdr.ttl = ip_hdr->ip_ttl;
    packet_info.ip_hdr.tos = ip_hdr->ip_tos;
    packet_info.ip_hdr.checksum = ip_hdr->ip_sum;
    packet_info.ip_hdr.header_data.assign(current_ptr, current_ptr + packet_info.ip_hdr.header_length);

    switch (ip_hdr->ip_p)
    {
    case IPPROTO_TCP:
    {
        packet_info.ip_hdr.protocol = "TCP";

        // Parse TCP Header
        const tcphdr *tcp_hdr = reinterpret_cast<const tcphdr *>(current_ptr + packet_info.ip_hdr.header_length);
        packet_info.tcp_hdr.source_port = ntohs(tcp_hdr->th_sport);
        packet_info.tcp_hdr.destination_port = ntohs(tcp_hdr->th_dport);
        packet_info.tcp_hdr.sequence_number = ntohl(tcp_hdr->th_seq);
        packet_info.tcp_hdr.acknowledge_number = ntohl(tcp_hdr->th_ack);
        packet_info.tcp_hdr.header_length = tcp_hdr->th_off * 4; // TCP header length in bytes
        packet_info.tcp_hdr.header_data.assign(reinterpret_cast<const u_char *>(tcp_hdr),
                                               reinterpret_cast<const u_char *>(tcp_hdr) + packet_info.tcp_hdr.header_length);
        int header_size = packet_info.ip_hdr.header_length + packet_info.tcp_hdr.header_length;
        packet_info.tcp_hdr.header_data.assign(
            reinterpret_cast<const u_char *>(tcp_hdr),
            reinterpret_cast<const u_char *>(tcp_hdr) + packet_info.tcp_hdr.header_length);

        int payload_length = packet_info.ip_hdr.total_length - header_size;

        if (payload_length > 0)
        {
            packet_info.tcp_hdr.data_payload.assign(
                current_ptr + header_size,
                current_ptr + header_size + payload_length); // raw
        }
    }
    case IPPROTO_UDP:
    {
        packet_info.ip_hdr.protocol = "UDP";
        const udphdr *udp_hdr = reinterpret_cast<const udphdr *>(current_ptr + packet_info.ip_hdr.header_length);
        packet_info.udp_hdr.source_port = ntohs(udp_hdr->uh_sport);
        packet_info.udp_hdr.destination_port = ntohs(udp_hdr->uh_dport);
        packet_info.udp_hdr.length = ntohs(udp_hdr->uh_ulen);

        int header_size = sizeof(udphdr);
        packet_info.udp_hdr.header_data.assign(
            reinterpret_cast<const u_char *>(udp_hdr),
            reinterpret_cast<const u_char *>(udp_hdr) + header_size);

        int payload_length = packet_info.ip_hdr.total_length - (packet_info.ip_hdr.header_length + header_size);

        if (payload_length > 0)
        {
            packet_info.udp_hdr.data_payload.assign(
                current_ptr + packet_info.ip_hdr.header_length + header_size,
                current_ptr + packet_info.ip_hdr.header_length + header_size + payload_length);
        }

        break;
    }
    case IPPROTO_ICMP:
    {
        packet_info.ip_hdr.protocol = "ICMP";

        // Parse ICMP Header
        const icmp *icmp_hdr = reinterpret_cast<const icmp *>(current_ptr + packet_info.ip_hdr.header_length);
        packet_info.icmp_hdr.type = icmp_hdr->icmp_type;
        packet_info.icmp_hdr.code = icmp_hdr->icmp_code;
        packet_info.icmp_hdr.checksum = ntohs(icmp_hdr->icmp_cksum);

        int header_size = sizeof(icmp);
        packet_info.icmp_hdr.header_data.assign(
            reinterpret_cast<const u_char *>(icmp_hdr),
            reinterpret_cast<const u_char *>(icmp_hdr) + header_size);

        int payload_length = packet_info.ip_hdr.total_length - (packet_info.ip_hdr.header_length + header_size);

        // Validate and extract payload
        if (payload_length > 0)
        {
            packet_info.icmp_hdr.data_payload.assign(
                current_ptr + packet_info.ip_hdr.header_length + header_size,
                current_ptr + packet_info.ip_hdr.header_length + header_size + payload_length);
        }
        break;
    }
    default:
        packet_info.ip_hdr.protocol = "UNKNOWN";
        break;
    }
    return packet_info;
}
void captureWindow(pcap_t *capture_device, std::string &capture_filter)
{
    // Apply filter if specified
    if (!capture_filter.empty())
    {
        struct bpf_program bpf;
        bpf_u_int32 netmask;
        if (pcap_compile(capture_device, &bpf, capture_filter.c_str(), 0, netmask) == PCAP_ERROR)
        {
            showErrorPopup("ERROR: pcap_compile() -> " + std::string(pcap_geterr(capture_device)));
        }
        if (pcap_setfilter(capture_device, &bpf) == PCAP_ERROR)
        {
            showErrorPopup("ERROR: pcap_setfilter() -> " + std::string(pcap_geterr(capture_device)));
        }
    }

    // Packet-related variables
    int link_hdr_type = pcap_datalink(capture_device);
    int link_hdr_length = (link_hdr_type == DLT_NULL) ? 4 : (link_hdr_type == DLT_EN10MB)   ? 14
                                                        : (link_hdr_type == DLT_IEEE802_11) ? 24
                                                                                            : 0;

    struct pcap_pkthdr *pkthdr;
    const u_char *packet_ptr;

    std::vector<Packet> packets;

    int selected_index = 0;
    bool is_paused = false;
    int scroll_offset = 0;

    // Base resolution for scaling
    const float baseWidth = 800.0f;
    const float baseHeight = 600.0f;
    const int ROW_HEIGHT = 22;
    const int VISIBLE_ROWS = 22;

    int screenWidth = GetScreenWidth();
    int screenHeight = GetScreenHeight();

    // GUI loop
    while (!WindowShouldClose())
    {
        float scaleX = screenWidth / baseWidth;
        float scaleY = screenHeight / baseHeight;

        if (!is_paused)
        {
            int res = pcap_next_ex(capture_device, &pkthdr, &packet_ptr);
            if (res == 1)
            {
                Packet new_packet = processPacket(packet_ptr, link_hdr_length);
                packets.push_back(new_packet);
            }
        }

        // Handle user input
        if (IsKeyPressed(KEY_DOWN) && selected_index < static_cast<int>(packets.size()) - 1)
        {
            selected_index++;
            if (selected_index - scroll_offset >= VISIBLE_ROWS)
                scroll_offset++;
        }
        if (IsKeyPressed(KEY_UP) && selected_index > 0)
        {
            selected_index--;
            if (selected_index < scroll_offset)
                scroll_offset--;
        }
        if (IsKeyDown(KEY_RIGHT) && selected_index < static_cast<int>(packets.size()) - 1)
        {
            selected_index++;
            if (selected_index - scroll_offset >= VISIBLE_ROWS)
                scroll_offset++;
        }
        if (IsKeyDown(KEY_LEFT) && selected_index > 0)
        {
            selected_index--;
            if (selected_index < scroll_offset)
                scroll_offset--;
        }
        if (IsKeyPressed(KEY_P))
            is_paused = !is_paused;

        if (IsKeyPressed(KEY_C))
            packets.clear();

        if (IsKeyPressed(KEY_ENTER) && !packets.empty())
            showPacketInfoWindow(packets[selected_index]);

        // GUI rendering
        BeginDrawing();
        ClearBackground(RAYWHITE);

        // Top menu with dynamic text
        DrawText(TextFormat("Options: P = %s | UP/DOWN = Select Packet | ENTER = View Raw Data",
                            is_paused ? "Resume" : "Pause"),
                 10 * scaleX, 10 * scaleY, 18 * scaleY, DARKGRAY);

        // Table header
        DrawRectangle(10 * scaleX, 40 * scaleY, 780 * scaleX, 20 * scaleY, LIGHTGRAY);
        DrawLine(10 * scaleX, 60 * scaleY, 790 * scaleX, 60 * scaleY, DARKGRAY);

        DrawText("ID", 20 * scaleX, 45 * scaleY, 18 * scaleY, BLACK);
        DrawText("SRC IP", 70 * scaleX, 45 * scaleY, 18 * scaleY, BLACK);
        DrawText("DST IP", 250 * scaleX, 45 * scaleY, 18 * scaleY, BLACK);
        DrawText("TTL", 550 * scaleX, 45 * scaleY, 18 * scaleY, BLACK);
        DrawText("TOS", 600 * scaleX, 45 * scaleY, 18 * scaleY, BLACK);
        DrawText("PROTO", 450 * scaleX, 45 * scaleY, 18 * scaleY, BLACK);

        // Draw packet data
        int y_offset = 70 * scaleY;
        for (unsigned int i = scroll_offset; i < packets.size() && i < scroll_offset + VISIBLE_ROWS; ++i)
        {
            const auto &packet = packets[i];
            Color row_color = (i == selected_index) ? SKYBLUE : BLACK;

            DrawText(TextFormat("%d", packet.ip_hdr.id), 20 * scaleX, y_offset, 18 * scaleY, row_color);
            DrawText(packet.ip_hdr.source.c_str(), 70 * scaleX, y_offset, 18 * scaleY, row_color);
            DrawText(packet.ip_hdr.destiny.c_str(), 250 * scaleX, y_offset, 18 * scaleY, row_color);
            DrawText(TextFormat("%d", packet.ip_hdr.ttl), 550 * scaleX, y_offset, 18 * scaleY, row_color);
            DrawText(TextFormat("0x%02X", packet.ip_hdr.tos), 600 * scaleX, y_offset, 18 * scaleY, row_color);
            DrawText(packet.ip_hdr.protocol.c_str(), 450 * scaleX, y_offset, 18 * scaleY, row_color);

            y_offset += ROW_HEIGHT * scaleY;
        }

        // Draw Scrollbar
        if (packets.size() > VISIBLE_ROWS)
        {
            float tableHeight = screenHeight - (70 * scaleY); // Available height for the table
            float scrollbar_height = tableHeight * (static_cast<float>(VISIBLE_ROWS) / packets.size());
            float scrollbar_pos = tableHeight * (static_cast<float>(scroll_offset) / packets.size());

            if (scrollbar_height > tableHeight)
                scrollbar_height = tableHeight; // Ensure the scrollbar doesn't exceed the table height

            DrawRectangle(790 * scaleX, (40 * scaleY) + scrollbar_pos, 10 * scaleX, scrollbar_height, DARKGRAY);
        }

        if (IsWindowResized())
        {
            screenWidth = GetScreenWidth();
            screenHeight = GetScreenHeight();
        }

        EndDrawing();
    }
}

void firstWindow(std::string &selected_device, std::string &capture_filter)
{
    std::vector<std::pair<std::string, std::string>> devices = getDevices();
    int selected_index = 0;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int screenWidth = GetScreenWidth();
    int screenHeight = GetScreenHeight();

    // Base resolution for scaling
    const float baseWidth = 800.0f;
    const float baseHeight = 600.0f;

    Rectangle textBox = {10, 80, 780, 40}; // Define a rectangle for the capture filter input box
    bool mouseOnText = false;
    int framesCounter = 0;

    while (!WindowShouldClose())
    {
        BeginDrawing();
        ClearBackground(RAYWHITE);

        float scaleX = screenWidth / baseWidth;
        float scaleY = screenHeight / baseHeight;

        // Adjust the positions and sizes using scaleX and scaleY
        DrawText("Capture:", scaleX * 10, scaleY * 10, scaleY * 20, DARKGRAY);

        // Capture filter input
        DrawText("Enter capture filter:", scaleX * 10, scaleY * 50, scaleY * 20, DARKGRAY);

        // Adjust the input box dimensions
        Rectangle scaledTextBox = {
            textBox.x * scaleX,
            textBox.y * scaleY,
            textBox.width * scaleX,
            textBox.height * scaleY};

        // Draw the input box
        DrawRectangleRec(scaledTextBox, LIGHTGRAY);
        if (mouseOnText)
            DrawRectangleLines((int)scaledTextBox.x, (int)scaledTextBox.y, (int)scaledTextBox.width, (int)scaledTextBox.height, RED);
        else
            DrawRectangleLines((int)scaledTextBox.x, (int)scaledTextBox.y, (int)scaledTextBox.width, (int)scaledTextBox.height, DARKGRAY);

        // Show the current capture filter text inside the input box
        DrawText(capture_filter.c_str(), (int)(scaledTextBox.x + 5), (int)(scaledTextBox.y + 8), scaleY * 20, BLACK);

        // Move down the devices section
        int devicesStartY = screenHeight / 4; // Adjust devices start position

        // Display device selection
        DrawText("Select a device/interface:", scaleX * 10, devicesStartY, scaleY * 20, DARKGRAY);

        for (size_t i = 0; i < devices.size(); ++i)
        {
            if (i == selected_index)
            {
                DrawRectangle(scaleX * 10, devicesStartY + scaleY * (30 + i * 30), scaleX * 780, scaleY * 30, LIGHTGRAY);
            }
            std::string device_name_description = devices[i].first + " - " + devices[i].second;
            DrawText(device_name_description.c_str(), scaleX * 20, devicesStartY + scaleY * (35 + i * 30), scaleY * 20, BLACK);
        }

        if (IsKeyPressed(KEY_DOWN) && selected_index < (int)devices.size() - 1)
        {
            selected_index++;
        }
        if (IsKeyPressed(KEY_UP) && selected_index > 0)
        {
            selected_index--;
        }
        if (IsKeyPressed(KEY_ENTER) && !devices.empty())
        {
            selected_device = devices[selected_index].first;
            break;
        }
        if (IsWindowResized())
        {
            screenWidth = GetScreenWidth();
            screenHeight = GetScreenHeight();
        }

        // Handle filter text input (Raylib input box logic)
        if (CheckCollisionPointRec(GetMousePosition(), scaledTextBox))
        {
            mouseOnText = true;
            SetMouseCursor(MOUSE_CURSOR_IBEAM); // Change cursor to I-beam when over the text box
        }
        else
        {
            mouseOnText = false;
            SetMouseCursor(MOUSE_CURSOR_DEFAULT); // Reset cursor when not over the text box
        }

        if (mouseOnText)
        {
            // Get the next character pressed (unicode)
            int key = GetCharPressed();

            // Process all the characters in the input queue
            while (key > 0)
            {
                // Only allow printable characters within the valid range (32 to 125)
                if ((key >= 32) && (key <= 125) && capture_filter.length() < 100)
                {
                    capture_filter += (char)key; // Append the character to the capture filter string
                }
                key = GetCharPressed(); // Check for more characters in the input buffer
            }

            // Handle backspace
            if (IsKeyPressed(KEY_BACKSPACE) && !capture_filter.empty())
            {
                capture_filter.pop_back(); // Remove the last character if backspace is pressed
            }
        }

        EndDrawing();
    }
}

int main()
{
    SetConfigFlags(FLAG_WINDOW_RESIZABLE);
    InitWindow(800, 600, "pcapsule");
    SetTargetFPS(60);
    SetExitKey(KEY_NULL);
    std::string selected_device;
    std::string capture_filter;
    firstWindow(selected_device, capture_filter);

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *capture_device = pcap_open_live(selected_device.c_str(), BUFSIZ, 0, -1, error_buffer);
    if (capture_device == nullptr)
    {
        showErrorPopup("ERROR: pcap_open_live() -> " + std::string(error_buffer)); // usually sudo problem
    }

    captureWindow(capture_device, capture_filter);

    CloseWindow();
    pcap_close(capture_device);
    return 0;
}
