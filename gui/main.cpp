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
#include <ctime>
#include <iomanip>

#include "packet.cpp"

#define TITLE_FONT_SIZE 24
#define BODY_FONT_SIZE 20

bool CustomButton(Rectangle box, const char *text, Color buttonColor, Color hoverColor, Color textColor)
{
    Vector2 mousePosition = GetMousePosition();

    // Check if mouse is hovering over the button
    bool isHovered = CheckCollisionPointRec(mousePosition, box);

    // Draw the button with hover effect
    DrawRectangleRec(box, isHovered ? hoverColor : buttonColor);
    DrawRectangleLinesEx(box, 1, BLACK); // Adjust thickness as needed

    // Center the text within the button
    int fontSize = 20;
    Vector2 textSize = MeasureTextEx(GetFontDefault(), text, fontSize, 1);
    DrawText(text,
             box.x + (box.width / 2) - (textSize.x / 2),
             box.y + (box.height / 2) - (textSize.y / 2),
             fontSize, textColor);

    // Return true if the button is clicked
    return isHovered && IsMouseButtonPressed(MOUSE_BUTTON_LEFT);
}

// F for costume font
void DrawTextF(const char *text, float posX, float posY, int fontSize, Color color)
{
    // Just ctrlH all DrawText functions to this
    static const Font custom_font = LoadFont("romulus.png");
    DrawTextEx(custom_font, text, (Vector2){posX, posY}, fontSize, 1, color);
}

// Helper function to wrap text
std::vector<std::string> WrapText(const std::string &text, int maxWidth, int fontSize)
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
}

void showErrorPopup(const std::string &errorMessage)
{
    int screen_width = GetScreenWidth();
    int screen_height = GetScreenHeight();

    // Base resolution for scaling
    const float baseWidth = 800.0f;
    const float baseHeight = 600.0f;

    while (!WindowShouldClose())
    {
        float scaleX = screen_width / baseWidth;
        float scaleY = screen_height / baseHeight;

        int popupWidth = 600 * scaleX;
        int popupHeight = 200 * scaleY;
        int popupX = (screen_width - popupWidth) / 2;
        int popupY = (screen_height - popupHeight) / 2;

        int textMaxWidth = popupWidth - 40 * scaleX; // Leave padding
        int fontSize = 18 * scaleY;

        // Wrap text to fit the popup width
        std::vector<std::string> wrappedText = WrapText(errorMessage, textMaxWidth, fontSize);

        BeginDrawing();
        ClearBackground(DARKGRAY);

        Rectangle error_box = {(float)popupX, (float)popupY, (float)popupWidth, (float)popupHeight};
        DrawRectangleRec(error_box, LIGHTGRAY);
        DrawRectangleLinesEx(error_box, 2, BLACK); // Border for the popup

        // Draw wrapped text
        int textX = popupX + 20 * scaleX;
        int textY = popupY + 40 * scaleY;
        for (const auto &line : wrappedText)
        {
            DrawText(line.c_str(), textX, textY, fontSize, BLACK);
            textY += fontSize + 2; // Add line spacing
        }
        Rectangle close_button = {
            popupX + popupWidth / 2 - 60 * scaleX,
            popupY + popupHeight - 50 * scaleY,
            120 * scaleX, 30 * scaleY};
        if (CustomButton(close_button, "close", RAYWHITE, LIGHTGRAY, BLACK))
        {
            break;
        }
        if (IsWindowResized())
        {
            screen_width = GetScreenWidth();
            screen_height = GetScreenHeight();
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

void HandleTextInput(std::string &input, const int max_length)
{
    int key = GetCharPressed();

    while (key > 0)
    {
        if ((key >= 32) && (key <= 125) && input.length() < max_length)
        {
            input += (char)key;
        }
        key = GetCharPressed();
    }

    if (!input.empty())
    {
        if (IsKeyPressed(KEY_BACKSPACE))
        {
            input.pop_back();
        }
        if (IsKeyPressed(KEY_DELETE))
        {
            input.clear();
        }
    }
}


void DrawPacketData(const u_char *data, int size, float x, float y, float scaleX, float scaleY, Color color)
{
    const int lineLength = 16;
    char hexLine[48 + 1];
    char asciiLine[lineLength + 1];
    int hexOffset = 0;
    int asciiOffset = 0;

     // Font size and spacing
    int fontSize = BODY_FONT_SIZE * scaleY;
    int lineSpacing = 20 * scaleY;

     // Calculate dynamic positions
    float hexX = x * scaleX;
    int hexBlockWidth = MeasureText("XX ", fontSize) * lineLength;
    float asciiX = hexX + hexBlockWidth + (10 * scaleX);

    for (int i = 0; i < size; ++i)
    {
        // Add hexadecimal representation to hexLine
        snprintf(&hexLine[hexOffset], 4, "%02X ", data[i]);
        hexOffset += 3;

         // Add ASCII or dot representation to asciiLine
        asciiLine[asciiOffset] = (data[i] >= 32 && data[i] <= 128) ? (char)data[i] : '.';
        asciiOffset++;
        if ((i + 1) % lineLength == 0 || i == size - 1)
        {    
            // Null-terminate the lines
            hexLine[hexOffset] = '\0';
            asciiLine[asciiOffset] = '\0';

            // Draw hex part
            DrawText(hexLine, hexX, y * scaleY, fontSize, color);

             // Draw ASCII part aligned with hex
            DrawText(asciiLine, asciiX, y * scaleY, fontSize, color);

             // Move to next line
            y += lineSpacing;

             // Reset offsets
            hexOffset = 0;
            asciiOffset = 0;
        }
    }
}

std::string getTimeStamp()
{
    time_t now = std::time(nullptr);
    tm localTime = *std::localtime(&now);
    std::stringstream timestamp;
    timestamp << std::put_time(&localTime, "%Y-%m-%d_%H-%M-%S");
    return timestamp.str();
}
void savePacketRaw(const Packet &packet)
{
    // hex or chars?
    return void();
}
void packetRawWindow(const Packet &packet)
{
    int screen_width = GetScreenWidth();
    int screen_height = GetScreenHeight();

    // Base resolution for scaling
    const float baseWidth = 800.0f;
    const float baseHeight = 600.0f;

    while (!WindowShouldClose())
    {
        float scaleX = screen_width / baseWidth;
        float scaleY = screen_height / baseHeight;

        BeginDrawing();
        ClearBackground(LIGHTGRAY);

        // Title
        DrawText("Packet Details", 20 * scaleX, 20 * scaleY, 24 * scaleY, DARKGRAY);

        float yOffset = 60 * scaleY; // Vertical spacing offset

        // Display protocol-specific details
        if (packet.ip_hdr.protocol == "TCP")
        {
            // Draw TCP Raw Payload Data
            DrawText("TCP Raw Payload Data:", 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.tcp_hdr.data_payload.data(), packet.tcp_hdr.data_payload.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.tcp_hdr.data_payload.size() / 16 + 1) * 20 * scaleY;
        }
        else if (packet.ip_hdr.protocol == "UDP")
        {
            // Draw UDP Raw Payload Data
            DrawText("UDP Raw Payload Data:", 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.udp_hdr.data_payload.data(), packet.udp_hdr.data_payload.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.udp_hdr.data_payload.size() / 16 + 1) * 20 * scaleY;
        }
        else if (packet.ip_hdr.protocol == "ICMP")
        {
            // Draw ICMP Raw Payload Data
            DrawText("ICMP Raw Payload Data:", 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.icmp_hdr.data_payload.data(), packet.icmp_hdr.data_payload.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.icmp_hdr.data_payload.size() / 16 + 1) * 20 * scaleY;
        }
        else
        {
            DrawText("NO RAW DATA AVAILABLE:", 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;
            yOffset += (packet.icmp_hdr.data_payload.size() / 16 + 1) * 20 * scaleY;
        }

        // Exit on ESC
        if (IsKeyPressed(KEY_ESCAPE))
        {
            break;
        }
        if (IsKeyPressed(KEY_S))
        {
            savePacketRaw(packet);
        }

        // Handle resizing
        if (IsWindowResized())
        {
            screen_width = GetScreenWidth();
            screen_height = GetScreenHeight();
        }

        EndDrawing();
    }
}
#include <fstream>
#include <iostream>
#include <string>

void savePacketDetails(const Packet &packet)
{
    std::string filename = "packet_details_" + getTimeStamp() + ".txt";
    std::ofstream outFile(filename);

    if (!outFile.is_open())
    {
        std::cerr << "Error opening file for writing!" << std::endl;
        return;
    }

    // Save Ethernet Header
    outFile << "Ethernet Source: " << packet.eth_hdr.source << std::endl;
    outFile << "Ethernet Destination: " << packet.eth_hdr.destiny << std::endl;
    outFile << "Ethernet Protocol: " << packet.eth_hdr.protocol << std::endl;
    outFile << std::endl;

    // Save IP Header Data
    outFile << "IP Header:" << std::endl;
    outFile << "Version: " << packet.ip_hdr.version << std::endl;
    outFile << "Header Length: " << packet.ip_hdr.header_length << std::endl;
    outFile << "Total Length: " << packet.ip_hdr.total_length << std::endl;
    outFile << "Checksum: " << packet.ip_hdr.checksum << std::endl;
    outFile << "Protocol: " << packet.ip_hdr.protocol << std::endl;
    outFile << "IP Header Data: " << std::endl;
    outFile << "Data: ";
    for (auto byte : packet.ip_hdr.header_data)
    {
        outFile << std::hex << (int)byte << " ";
    }
    outFile << std::endl
            << std::endl;

    // Save protocol-specific details
    if (packet.ip_hdr.protocol == "TCP")
    {
        outFile << "TCP Header:" << std::endl;
        outFile << "Source Port: " << packet.tcp_hdr.source_port << std::endl;
        outFile << "Destination Port: " << packet.tcp_hdr.destination_port << std::endl;
        outFile << "Sequence Number: " << packet.tcp_hdr.sequence_number << std::endl;
        outFile << "Acknowledgement Number: " << packet.tcp_hdr.acknowledge_number << std::endl;
        outFile << "Header Length: " << packet.tcp_hdr.header_length << std::endl;
        outFile << "TCP Header Data: " << std::endl;
        outFile << "Data: ";
        for (auto byte : packet.tcp_hdr.header_data)
        {
            outFile << std::hex << (int)byte << " ";
        }
        outFile << std::endl
                << std::endl;
    }
    else if (packet.ip_hdr.protocol == "UDP")
    {
        outFile << "UDP Header:" << std::endl;
        outFile << "Source Port: " << packet.udp_hdr.source_port << std::endl;
        outFile << "Destination Port: " << packet.udp_hdr.destination_port << std::endl;
        outFile << "Length: " << packet.udp_hdr.length << std::endl;
        outFile << "Checksum: " << packet.udp_hdr.checksum << std::endl;
        outFile << "UDP Header Data: " << std::endl;
        outFile << "Data: ";
        for (auto byte : packet.udp_hdr.header_data)
        {
            outFile << std::hex << (int)byte << " ";
        }
        outFile << std::endl
                << std::endl;
    }
    else if (packet.ip_hdr.protocol == "ICMP")
    {
        outFile << "ICMP Header:" << std::endl;
        outFile << "Type: " << packet.icmp_hdr.type << std::endl;
        outFile << "Code: " << packet.icmp_hdr.code << std::endl;
        outFile << "Checksum: " << packet.icmp_hdr.checksum << std::endl;
        outFile << "ICMP Header Data: " << std::endl;
        outFile << "Data: ";
        for (auto byte : packet.icmp_hdr.header_data)
        {
            outFile << std::hex << (int)byte << " ";
        }
        outFile << std::endl
                << std::endl;
    }

    // Close the file
    outFile.close();
    std::cout << "Packet details saved to " << filename << std::endl;
}

void packetDetailsWindow(const Packet &packet)
{
    int screen_width = GetScreenWidth();
    int screen_height = GetScreenHeight();

    // Base resolution for scaling
    const float baseWidth = 800.0f;
    const float baseHeight = 600.0f;

    while (!WindowShouldClose())
    {
        float scaleX = screen_width / baseWidth;
        float scaleY = screen_height / baseHeight;

        BeginDrawing();
        ClearBackground(LIGHTGRAY);

        // Title
        DrawText("Packet Details", 20 * scaleX, 20 * scaleY, 24 * scaleY, DARKGRAY);

        float yOffset = 60 * scaleY; // Vertical spacing offset

        // Display Ethernet Header
        DrawText(TextFormat("Ethernet Source: %s", packet.eth_hdr.source.c_str()),
                 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Ethernet Destination: %s", packet.eth_hdr.destiny.c_str()),
                 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Ethernet Protocol: %i", packet.eth_hdr.protocol),
                 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
        yOffset += 30 * scaleY;

        // Draw IP Header Data
        DrawText("IP Header:", 20 * scaleX, yOffset, 20 * scaleY, DARKGRAY);
        yOffset += 30 * scaleY;

        DrawText(TextFormat("Version: %i", packet.ip_hdr.version),
                 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Header Length: %i", packet.ip_hdr.header_length),
                 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Total Length: %i", packet.ip_hdr.total_length),
                 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Checksum: %i", packet.ip_hdr.checksum),
                 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
        yOffset += 20 * scaleY;

        DrawText(TextFormat("Protocol: %s", packet.ip_hdr.protocol.c_str()),
                 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
        yOffset += 20 * scaleY;
        DrawText("IP Header Data:", 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
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
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Destination Port: %i", packet.tcp_hdr.destination_port),
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Sequence Number: %i", packet.tcp_hdr.sequence_number),
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Acknowledgement Number: %i", packet.tcp_hdr.acknowledge_number),
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Header Length: %i", packet.tcp_hdr.header_length),
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            // Draw TCP Header Data
            DrawText("TCP Header Data:", 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.tcp_hdr.header_data.data(), packet.tcp_hdr.header_data.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.tcp_hdr.header_data.size() / 16 + 1) * 20 * scaleY;
        }
        else if (packet.ip_hdr.protocol == "UDP")
        {
            DrawText("UDP Header:", 20 * scaleX, yOffset, 20 * scaleY, DARKGRAY);
            yOffset += 30 * scaleY;

            DrawText(TextFormat("Source Port: %i", packet.udp_hdr.source_port),
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Destination Port: %i", packet.udp_hdr.destination_port),
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Length: %i", packet.udp_hdr.length),
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Checksum: %i", packet.udp_hdr.checksum),
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            // Draw UDP Header Data
            DrawText("UDP Header Data:", 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.udp_hdr.header_data.data(), packet.udp_hdr.header_data.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.udp_hdr.header_data.size() / 16 + 1) * 20 * scaleY;
        }
        else if (packet.ip_hdr.protocol == "ICMP")
        {
            DrawText("ICMP Header:", 20 * scaleX, yOffset, 20 * scaleY, DARKGRAY);
            yOffset += 30 * scaleY;

            DrawText(TextFormat("Type: %s", packet.icmp_hdr.type.c_str()),
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Code: %i", packet.icmp_hdr.code),
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            DrawText(TextFormat("Checksum: %i", packet.icmp_hdr.checksum),
                     20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;

            // Draw ICMP Header Data
            DrawText("ICMP Header Data:", 20 * scaleX, yOffset, BODY_FONT_SIZE * scaleY, BLACK);
            yOffset += 20 * scaleY;
            DrawPacketData(packet.icmp_hdr.header_data.data(), packet.icmp_hdr.header_data.size(),
                           20 * scaleX, yOffset, scaleX, scaleY, DARKGRAY);
            yOffset += (packet.icmp_hdr.header_data.size() / 16 + 1) * 20 * scaleY;
        }

        // Exit on ESC
        if (IsKeyPressed(KEY_ESCAPE))
        {
            break;
        }

        if (IsKeyPressed(KEY_S))
        {
            savePacketDetails(packet);
        }
        // Handle resizing
        if (IsWindowResized())
        {
            screen_width = GetScreenWidth();
            screen_height = GetScreenHeight();
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

void savePacketsCSV(const std::vector<Packet> &packets)
{
    // Format the timestamp as "packets_YYYY-MM-DD_HH-MM-SS.csv"
    std::ostringstream filenameStream;
    filenameStream << "packets_"
                   << getTimeStamp()
                   << ".csv";
    std::string filename = filenameStream.str();

    // Open the file
    std::ofstream file(filename);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file for writing: " << filename << std::endl;
        return;
    }

    file << "ID,Source,Destiny,Protocol,TTL,TOS\n";

    // Write packet data
    for (const Packet &packet : packets)
    {
        file << std::dec << packet.ip_hdr.id << ","
             << packet.ip_hdr.source << ","
             << packet.ip_hdr.destiny << ","
             << packet.ip_hdr.protocol << ","
             << packet.ip_hdr.ttl << ","
             << "0x" << std::hex << std::uppercase << static_cast<int>(packet.ip_hdr.tos) << "\n";
    }

    file.close();

    std::cout << "Packet data saved to: " << filename << std::endl;
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
    const int VISIBLE_ROWS = 24;

    int screen_width = GetScreenWidth();
    int screen_height = GetScreenHeight();

    // GUI loop
    while (!WindowShouldClose())
    {
        float scaleX = screen_width / baseWidth;
        float scaleY = screen_height / baseHeight;

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

        if (selected_index > 0)
        {
            if (IsKeyPressed(KEY_UP) || IsKeyDown(KEY_LEFT))
            {
                selected_index--;
                if (selected_index < scroll_offset)
                    scroll_offset--;
            }
        }
        if (selected_index < static_cast<int>(packets.size()) - 1)
        {
            if (IsKeyDown(KEY_RIGHT) || IsKeyPressed(KEY_DOWN))
            {
                selected_index++;
                if (selected_index - scroll_offset >= ROW_HEIGHT)
                    scroll_offset++;
            }
        }

        if (IsKeyPressed(KEY_P))
            is_paused = !is_paused;

        if (IsKeyPressed(KEY_C))
            packets.clear();
        if (IsKeyPressed(KEY_S) && !packets.empty())
            savePacketsCSV(packets); // TODO

        if (IsKeyPressed(KEY_D) && !packets.empty())
            packetDetailsWindow(packets[selected_index]);

        if (IsKeyPressed(KEY_R) && !packets.empty())
            packetRawWindow(packets[selected_index]);

        // GUI rendering
        BeginDrawing();
        ClearBackground(RAYWHITE);

        // Top menu with dynamic text
        DrawText(TextFormat("P = %s | ARROWS = Select | C = clear | S = save | D = Details | R = Raw ",
                            is_paused ? "Resume" : "Pause"),
                 10 * scaleX, 10 * scaleY, BODY_FONT_SIZE * scaleY, DARKGRAY);

        // Table header
        DrawRectangle(10 * scaleX, 40 * scaleY, 780 * scaleX, 25 * scaleY, LIGHTGRAY);
        DrawLine(10 * scaleX, 65 * scaleY, 790 * scaleX, 65 * scaleY, DARKGRAY);

        DrawText("ID", 20 * scaleX, 45 * scaleY, BODY_FONT_SIZE * scaleY, BLACK);
        DrawText("SOURCE IP", 120 * scaleX, 45 * scaleY, BODY_FONT_SIZE * scaleY, BLACK);
        DrawText("DESTINY IP", 300 * scaleX, 45 * scaleY, BODY_FONT_SIZE * scaleY, BLACK);
        DrawText("PROTOCOL", 470 * scaleX, 45 * scaleY, BODY_FONT_SIZE * scaleY, BLACK);
        DrawText("TTL", 630 * scaleX, 45 * scaleY, BODY_FONT_SIZE * scaleY, BLACK);
        DrawText("TOS", 690 * scaleX, 45 * scaleY, BODY_FONT_SIZE * scaleY, BLACK);

        // Draw packet data
        int y_offset = 70 * scaleY;
        for (unsigned int i = scroll_offset; i < packets.size() && i < scroll_offset + VISIBLE_ROWS; ++i)
        {
            const auto &packet = packets[i];
            Color row_color = (i == selected_index) ? SKYBLUE : BLACK;

            DrawText(TextFormat("%d", packet.ip_hdr.id), 20 * scaleX, y_offset, BODY_FONT_SIZE * scaleY, row_color);
            DrawText(packet.ip_hdr.source.c_str(), 120 * scaleX, y_offset, BODY_FONT_SIZE * scaleY, row_color);
            DrawText(packet.ip_hdr.destiny.c_str(), 300 * scaleX, y_offset, BODY_FONT_SIZE * scaleY, row_color);
            DrawText(packet.ip_hdr.protocol.c_str(), 470 * scaleX, y_offset, BODY_FONT_SIZE * scaleY, row_color);
            DrawText(TextFormat("%d", packet.ip_hdr.ttl), 630 * scaleX, y_offset, BODY_FONT_SIZE * scaleY, row_color);
            DrawText(TextFormat("0x%02X", packet.ip_hdr.tos), 690 * scaleX, y_offset, BODY_FONT_SIZE * scaleY, row_color);

            y_offset += ROW_HEIGHT * scaleY;
        }

        // Draw Scrollbar
        if (packets.size() > ROW_HEIGHT)
        {
            float tableHeight = screen_height - (70 * scaleY); // Available height for the table
            float scrollbar_height = tableHeight * (static_cast<float>(ROW_HEIGHT) / packets.size());
            float scrollbar_pos = tableHeight * (static_cast<float>(scroll_offset) / packets.size());

            if (scrollbar_height > tableHeight)
                scrollbar_height = tableHeight; // Ensure the scrollbar doesn't exceed the table height

            DrawRectangle(790 * scaleX, (40 * scaleY) + scrollbar_pos, 10 * scaleX, scrollbar_height, DARKGRAY);
        }

        screen_width = GetScreenWidth();
        screen_height = GetScreenHeight();

        EndDrawing();
    }
}

void filterWindow(std::string &capture_filter)
{
    int screen_width = GetScreenWidth();
    int screen_height = GetScreenHeight();

    // Base resolution for scaling
    const float baseWidth = 800.0f;
    const float baseHeight = 600.0f;

    // Filter text boxes and states
    Rectangle textBoxes[5] = {
        {10, 80, 780, 40},  // IP Source
        {10, 140, 780, 40}, // IP Destination
        {10, 200, 780, 40}, // TCP Source Port
        {10, 260, 780, 40}, // TCP Destination Port
        {10, 320, 780, 40}  // Host
    };

    const std::vector<std::string> labels = {"IP Source:", "IP Destination:", "TCP Src Port:", "TCP Dst Port:", "Host:"};
    const int inputs_size = 5;
    std::vector<std::string> input_buffers(inputs_size, ""); // Initialize input buffers
    std::vector<bool> mouseOnText(inputs_size, false);

    bool showWindow = true;

    while (showWindow && !WindowShouldClose())
    {
        BeginDrawing();
        ClearBackground(DARKGRAY);

        float scaleX = screen_width / baseWidth;
        float scaleY = screen_height / baseHeight;

        for (int i = 0; i < inputs_size; ++i)
        {
            // Adjust scaled rectangle for the current text box
            Rectangle scaledTextBox = {
                textBoxes[i].x * scaleX,
                textBoxes[i].y * scaleY,
                textBoxes[i].width * scaleX,
                textBoxes[i].height * scaleY};

            // Draw label and input box
            DrawText(labels[i].c_str(), scaledTextBox.x, scaledTextBox.y - 20, scaleY + 20, WHITE);
            DrawRectangleRec(scaledTextBox, LIGHTGRAY);

            if (mouseOnText[i])
                DrawRectangleLinesEx(scaledTextBox, 2, RED);
            else
                DrawRectangleLinesEx(scaledTextBox, 2, BLACK);

            // Show the current text inside the input box
            DrawText(input_buffers[i].c_str(), scaledTextBox.x + 5, scaledTextBox.y + 10, scaleY * 20, BLACK);

            // Handle mouse interaction
            if (CheckCollisionPointRec(GetMousePosition(), scaledTextBox))
            {
                SetMouseCursor(MOUSE_CURSOR_IBEAM);
                if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
                {
                    for (int j = 0; j < inputs_size; ++j)
                        mouseOnText[j] = (j == i); // Select the clicked box
                }
            }

            // Handle text input for the active box
            if (mouseOnText[i])
            {
                HandleTextInput(input_buffers[i], 100); // Use the provided function
            }
        }

        // Apply button
        Rectangle applyButton = {250 * scaleX, 400 * scaleY, 80 * scaleX, 30 * scaleY};

        if (CustomButton(applyButton, "Apply", LIGHTGRAY, DARKGRAY, BLACK))
        {

            // Construct the filter string
            capture_filter.clear();
            if (!input_buffers[0].empty())
                capture_filter += "ip.src == " + input_buffers[0];
            if (!input_buffers[1].empty())
            {
                if (!capture_filter.empty())
                    capture_filter += " and ";
                capture_filter += "ip.dst == " + input_buffers[1];
            }
            if (!input_buffers[2].empty())
            {
                if (!capture_filter.empty())
                    capture_filter += " and ";
                capture_filter += "tcp.srcport == " + input_buffers[2];
            }
            if (!input_buffers[3].empty())
            {
                if (!capture_filter.empty())
                    capture_filter += " and ";
                capture_filter += "tcp.dstport == " + input_buffers[3];
            }
            if (!input_buffers[4].empty())
            {
                if (!capture_filter.empty())
                    capture_filter += " and ";
                capture_filter += "host " + input_buffers[4];
            }
            showWindow = false; // Close the filter window
        }

        // Cancel button
        Rectangle cancelButton = {370 * scaleX, 400 * scaleY, 80 * scaleX, 30 * scaleY};
        if (CustomButton(cancelButton, "Cancel", LIGHTGRAY, DARKGRAY, BLACK))
        {

            screen_width = GetScreenWidth();
            screen_height = GetScreenHeight();
            showWindow = false; // Close the filter window
        }

        // Handle window resizing
        if (IsWindowResized())
        {
            screen_width = GetScreenWidth();
            screen_height = GetScreenHeight();
        }

        EndDrawing();
    }
}

void deviceWindow(std::string &selected_device, std::string &capture_filter)
{
    std::vector<std::pair<std::string, std::string>> devices = getDevices();
    int selected_index = 0;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int screen_width = GetScreenWidth();
    int screen_height = GetScreenHeight();

    // Base resolution for scaling
    const float baseWidth = 800.0f;
    const float baseHeight = 600.0f;

    Rectangle textBox = {10, 80, 780, 40}; // Define a rectangle for the capture filter input box
    int framesCounter = 0;

    while (!WindowShouldClose())
    {
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
        BeginDrawing();
        ClearBackground(RAYWHITE);

        float scaleX = screen_width / baseWidth;
        float scaleY = screen_height / baseHeight;

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

        if (CheckCollisionPointRec(GetMousePosition(), scaledTextBox))
        {
            DrawRectangleLines((int)scaledTextBox.x, (int)scaledTextBox.y, (int)scaledTextBox.width, (int)scaledTextBox.height, RED);
            SetMouseCursor(MOUSE_CURSOR_IBEAM); // Change cursor to I-beam when over the text box
            HandleTextInput(capture_filter, screen_width / 12);
        }
        else
        {
            DrawRectangleLines((int)scaledTextBox.x, (int)scaledTextBox.y, (int)scaledTextBox.width, (int)scaledTextBox.height, DARKGRAY);
            SetMouseCursor(MOUSE_CURSOR_DEFAULT); // Reset cursor when not over the text box
        }

        // Show the current capture filter text inside the input box
        DrawText(capture_filter.c_str(), (int)(scaledTextBox.x + 5), (int)(scaledTextBox.y + 8), scaleY * 20, BLACK);
        Rectangle filter_window = {10 * scaleX, 130 * scaleY, 140 * scaleX, 30 * scaleY};

        if (CustomButton(filter_window, "Set Filters", LIGHTGRAY, DARKGRAY, BLACK))
        {
            filterWindow(capture_filter); // Call the filter window
        }
        // Move down the devices section
        int devicesStartY = screen_height / 3; // Adjust devices start position

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

        screen_width = GetScreenWidth();
        screen_height = GetScreenHeight();

        EndDrawing();
    }
}

int main()
{
    SetConfigFlags(FLAG_WINDOW_RESIZABLE);
    InitWindow(800, 600, "pcapsule");
    SetExitKey(KEY_NULL);
    std::string selected_device;
    std::string capture_filter;

    deviceWindow(selected_device, capture_filter);

    // Try to open capture device
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
