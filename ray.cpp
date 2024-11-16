#include "raylib.h"
#include <vector>
#include <iostream>
#include <string>
#include <utility>
#include <cstdlib>			 // exit()
#include <pcap/pcap.h>		 // inet_ntoa
#include <netinet/ip_icmp.h> // icmp_header
#include <netinet/tcp.h>	 // tcp_header
#include <netinet/udp.h>	 // udp_header
#include <fstream>




// Función para mostrar popup de error
void showErrorPopup(const std::string &errorMessage) {
    const int popupWidth = 600;
    const int textX = 120;
    const int textY = 260;
    const int lineHeight = 20;
    const int textMaxWidth = popupWidth - 40; // Leave padding
    std::vector<std::string> wrappedText;

    // Function to wrap text
    auto wrapText = [](const std::string &text, int maxWidth) -> std::vector<std::string> {
        std::vector<std::string> lines;
        std::string line;
        for (size_t i = 0; i < text.size(); ++i) {
            line += text[i];
            if (MeasureText(line.c_str(), 18) > maxWidth || text[i] == '\n') {
                if (text[i] != ' ' && text[i] != '\n') {
                    size_t lastSpace = line.find_last_of(' ');
                    if (lastSpace != std::string::npos) {
                        lines.push_back(line.substr(0, lastSpace));
                        line = line.substr(lastSpace + 1);
                    } else {
                        lines.push_back(line);
                        line.clear();
                    }
                } else {
                    lines.push_back(line);
                    line.clear();
                }
            }
        }
        if (!line.empty()) lines.push_back(line);
        return lines;
    };

    wrappedText = wrapText(errorMessage, textMaxWidth);

    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(DARKGRAY);

        DrawRectangle(100, 200, 600, 200, RAYWHITE);
        DrawText("Error:", 120, 220, 20, RED);

        // Draw wrapped text
        int currentY = textY;
        for (const auto &line : wrappedText) {
            DrawText(line.c_str(), textX, currentY, 18, BLACK);
            currentY += lineHeight;
        }

        DrawRectangle(340, 340, 120, 40, LIGHTGRAY);
        DrawText("Close", 370, 350, 20, BLACK);

        if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
            Vector2 mousePosition = GetMousePosition();
            if (mousePosition.x >= 340 && mousePosition.x <= 460 &&
                mousePosition.y >= 340 && mousePosition.y <= 380) {
                CloseWindow();
                exit(1);
            }
        }

        EndDrawing();
    }
}

std::vector<std::pair<std::string, std::string>> getDevices() {
    std::vector<std::pair<std::string, std::string>> devices;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

	if (pcap_findalldevs(&alldevs, error_buffer)){
        showErrorPopup("ERROR: pcap_findalldevs() -> " + std::string(error_buffer));
    }

    for (pcap_if_t *dev = alldevs; dev; dev = dev->next) {
        std::string description = dev->description ? dev->description : "No description";
        devices.emplace_back(dev->name, description);
    }

    pcap_freealldevs(alldevs);
    return devices;
}

void selectDeviceWindow(std::string& selected_device){

    std::vector<std::pair<std::string, std::string>> devices = getDevices();
    int selected_index = 0;
    char error_buffer[PCAP_ERRBUF_SIZE];

    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(RAYWHITE);

        DrawText("Select a device/interface:", 10, 10, 20, DARKGRAY);

        for (size_t i = 0; i < devices.size(); ++i) {
            if (i == selected_index) {
                DrawRectangle(10, 40 + i * 30, 780, 30, LIGHTGRAY);
            }
            std::string device_name_description = devices[i].first + " - " + devices[i].second;
            DrawText(device_name_description.c_str(), 20, 45 + i * 30, 20, BLACK);
        }

        if (IsKeyPressed(KEY_DOWN) && selected_index < (int)devices.size() - 1) {
            selected_index++;
        }
        if (IsKeyPressed(KEY_UP) && selected_index > 0) {
            selected_index--;
        }
        if (IsKeyPressed(KEY_ENTER) && !devices.empty()) {
            selected_device = devices[selected_index].first;
            break;
        }
        EndDrawing();
    }
}
void captureWindow(pcap_t* capture_device, int link_hdr_length) {
    struct pcap_pkthdr* pkthdr;
    const u_char* packet_ptr;

    // Store captured packet information
    struct PacketInfo {
        int id;
        std::string src_ip;
        std::string dst_ip;
        std::string protocol;
        int ttl;
        int tos;
    };
    std::vector<PacketInfo> packets;

    // GUI loop
    while (!WindowShouldClose()) {
        // Capture packets
        int res = pcap_next_ex(capture_device, &pkthdr, &packet_ptr);
        if (res == 1) { // Packet successfully captured
            const u_char* current_ptr = packet_ptr + link_hdr_length;
            struct ip* ip_hdr = (struct ip*)current_ptr;

            PacketInfo packet_info;
            packet_info.id = ntohs(ip_hdr->ip_id);
            packet_info.src_ip = inet_ntoa(ip_hdr->ip_src);
            packet_info.dst_ip = inet_ntoa(ip_hdr->ip_dst);
            packet_info.ttl = ip_hdr->ip_ttl;
            packet_info.tos = ip_hdr->ip_tos;

            // Determine protocol
            int protocol_type = ip_hdr->ip_p;
            switch (protocol_type) {
                case IPPROTO_TCP: packet_info.protocol = "TCP"; break;
                case IPPROTO_UDP: packet_info.protocol = "UDP"; break;
                case IPPROTO_ICMP: packet_info.protocol = "ICMP"; break;
                default: packet_info.protocol = "UNKNOWN"; break;
            }

            packets.push_back(packet_info);
            if (packets.size() > 20) {
                packets.erase(packets.begin()); // Keep the list size manageable
            }
        }

        // Draw packets in a table
        BeginDrawing();
        ClearBackground(RAYWHITE);

        DrawText("Captured Packets:", 10, 10, 20, DARKGRAY);
        DrawRectangle(10, 40, 780, 500, LIGHTGRAY);
        DrawLine(10, 70, 790, 70, DARKGRAY); // Table header separator

        // Draw table header
        DrawText("ID", 20, 50, 18, BLACK);
        DrawText("SRC IP", 70, 50, 18, BLACK);
        DrawText("DST IP", 250, 50, 18, BLACK);
        DrawText("PROTO", 450, 50, 18, BLACK);
        DrawText("TTL", 550, 50, 18, BLACK);
        DrawText("TOS", 600, 50, 18, BLACK);

        // Draw captured packet data
        int y_offset = 80;
        for (size_t i = 0; i < packets.size(); ++i) {
            const auto& packet = packets[i];
            DrawText(TextFormat("%d", packet.id), 20, y_offset, 18, BLACK);
            DrawText(packet.src_ip.c_str(), 70, y_offset, 18, BLACK);
            DrawText(packet.dst_ip.c_str(), 250, y_offset, 18, BLACK);
            DrawText(packet.protocol.c_str(), 450, y_offset, 18, BLACK);
            DrawText(TextFormat("%d", packet.ttl), 550, y_offset, 18, BLACK);
            DrawText(TextFormat("0x%02X", packet.tos), 600, y_offset, 18, BLACK);
            y_offset += 20;
        }

        // Add Stop button
        DrawRectangle(10, 550, 100, 30, RED);
        DrawText("STOP", 30, 555, 20, WHITE);
        if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
            Vector2 mousePos = GetMousePosition();
            if (mousePos.x >= 10 && mousePos.x <= 110 && mousePos.y >= 550 && mousePos.y <= 580) {
                break; // Exit the capture loop
            }
        }

        EndDrawing();
    }
}


int main() {
    InitWindow(800, 600, "pcapsule");
    SetTargetFPS(60);
    std::string selected_device;
    selectDeviceWindow(selected_device);

    
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *capture_device = pcap_open_live(selected_device.c_str(), BUFSIZ, 0, -1, error_buffer);
    if (capture_device == nullptr)
    {
        showErrorPopup("ERROR: pcap_open_live() -> "+ std::string(error_buffer));
    }

    int link_hdr_type = pcap_datalink(capture_device); // frame header
        int link_hdr_length = 0;

    switch (link_hdr_type) {
        case DLT_NULL: link_hdr_length = 4; break;       // Loopback (lo)
        case DLT_EN10MB: link_hdr_length = 14; break;    // Ethernet
        case DLT_IEEE802_11: link_hdr_length = 24; break; // WLAN
        default: link_hdr_length = 0; break;
    }

    captureWindow(capture_device, link_hdr_length);
    pcap_close(capture_device);

    CloseWindow();
    return 0;
}
