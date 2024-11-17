#include "raylib.h"
#include <vector>
#include <iostream>
#include <string>
#include <utility>
#include <pcap/pcap.h>       // inet_ntoa
#include <netinet/ip_icmp.h> // icmp_header
#include <netinet/tcp.h>     // tcp_header
#include <netinet/udp.h>     // udp_header
#include <fstream>

// Función para mostrar popup de error
void showErrorPopup(const std::string &errorMessage)
{
    const int popupWidth = 600;
    const int textX = 120;
    const int textY = 260;
    const int lineHeight = 20;
    const int textMaxWidth = popupWidth - 40; // Leave padding
    std::vector<std::string> wrappedText;

    // Function to wrap text
    auto wrapText = [](const std::string &text, int maxWidth) -> std::vector<std::string>
    {
        std::vector<std::string> lines;
        std::string line;
        for (size_t i = 0; i < text.size(); ++i)
        {
            line += text[i];
            if (MeasureText(line.c_str(), 18) > maxWidth || text[i] == '\n')
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

    wrappedText = wrapText(errorMessage, textMaxWidth);

    while (!WindowShouldClose())
    {
        BeginDrawing();
        ClearBackground(DARKGRAY);

        DrawRectangle(100, 200, 600, 200, RAYWHITE);
        DrawText("Error:", 120, 220, 20, RED);

        // Draw wrapped text
        int currentY = textY;
        for (const auto &line : wrappedText)
        {
            DrawText(line.c_str(), textX, currentY, 18, BLACK);
            currentY += lineHeight;
        }

        DrawRectangle(340, 340, 120, 40, LIGHTGRAY);
        DrawText("Close", 370, 350, 20, BLACK);

        if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
        {
            Vector2 mousePosition = GetMousePosition();
            if (mousePosition.x >= 340 && mousePosition.x <= 460 &&
                mousePosition.y >= 340 && mousePosition.y <= 380)
            {
                CloseWindow();
            }
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


struct Packet
{
    int id;
    std::string src_ip;
    std::string dst_ip;
    int ttl;
    int tos;
    std::string protocol;
};



void showRawPacketWindow(const Packet &packet)
{
    SetWindowTitle("Raw Packet Data");
    while (!WindowShouldClose())
    {
        BeginDrawing();
        ClearBackground(LIGHTGRAY);

        DrawText("Packet Raw Data Viewer", 10, 10, 20, DARKGRAY);
        DrawText("Press ESC to return.", 10, 40, 18, RED);

        // Display raw data (replace with actual raw data logic)
        DrawText("Lorem Ipsum - Placeholder for Raw Data", 10, 80, 18, BLACK);

        if (IsKeyPressed(KEY_ESCAPE))
            break;

        EndDrawing();
    }
    SetWindowTitle("Packet Capture");
}

void captureWindow(pcap_t *capture_device, std::string &capture_filter)
{
    // Apply filter if so
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
    int link_hdr_type = pcap_datalink(capture_device); // frame header
    int link_hdr_length = 0;

    switch (link_hdr_type)
    {
    case DLT_NULL:
        link_hdr_length = 4;
        break; // Loopback (lo)
    case DLT_EN10MB:
        link_hdr_length = 14;
        break; // Ethernet
    case DLT_IEEE802_11:
        link_hdr_length = 24;
        break; // WLAN
    default:
        link_hdr_length = 0;
        break;
    }

    struct pcap_pkthdr *pkthdr;
    const u_char *packet_ptr;

    std::vector<Packet> packets;

    int selected_index = 0; // Keeps track of the selected packet index
    bool is_paused = false; // Paused state
    int scroll_offset = 0;  // For scrolling through packets

    const int ROW_HEIGHT = 22;   // Height of a single row in the table
    const int VISIBLE_ROWS = 22; // Number of rows visible at a time

    // GUI loop
    while (!WindowShouldClose())
    {
        if (!is_paused)
        {
            // Capture packets
            int res = pcap_next_ex(capture_device, &pkthdr, &packet_ptr);
            if (res == 1)
            { // Packet successfully captured
                const u_char *current_ptr = packet_ptr + link_hdr_length;
                struct ip *ip_hdr = (struct ip *)current_ptr;

                Packet packet_info;
                packet_info.id = ntohs(ip_hdr->ip_id);
                packet_info.src_ip = inet_ntoa(ip_hdr->ip_src);
                packet_info.dst_ip = inet_ntoa(ip_hdr->ip_dst);
                packet_info.ttl = ip_hdr->ip_ttl;
                packet_info.tos = ip_hdr->ip_tos;

                // Determine protocol
                int protocol_type = ip_hdr->ip_p;
                switch (protocol_type)
                {
                case IPPROTO_TCP:
                    packet_info.protocol = "TCP";
                    break;
                case IPPROTO_UDP:
                    packet_info.protocol = "UDP";
                    break;
                case IPPROTO_ICMP:
                    packet_info.protocol = "ICMP";
                    break;
                default:
                    packet_info.protocol = "UNKNOWN";
                    break;
                }

                packets.push_back(packet_info);
            }
        }

        // Handle user input
        if (IsKeyPressed(KEY_DOWN) && selected_index < static_cast<int>(packets.size()) - 1)
        {
            selected_index++;
            if (selected_index - scroll_offset >= VISIBLE_ROWS)
            {
                scroll_offset++;
            }
        }
        if (IsKeyDown(KEY_RIGHT) && selected_index < static_cast<int>(packets.size()) - 1)
        {
            selected_index++;
            if (selected_index - scroll_offset >= VISIBLE_ROWS)
            {
                scroll_offset++;
            }
        }
        if (IsKeyPressed(KEY_UP) && selected_index > 0)
        {
            selected_index--;
            if (selected_index < scroll_offset)
            {
                scroll_offset--;
            }
        }
        if (IsKeyDown(KEY_LEFT) && selected_index > 0)
        {
            selected_index--;
            if (selected_index < scroll_offset)
            {
                scroll_offset--;
            }
        }
        if (IsKeyPressed(KEY_P))
        {
            is_paused = !is_paused; // Toggle pause
        }
        if (IsKeyPressed(KEY_C))
        {
            packets.clear();
        }
        if (IsKeyPressed(KEY_ENTER) && !packets.empty())
        {
            showRawPacketWindow(packets[selected_index]);
        }

        // GUI Rendering
        BeginDrawing();
        ClearBackground(RAYWHITE);

        // Top Menu with Dynamic Pause/Resume Text
        std::string pause_text = is_paused ? "Resume" : "Pause";
        DrawText(TextFormat("Options: P = %s | UP/DOWN = Select Packet | ENTER = View Raw Data", pause_text.c_str()), 10, 10, 18, DARKGRAY);

        // Table Header
        DrawRectangle(10, 40, 780, 20, LIGHTGRAY);
        DrawLine(10, 60, 790, 60, DARKGRAY);
        DrawText("ID", 20, 45, 18, BLACK);
        DrawText("SRC IP", 70, 45, 18, BLACK);
        DrawText("DST IP", 250, 45, 18, BLACK);
        DrawText("TTL", 550, 45, 18, BLACK);
        DrawText("TOS", 600, 45, 18, BLACK);
        DrawText("PROTO", 450, 45, 18, BLACK);

        // Draw Captured Packet Data with Scrolling
        int y_offset = 70;
        for (unsigned int i = scroll_offset; i < packets.size() && i < scroll_offset + VISIBLE_ROWS; ++i)
        {
            const auto &packet = packets[i];
            Color row_color = (i == selected_index) ? SKYBLUE : BLACK;
            DrawText(TextFormat("%d", packet.id), 20, y_offset, 18, row_color);
            DrawText(packet.src_ip.c_str(), 70, y_offset, 18, row_color);
            DrawText(packet.dst_ip.c_str(), 250, y_offset, 18, row_color);
            DrawText(TextFormat("%d", packet.ttl), 550, y_offset, 18, row_color);
            DrawText(TextFormat("0x%02X", packet.tos), 600, y_offset, 18, row_color);
            DrawText(packet.protocol.c_str(), 450, y_offset, 18, row_color);
            y_offset += ROW_HEIGHT;
        }

        // Draw Scroll Indicator
        if (packets.size() > VISIBLE_ROWS)
        {
            float scrollbar_height = 500.0f * VISIBLE_ROWS / packets.size();
            float scrollbar_pos = 500.0f * scroll_offset / packets.size();
            DrawRectangle(790, 40 + scrollbar_pos, 10, scrollbar_height, DARKGRAY);
        }

        EndDrawing();
    }
}


void firstWindow(std::string &selected_device, std::string &capture_filter)
{
    std::vector<std::pair<std::string, std::string>> devices = getDevices();
    int selected_index = 0;
    char error_buffer[PCAP_ERRBUF_SIZE];

    Rectangle textBox = {10, 80, 780, 40}; // Define a rectangle for the capture filter input box
    bool mouseOnText = false;
    int framesCounter = 0;

    while (!WindowShouldClose())
    {
        BeginDrawing();
        ClearBackground(RAYWHITE);
        DrawText("Capture:", 10, 10, 20, DARKGRAY);

        // Capture filter input
        DrawText("Enter capture filter:", 10, 50, 20, DARKGRAY);

        // Draw the input box
        DrawRectangleRec(textBox, LIGHTGRAY);
        if (mouseOnText)
            DrawRectangleLines((int)textBox.x, (int)textBox.y, (int)textBox.width, (int)textBox.height, RED);
        else
            DrawRectangleLines((int)textBox.x, (int)textBox.y, (int)textBox.width, (int)textBox.height, DARKGRAY);

        // Show the current capture filter text inside the input box
        DrawText(capture_filter.c_str(), (int)textBox.x + 5, (int)textBox.y + 8, 20, BLACK);

        // Move down the devices section
        int devicesStartY = 130; // Move the start position of the devices list down to avoid overlap

        // Display device selection
        DrawText("Select a device/interface:", 10, devicesStartY, 20, DARKGRAY);

        for (size_t i = 0; i < devices.size(); ++i)
        {
            if (i == selected_index)
            {
                DrawRectangle(10, devicesStartY + 30 + i * 30, 780, 30, LIGHTGRAY);
            }
            std::string device_name_description = devices[i].first + " - " + devices[i].second;
            DrawText(device_name_description.c_str(), 20, devicesStartY + 35 + i * 30, 20, BLACK);
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

        // Handle filter text input (Raylib input box logic)
        if (CheckCollisionPointRec(GetMousePosition(), textBox))
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
