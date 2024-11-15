#include "raylib.h"
#include <pcap/pcap.h>
#include <vector>
#include <string>
#include <utility>

// Función para mostrar popup de error
void showErrorPopup(const std::string &errorMessage) {
    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(DARKGRAY);

        DrawRectangle(100, 200, 600, 200, RAYWHITE);
        DrawText("Error:", 120, 220, 20, RED);
        DrawText(errorMessage.c_str(), 120, 260, 18, BLACK);

        DrawRectangle(340, 340, 120, 40, LIGHTGRAY);
        DrawText("Cerrar", 370, 350, 20, BLACK);

        if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
            Vector2 mousePosition = GetMousePosition();
            if (mousePosition.x >= 340 && mousePosition.x <= 460 &&
                mousePosition.y >= 340 && mousePosition.y <= 380) {
                CloseWindow();
                exit(1); // Terminar programa con código de error
            }
        }

        EndDrawing();
    }
}

// Función para obtener dispositivos disponibles
std::vector<std::pair<std::string, std::string>> getDevices() {
    std::vector<std::pair<std::string, std::string>> devicesList;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        showErrorPopup("Error al obtener dispositivos: " + std::string(errbuf));
        // Nunca se alcanza este punto porque showErrorPopup termina el programa
    }

    for (pcap_if_t *dev = alldevs; dev; dev = dev->next) {
        std::string description = dev->description ? dev->description : "Sin descripción";
        devicesList.emplace_back(dev->name, description);
    }

    pcap_freealldevs(alldevs);
    return devicesList;
}

int main() {
    InitWindow(800, 600, "pcapsule");
    SetTargetFPS(60);

    // Obtener dispositivos de red
    std::vector<std::pair<std::string, std::string>> devices = getDevices();
    int selectedIndex = 0;
    std::string selectedDevice;

    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(RAYWHITE);

        DrawText("Selecciona un dispositivo:", 10, 10, 20, DARKGRAY);

        for (size_t i = 0; i < devices.size(); i++) {
            if (i == selectedIndex) {
                DrawRectangle(10, 40 + i * 30, 780, 30, LIGHTGRAY);
            }
            std::string deviceText = devices[i].first + " - " + devices[i].second;
            DrawText(deviceText.c_str(), 20, 45 + i * 30, 20, BLACK);
        }

        if (IsKeyPressed(KEY_DOWN) && selectedIndex < (int)devices.size() - 1) {
            selectedIndex++;
        }
        if (IsKeyPressed(KEY_UP) && selectedIndex > 0) {
            selectedIndex--;
        }
        if (IsKeyPressed(KEY_ENTER) && !devices.empty()) {
            selectedDevice = devices[selectedIndex].first;
            break; // Salir para proceder a capturar tráfico
        }

        EndDrawing();
    }

    // Mostrar dispositivo seleccionado
    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(RAYWHITE);

        DrawText("Dispositivo seleccionado:", 10, 10, 20, DARKGRAY);
        DrawText(selectedDevice.c_str(), 10, 50, 20, DARKBLUE);

        if (IsKeyPressed(KEY_ESCAPE)) {
            break; // Salir del programa
        }

        EndDrawing();
    }

    CloseWindow();
    return 0;
}
