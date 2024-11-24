# Proyecto_Redes-I
Package sniffer made with libpcap in c++

## Compilación

Para compilar el programa, se requiere el compilador `gcc`/`g++` en una versión mayor o igual a C++11. Las instrucciones para compilar son las siguientes:

### Para Linux/macOS:
```bash
g++ main.cpp -lnpcap
```

### Para Windows:
```bash
g++.exe main.cpp -lwpcap
```

### Dependencias

#### Windows
1. Descarga e instala `npcap` desde <https://npcap.com/#download>.

#### macOS
1. Instala `libpcap` utilizando el gestor de paquetes [Homebrew](https://brew.sh/):
    ```bash
    brew install libpcap
    ```

#### Linux
1. **Para sistemas basados en Debian/Ubuntu**:
    ```bash
    sudo apt install libpcap-dev
    ```
2. **Para sistemas basados en Fedora**:
    ```bash
    sudo dnf install libpcap-devel
    ```
3. **Para sistemas basados en Arch Linux**:
    ```bash
    sudo pacman -S libpcap
    ```

#### Nix/NixOS
1. Si estás usando Nix o NixOS, las librerias ya están incluidos en el archivo `default.nix`. Solo es necesario ejecutar:
    ```bash
    nix-shell
    ```

## Requisitos

- [x] lenguaje de desarrollo c/c++
- [x] uso de librería libpcap para (Linux/MacOS)
- [x] interfaz basada en texto amigable con el usuario (requerida)
- [x] interfaz gráfica amigable con el usuario (opcional)
- [x] captura y análisis de paquetes,
    - [x] parada/inicio
    - [x] filtros de captura,
    - [x] exportación a archivo “csv” (requerido) o "xlsx/ods" (opcional), del tráfico capturado.
- [x] la interfaz deberá contar con 3 áreas claramente definidas:
    - [x] 1. área en donde se muestre el tráfico capturado.
    - [x] 2. área en donde se muestre la información de manera estructurada del paquete capturado que se seleccione en el área de tráfico capturado.
    - [x] 3. área en donde se muestre el contenido “raw” del paquete capturado que se seleccione en el área de tráfico capturado.
- [x] 4 diferentes tipos de filtro del tráfico capturado: 
    - [x] ip fuente
    - [x] ip destino
    - [x] puerto fuente
    - [x] puerto destino
    - [x] protocolo
    - [x] entre otros
- [ ] manual del usuario, archivo electrónico (mandatorio) o ayuda en línea (opcional).
- [ ] reporte 

## Referencias

- Ayeni, O. et al. (2021). *Design and Implementation of a Packet Sniffing Library*. Recuperado de <https://infonomics-society.org/wp-content/uploads/Design-and-Implementation-of-a-Packet-Sniffing-Library.pdf>
- Bao, C. (2022). *Write a Linux packet sniffer from scratch: part one- PF_PACKET socket and promiscuous mode*. Recuperado de <https://organicprogrammer.com/2022/02/22/how-to-implement-libpcap-on-linux-with-raw-socket-part1/>
- Casado, M. (2005). *The Sniffer's Guide to Raw Traffic* Recuperado de <http://yuba.stanford.edu/~casado/pcap/section1.html>
- npcap. (s.f.). *Npcap Development Tutorial*. Recuperado de <https://npcap.com/guide/npcap-tutorial.html>
- Martin, L. (2008). *hakin9*. Recuperado de <http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf>
- Silver Moon. (2020). *How to code a Packet Sniffer in C with Libpcap on Linux*. Recuperado de <https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/>
- talalio. (2023). *Building a packet sniffer*. Recuperado de <https://talalio.medium.com/building-a-packet-sniffer-9460f394041>
- tcpdump.org. (s.f.). *Programming with pcap*. Recuperado de <https://www.tcpdump.org/pcap.html>
- Vic Hargrave. (2022). *Develop a Packet Sniffer with Libpcap*. Recuperado de <https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/>

