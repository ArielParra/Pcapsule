
//mostrar deviecs si no hay -i para elegir con numero/opciones 

//https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
```bash

TCP : 57   UDP : 17   ICMP : 16   IGMP : 1   Others : 0   Total : 90

***********************UDP Packet*************************

Ethernet Header
   |-Destination Address : 00-1C-C0-F8-79-EE 
   |-Source Address      : 00-1E-58-B8-D4-69 
   |-Protocol            : 8 

IP Header
   |-IP Version        : 4
   |-IP Header Length  : 5 DWORDS or 20 Bytes
   |-Type Of Service   : 0
   |-IP Total Length   : 257  Bytes(Size of Packet)
   |-Identification    : 13284
   |-TTL      : 63
   |-Protocol : 17
   |-Checksum : 55095
   |-Source IP        : 208.67.222.222
   |-Destination IP   : 192.168.0.6

UDP Header
   |-Source Port      : 53
   |-Destination Port : 33247
   |-UDP Length       : 237
   |-UDP Checksum     : 30099

IP Header
    00 1C C0 F8 79 EE 00 1E 58 B8 D4 69 08 00 45 00         ....y...X..i..E.
    01 01 33 E4                                             ..3.
UDP Header
    00 00 3F 11 D7 37 D0 43                                 ..?..7.C
Data Payload
    AF BD 81 80 00 01 00 01 00 04 00 04 02 31 36 03         ...?.........16.
    32 33 35 03 31 32 35 02 37 34 07 69 6E 2D 61 64         235.125.74.in-ad
    64 72 04 61 72 70 61 00 00 0C 00 01 C0 0C 00 0C         dr.arpa.........
    00 01 00 01 4F E5 00 1B 0F 73 69 6E 30 31 73 30         ....O....sin01s0
    34 2D 69 6E 2D 66 31 36 05 31 65 31 30 30 03 6E         4-in-f16.1e100.n
    65 74 00 C0 13 00 02 00 01 00 01 42 28 00 10 03         et.........B(...
    4E 53 31 06 47 4F 4F 47 4C 45 03 43 4F 4D 00 C0         NS1.GOOGLE.COM..
    13 00 02 00 01 00 01 42 28 00 06 03 4E 53 33 C0         .......B(...NS3.
    63 C0 13 00 02 00 01 00 01 42 28 00 06 03 4E 53         c........B(...NS
    34 C0 63 C0 13 00 02 00 01 00 01 42 28 00 06 03         4.c........B(...
    4E 53 32 C0 63 C0 5F 00 01 00 01 00 02 7E 59 00         NS2.c._......~Y.
    04 D8 EF 20 0A C0 9F 00 01 00 01 00 02 7E 59 00         ... .........~Y.
    04 D8 EF 22 0A C0 7B 00 01 00 01 00 03 81 F3 00         ..."..{.........
    04 D8 EF 24 0A C0 8D 00 01 00 01 00 02 A1 AA 00         ...$............
    04 D8 EF 26 0A                                          ...&.

###########################################################

***********************TCP Packet*************************

Ethernet Header
   |-Destination Address : 00-1E-58-B8-D4-69 
   |-Source Address      : 00-1C-C0-F8-79-EE 
   |-Protocol            : 8 

IP Header
   |-IP Version        : 4
   |-IP Header Length  : 5 DWORDS or 20 Bytes
   |-Type Of Service   : 0
   |-IP Total Length   : 57  Bytes(Size of Packet)
   |-Identification    : 45723
   |-TTL      : 64
   |-Protocol : 6
   |-Checksum : 12762
   |-Source IP        : 192.168.0.6
   |-Destination IP   : 130.239.18.172

TCP Header
   |-Source Port      : 57319
   |-Destination Port : 6667
   |-Sequence Number    : 2867385066
   |-Acknowledge Number : 443542543
   |-Header Length      : 5 DWORDS or 20 BYTES
   |-Urgent Flag          : 0
   |-Acknowledgement Flag : 1
   |-Push Flag            : 1
   |-Reset Flag           : 0
   |-Synchronise Flag     : 0
   |-Finish Flag          : 0
   |-Window         : 62780
   |-Checksum       : 22133
   |-Urgent Pointer : 0

                        DATA Dump                         
IP Header
    00 1E 58 B8 D4 69 00 1C C0 F8 79 EE 08 00 45 00         ..X..i....y...E.
    00 39 B2 9B                                             .9..
TCP Header
    40 00 40 06 31 DA C0 A8 00 06 82 EF 12 AC DF E7         @.@.1...........
    1A 0B AA E8                                             ....
Data Payload
    50 49 4E 47 20 31 33 32 33 32 37 30 35 36 36 0D         PING 1323270566.
    0A                                                      .

###########################################################

```