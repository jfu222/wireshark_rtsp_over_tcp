#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


//以太网帧数据结构（物理层的数据帧）
typedef struct _ETHERNET_FRAME_
{
    int frame_number; //帧序号
    unsigned long long timestamp; //8bytes 帧时间戳
    char timestampStr[80]; //帧时间戳 Arrival Time: Nov  1, 2019 15:35:59.430461000 中国标准时间
    int frame_length; //4bytes 帧数据大小（不包含头部本身16字节，单位：字节）一般为 0x05EA = 1514 bytes
    int capture_length; //4bytes 捕获的帧数据大小
    int file_offset; //文件偏移

public:
    int printInfo()
    {
        printf("\n-----ETHERNET_FRAME-----\n");
        printf("frame_number: %d\n", frame_number);
        printf("timestamp: 0x%x\n", timestamp);
        printf("timestampStr: %s\n", timestampStr);
        printf("frame_length: %d (0x%x) bytes\n", frame_length, frame_length);
        printf("capture_length: %d (0x%x) bytes\n", capture_length, capture_length);
        printf("file_offset: %d (0x%x)\n", file_offset, file_offset);
        return 0;
    }
}ETHERNET_FRAME;


//数据链路层以太网帧头部（以太网协议版本II）
typedef struct _ETHERNET_II_HEADER_
{
    char destination_address[50]; //6bytes 目的MAC：厂名_序号（网卡地址） Address: HuaweiTe_70:5c:3c (08:4f:0a:70:5c:3c)
    char source_address[50]; //6bytes 源MAC：厂名_序号（网卡地址） Address: Hangzhou_68:5c:9c (48:7a:da:68:5c:9c)
    int type; //2bytes 帧内封装的上层协议类型（IP=0x0800，ARP=0806，RARP=0835 [TCP-IP详解卷1:协议 图2-1 16页]）Type: IPv4 (0x0800)

public:
    int printInfo()
    {
        printf("-----ETHERNET_II_HEADER-----\n");
        printf("destination_address: %s\n", destination_address);
        printf("source_address: %s\n", source_address);
        printf("type: 0x%04x %s\n", type, (type == 0x0800) ? "IPv4" : "unknown");
        return 0;
    }
}ETHERNET_II_HEADER;


//互联网层IP包头部 [TCP-IP详解卷1:协议 图3-1 24页]
typedef struct _INTERNET_PROTOCOL_V4_HEADER_
{
    int version; //4bit 版本 Version: 4
    int ip_header_length; //4bit IP包头部长度 Header Length: 20 bytes (5)
    int differentiated_services_field; //8bit 差分服务字段 Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
    int total_length; //16bit IP包的总长度 Total Length: 52
    int identification; //16bit 标志字段 Identification: 0x0000 (0)
    int flags_reserved_1bit; //1bit 标志字段 0 = Reserved bit: Not set
    int flags_do_not_fragment_set_1bit; //1bit 标志字段 .1.. .... .... .... = Don't fragment: Set
    int flags_more_fragments_1bit; //1bit 标志字段 ..0. .... .... .... = More fragments: Not set
    int flags_fragments_offset_13bits; //13bit 标志字段 分段偏移量（将一个IP包分段后传输时，本段的标识）...0 0000 0000 0000 = Fragment offset: 0
    int time_to_live; //8bit 生存期TTL Time to live: 62
    int protocol; //8bit 此包内封装的上层协议 Protocol: TCP (6); UDP(17) https://tools.ietf.org/html/rfc1700 Page7
    char protocol_str[10]; //8bit 此包内封装的上层协议 Protocol: TCP (6)
    int header_checksum; //16bit 头部数据的校验和 Header checksum: 0x326e [validation disabled]
    int source_ip_addr; //32bit 源IP地址 Source: 172.31.25.211
    char source_ip_addr_str[20]; //32bit 源IP地址 Source: 172.31.25.211
    int destination_ip_addr; //32bit 目的IP地址 Destination: 43.123.24.233
    char destination_ip_addr_str[20]; //32bit 目的IP地址 Destination: 43.123.24.233

public:
    int printInfo()
    {
        printf("-----INTERNET_PROTOCOL_V4_HEADER-----\n");
        printf("version: %d\n", version);
        printf("ip_header_length: %d bytes\n", ip_header_length);
        printf("differentiated_services_field: %d\n", differentiated_services_field);
        printf("total_length: %d bytes\n", total_length);
        printf("identification: %d (0x%x)\n", identification, identification);
        printf("flags_reserved_1bit: %d\n", flags_reserved_1bit);
        printf("flags_do_not_fragment_set_1bit: %d\n", flags_do_not_fragment_set_1bit);
        printf("flags_more_fragments_1bit: %d\n", flags_more_fragments_1bit);
        printf("flags_fragments_offset_13bits: %d\n", flags_fragments_offset_13bits);
        printf("time_to_live: %d\n", time_to_live);
        printf("protocol: %d\n", protocol);
        printf("protocol_str: %s\n", protocol_str);
        printf("header_checksum: 0x%x\n", header_checksum);
        printf("source_ip_addr: 0x%x\n", source_ip_addr);
        printf("source_ip_addr_str: %s\n", source_ip_addr_str);
        printf("destination_ip_addr: 0x%x\n", destination_ip_addr);
        printf("destination_ip_addr_str: %s\n", destination_ip_addr_str);
        return 0;
    }
}INTERNET_PROTOCOL_V4_HEADER;


/*
https://tools.ietf.org/html/rfc2460#section-3

IPv6 Header Format

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                         Source Address                        +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                      Destination Address                      +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct _INTERNET_PROTOCOL_V6_HEADER_
{
    int version; //4-bit Internet Protocol version number = 6
    int traffic_class; //8-bit traffic class field.
    int flow_label; //20-bit flow label.
    int payload_length; //16-bit unsigned integer. Length of the IPv6 payload, i.e., the rest of the packet following this IPv6 header, in octets.
    int next_header; //8-bit selector. Identifies the type of header immediately following the IPv6 header. Protocol: TCP (6); UDP(17) https://tools.ietf.org/html/rfc1700 Page7
    int hop_limit; //8-bit unsigned integer.  Decremented by 1 by each node that forwards the packet. The packet is discarded if Hop Limit is decremented to zero.
    char source_address[16]; //128-bit address of the originator of the packet.See [ADDRARCH]. Source: fe80::35df:9e1:c898:7eb8
    char destination_address[16]; //128-bit address of the intended recipient of the packet (possibly not the ultimate recipient, if a Routing header is present). Destination: ff02::1:2

public:
    int printInfo()
    {
        printf("-----INTERNET_PROTOCOL_V6_HEADER-----\n");
        printf("version: %d\n", version);
        printf("traffic_class: %d\n", traffic_class);
        printf("flow_label: %d\n", flow_label);
        printf("payload_length: %d bytes\n", payload_length);
        printf("next_header: %d (0x%x)\n", next_header, next_header);
        printf("hop_limit: %d\n", hop_limit);

        printf("source_address: ");
        for(int i = 0; i < 16; i += 2)
        {
            if(i != 14)
            {
                printf("%02x%02x::\n", source_address[i], source_address[i + 1]);
            }else if(i != 14)
            {
                printf("%02x%02x\n", source_address[i], source_address[i + 1]);
            }
        }
        printf("\n");
        
        printf("destination_address: ");
        for(int i = 0; i < 16; i += 2)
        {
            if(i != 14)
            {
                printf("%02x%02x::\n", destination_address[i], destination_address[i + 1]);
            }else if(i != 14)
            {
                printf("%02x%02x\n", destination_address[i], destination_address[i + 1]);
            }
        }
        printf("\n");
        return 0;
    }
}INTERNET_PROTOCOL_V6_HEADER;


typedef struct _INTERNET_PROTOCOL_HEADER_
{
    int ip_version; // 0, 4 or 6
    INTERNET_PROTOCOL_V4_HEADER ipv4;
    INTERNET_PROTOCOL_V6_HEADER ipv6;

public:
    int printInfo()
    {
        printf("-----INTERNET_PROTOCOL_HEADER-----\n");
        if(ip_version == 4)
        {
            ipv4.printInfo();
        }
        else if(ip_version == 6)
        {
            ipv6.printInfo();
        }
        else
        {
            printf("%s(%d): %s: Error: ip_version=%d; not 4 or 6\n", __FILE__, __LINE__, __FUNCTION__, ip_version);
            return -1;
        }
        return 0;
    };
}INTERNET_PROTOCOL_HEADER;


/*
TCP选项:

Kind(1byte)    Option-Total-Length(bytes)       Meaning
-----------    --------------------------       -------
0              1                                End of option list
1              1                                No-Operation
2              4=1+1+2                          Maximum Segment Size (MSS)
3              3=1+1+1                          TCP Window Scale Option (WSopt)
4              2=1+1                            SACK permitted(Selective Acknowledgment, 选择性确认)
5              2=1+1                            SACK packet
6              -                                Undefine
7              -                                Undefine
8              10=1+1+8                         TCP Timestamps Option (TSopt)

例如：kind=1，表示无操作，NOP主要是用来填充4字节对齐

例如：kind=8，表示是TCP时间戳选项，该选项总共占用10个字节，kind字段占用1个字节，
option_length字段占用1个字节，接下来的4个字节表示发生方时间戳值，剩下的最后4个
字节表示时间戳回显应答值
*/
typedef struct _TCP_OPTIONS_
{
    int kind; //8bits TCP选项的类型
    int length; //8bits TCP选项的总长度（单位：byte，包含本字段长度）
    char data[32]; //只有当length大于2时，此字段才有效

public:
    int printInfo()
    {
        printf("-----TCP_OPTIONS-----\n");
        printf("kind: %d\n", kind);
        printf("length: %d bytes\n", length);

        printf("data: ");
        if (kind == 2)
        {
            int mss = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
            printf("Maximum Segment Size (MSS): %d bytes", mss);
        }
        else if (kind == 3)
        {
            printf("TCP Window Scale Option (WSopt): %d", data[0]);
        }
        else if (kind == 8)
        {
            printf("TCP Timestamps Option (TSopt): %d", data[0]);
        }
        printf("\n");

        return 0;
    }
}TCP_OPTIONS;


//传输层TCP数据段头部 [TCP-IP详解卷1:协议 图17-2 172页] Transmission Control Protocol
typedef struct _TRANSMISSION_CONTROL_PROTOCOL_HEADER_
{
    int source_port; //16bit 源端口号 Source Port: 554
    int destination_port; //16bit 目的端口号 Destination Port: 55014
    unsigned int sequence_number; //32bit 序列号 Sequence number: 0    (relative sequence number)
    unsigned int next_sequence_number; //32bit 下一个期望的序列号 = sequence_number + tcp_payload_length
    unsigned int acknowledgment_number; //32bit 确认序列号 Acknowledgment number: 1    (relative ack number)
    int tcp_header_length; //4bit 给出头部占32比特的数目。没有任何选项字段的TCP头部长度为20字节（5x32=160比特）；最多可以有60字节的TCP头部。 1000 .... = Header Length: 32 bytes (8)
    int flags_reserved_3bit; //3bit 保留字段 000. .... .... = Reserved: Not set
    int flags_nonce_1bit; //1bit 保留字段 ....0 .... .... = Nonce: Not set
    int flags_congestion_window_reduced_1bit; //1bit 拥塞窗口减少 ...... 0... .... = Congestion Window Reduced (CWR): Not set
    int flags_ecn_echo_1bit; //1bit 显式拥塞通知Explicit Congestion Notification .... .0.. .... = ECN-Echo: Not set
    int flags_urgent_1bit; //1bit 紧急指针URG（ urgent pointer）有效 .... ..0. .... = Urgent: Not set
    int flags_acknowledgment_1bit; //1bit 确认序号有效ACK .... ...1 .... = Acknowledgment: Set
    int flags_push_1bit; //1bit 接收方应该尽快将这个报文段交给应用层PSH .... .... 0... = Push: Not set
    int flags_reset_1bit; //1bit 重建连接RST .... .... .0.. = Reset: Not set
    int flags_syn_1bit; //1bit 同步序号用来发起一个连接SYN .... .... ..1. = Syn: Set
    int flags_fin_1bit; //1bit 发端完成发送任务FIN .... .... ...0 = Fin: Not set
    int window_size; //16bit 流量控制的窗口大小 Window size value: 29200
    int checksum; //16bit TCP数据段的校验和 Checksum: 0x7f9e [unverified]
    int urgent_pointer; //16bit 紧急指针 Urgent pointer: 0
    int tcp_options_size; //TCP可选项的数目，范围[1,40]，等于0时tcp_options[40]字段无效
    TCP_OPTIONS tcp_options[40]; //TCP可选项
    unsigned char *tcp_payload; //TCP有效载荷
    int tcp_payload_length; //注意：一个TCP包的有效载荷可能被RTP人为的分成两个部分，原因是：单个RTP包的大小超出了TCP的最大载荷容量（即1460bytes），这时候超出的部分只有放入下一个TCP包

public:
    int printInfo()
    {
        printf("-----TRANSMISSION_CONTROL_PROTOCOL_HEADER-----\n");
        printf("source_port: %d\n", source_port);
        printf("destination_port: %d\n", destination_port);
        printf("sequence_number: %u (0x%x)\n", sequence_number, sequence_number);
        printf("next_sequence_number(Calculate): %u (0x%x)\n", next_sequence_number, next_sequence_number);
        printf("acknowledgment_number: %u (0x%x)\n", acknowledgment_number, acknowledgment_number);
        printf("tcp_header_length: %d bytes\n", tcp_header_length);
        printf("flags_reserved_3bit: 0x%x\n", flags_reserved_3bit);
        printf("flags_nonce_1bit: %d\n", flags_nonce_1bit);
        printf("flags_congestion_window_reduced_1bit: %d\n", flags_congestion_window_reduced_1bit);
        printf("flags_ecn_echo_1bit: %d\n", flags_ecn_echo_1bit);
        printf("flags_urgent_1bit %d\n", flags_urgent_1bit);
        printf("flags_acknowledgment_1bit: %d\n", flags_acknowledgment_1bit);
        printf("flags_push_1bit: %d\n", flags_push_1bit);
        printf("flags_reset_1bit: %d\n", flags_reset_1bit);
        printf("flags_syn_1bit: %d\n", flags_syn_1bit);
        printf("flags_fin_1bit: %d\n", flags_fin_1bit);
        printf("window_size: %d bytes\n", window_size);
        printf("checksum: 0x%x\n", checksum);
        printf("urgent_pointer: %d\n", urgent_pointer);
        printf("tcp_options_size: %d\n", tcp_options_size);

        for (int i = 0; i < tcp_options_size; ++i)
        {
            printf("tcp_options: %d/%d\n", i, tcp_options_size);
            tcp_options[i].printInfo();
        }
        
        printf("tcp_payload_length: %d bytes\n", tcp_payload_length);
        if (tcp_payload_length >= 6)
        {
            printf("payload: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", 
                tcp_payload[0], tcp_payload[1], tcp_payload[2], tcp_payload[3], tcp_payload[4], tcp_payload[5]);
        }

        return 0;
    }
}TRANSMISSION_CONTROL_PROTOCOL_HEADER;


//User Datagram Protocol (UDP协议)
//https://tools.ietf.org/html/rfc768
typedef struct _USER_DATAGRAM_PROTOCOL_HEADER_
{
    int source_port; //16-bit
    int destination_port; //16-bit
    int udp_header_and_data_length; //16-bit Length  is the length  in octets  of this user datagram  including  this header and the data.
    int checksum; //16-bit
    unsigned char *udp_payload; //UDP有效载荷
    int udp_payload_length; 

public:
    int printInfo()
    {
        printf("-----USER_DATAGRAM_PROTOCOL_HEADER-----\n");
        printf("source_port: %d\n", source_port);
        printf("destination_port: %d\n", destination_port);
        printf("udp_header_and_data_length: %d(0x%x)\n", udp_header_and_data_length, udp_header_and_data_length);
        printf("checksum: 0x%x\n", checksum);
        printf("udp_payload_length: %d(0x%x)\n", udp_payload_length, udp_payload_length);
        if (udp_payload_length >= 6)
        {
            printf("payload: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", 
                udp_payload[0], udp_payload[1], udp_payload[2], udp_payload[3], udp_payload[4], udp_payload[5]);
        }

        return 0;
    };
}USER_DATAGRAM_PROTOCOL_HEADER;


typedef struct _TCP_FRAME_INFO_
{
    ETHERNET_FRAME ethernet_frame;
    ETHERNET_II_HEADER ethernet_ii_header;
    INTERNET_PROTOCOL_HEADER ip_header;
    TRANSMISSION_CONTROL_PROTOCOL_HEADER tcp_packet;
    USER_DATAGRAM_PROTOCOL_HEADER udp_packet;

public:
    int printInfo()
    {
        ethernet_frame.printInfo();
        ethernet_ii_header.printInfo();
        ip_header.printInfo();
        if((ip_header.ip_version == 4 && ip_header.ipv4.protocol == 6) //6=TCP
            || (ip_header.ip_version == 6 && ip_header.ipv6.next_header == 6)
            )
        {
            tcp_packet.printInfo();
        }
        else if((ip_header.ip_version == 4 && ip_header.ipv4.protocol == 17) //17=UDP
            || (ip_header.ip_version == 6 && ip_header.ipv6.next_header == 17)
            )
        {
            udp_packet.printInfo();
        }
        return 0;
    }
}TCP_FRAME_INFO;


//------------TCP/IP协议--------------
class CTcpIpProtocol
{
public:

public:
    CTcpIpProtocol();
    ~CTcpIpProtocol();

    int readOneEthernetFrame(unsigned char *buffer, int bufferSize, ETHERNET_FRAME &ethernetFrame, unsigned char *&newPos, unsigned char *bufferBase);
    int readOneEthernetIIHeader(unsigned char *buffer, int bufferSize, ETHERNET_II_HEADER &ethernetIIHeader, unsigned char *&newPos, unsigned char *bufferBase);
    int readOneInterNetProtocolHeader(unsigned char *buffer, int bufferSize, INTERNET_PROTOCOL_HEADER &internetProtocolHeader, unsigned char *&newPos, unsigned char *bufferBase);
    int readOneTransmissionControlProtocolHeader(unsigned char *buffer, int bufferSize, TRANSMISSION_CONTROL_PROTOCOL_HEADER &tcpHeader, unsigned char *&newPos, unsigned char *bufferBase);
    int readOneUserDatagramProtocolHeader(unsigned char *buffer, int bufferSize, USER_DATAGRAM_PROTOCOL_HEADER &udpHeader, unsigned char *&newPos, unsigned char *bufferBase);
};


//---------------------
/*
IP协议的protocol字段

0        保留字段，用于IPv6(跳跃点到跳跃点选项)
1        Internet控制消息 (ICMP)
2        Internet组管理 (IGMP)
3        网关到网关 (GGP)
4        1P中的IP(封装)
5        流
6        传输控制 (TCP)
7        CBT
8        外部网关协议 (EGP)
9        任何私有内部网关(Cisco在它的IGRP实现中使用) (IGP)
10        BBNRCC监视
11        网络语音协议
12        PUP
13        ARGUS
14        EMCON
15        网络诊断工具
16        混乱(Chaos)
17        用户数据报文 (UDP)
18        复用
19        DCN测量子系统
20        主机监视
21        包无线测量
22        XEROXNSIDP
23        Trunk-1
24        Trunk-2
25        leaf-1
26        1eaf-2
27        可靠的数据协议
28        Internet可靠交易
29        1SO传输协议第四类 (TP4)
30        大块数据传输协议
31        MFE网络服务协议
32        MERIT节点之间协议
33        序列交换协议
34        第三方连接协议
35        域之间策略路由协议
36        XTP
37        数据报文传递协议
38        IDPR控制消息传输协议
39        TP+ +传输协议
40        IL传输协议
41        1Pv6
42        资源命令路由协议
43        1Pv6的路由报头
44        1Pv6的片报头
45        域之间路由协议
46        保留协议
47        通用路由封装
48        可移动主机路由协议
49        BNA
50        1Pv6封装安全有效负载
51        1Pv6验证报头
52        集成的网络层安全TUBA
53        带加密的IP
54        NBMA地址解析协议
55        IP可移动性
56        使用Kryptonet钥匙管理的传输层安全协议
57        SKIP
58        1Pv6的ICMP
59        1Pv6的无下一个报头
60        IPv6的信宿选项
61        任何主机内部协议
62        CFTP
63        任何本地网络
64        SATNET和BackroomEXPAK
65        Kryptolan
66        MIT远程虚拟磁盘协议
67        Internet Pluribus包核心
68        任何分布式文件系统
69        SATNET监视
70        VISA协议
71        Internet包核心工具
72        计算机协议Network Executive
73        计算机协议Heart Beat
74        Wang Span网络
75        包视频协议
76        Backroom SATNET监视
77        SUN ND PROTOCOL—临时
78        WIDEBAND监视
79        WIDEBAND EXPAK
80        ISO Internet协议
81        VMTP
82        SECURE—VMTP(安全的VMTP)
83        VINES
84        TTP
85        NSFNET—IGP
86        不同网关协议
87        TCF
88        EIGRP
89        OSPF IGP
90        Sprite RPC协议
9]        Locus地址解析协议
92        多播传输协议
93        AX.25帧
94        IP内部的IP封装协议
95        可移动网络互连控制协议
96        旗语通讯安全协议
97        IP中的以太封装
98        封装报头
99        任何私有加密方案
100        GMTP
101        Ipsilon流量管理协议
102        PNNI over IP
103        协议独立多播
104        ARIS
105        SCPS
106        QNX
107        活动网络
108        IP有效负载压缩协议
109        Sitara网络协议
110        Compaq对等协议
111        IP中的IPX
112        虚拟路由器冗余协议
113        PGM可靠传输协议
114        任何0跳跃协议
115        第二层隧道协议
116        D-II数据交换(DDX)
117        交互式代理传输协议
118        日程计划传输协议
119        SpectraLink无线协议
120        UTI
121        简单消息协议
122        SM
123        性能透明性协议
124        ISIS over IPv4
125        FIRE
126        Combat无线传输协议
127        Combat无线用户数据报文
128        SSCOPMCE
129        IPLT
130        安全包防护
131        IP中的私有IP封装
132        流控制传输协议
133～254   未分配
255        保留
*/
