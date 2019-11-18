#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>
#include <vector>
#include "TcpIpProtocol.h"


#define MAX(a, b)  (((a) > (b)) ? (a) : (b))
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

#define RETURN_IF_FAILED(condition, ret)                                                      \
    do                                                                                        \
    {                                                                                         \
        if (condition)                                                                        \
        {                                                                                     \
            printf("%s(%d): %s: Error: ret=%d;\n", __FILE__, __LINE__, __FUNCTION__, ret);    \
            return ret;                                                                       \
        }                                                                                     \
    } while (0)


#define BREAK_IF_FAILED(condition)                                                        \
    if (condition)                                                                        \
    {                                                                                     \
        printf("%s(%d): %s: Error: ret=%d;\n", __FILE__, __LINE__, __FUNCTION__, ret);    \
        break;                                                                            \
    }


CTcpIpProtocol::CTcpIpProtocol()
{

}


CTcpIpProtocol::~CTcpIpProtocol()
{

}


int CTcpIpProtocol::readOneEthernetFrame(unsigned char *buffer, int bufferSize, ETHERNET_FRAME &ethernetFrame, unsigned char *&newPos, unsigned char *bufferBase)
{
    int ret = 0;

    RETURN_IF_FAILED(bufferSize < 16, -1);

    //-------------------------
    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;

    ethernetFrame.file_offset = p1 - bufferBase;

    unsigned long long t1 = (p1[3] << 24) | (p1[2] << 16) | (p1[1] << 8) | (p1[0] << 0);
    unsigned long long t2 = (p1[7] << 24) | (p1[6] << 16) | (p1[5] << 8) | (p1[4] << 0);
    ethernetFrame.timestamp = (t1 << 32) | t2;
    time_t timestamp = t1;
    strftime(ethernetFrame.timestampStr, 80, "%Y-%m-%d %H:%M:%S", localtime(&timestamp));
    sprintf(ethernetFrame.timestampStr, "%s.%d", ethernetFrame.timestampStr, t2);

    p1 += 8;

    memcpy(&ethernetFrame.frame_length, p1, 4);
    p1 += 4;
    
    memcpy(&ethernetFrame.capture_length, p1, 4);
    p1 += 4;

    newPos = p1;

    return ret;
}


int CTcpIpProtocol::readOneEthernetIIHeader(unsigned char *buffer, int bufferSize, ETHERNET_II_HEADER &ethernetIIHeader, unsigned char *&newPos, unsigned char *bufferBase)
{
    int ret = 0;

    RETURN_IF_FAILED(bufferSize < 16, -1);

    //-------------------------
    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;

    sprintf(ethernetIIHeader.destination_address, "%02x:%02x:%02x:%02x:%02x:%02x", p1[0], p1[1], p1[2], p1[3], p1[4], p1[5]);
    p1 += 6;
    
    sprintf(ethernetIIHeader.source_address, "%02x:%02x:%02x:%02x:%02x:%02x", p1[0], p1[1], p1[2], p1[3], p1[4], p1[5]);
    p1 += 6;

    ethernetIIHeader.type = (p1[0] << 8) | p1[1]; //Type: IPv4 (0x0800)

    p1 += 2;
    newPos = p1;

    return ret;
}


int CTcpIpProtocol::readOneInterNetProtocolHeader(unsigned char *buffer, int bufferSize, INTERNET_PROTOCOL_HEADER &internetProtocolHeader, unsigned char *&newPos, unsigned char *bufferBase)
{
    int ret = 0;

    RETURN_IF_FAILED(bufferSize < 20, -1); //IP头部占用20个字节

    //-------------------------
    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;

    internetProtocolHeader.version = p1[0] >> 4; //IP version: 4
    internetProtocolHeader.ip_header_length = (p1[0] & 0x0F) * 32 / 8;
    p1 += 1;

    internetProtocolHeader.differentiated_services_field = *p1;
    p1 += 1;
    
    internetProtocolHeader.total_length = (p1[0] << 8) | p1[1];
    p1 += 2;
    
    internetProtocolHeader.identification = (p1[0] << 8) | p1[1];
    p1 += 2;
    
    internetProtocolHeader.flags_reserved_1bit = (p1[0] & 0x80) >> 7;
    internetProtocolHeader.flags_do_not_fragment_set_1bit = (p1[0] & 0x40) >> 6;
    internetProtocolHeader.flags_more_fragments_1bit = (p1[0] & 0x20) >> 5;
    internetProtocolHeader.flags_fragments_offset_13bits = ((p1[0] & 0x1F) << 8) | p1[1];
    p1 += 2;

    internetProtocolHeader.time_to_live = p1[0];
    p1 += 1;

    internetProtocolHeader.protocol = p1[0];
    p1 += 1;

    if(internetProtocolHeader.protocol == 6)
    {
        sprintf(internetProtocolHeader.protocol_str, "TCP(6)");
    }

    internetProtocolHeader.header_checksum = (p1[0] << 8) | p1[1];
    p1 += 2;
    
    internetProtocolHeader.source_ip_addr = (p1[0] << 24) | (p1[1] << 16) | (p1[2] << 8) | p1[3];
    sprintf(internetProtocolHeader.source_ip_addr_str, "%d.%d.%d.%d", p1[0], p1[1], p1[2], p1[3]);
    p1 += 4;
    
    internetProtocolHeader.destination_ip_addr = (p1[0] << 24) | (p1[1] << 16) | (p1[2] << 8) | p1[3];
    sprintf(internetProtocolHeader.destination_ip_addr_str, "%d.%d.%d.%d", p1[0], p1[1], p1[2], p1[3]);
    p1 += 4;

    newPos = p1;

    return ret;
}


int CTcpIpProtocol::readOneTransmissionControlProtocolHeader(unsigned char *buffer, int bufferSize, TRANSMISSION_CONTROL_PROTOCOL_HEADER &tcpHeader, unsigned char *&newPos, unsigned char *bufferBase)
{
    int ret = 0;

    RETURN_IF_FAILED(bufferSize < 16, -1);

    //-------------------------
    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;
    
    tcpHeader.source_port = (p1[0] << 8) | p1[1];
    p1 += 2;
    
    tcpHeader.destination_port = (p1[0] << 8) | p1[1];
    p1 += 2;
    
    tcpHeader.sequence_number = (p1[0] << 24) | (p1[1] << 16) | (p1[2] << 8) | p1[3];
    p1 += 4;
    
    tcpHeader.acknowledgment_number = (p1[0] << 24) | (p1[1] << 16) | (p1[2] << 8) | p1[3];
    p1 += 4;
    
    tcpHeader.tcp_header_length = (p1[0] >> 4) * 4;
    tcpHeader.flags_reserved_3bit = (p1[0] & 0x0E) >> 1;
    tcpHeader.flags_nonce_1bit = p1[0] & 0x01;
    p1 += 1;
    
    tcpHeader.flags_congestion_window_reduced_1bit = (p1[0] & 0x80) >> 7;
    tcpHeader.flags_ecn_echo_1bit = (p1[0] & 0x40) >> 6;
    tcpHeader.flags_urgent_1bit = (p1[0] & 0x20) >> 5;
    tcpHeader.flags_acknowledgment_1bit = (p1[0] & 0x10) >> 4;
    tcpHeader.flags_push_1bit = (p1[0] & 0x08) >> 3;
    tcpHeader.flags_reset_1bit = (p1[0] & 0x04) >> 2;
    tcpHeader.flags_syn_1bit = (p1[0] & 0x02) >> 1;
    tcpHeader.flags_fin_1bit = (p1[0] & 0x01) >> 0;
    p1 += 1;
    
    tcpHeader.window_size = (p1[0] << 8) | p1[1];
    p1 += 2;
    
    tcpHeader.checksum = (p1[0] << 8) | p1[1];
    p1 += 2;
    
    tcpHeader.urgent_pointer = (p1[0] << 8) | p1[1];
    p1 += 2;
    
    //-----------tcp options------------------
    int tcp_options_size = tcpHeader.tcp_header_length - (p1 - p + 1);

    p2 = p1 + tcp_options_size;

    TCP_OPTIONS tcp_option;

    while(p1 + 1 <= p2)
    {
        memset(&tcp_option, 0, sizeof(TCP_OPTIONS));
        
        tcp_option.kind = p1[0];
        p1 += 1;

        if(tcp_option.kind == 0)
        {
            
        }else if(tcp_option.kind == 1)
        {

        }else if(tcp_option.kind == 2) //Maximum Segment Size (MSS)
        {
            tcp_option.length = p1[0];
            p1 += 1;
            RETURN_IF_FAILED(tcp_option.length != 4, -1);
        }else if(tcp_option.kind == 3) //TCP Window Scale Option (WSopt)
        {
            tcp_option.length = p1[0];
            p1 += 1;
            RETURN_IF_FAILED(tcp_option.length != 3, -1);
        }else if(tcp_option.kind == 4) //SACK permitted
        {
            tcp_option.length = p1[0];
            p1 += 1;
            RETURN_IF_FAILED(tcp_option.length != 2, -1);
        }else if(tcp_option.kind == 5) //SACK packet
        {
            tcp_option.length = p1[0];
            p1 += 1;
            RETURN_IF_FAILED(tcp_option.length != 2, -1);
        }else if(tcp_option.kind == 6) //Undefine
        {
            RETURN_IF_FAILED(-1, -1);
        }else if(tcp_option.kind == 7) //Undefine
        {
            RETURN_IF_FAILED(-1, -1);
        }else if(tcp_option.kind == 8) //TCP Timestamps Option (TSopt)
        {
            tcp_option.length = p1[0];
            p1 += 1;
            RETURN_IF_FAILED(tcp_option.length != 10, -1);
        }else
        {
            RETURN_IF_FAILED(-1, -1);
        }

        if(tcp_option.length > 2)
        {
            memcpy(tcp_option.data, p1, tcp_option.length - 2);
            p1 += tcp_option.length - 2;
            tcp_option.data[tcp_option.length - 2] = '\0';
        }

        memcpy(&tcpHeader.tcp_options[tcpHeader.tcp_options_size], &tcp_option, sizeof(TCP_OPTIONS));
        tcpHeader.tcp_options_size++;
    }

    //-------------------
    int len = p1 - p;
    RETURN_IF_FAILED(p1 - p != tcpHeader.tcp_header_length, -1);

    newPos = p1;

    return ret;
}

