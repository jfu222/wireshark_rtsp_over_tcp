#pragma once


/*
https://tools.ietf.org/html/rfc3984 Page11

Type   Packet    Type name                        Section
---------------------------------------------------------
0      undefined                                    -
1-23   NAL unit  Single NAL unit packet per H.264   5.6
24     STAP-A    Single-time aggregation packet     5.7.1
25     STAP-B    Single-time aggregation packet     5.7.1
26     MTAP16    Multi-time aggregation packet      5.7.2
27     MTAP24    Multi-time aggregation packet      5.7.2
28     FU-A      Fragmentation unit                 5.8
29     FU-B      Fragmentation unit                 5.8
30-31  undefined         -                          -

*/
typedef enum _H264_RTP_PACKET_TYPE_
{
    SINGLE_NAL_UNIT = 1,
    STAP_A = 24,
    STAP_B,
    MTAP16,
    MTAP24,
    FU_A,
    FU_B,
    UNDEFINED,
}H264_RTP_PACKET_TYPE;


typedef struct _H264_DATA_
{
    char start_code[5]; // 00 00 00 01 67
    int start_code_length; // 0 or 5，如果为5，则表示一个h264包的开始，为0表示中间部分或结束部分
    int nal_unit_type_h264; //nal的类型（取值范围：1-23）
    int nal_unit_type_h264_rtp; //nal的rtp类型（1-23时表示的意思和h264的nal_unit_type定义一致）
    unsigned char *h264_sub_packet_data; //一个h264包可能被拆成多个RTP包碎片
    int h264_sub_packet_data_length; //h264碎片大小

public:
    int printInfo()
    {
        printf("-----H264_DATA-----\n");
        printf("start_code: %02x %02x %02x %02x %02x\n", start_code[0], start_code[1], start_code[2], start_code[3], start_code[4]);
        printf("start_code_length: %d bytes\n", start_code_length);
        printf("nal_unit_type_h264: %d\n", nal_unit_type_h264);
        printf("nal_unit_type_h264_rtp: %d\n", nal_unit_type_h264_rtp);
        printf("h264_sub_packet_data_length: %d\n", h264_sub_packet_data_length);
        
        if (h264_sub_packet_data_length >= 6)
        {
            printf("h264_data: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", 
                h264_sub_packet_data[0], h264_sub_packet_data[1], h264_sub_packet_data[2], 
                h264_sub_packet_data[3], h264_sub_packet_data[4], h264_sub_packet_data[5]);
        }
        return 0;
    }
}H264_DATA;


/*
RFC3550 Page12
The RTP header has the following format:

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|      PT     |          sequence number      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       timestamp                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            synchronization source (SSRC) identifier           |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|            contributing source (CSRC) identifiers             |
|                    ....                                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Real-Time Transport Protocol
10.. .... = Version: RFC 1889 Version (2)
..1. .... = Padding: True
...0 .... = Extension: False
.... 0000 = Contributing source identifiers count: 0
0... .... = Marker: False
Payload type: DynamicRTP-Type-96 (96)
Sequence number: 48657
Timestamp: 706810978
Synchronization Source identifier: 0x45439e03 (1162059267)
Payload: 420101016000000300b0000003000003007ba003c08010e5...
Padding data: 0000
Padding count: 3
*/
typedef struct _RTP_HEADER_AND_PAYLOAD_
{
    int rtp_packet_total_size; //该rtp包的总大小（单位：字节）
    int channel; //rtsp通道，偶数为数据通道，比如0-表示视频通道,2-表示音频通道
    int version;//2bits 用来标志使用的RTP版本 10.. .... = Version: RFC 1889 Version (2)
    int padding;//1bit .如果为1，则该RTP包的尾部包含附加的填充字节 1. .... = Padding: True
    int extension;//1bit 如果为1，RTP头部后面有一个扩展头部 ...0 .... = Extension: False
    int contributing_source_identifiers_count;//4bits 头部后面跟着的CSRC的数目 .... 0000 = Contributing source identifiers count: 0
    int marker;//1bit 标记位(1代表一帧数据的结束) 0... .... = Marker: False
    int payload_type;//7bits RTP载荷类型 Payload type: DynamicRTP-Type-96 (96); 96是指h264编码
    unsigned int sequence_number;//16bits 序列号 Sequence number: 48657
    unsigned int timestamp;//32bits 该RTP包中数据的第一个字节的采样时刻 Timestamp: 706810978
    int synchronization_source_identifier;//32bits 同步源标识符(SSRC)指RTP包流的来源 Synchronization Source identifier: 0x45439e03 (1162059267)
    int rtp_header_extension_defined_by_profile;//32bits
    int rtp_header_extension_length;//32bits (长度不包含本身)
    int rtp_payload_size;//RTP包有效载荷大小
    unsigned char *rtp_payload;//RTP包有效载荷 Payload: 420101016000000300b0000003000003007ba003c08010e5...
    int padding_data;//(padding_count - 8)bits 附加的填充字节 Padding data: 0000
    int padding_count;//8bits 附加的填充字节数目(包含自身) Padding count: 3
    H264_DATA h264_data; //h264数据

public:
    int printInfo()
    {
        printf("-----RTP_HEADER_AND_PAYLOAD-----\n");
        printf("rtp_packet_total_size: %d (0x%x) bytes\n", rtp_packet_total_size, rtp_packet_total_size);
        printf("channel: %d\n", channel);
        printf("version: %d\n", version);
        printf("padding: %d\n", padding);
        printf("extension: %d\n", extension);
        printf("contributing_source_identifiers_count: %d\n", contributing_source_identifiers_count);
        printf("marker: %d\n", marker);
        printf("payload_type: %d\n", payload_type);
        printf("sequence_number: %u (0x%x)\n", sequence_number, sequence_number);
        printf("timestamp: %u (0x%x)\n", timestamp, timestamp);
        printf("synchronization_source_identifier: %d (0x%x)\n", synchronization_source_identifier, synchronization_source_identifier);
        printf("rtp_header_extension_defined_by_profile: %d\n", rtp_header_extension_defined_by_profile);
        printf("rtp_header_extension_length: %d\n", rtp_header_extension_length);
        printf("rtp_payload_size: %d (0x%x)\n", rtp_payload_size, rtp_payload_size);
        printf("padding_count: %d\n", padding_count);
        
        if (rtp_payload_size >= 6)
        {
            printf("rtp_payload: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", 
                rtp_payload[0], rtp_payload[1], rtp_payload[2], 
                rtp_payload[3], rtp_payload[4], rtp_payload[5]);
        }

        h264_data.printInfo();
        return 0;
    }
}RTP_HEADER_AND_PAYLOAD;


/*
abbrev.  name                 value
SR       sender report          200
RR       receiver report        201
SDES     source description     202
BYE      goodbye                203
APP      application-defined    204

https://tools.ietf.org/html/rfc3550 Page35

SR: Sender Report RTCP Packet

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header |V=2|P|    RC   |   PT=SR=200   |             length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         SSRC of sender                        |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
sender |              NTP timestamp, most significant word             |
info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             NTP timestamp, least significant word             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         RTP timestamp                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     sender's packet count                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      sender's octet count                     |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_1 (SSRC of first source)                 |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  1    | fraction lost |       cumulative number of packets lost       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           extended highest sequence number received           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      interarrival jitter                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         last SR (LSR)                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                   delay since last SR (DLSR)                  |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_2 (SSRC of second source)                |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  2    :                               ...                             :
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
       |                  profile-specific extensions                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct _RTCP_SR_
{
    int rtcp_packet_total_size; //该rtcp包的总大小（单位：字节）
    int version;//2bits
    int padding;//1bit
    int reception_report_count;//5bits reception report count (RC)
    int payload_type;//8bits RTCP载荷类型 Contains the constant 200 to identify this as an RTCP SR packet.
    int packet_length;//16bits The length of this RTCP packet in 32-bit words minus one,including the header and any padding.
    //...
public:
    int printInfo()
    {
        printf("-----RTP_HEADER_AND_PAYLOAD-----\n");
        printf("rtcp_packet_total_size: %d (0x%x) bytes\n", rtcp_packet_total_size, rtcp_packet_total_size);
        printf("version: %d\n", version);
        printf("padding: %d\n", padding);
        printf("reception_report_count: %d\n", reception_report_count);
        printf("payload_type: %d\n", payload_type);
        printf("packet_length: %d (0x%x) bytes\n", packet_length, packet_length);
        return 0;
    }
}RTCP_SR;


typedef struct _RTCP_INFO_
{
    RTCP_SR rtcp_sr;
}RTCP_INFO;


typedef struct _RTP_AND_RTCP_INFO_
{
    RTP_HEADER_AND_PAYLOAD rtp_header_and_payload;
    RTCP_INFO rtcp_info;
}RTP_AND_RTCP_INFO;


//------------RTP协议 Real-Time Transport Protocol--------------
class CRtpProtocol
{
public:


public:
    CRtpProtocol();
    ~CRtpProtocol();

    int splitRtpPacket(unsigned char *buffer, int bufferSize, RTP_HEADER_AND_PAYLOAD &rtp_header_payload, std::string &strErrorType);
    int splitRtcpPacket(unsigned char *buffer, int bufferSize, RTCP_INFO &rtcp_info);
    int splitH264Payload(RTP_HEADER_AND_PAYLOAD &rtp_header_payload, std::string &strErrorType);
    int splitSingleH264FileToMultiFilesByIFrame(std::string inputFilename, std::string outputDir);
    int splitSingleH264FileToMultiFilesByStartCode(std::string inputFilename, std::string outputDir);
};

