#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include "WiresharkRtspOverTcp.h"
#include "CommonFunction.h"


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


//#define MSS1    1460 * 1 //tcpdump捕获的TCP包中，存在大小超过1460字节的包，原因可能跟捕获机制有关
#define MSS1    1460 * 5
#define MSS2    1460 * 10


CWiresharkRtspOverTcp::CWiresharkRtspOverTcp()
{
    m_inputFilename = "";
    m_outputFilename = "";
    m_fileType = CAPTURE_NETWORK_PACKET_FILE_TYPE_UNKNOWN;
    m_fp_out = NULL;
}


CWiresharkRtspOverTcp::~CWiresharkRtspOverTcp()
{
    if (m_fp_out)
    {
        fclose(m_fp_out);
        m_fp_out = NULL;
    }
}


int CWiresharkRtspOverTcp::splitRtspOverTcp(std::string inputFilename, std::string rtspServerIp, int rtspServerPort, std::string outputDir, int startFrameNumber, int endFrameNumber)
{
    int ret = 0;

    //--------先探测文件格式------------
    ret = probeFileType(inputFilename.c_str(), m_fileType);
    RETURN_IF_FAILED(ret != 0, -1);

    printf("%s(%d): %s: m_fileType=%d;\n", __FILE__, __LINE__, __FUNCTION__, m_fileType);

    std::string dirName = "";
    std::string baseName = "";
    std::string extensionName = "";

    ret = getFileDirnameAndBasenameAndExtname(inputFilename.c_str(), dirName, baseName, extensionName);
    RETURN_IF_FAILED(ret != 0, -1);

    m_inputFilename = inputFilename;
    m_outputFilename = outputDir + "/" + baseName;
    m_outputDir = outputDir;

    std::string filterRule_rtspServerIp = rtspServerIp;
    int filterRule_rtspServerPort = rtspServerPort;

    ret = createNestedDir(outputDir.c_str());

    //-------------------------
    std::string outFileTcpPayload = m_outputFilename + "." + filterRule_rtspServerIp + ".tcp_payload";
    
    printf("%s\n", outFileTcpPayload.c_str());

    FILE * fp1 = fopen(outFileTcpPayload.c_str(), "wb");
    if (fp1 == NULL)
    {
        printf("%s(%d): %s: Cannot open file to write! outFileTcpPayload='%s'\n", __FILE__, __LINE__, __FUNCTION__, outFileTcpPayload.c_str());
        return -1;
    }
    
    //-------------------------
    bool isSaveTcpdumpFile =false;

    if(startFrameNumber > 0 && endFrameNumber > 0 && startFrameNumber < endFrameNumber)
    {
        isSaveTcpdumpFile = true;
    }
    
    std::string outputTcpdumpFilename = outputDir + "/test_cut_"+ std::to_string(startFrameNumber) + "_" + std::to_string(endFrameNumber) +".cap";
    FILE *fp2 = NULL;

    if(isSaveTcpdumpFile && m_fileType == CAPTURE_NETWORK_PACKET_FILE_TYPE_CAP_BY_TCPDUMP)
    {
        fp2 = fopen(outputTcpdumpFilename.c_str(), "wb");
        printf("%s(%d): %s: outputTcpdumpFilename='%s'\n", __FILE__, __LINE__, __FUNCTION__, outputTcpdumpFilename.c_str());
        if (fp2 == NULL)
        {
            printf("%s(%d): %s: Cannot open file to write! outputTcpdumpFilename='%s'\n", __FILE__, __LINE__, __FUNCTION__, outputTcpdumpFilename.c_str());
            return -1;
        }

        ret = m_tcpdumpCapFile.writeTcpdumpCapFileHeader(fp2);
        RETURN_IF_FAILED(ret != 0, -1);
    }
    //-------------------------
    unsigned char *p1 = NULL;
    unsigned char *p2 = NULL;

    int frame_number = 0;
    int tcp_next_sequence_number = 0; //用于判断TCP包是否乱序
    CTcpIpProtocol tcpIpProtocol;
    int tcp_buffer_size_used = 0;
    size_t writeBytes = 0;
    unsigned char tcp_buffer[MSS2];
    int tcp_buffer_filled_size = 0;

    //存储乱序的TCP包，需要按照tcp_sequence_number重排序
    //后一个包的tcp_sequence_number号小于前一个包的tcp_sequence_number+tcp_payload_length时，就会认为是乱序了
    //此处定义：对于TCP协议，Previous segment not captured 开始就算乱序了
    std::map<int, TCP_FRAME_INFO> hashTcpOutOfOrder; //存储乱序的TCP包

    while (1)
    {
        frame_number++;
        printf("frame_number=%d;\n", frame_number);

        unsigned char *framePos = NULL;
        int frameSize = 0;
        
        ret = getNextNetworkFrame(framePos, frameSize);
        BREAK_IF_FAILED(ret != 0);

        //---------------如果要保存中间某一段cap文件帧------------------
        if(isSaveTcpdumpFile && m_fileType == CAPTURE_NETWORK_PACKET_FILE_TYPE_CAP_BY_TCPDUMP && fp2 
            && frame_number >= startFrameNumber && frame_number <= endFrameNumber)
        {
            writeBytes = fwrite(framePos, frameSize, 1, fp2);

            if(frame_number >= endFrameNumber)
            {
                break;
            }
        }

        if (p2 == NULL)
        {
            p2 = framePos;
        }

        //--------------------------------
        TCP_FRAME_INFO tcp_frame_info;
        memset(&tcp_frame_info, 0, sizeof(TCP_FRAME_INFO));

        ret = readOneEthernetFrame(framePos, frameSize, frame_number, tcp_frame_info, p1, p2);
        BREAK_IF_FAILED(ret != 0);

        //------------过滤IP地址-----------------
        std::string ip_src = tcp_frame_info.ip_header.ipv4.source_ip_addr_str;

        if (!(tcp_frame_info.ip_header.ip_version == 4
                && tcp_frame_info.ip_header.ipv4.protocol == 6 //TCP=6
                && tcp_frame_info.tcp_packet.source_port == filterRule_rtspServerPort //554
                && ip_src == filterRule_rtspServerIp
            ))
        {
            continue;
        }

        //------------------------
        if (tcp_next_sequence_number == 0)
        {
            tcp_next_sequence_number = tcp_frame_info.tcp_packet.next_sequence_number;
        }
        else
        {
            if (tcp_frame_info.tcp_packet.sequence_number != tcp_next_sequence_number) //说明TCP包乱序了
            {
                std::map<int, TCP_FRAME_INFO>::iterator it = hashTcpOutOfOrder.find(tcp_next_sequence_number);
                hashTcpOutOfOrder[tcp_frame_info.tcp_packet.sequence_number] = tcp_frame_info; //暂时把从第一个乱序包之后的包存储起来
                if (it == hashTcpOutOfOrder.end()) //说明没在存储的乱序包数组中找到
                {
                    printf("11-22: it == hashTcpOutOfOrder.end(): frame_number=%d; tcp_frame_info.tcp_packet.sequence_number(%u) != tcp_next_sequence_number(%u); hashTcpOutOfOrder.size=%d;\n", 
                        tcp_frame_info.ethernet_frame.frame_number, tcp_frame_info.tcp_packet.sequence_number, tcp_next_sequence_number, hashTcpOutOfOrder.size());
                    continue;
                }
                else
                {
                    tcp_frame_info = hashTcpOutOfOrder[tcp_next_sequence_number];
                    hashTcpOutOfOrder.erase(it); //删除掉
                    tcp_next_sequence_number = tcp_frame_info.tcp_packet.next_sequence_number;
                    printf("11-33:: frame_number=%d; tcp_frame_info.tcp_packet.sequence_number(%u) != tcp_next_sequence_number(%u); hashTcpOutOfOrder.size=%d;\n",
                        tcp_frame_info.ethernet_frame.frame_number, tcp_frame_info.tcp_packet.sequence_number, tcp_next_sequence_number, hashTcpOutOfOrder.size());
                }
            }
            else
            {
                tcp_next_sequence_number = tcp_frame_info.tcp_packet.next_sequence_number;
                printf("####### 11-44:: frame_number=%d;\n", tcp_frame_info.ethernet_frame.frame_number);
            }
        }

        BREAK_IF_FAILED(tcp_frame_info.tcp_packet.tcp_payload_length < 0);

//        ret = tcp_frame_info.printInfo();

        //------------------------
        if (tcp_frame_info.tcp_packet.tcp_payload_length > 0)
        {
            writeBytes = fwrite(tcp_frame_info.tcp_packet.tcp_payload, tcp_frame_info.tcp_packet.tcp_payload_length, 1, fp1);
        }
    }

    printf("\n############################# 1111: tcp_next_sequence_number=%u; hashTcpOutOfOrder.size=%d;\n", tcp_next_sequence_number, hashTcpOutOfOrder.size());
    
    //----------------------------------------
    while (hashTcpOutOfOrder.size() > 0)
    {
        std::map<int, TCP_FRAME_INFO>::iterator it = hashTcpOutOfOrder.find(tcp_next_sequence_number);
        if (it == hashTcpOutOfOrder.end()) //说明没在存储的乱序包数组中找到
        {
            printf("11-55: it == hashTcpOutOfOrder.end(): tcp_next_sequence_number=%u; hashTcpOutOfOrder.size=%d;\n",
                tcp_next_sequence_number, hashTcpOutOfOrder.size());
            break;
        }
        else
        {
            TCP_FRAME_INFO tcp_frame_info = hashTcpOutOfOrder[tcp_next_sequence_number];
            hashTcpOutOfOrder.erase(it); //删除掉
            tcp_next_sequence_number = tcp_frame_info.tcp_packet.next_sequence_number;
            printf("11-66:: frame_number=%d; tcp_frame_info.tcp_packet.sequence_number(%u) != tcp_next_sequence_number(%u); hashTcpOutOfOrder.size=%d;\n",
                tcp_frame_info.ethernet_frame.frame_number, tcp_frame_info.tcp_packet.sequence_number, tcp_next_sequence_number, hashTcpOutOfOrder.size());
            
            BREAK_IF_FAILED(tcp_frame_info.tcp_packet.tcp_payload_length < 0);

//            ret = tcp_frame_info.printInfo();

            //------------------------
            if (tcp_frame_info.tcp_packet.tcp_payload_length > 0)
            {
                writeBytes = fwrite(tcp_frame_info.tcp_packet.tcp_payload, tcp_frame_info.tcp_packet.tcp_payload_length, 1, fp1);
            }
        }
    }

    printf("\n############################# 2222: tcp_next_sequence_number=%u; hashTcpOutOfOrder.size=%d;\n", tcp_next_sequence_number, hashTcpOutOfOrder.size());

    if (fp1)
    {
        fclose(fp1);
        fp1 = NULL;
    }
    if (fp2)
    {
        fclose(fp2);
        fp2 = NULL;
    }

    //--------------------------------
    if(isSaveTcpdumpFile)
    {
        printf("%s(%d): %s: isSaveTcpdumpFile=%d;\n", __FILE__, __LINE__, __FUNCTION__, isSaveTcpdumpFile);
        return 0;
    }

    CRtspProtocol rtspProtocol;
    ret = rtspProtocol.splitRtpPayloadFile(outFileTcpPayload, m_outputFilename);
    RETURN_IF_FAILED(ret != 0, ret);

    return ret;
}


int CWiresharkRtspOverTcp::readOneEthernetFrame(unsigned char *buffer, int bufferSize, int frame_number, TCP_FRAME_INFO &tcp_frame_info, unsigned char *&newPos, unsigned char *bufferBase)
{
    int ret = 0;

    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;
    unsigned char *p3 = buffer + bufferSize - 1;

    CTcpIpProtocol tcpIpProtocol;

    //-------Ethernet Frame---------
    ret = tcpIpProtocol.readOneEthernetFrame(p1, p3 - p1 + 1, tcp_frame_info.ethernet_frame, p1, bufferBase);
    RETURN_IF_FAILED(ret != 0, ret);
    RETURN_IF_FAILED(tcp_frame_info.ethernet_frame.capture_length != tcp_frame_info.ethernet_frame.frame_length, -1);

    tcp_frame_info.ethernet_frame.frame_number = frame_number;

    //-------Ethernet II Header---------
    ret = tcpIpProtocol.readOneEthernetIIHeader(p1, p3 - p1 + 1, tcp_frame_info.ethernet_ii_header, p1, bufferBase);
    RETURN_IF_FAILED(ret != 0, ret);

    if(tcp_frame_info.ethernet_ii_header.type != 0x0800) //IP=0x0800
    {
        printf("%s(%d): %s: Warn: tcp_frame_info.ethernet_ii_header.type(0x%x) != 0x0800(IP);\n", __FILE__, __LINE__, __FUNCTION__, tcp_frame_info.ethernet_ii_header.type);
        
        newPos = p1 + tcp_frame_info.ethernet_frame.capture_length;
        return 0;
    }

    //-------Internet Protocol Header---------
    ret = tcpIpProtocol.readOneInterNetProtocolHeader(p1, p3 - p1 + 1, tcp_frame_info.ip_header, p1, bufferBase);
    RETURN_IF_FAILED(ret != 0, ret);

    //--------------------------
    if((tcp_frame_info.ip_header.ip_version == 4 && tcp_frame_info.ip_header.ipv4.protocol == 6) //6=TCP
        || (tcp_frame_info.ip_header.ip_version == 6 && tcp_frame_info.ip_header.ipv6.next_header == 6)
        )
    {
        //-------TCP Header---------
        ret = tcpIpProtocol.readOneTransmissionControlProtocolHeader(p1, p3 - p1 + 1, tcp_frame_info.tcp_packet, p1, bufferBase);
        RETURN_IF_FAILED(ret != 0, ret);

        //-------TCP Payload---------
        tcp_frame_info.tcp_packet.tcp_payload_length = tcp_frame_info.ip_header.ipv4.total_length - tcp_frame_info.ip_header.ipv4.ip_header_length - tcp_frame_info.tcp_packet.tcp_header_length;
        tcp_frame_info.tcp_packet.tcp_payload = p1;
        RETURN_IF_FAILED(tcp_frame_info.tcp_packet.tcp_payload_length > MSS1, -1);

        tcp_frame_info.tcp_packet.next_sequence_number = 0;
        if (tcp_frame_info.tcp_packet.tcp_payload_length > 0)
        {
            tcp_frame_info.tcp_packet.next_sequence_number = tcp_frame_info.tcp_packet.sequence_number + tcp_frame_info.tcp_packet.tcp_payload_length;
        }
    }
    else  if((tcp_frame_info.ip_header.ip_version == 4 && tcp_frame_info.ip_header.ipv4.protocol == 17) //17=UDP
        || (tcp_frame_info.ip_header.ip_version == 6 && tcp_frame_info.ip_header.ipv6.next_header == 17)
        )
    {
        //-------UDP Header---------
        ret = tcpIpProtocol.readOneUserDatagramProtocolHeader(p1, p3 - p1 + 1, tcp_frame_info.udp_packet, p1, bufferBase);
        RETURN_IF_FAILED(ret != 0, ret);

        //-------UDP Payload---------
        tcp_frame_info.udp_packet.udp_payload_length = tcp_frame_info.udp_packet.udp_header_and_data_length - 8;
        tcp_frame_info.udp_packet.udp_payload = p1;
    }
    else
    {
        
    }
//    ret = tcp_frame_info.printInfo();

    newPos = p1;

    return ret;
}


int CWiresharkRtspOverTcp::writeDataToFile(TCP_FRAME_INFO &tcp_frame_info, unsigned char *tcp_buffer, int &tcp_buffer_filled_size, int &tcp_buffer_size_used)
{
    int ret = 0;

    size_t writeBytes = 0;

    //------------------------
    if (tcp_buffer_filled_size + tcp_frame_info.tcp_packet.tcp_payload_length > MSS2)
    {
        printf("%s(%d): %s: Error: tcp_buffer_filled_size(%d) + tcp_frame_info.tcp_packet.tcp_payload.tcp_payload_length(%d) > MSS2(%d);\n", 
            __FILE__, __LINE__, __FUNCTION__, tcp_buffer_filled_size, tcp_frame_info.tcp_packet.tcp_payload_length, MSS2);
        return -1;
    }

    memcpy(tcp_buffer + tcp_buffer_filled_size, tcp_frame_info.tcp_packet.tcp_payload, tcp_frame_info.tcp_packet.tcp_payload_length);
    tcp_buffer_filled_size += tcp_frame_info.tcp_packet.tcp_payload_length;

    //------------------------
/*    char outFile[600] = "";
    sprintf(outFile, "../data/%d.rtsp.data", tcp_frame_info.ethernet_frame.frame_number);
    printf("%s\n", outFile);
    FILE * fp2 = fopen(outFile, "wb");
    RETURN_IF_FAILED(fp2 == NULL, -1);

    writeBytes = fwrite(tcp_frame_info.tcp_packet.tcp_payload.payload, tcp_frame_info.tcp_packet.tcp_payload.tcp_payload_length, 1, fp2);

    fclose(fp2);
*/
    //---------------------
    CRtspProtocol rtspProtocol;
    RTSP_HEADER_AND_PAYLAOAD_INFO rtsp_header_and_payload_info;
    memset(&rtsp_header_and_payload_info, 0, sizeof(RTSP_HEADER_AND_PAYLAOAD_INFO));

    tcp_buffer_size_used = 0;
//    ret = rtspProtocol.splitRtspPacket(tcp_buffer, tcp_buffer_filled_size, rtsp_header_and_payload_info, tcp_buffer_size_used);

    RETURN_IF_FAILED(tcp_buffer_size_used > tcp_buffer_filled_size, -1);

    printf("1111: frame_number=%d; splitRtspPacket: tcp_buffer_filled_size=%d; tcp_buffer_size_used=%d; tcp_payload_segment_data2_length=%d;\n",
        tcp_frame_info.ethernet_frame.frame_number, tcp_buffer_filled_size, tcp_buffer_size_used, tcp_buffer_filled_size - tcp_buffer_size_used);

    //--------------------------
    int rtsp_interleaved_frame_length = rtsp_header_and_payload_info.rtsp_interleaved_frame.size();
    if (rtsp_interleaved_frame_length > 0)
    {
//        char outFile2[600] = "";
//        sprintf(outFile2, "../data/%d.h264", tcp_frame_info.ethernet_frame.frame_number);
//        sprintf(outFile2, "../test2.h264", tcp_frame_info.ethernet_frame.frame_number);
//        printf("%s\n", outFile2);
//        FILE * fp3 = fopen(outFile2, "wb");
//        static FILE * fp3 = fopen(outFile2, "wb");
//        RETURN_IF_FAILED(fp3 == NULL, -1);

        printf("2222: frame_number=%d;\n", tcp_frame_info.ethernet_frame.frame_number);

        for (int i = 0; i < rtsp_interleaved_frame_length; ++i)
        {
            printf("3333: frame_number=%d; i=%d; rtsp_interleaved_frame_length=%d; h264.start_code_length=%d; nal_unit_type_h264_rtp=%d; "
                "nal_unit_type_h264=%d; h264_sub_packet_data_length=%d; rtp_payload_size=%d; rtp_length=%d;\n",
                tcp_frame_info.ethernet_frame.frame_number, i, rtsp_interleaved_frame_length,
                rtsp_header_and_payload_info.rtsp_interleaved_frame[i].rtp_and_rtcp.rtp_header_and_payload.h264_data.start_code_length,
                rtsp_header_and_payload_info.rtsp_interleaved_frame[i].rtp_and_rtcp.rtp_header_and_payload.h264_data.nal_unit_type_h264_rtp,
                rtsp_header_and_payload_info.rtsp_interleaved_frame[i].rtp_and_rtcp.rtp_header_and_payload.h264_data.nal_unit_type_h264,
                rtsp_header_and_payload_info.rtsp_interleaved_frame[i].rtp_and_rtcp.rtp_header_and_payload.h264_data.h264_sub_packet_data_length,
                rtsp_header_and_payload_info.rtsp_interleaved_frame[i].rtp_and_rtcp.rtp_header_and_payload.rtp_payload_size,
                rtsp_header_and_payload_info.rtsp_interleaved_frame[i].rtp_length
                );

            if (rtsp_header_and_payload_info.rtsp_interleaved_frame[i].rtp_and_rtcp.rtp_header_and_payload.h264_data.start_code_length > 0)
            {
                if (m_fp_out)
                {
                    writeBytes = fwrite(rtsp_header_and_payload_info.rtsp_interleaved_frame[i].rtp_and_rtcp.rtp_header_and_payload.h264_data.start_code,
                        rtsp_header_and_payload_info.rtsp_interleaved_frame[i].rtp_and_rtcp.rtp_header_and_payload.h264_data.start_code_length, 1, m_fp_out);
                }
            }

            if (m_fp_out)
            {
                writeBytes = fwrite(rtsp_header_and_payload_info.rtsp_interleaved_frame[i].rtp_and_rtcp.rtp_header_and_payload.h264_data.h264_sub_packet_data,
                    rtsp_header_and_payload_info.rtsp_interleaved_frame[i].rtp_and_rtcp.rtp_header_and_payload.h264_data.h264_sub_packet_data_length, 1, m_fp_out);
            }
        }

//        fclose(fp3);
    }

    //------------------------------------------------
    if (tcp_buffer_size_used < tcp_buffer_filled_size)
    {
        unsigned char aa = tcp_buffer[tcp_buffer_size_used + 0];;
        //memcpy(tcp_buffer, tcp_buffer + tcp_buffer_size_used, tcp_buffer_filled_size - tcp_buffer_size_used);
        for (int i = 0; i < tcp_buffer_filled_size - tcp_buffer_size_used; ++i)
        {
            tcp_buffer[i] = tcp_buffer[tcp_buffer_size_used + i];
        }
        tcp_buffer_filled_size -= tcp_buffer_size_used;
    }
    else if (tcp_buffer_size_used == tcp_buffer_filled_size)
    {
        tcp_buffer_filled_size = 0;
    }

    return ret;
}


int CWiresharkRtspOverTcp::probeFileType(const char *inputFilename, CAPTURE_NETWORK_PACKET_FILE_TYPE &fileType)
{
    int ret = 0;

    fileType = CAPTURE_NETWORK_PACKET_FILE_TYPE_UNKNOWN;

    //-------------------
    ret = m_tcpdumpCapFile.probeFileType(inputFilename);
    if (ret == 0) //说明是cap格式文件
    {
        fileType = CAPTURE_NETWORK_PACKET_FILE_TYPE_CAP_BY_TCPDUMP;
        return 0;
    }

    //-------------------
    ret = m_wiresharkPcapngFile.probeFileType(inputFilename);
    if (ret == 0) //说明是pcapng格式文件
    {
        fileType = CAPTURE_NETWORK_PACKET_FILE_TYPE_PCAPNG_BY_WIRESHARK;
        return 0;
    }

    return -1;
}


int CWiresharkRtspOverTcp::getNextNetworkFrame(unsigned char *&framePos, int &frameSize)
{
    int ret = 0;

    //-------------------------
    switch (m_fileType)
    {
    case CAPTURE_NETWORK_PACKET_FILE_TYPE_CAP_BY_TCPDUMP:
        {
            ret = m_tcpdumpCapFile.getNextNetworkFrame(framePos, frameSize);
            RETURN_IF_FAILED(ret != 0, -1);
            break;
        }
    case CAPTURE_NETWORK_PACKET_FILE_TYPE_PCAPNG_BY_WIRESHARK:
        {
            ret = m_wiresharkPcapngFile.getNextNetworkFrame(framePos, frameSize);
            RETURN_IF_FAILED(ret != 0, -1);
            break;
        }
    default:
        {
            break;
        }
    }

    return ret;
}
