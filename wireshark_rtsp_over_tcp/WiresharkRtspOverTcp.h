#pragma once
#include "TcpdumpCapFile.h"
#include "WiresharkPcapngFile.h"
#include "TcpIpProtocol.h"
#include "RtspProtocol.h"
#include "RtpProtocol.h"
#include <string>
#include <vector>


typedef enum _CAPTURE_NETWORK_PACKET_FILE_TYPE_
{
    CAPTURE_NETWORK_PACKET_FILE_TYPE_UNKNOWN = 0,
    CAPTURE_NETWORK_PACKET_FILE_TYPE_CAP_BY_TCPDUMP, //linux tcpdump程序产生的后缀名为cap的文件
    CAPTURE_NETWORK_PACKET_FILE_TYPE_PCAPNG_BY_WIRESHARK, //win wireshark程序产生的后缀名为pcapng的文件 https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#appendixPBFM
}CAPTURE_NETWORK_PACKET_FILE_TYPE;


class CWiresharkRtspOverTcp
{
public:
    std::string m_inputFilename;
    std::string m_outputDir; //用于保存h264结果的文件目录
    std::string m_outputFilename; //输出h264文件
    CAPTURE_NETWORK_PACKET_FILE_TYPE m_fileType;

    FILE * m_fp_out;

    CTcpdumpCapFile m_tcpdumpCapFile;
    CWiresharkPcapngFile m_wiresharkPcapngFile;

public:
    CWiresharkRtspOverTcp();
    ~CWiresharkRtspOverTcp();

    int splitRtspOverTcp(std::string inputFilename, std::string rtspServerIp, int rtspServerPort, std::string outputDir, int startFrameNumber, int endFrameNumber);
    int readOneEthernetFrame(unsigned char *buffer, int bufferSize, int frame_number, TCP_FRAME_INFO &tcp_frame_info, unsigned char *&newPos, unsigned char *bufferBase);
    int writeDataToFile(TCP_FRAME_INFO &tcp_frame_info, unsigned char *tcp_buffer, int &tcp_buffer_filled_size, int &tcp_buffer_size_used);
    int probeFileType(const char *inputFilename, CAPTURE_NETWORK_PACKET_FILE_TYPE &fileType); //探测抓包文件的类型
    int getNextNetworkFrame(unsigned char *&framePos, int &frameSize);
};

