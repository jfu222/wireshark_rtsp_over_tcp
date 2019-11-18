#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

typedef struct _TCPDUMP_CAP_FILE_HEADER_
{
    int magic; //4bytes [D4 C3 B2 A1] = 0xA1B2C3D4
    int version_major;//2bytes [02 00] = 2
    int version_minor;//2bytes [04 00] = 4
    int time_zone;//4bytes 时区
    int timestamp_accuracy;//4bytes 时间戳精度
    int max_capture_size_per_packet;//4bytes 每个包的抓包的最大值（单位：字节） [00 00 04 00] = 0x40000 = 262144;
    int data_link_layer_type;//4bytes 数据链路层类型 [01 00 00 00] = 1 = LINKTYPE_ETHERNET; https://www.tcpdump.org/linktypes.html
}TCPDUMP_CAP_FILE_HEADER;


class CTcpdumpCapFile
{
public:
    std::string m_inputFilename;
    FILE * m_fp;
    long m_fileSize;
    unsigned char * m_buffer;
    long m_bufferSize;
    unsigned char * m_bufferPosNow; //文件读取到的当前位置

    TCPDUMP_CAP_FILE_HEADER m_fileHeader;

public:
    CTcpdumpCapFile();
    ~CTcpdumpCapFile();

    int probeFileType(const char *inputFilename); //探测抓包文件的类型
    int getNextNetworkFrame(unsigned char *&framePos, int &frameSize);
    int writeTcpdumpCapFileHeader(FILE * fp);
};

