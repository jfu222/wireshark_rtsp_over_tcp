#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>


/*
   http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#section_block

   Figure 9: Section Header Block Format

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                   Block Type = 0x0A0D0D0A                     |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                      Byte-Order Magic                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |          Major Version        |         Minor Version         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                                                               |
   |                          Section Length                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
*/
typedef struct _WIRESHARK_PCAPNG_FILE_HEADER_
{
    int block_type; //4bytes 0x0A0D0D0A
    int block_total_length; //4bytes 0x000000B4
    int magic; //4bytes 0x1A2B3C4D (注意：和cap文件的magic不一样)
    int version_major;//2bytes 0x0001
    int version_minor;//2bytes 0x0000
    int section_length; //4bytes 0xFFFFFFFFFFFFFFFF
}WIRESHARK_PCAPNG_FILE_HEADER;


//Wireshark的源代码git地址 https://github.com/wireshark/wireshark
class CWiresharkPcapngFile
{
public:
    std::string m_inputFilename;
    FILE * m_fp;
    long m_fileSize;
    unsigned char * m_buffer;
    long m_bufferSize;
    unsigned char * m_bufferPosNow; //文件读取到的当前位置

    WIRESHARK_PCAPNG_FILE_HEADER m_fileHeader;

public:
    CWiresharkPcapngFile();
    ~CWiresharkPcapngFile();

    int probeFileType(const char *inputFilename); //探测抓包文件的类型
    int getNextNetworkFrame(unsigned char *&framePos, int &frameSize);
};

