#include "TcpdumpCapFile.h"
#include "TcpIpProtocol.h"


#define RETURN_IF_FAILED(condition, ret)                                                      \
    do                                                                                        \
    {                                                                                         \
        if (condition)                                                                        \
        {                                                                                     \
            printf("%s(%d): %s: Error: ret=%d;\n", __FILE__, __LINE__, __FUNCTION__, ret);    \
            return ret;                                                                       \
        }                                                                                     \
    } while (0)


CTcpdumpCapFile::CTcpdumpCapFile()
{
    m_inputFilename = "";
    m_fp = NULL;
    m_fileSize = 0;
    m_buffer = NULL;
    m_bufferSize = 0;
    m_bufferPosNow = NULL;
}


CTcpdumpCapFile::~CTcpdumpCapFile()
{
    if (m_fp)
    {
        fclose(m_fp);
        m_fp = NULL;
    }

    if (m_buffer)
    {
        free(m_buffer);
        m_buffer = NULL;
    }
}


int CTcpdumpCapFile::probeFileType(const char *inputFilename)
{
    RETURN_IF_FAILED(inputFilename == NULL, -1);

    printf("%s(%d): %s: inputFilename=%s;\n", __FILE__, __LINE__, __FUNCTION__, inputFilename);

    FILE * fp = fopen(inputFilename, "rb");
    RETURN_IF_FAILED(fp == NULL, -2);

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *buffer = (unsigned char *)malloc(sizeof(unsigned char) * fileSize); //暂时将整个文件读入内存，后续可以改成按frame大小读取
    RETURN_IF_FAILED(buffer == NULL, -3);

    size_t readSize = fread(buffer, fileSize, 1, fp);
    if (readSize != 1)
    {
        printf("%s(%d): Error: read_size=%d != 1\n", __FUNCTION__, __LINE__, readSize);
        fclose(fp);
        free(buffer);
    }

    fclose(fp);
    fp = NULL;

    RETURN_IF_FAILED(fileSize < 24, -3);

    //--------------------
    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;
    unsigned char *p3 = buffer + fileSize - 1;

    if (p1[0] == 0xD4 && p1[1] == 0xC3 && p1[2] == 0xB2 && p1[3] == 0xA1)
    {
        m_fileHeader.magic = (p1[3] << 24) | (p1[2] << 16) | (p1[1] << 8) | p1[0];
        p1 += 4;

        m_fileHeader.version_major = (p1[1] << 8) | p1[0];
        p1 += 2;

        m_fileHeader.version_minor = (p1[1] << 8) | p1[0];
        p1 += 2;

        m_fileHeader.time_zone = (p1[3] << 24) | (p1[2] << 16) | (p1[1] << 8) | p1[0];
        p1 += 4;

        m_fileHeader.timestamp_accuracy = (p1[3] << 24) | (p1[2] << 16) | (p1[1] << 8) | p1[0];
        p1 += 4;

        m_fileHeader.max_capture_size_per_packet = (p1[3] << 24) | (p1[2] << 16) | (p1[1] << 8) | p1[0];
        p1 += 4;

        m_fileHeader.data_link_layer_type = (p1[3] << 24) | (p1[2] << 16) | (p1[1] << 8) | p1[0];
        p1 += 4;

        if (m_fileHeader.data_link_layer_type != 1)
        {
            printf("%s(%d): %s: Error: tcpdumpFileHeader.data_link_layer_type(%d) != 1;\n", __FILE__, __LINE__, __FUNCTION__, m_fileHeader.data_link_layer_type); //目前暂时只支持LINKTYPE_ETHERNET以太帧
            
            if (buffer)
            {
                free(buffer);
                buffer = NULL;
            }

            return -1;
        }

        //-------------------------
        m_inputFilename = inputFilename;
        m_fileSize = fileSize;
        m_bufferSize = fileSize;
        m_buffer = buffer;
        m_bufferPosNow = p1;

        printf("%s(%d): OK. This file is tcpdump-cap file format.\n", __FUNCTION__, __LINE__, readSize);

        return 0;
    }
    
    //------------------
    if (buffer)
    {
        free(buffer);
        buffer = NULL;
    }

    return -1;
}


int CTcpdumpCapFile::getNextNetworkFrame(unsigned char *&framePos, int &frameSize)
{
    int ret = 0;

    //-------------------------
    unsigned char *p = NULL;
    CTcpIpProtocol tcpIpProtocol;
    ETHERNET_FRAME ethernetFrame;

    memset(&ethernetFrame, 0, sizeof(ETHERNET_FRAME));
    
    ret = tcpIpProtocol.readOneEthernetFrame(m_bufferPosNow, m_bufferSize - (m_bufferPosNow - m_buffer), ethernetFrame, p, m_buffer);
    RETURN_IF_FAILED(ret != 0, ret);

    framePos = m_bufferPosNow;
    frameSize = ethernetFrame.frame_length + 16;

    m_bufferPosNow += frameSize;

    return 0;
}


int CTcpdumpCapFile::writeTcpdumpCapFileHeader(FILE * fp)
{
    int ret = 0;
    RETURN_IF_FAILED(fp == NULL, ret);
    size_t writeBytes = 0;

    writeBytes = fwrite(&m_fileHeader.magic, 1, 4, fp);
    writeBytes = fwrite(&m_fileHeader.version_major, 1, 2, fp);
    writeBytes = fwrite(&m_fileHeader.version_minor, 1, 2, fp);
    writeBytes = fwrite(&m_fileHeader.time_zone, 1, 4, fp);
    writeBytes = fwrite(&m_fileHeader.timestamp_accuracy, 1, 4, fp);
    writeBytes = fwrite(&m_fileHeader.max_capture_size_per_packet, 1, 4, fp);
    writeBytes = fwrite(&m_fileHeader.data_link_layer_type, 1, 4, fp);

    return 0;
}
