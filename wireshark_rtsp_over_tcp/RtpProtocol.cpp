#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>
#include <vector>
#include "RtpProtocol.h"
#include "CommonFunction.h"


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


CRtpProtocol::CRtpProtocol()
{

}


CRtpProtocol::~CRtpProtocol()
{

}


int CRtpProtocol::splitRtpPacket(unsigned char *buffer, int bufferSize, RTP_HEADER_AND_PAYLOAD &rtp_header_payload, std::string &strErrorType)
{
    int ret = 0;

    //-------------------------
    RETURN_IF_FAILED(bufferSize < 12, -1);

    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;
    unsigned char *p3 = buffer + bufferSize - 1;

    rtp_header_payload.rtp_packet_total_size = bufferSize;

    rtp_header_payload.version = (p1[0] & 0xC0) >> 6;
    rtp_header_payload.padding = (p1[0] & 0x20) >> 5;
    rtp_header_payload.extension = (p1[0] & 0x10) >> 4;
    rtp_header_payload.contributing_source_identifiers_count = (p1[0] & 0x0F) >> 4;
    p1++;

    rtp_header_payload.marker = (p1[0] & 0x80) >> 7;
    rtp_header_payload.payload_type = p1[0] & 0x7F; //Payload type: DynamicRTP-Type-96 (96)
    p1++;

    rtp_header_payload.sequence_number = (p1[0] << 8) | p1[1];
    p1 += 2;

    rtp_header_payload.timestamp = (p1[0] << 24) | (p1[1] << 16) | (p1[2] << 8) | p1[3];
    p1 += 4;

    rtp_header_payload.synchronization_source_identifier = (p1[0] << 24) | (p1[1] << 16) | (p1[2] << 8) | p1[3];
    p1 += 4;

    for (int i = 0; i < rtp_header_payload.contributing_source_identifiers_count; ++i)
    {
        RETURN_IF_FAILED(p3 - (p1 + 4) < 0, -1);
        p1 += 4;
    }

    //-------------------------------------
    rtp_header_payload.padding_count = 0;

    if (rtp_header_payload.padding == 1)
    {
        rtp_header_payload.padding_count = *p3;
    }

    if (rtp_header_payload.extension == 1)
    {
        rtp_header_payload.rtp_header_extension_defined_by_profile = (p1[0] << 24) | (p1[1] << 16) | (p1[2] << 8) | p1[3];
        p1 += 4;

        rtp_header_payload.rtp_header_extension_length = (p1[0] << 24) | (p1[1] << 16) | (p1[2] << 8) | p1[3];
        p1 += 4;

        for (int i = 0; i < rtp_header_payload.rtp_header_extension_length; ++i)
        {
            RETURN_IF_FAILED(p3 - (p1 + 4) < 0, -1);
            p1 += 4;
        }
    }

    rtp_header_payload.rtp_payload_size = (p3 - rtp_header_payload.padding_count) - p1 + 1;
    rtp_header_payload.rtp_payload = p1;

    RETURN_IF_FAILED(rtp_header_payload.rtp_payload_size < 0, -1);

    //------------------
    ret = splitH264Payload(rtp_header_payload, strErrorType);

    rtp_header_payload.printInfo();

    RETURN_IF_FAILED(ret != 0, ret);

    return ret;
}


int CRtpProtocol::splitRtcpPacket(unsigned char *buffer, int bufferSize, RTCP_INFO &rtcp_info)
{
    int ret = 0;

    return ret;
}


/*
+---------------+
|0|1|2|3|4|5|6|7|
+-+-+-+-+-+-+-+-+
|F|NRI|  Type   |
+---------------+


nal_unit_type    Content of NAL unit and RBSP syntax structure      C
0                   Unspecified                                     -
1                   Coded slice of a non-IDR picture                2, 3, 4
2                   Coded slice data partition A                    2
3                   Coded slice data partition B                    3
4                   Coded slice data partition C                    4
5                   Coded slice of an IDR picture                   2, 3
6                   Supplemental enhancement information (SEI)      5
7                   Sequence parameter set                          0
8                   Picture parameter set                           1
9                   Access unit delimiter                           6
10                  End of sequence                                 7
11                  End of stream                                   8
12                  Filler data                                     9
13                  Sequence parameter set extension                10
14                  Prefix NAL unit                                 2
15                  Subset sequence parameter set                   0
16                  Depth parameter set                             11
17..18              Reserved                                        -
19                  Coded slice of an auxiliary coded               2, 3, 4
20                  Coded slice extension                           2, 3, 4
21                  Coded slice extension for a depth view          2, 3, 4
13..23              Reserved                                        -
24..31              Unspecified                                     -


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
30-31  undefined        -                           -

Type   Packet    Single NAL    Non-Interleaved    Interleaved
                 Unit Mode           Mode             Mode
-------------------------------------------------------------
0      undefined     ig               ig               ig
1-23   NAL unit     yes              yes               no
24     STAP-A        no              yes               no
25     STAP-B        no               no              yes
26     MTAP16        no               no              yes
27     MTAP24        no               no              yes
28     FU-A          no              yes              yes
29     FU-B          no               no              yes
30-31  undefined     ig               ig               ig

https://tools.ietf.org/html/rfc3984 Page18

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|F|NRI|  Type   |                                               |
+-+-+-+-+-+-+-+-+                                               |
|                                                               |
|              Bytes 2..n of a single NAL unit                  |
|                                                               |
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               :...OPTIONAL RTP padding        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Figure 2. RTP payload format for single NAL unit packet

*/
int CRtpProtocol::splitH264Payload(RTP_HEADER_AND_PAYLOAD &rtp_header_payload, std::string &strErrorType)
{
    int ret = 0;
    
    strErrorType = ".error";
    unsigned char * p = rtp_header_payload.rtp_payload;
    int forbidden_zero_bit = (p[0] & 0x80) >> 7;

    if (forbidden_zero_bit == 1) //对于h264 NALU，该字段必须置0，置1表示发生错误，必须丢弃该NALU
    {
        printf("%s(%d): %s: Error: forbidden_zero_bit == 1\n", __FILE__, __LINE__, __FUNCTION__);
        return -1;
    }

    int nal_ref_idc = (p[0] & 0x60) >> 5;
    int nal_unit_type = p[0] & 0x1F;

    size_t writeBytes = 0;
    char h264_start_code[] = {0x00, 0x00, 0x00, 0x01};

    memcpy(&rtp_header_payload.h264_data.start_code, h264_start_code, 4);
    rtp_header_payload.h264_data.start_code_length = 0;
    rtp_header_payload.h264_data.nal_unit_type_h264_rtp = nal_unit_type;

    printf("%s(%d): %s: Info: nal_unit_type = %d; rtp_header_payload.payload_size=%d (0x%04x);\n", __FILE__, __LINE__, __FUNCTION__, nal_unit_type, rtp_header_payload.rtp_payload_size, rtp_header_payload.rtp_payload_size);

    if (nal_unit_type >= 1 && nal_unit_type <= 23) //h264 NAL unit
    {
        rtp_header_payload.h264_data.start_code[4] = p[0];
        rtp_header_payload.h264_data.start_code_length = 5;
        rtp_header_payload.h264_data.nal_unit_type_h264 = nal_unit_type;
        rtp_header_payload.h264_data.h264_sub_packet_data = rtp_header_payload.rtp_payload + 1;
        rtp_header_payload.h264_data.h264_sub_packet_data_length = rtp_header_payload.rtp_payload_size - 1;
    }
    else if (nal_unit_type == 24) //STAP-A
    {
        printf("%s(%d): %s: Undefine STAP-A: undefine nal_unit_type = %d;\n", __FILE__, __LINE__, __FUNCTION__, nal_unit_type);
        strErrorType = ".STAP-A";
        return -1;
    }
    else if (nal_unit_type == 25) //STAP-B
    {
        printf("%s(%d): %s: Undefine STAP-B: undefine nal_unit_type = %d;\n", __FILE__, __LINE__, __FUNCTION__, nal_unit_type);
        strErrorType = ".STAP-B";
        return -1;
    }
    else if (nal_unit_type == 26) //MTAP16
    {
        printf("%s(%d): %s: Undefine MTAP16: undefine nal_unit_type = %d;\n", __FILE__, __LINE__, __FUNCTION__, nal_unit_type);
        strErrorType = ".MTAP16";
        return -1;
    }
    else if (nal_unit_type == 27) //MTAP24
    {
        printf("%s(%d): %s: Undefine MTAP24: undefine nal_unit_type = %d;\n", __FILE__, __LINE__, __FUNCTION__, nal_unit_type);
        strErrorType = ".MTAP24";
        return -1;
    }
    else if (nal_unit_type == 28) //FU-A
    {
        /*
          FU_header
         +---------------+
         |0|1|2|3|4|5|6|7|
         +-+-+-+-+-+-+-+-+
         |S|E|R|  Type   |
         +---------------+
        */
        //unsigned char FU_indicator = p[0];
        //unsigned char FU_header = p[1];

        int is_start_of_a_fragmented_NAL_unit = (p[1] & 0x80) >> 7;
        int is_end_of_a_fragmented_NAL_unit = (p[1] & 0x40) >> 6;
        int reserved = (p[1] & 0x20) >> 5;
        int nal_unit_payload_type = p[1] & 0x1F;

        unsigned char h264_first_byte = (p[0] & 0xE0) | (p[1] & 0x1F);

        if (is_start_of_a_fragmented_NAL_unit == 1)
        {
            rtp_header_payload.h264_data.start_code[4] = h264_first_byte;
            rtp_header_payload.h264_data.start_code_length = 5;
        }
        rtp_header_payload.h264_data.nal_unit_type_h264 = nal_unit_payload_type;
        rtp_header_payload.h264_data.h264_sub_packet_data = rtp_header_payload.rtp_payload + 2;
        rtp_header_payload.h264_data.h264_sub_packet_data_length = rtp_header_payload.rtp_payload_size - 2;
    }
    else if (nal_unit_type == 29) //FU-B
    {
        printf("%s(%d): %s: Undefine FU-B: undefine nal_unit_type = %d;\n", __FILE__, __LINE__, __FUNCTION__, nal_unit_type);
        strErrorType = ".FU-B";
        return -1;
    }
    else
    {
        printf("%s(%d): %s: Error: undefine nal_unit_type = %d;\n", __FILE__, __LINE__, __FUNCTION__, nal_unit_type);
        strErrorType = ".Unknown";
        return -1;
    }

    return ret;
}


//按照GOP来拆分H264裸码流文件，拆分后，可以使用"ffmpeg -i ./test.h264 -f image2 ./jpg_dir/image-%02d.jpg"
//命令来将H264文件解码并保存成jpg图片
int CRtpProtocol::splitSingleH264FileToMultiFilesByIFrame(std::string inputFilename, std::string outputDir)
{
    int ret = 0;
    
    ret = createNestedDir(outputDir.c_str());
    if (ret != 0)
    {
        printf("%s(%d): %s: Error: Cannot create directory! outputDir ='%s'; ret=%d;\n", __FILE__, __LINE__, __FUNCTION__, outputDir.c_str(), ret);
        return -1;
    }

    //---------------
    printf("%s\n", inputFilename.c_str());

    FILE * fp = fopen(inputFilename.c_str(), "rb");
    if (fp == NULL)
    {
        printf("%s(%d): %s: Error: Cannot open file to read! inputFilename='%s'\n", __FILE__, __LINE__, __FUNCTION__, inputFilename.c_str());
        return -1;
    }

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

    //------------------
    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;
    unsigned char *p3 = buffer + fileSize - 1;
    int gop_cnt = 1;
    int nalu_cnt = 0;
     std::string outFilename = "";
     size_t writeBytes = 0;

    while(p1 + 5 < p3)
    {
        if(p1[0] == 0x00 && p1[1] == 0x00 && p1[2] == 0x00 && p1[3] == 0x01) //h264 start code
        {
            int forbidden_zero_bit = (p1[4] & 0x80) >> 7;

            if (forbidden_zero_bit == 1) //对于h264 NALU，该字段必须置0，置1表示发生错误，必须丢弃该NALU
            {
                printf("%s(%d): %s: Error: forbidden_zero_bit == 1\n", __FILE__, __LINE__, __FUNCTION__);
//                return -1;
            }

            int nal_ref_idc = (p1[4] & 0x60) >> 5;
            int nal_unit_type = p1[4] & 0x1F;

            if(nal_unit_type == 7) //sps
            {
                if(nalu_cnt > 0)
                {
                    outFilename = outputDir + "/gop" + std::to_string(gop_cnt) + ".naluCnt" + std::to_string(nalu_cnt) + ".h264";
                    printf("%s(%d): %s: outFilename=%s;\n", __FILE__, __LINE__, __FUNCTION__, outFilename.c_str());

                    FILE * fp2 = fopen(outFilename.c_str(), "wb");
                    if (fp2 == NULL)
                    {
                        printf("%s(%d): %s: Cannot open file to write! outFilename='%s'\n", __FILE__, __LINE__, __FUNCTION__, outFilename.c_str());
                        return -1;
                    }
                    writeBytes = fwrite(p2, p1 - p2, 1, fp2);
                    fclose(fp2);

                    nalu_cnt = 0;
                    gop_cnt++;
                }

                if(nalu_cnt == 0)
                {
                    p2 = p1;
                }
            }
            nalu_cnt++;
        }
        p1++;
    }
    
    //--------------------
    if (nalu_cnt > 0)
    {
        p1 = p3;

        outFilename = outputDir + "/gop" + std::to_string(gop_cnt) + ".naluCnt" + std::to_string(nalu_cnt) + ".h264";
        printf("%s(%d): %s: outFilename=%s;\n", __FILE__, __LINE__, __FUNCTION__, outFilename.c_str());

        FILE * fp2 = fopen(outFilename.c_str(), "wb");
        if (fp2 == NULL)
        {
            printf("%s(%d): %s: Cannot open file to write! outFilename='%s'\n", __FILE__, __LINE__, __FUNCTION__, outFilename.c_str());
            return -1;
        }
        writeBytes = fwrite(p2, p1 - p2 + 1, 1, fp2);
        fclose(fp2);

        nalu_cnt = 0;
        gop_cnt++;
    }

    //------------------
    if(buffer)
    {
        free(buffer);
        buffer = NULL;
    }

    return ret;
}


int CRtpProtocol::splitSingleH264FileToMultiFilesByStartCode(std::string inputFilename, std::string outputDir)
{
    int ret = 0;
    
    ret = createNestedDir(outputDir.c_str());
    if (ret != 0)
    {
        printf("%s(%d): %s: Error: Cannot create directory! outputDir ='%s'; ret=%d;\n", __FILE__, __LINE__, __FUNCTION__, outputDir.c_str(), ret);
        return -1;
    }

    //---------------
    printf("%s\n", inputFilename.c_str());

    FILE * fp = fopen(inputFilename.c_str(), "rb");
    if (fp == NULL)
    {
        printf("%s(%d): %s: Error: Cannot open file to read! inputFilename='%s'\n", __FILE__, __LINE__, __FUNCTION__, inputFilename.c_str());
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *buffer = (unsigned char *)malloc(sizeof(unsigned char) * fileSize); //暂时将整个文件读入内存，后续可以改成指定大小读取
    RETURN_IF_FAILED(buffer == NULL, -3);

    size_t readSize = fread(buffer, fileSize, 1, fp);
    if (readSize != 1)
    {
        printf("%s(%d): Error: read_size=%d != 1\n", __FUNCTION__, __LINE__, readSize);
        fclose(fp);
        free(buffer);
    }

    fclose(fp);

    //------------------
    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;
    unsigned char *p3 = buffer + fileSize - 1;
    int nalu_cnt = 0;
    int nalu_cnt2 = 0;
    int nal_unit_type2 = 0;
     std::string outFilename = "";
     size_t writeBytes = 0;

    while(p1 + 5 < p3)
    {
        if(p1[0] == 0x00 && p1[1] == 0x00 && p1[2] == 0x00 && p1[3] == 0x01) //h264 start code
        {
            int forbidden_zero_bit = (p1[4] & 0x80) >> 7;

            if (forbidden_zero_bit == 1) //对于h264 NALU，该字段必须置0，置1表示发生错误，必须丢弃该NALU
            {
                printf("%s(%d): %s: Error: forbidden_zero_bit == 1\n", __FILE__, __LINE__, __FUNCTION__);
//                return -1;
            }

            int nal_ref_idc = (p1[4] & 0x60) >> 5;
            int nal_unit_type = p1[4] & 0x1F;

//            if(nal_unit_type == 7) //sps
            {
                if(nalu_cnt > 0)
                {
                    outFilename = outputDir + "/naluCnt" + std::to_string(nalu_cnt2) + ".nalType" + std::to_string(nal_unit_type2) + ".h264";
                    printf("%s(%d): %s: outFilename=%s;\n", __FILE__, __LINE__, __FUNCTION__, outFilename.c_str());

                    FILE * fp2 = fopen(outFilename.c_str(), "wb");
                    if (fp2 == NULL)
                    {
                        printf("%s(%d): %s: Cannot open file to write! outFilename='%s'\n", __FILE__, __LINE__, __FUNCTION__, outFilename.c_str());
                        return -1;
                    }
                    writeBytes = fwrite(p2, p1 - p2, 1, fp2);
                    fclose(fp2);

                    nalu_cnt = 0;
                }

                if(nalu_cnt == 0)
                {
                    p2 = p1;
                    nal_unit_type2 = nal_unit_type;
                }
            }
            nalu_cnt++;
            nalu_cnt2++;
        }
        p1++;
    }
    
    //--------------------
    if (nalu_cnt > 0)
    {
        p1 = p3;
        
        outFilename = outputDir + "/naluCnt" + std::to_string(nalu_cnt2) + ".nalType" + std::to_string(nal_unit_type2) + ".h264";
        printf("%s(%d): %s: outFilename=%s;\n", __FILE__, __LINE__, __FUNCTION__, outFilename.c_str());

        FILE * fp2 = fopen(outFilename.c_str(), "wb");
        if (fp2 == NULL)
        {
            printf("%s(%d): %s: Cannot open file to write! outFilename='%s'\n", __FILE__, __LINE__, __FUNCTION__, outFilename.c_str());
            return -1;
        }
        writeBytes = fwrite(p2, p1 - p2 + 1, 1, fp2);
        fclose(fp2);

        nalu_cnt = 0;
    }

    //------------------
    if(buffer)
    {
        free(buffer);
        buffer = NULL;
    }

    return ret;
}
