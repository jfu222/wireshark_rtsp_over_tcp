#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>
#include <vector>
#include "RtspProtocol.h"
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



CRtspProtocol::CRtspProtocol()
{
    m_inputFilename = "";
    m_outputDir = "";
    m_outputFilename = "";
}


CRtspProtocol::~CRtspProtocol()
{
    int ret = closeFile();
}


int CRtspProtocol::splitRtpPayloadFile(std::string inputFilename, std::string outputFilename)
{
    int ret = 0;
    
    RETURN_IF_FAILED(inputFilename == "", -1);
    
    m_inputFilename = inputFilename;
    m_outputFilename = outputFilename;
    
    std::string dirName = "";
    std::string baseName = "";
    std::string extensionName = "";

    ret = getFileDirnameAndBasenameAndExtname(m_outputFilename.c_str(), dirName, baseName, extensionName);
    RETURN_IF_FAILED(ret != 0, -1);

    m_outputDir = dirName;

    //-------------------------
    printf("%s(%d): %s: inputFilename=%s;\n", __FILE__, __LINE__, __FUNCTION__, inputFilename.c_str());

    FILE * fp = fopen(inputFilename.c_str(), "rb");
    if(fp == NULL)
    {
        printf("%s(%d): %s: Cannot open file to read. inputFilename=%s;\n", __FILE__, __LINE__, __FUNCTION__, inputFilename.c_str());
        return -2;
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
    fp = NULL;
    
    //---------------------
    int bufferSizeUsed = 0;
    RTSP_HEADER_AND_PAYLAOAD_INFO rtsp_header_and_payload_info;

    memset(&rtsp_header_and_payload_info, 0, sizeof(RTSP_HEADER_AND_PAYLAOAD_INFO));
    
    ret = splitRtspPacket(buffer, fileSize, rtsp_header_and_payload_info, bufferSizeUsed);
    printf("%s(%d): %s: ret=%d; bufferSizeUsed=%d; fileSize=%d;\n", __FILE__, __LINE__, __FUNCTION__, ret, bufferSizeUsed, bufferSizeUsed);
    
    int ret2 = closeFile();

    RETURN_IF_FAILED(ret != 0, ret);

    return ret;
}


int CRtspProtocol::splitRtspPacket(unsigned char *buffer, int bufferSize, RTSP_HEADER_AND_PAYLAOAD_INFO &rtsp_header_and_payload_info, int &bufferSizeUsed)
{
    int ret = 0;

    //-------------------------
    RETURN_IF_FAILED(bufferSize < 0, -1);

    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;
    unsigned char *p3 = buffer + bufferSize - 1;
    int flag = 0;
    int bufferSizeUsedTemp = 0;
    size_t writeBytes = 0;
    std::string outputFilename = "";
    std::string outputFilenameH264 = "";
    CRtpProtocol rtpProtocol;

    //------------------
    while(p2 < p3)
    {
        p1 = p2;

        if(*p2 == '$') //RTP 音视频数据开始标识符
        {
            RTSP_INTERLEAVED_FRAME rtp_interleaved_frame;
            bufferSizeUsed = 0;

            memset(&rtp_interleaved_frame, 0, sizeof(RTSP_INTERLEAVED_FRAME));

            rtp_interleaved_frame.interleaved_frame_data = p2;

            rtp_interleaved_frame.magic = *p2;
            p2++;

            rtp_interleaved_frame.channel = *p2;
            p2++;
            
            if(p2[0] == 0x05 && p2[1] == 0x95 && p2[2] == 0x80 && p2[3] == 0x60)
            {
                int a = 1;
            }

            int rtp_length = p2[0] << 8 | p2[1];
            rtp_interleaved_frame.rtp_length = rtp_length;
            rtp_interleaved_frame.rtp_real_read_bytes_in_single_tcp_packet = rtp_length;
            p2 += 2;

            int left_length = p3 - p2 + 1;
            if (left_length < rtp_length) //该RTP包数据超出了单个TCP包载荷大小
            {
                rtp_interleaved_frame.rtp_real_read_bytes_in_single_tcp_packet = left_length;
                printf("%s(%d): %s: Error: left_length(%d) < rtp_length(%d)\n", __FILE__, __LINE__, __FUNCTION__, left_length, rtp_length);
                break;
            }

            printf("%s(%d): %s: rtp_interleaved_frame.channel=%d; left_length=%d; rtp_length=%d; bufferSize=%d; file_offset=%d;\n",
                __FILE__, __LINE__, __FUNCTION__, rtp_interleaved_frame.channel, left_length, rtp_length, bufferSize, bufferSize - left_length);

            //-----------------------------
            std::string strErrorType = "";

            if (rtp_interleaved_frame.channel == 0) //偶数通道传送RTP数据(音/视频数据)
            {
                rtp_interleaved_frame.rtp_and_rtcp.rtp_header_and_payload.channel = rtp_interleaved_frame.channel;
                ret = rtpProtocol.splitRtpPacket(rtp_interleaved_frame.interleaved_frame_data + 4, rtp_interleaved_frame.rtp_real_read_bytes_in_single_tcp_packet, rtp_interleaved_frame.rtp_and_rtcp.rtp_header_and_payload, strErrorType);

                if (ret == 0)
                {
                    FILE * fp = NULL;
                    ret = openFileToWrite(rtp_interleaved_frame.channel, fp, outputFilename, ".h264"); //一般来说 channel=0表示视频通道，channel=2表示音频通道，具体值在RTSP sdp中设置
                    if (fp)
                    {
                        outputFilenameH264 = outputFilename;

                        if (rtp_interleaved_frame.rtp_and_rtcp.rtp_header_and_payload.h264_data.start_code_length > 0)
                        {
                            writeBytes = fwrite(rtp_interleaved_frame.rtp_and_rtcp.rtp_header_and_payload.h264_data.start_code,
                                rtp_interleaved_frame.rtp_and_rtcp.rtp_header_and_payload.h264_data.start_code_length, 1, fp);
                        }

                        writeBytes = fwrite(rtp_interleaved_frame.rtp_and_rtcp.rtp_header_and_payload.h264_data.h264_sub_packet_data,
                            rtp_interleaved_frame.rtp_and_rtcp.rtp_header_and_payload.h264_data.h264_sub_packet_data_length, 1, fp);
                    }
                }
                else
                {
                    printf("%s(%d): %s: Error: ret=%d;\n", __FILE__, __LINE__, __FUNCTION__, ret);

                    FILE * fp = NULL;
                    std::string strTemp = strErrorType + ".not_h264";
                    ret = openFileToWrite(rtp_interleaved_frame.channel, fp, outputFilename, strTemp);
                    if (fp)
                    {
                        writeBytes = fwrite(rtp_interleaved_frame.interleaved_frame_data + 4,
                            rtp_interleaved_frame.rtp_real_read_bytes_in_single_tcp_packet, 1, fp);
                    }
                }
            }
            else if (rtp_interleaved_frame.channel % 2 == 0) //偶数通道传送RTP数据(音/视频数据)
            {
                FILE * fp = NULL;
                ret = openFileToWrite(rtp_interleaved_frame.channel, fp, outputFilename, ".maybe_audio");
                if (fp)
                {
                    writeBytes = fwrite(rtp_interleaved_frame.interleaved_frame_data + 4,
                        rtp_interleaved_frame.rtp_real_read_bytes_in_single_tcp_packet, 1, fp);
                }
            }
            else//奇数通道传送RTCP数据
            {
                ret = rtpProtocol.splitRtcpPacket(rtp_interleaved_frame.interleaved_frame_data + 4, rtp_interleaved_frame.rtp_real_read_bytes_in_single_tcp_packet, rtp_interleaved_frame.rtp_and_rtcp.rtcp_info);
//                RETURN_IF_FAILED(ret != 0, -1);

                if (ret == 0)
                {
                    FILE * fp = NULL;
                    ret = openFileToWrite(rtp_interleaved_frame.channel, fp, outputFilename, ".rtcp");
                    if (fp)
                    {
                        writeBytes = fwrite(rtp_interleaved_frame.interleaved_frame_data + 4,
                            rtp_interleaved_frame.rtp_real_read_bytes_in_single_tcp_packet, 1, fp);
                    }
                }
                else
                {
                    printf("%s(%d): %s: Error: ret=%d;\n", __FILE__, __LINE__, __FUNCTION__, ret);
                }
            }

            p2 += rtp_interleaved_frame.rtp_real_read_bytes_in_single_tcp_packet - 1;
            bufferSizeUsed += rtp_interleaved_frame.rtp_real_read_bytes_in_single_tcp_packet + 4;
        }else if(p2 + 9 < p3 && memcmp(p2, "RTSP/1.0 ", 9) == 0)
        {
            while (p2 + 1 < p3 && *(p2 + 1) != '$') //注意：'$'(ascii 0x24)是RTP数据标识符， RTSP Interleaved Frame, Channel: 0x00, 36 bytes
            {
                p2++;
            }
            ret = splitRtspSeverResponse(p1, p2 - p1 + 1, rtsp_header_and_payload_info, bufferSizeUsedTemp);
            RETURN_IF_FAILED(ret != 0, ret);

            bufferSizeUsed += bufferSizeUsedTemp;
        }
        else
        {
//            printf("%s(%d): %s: Error: p2[0]: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", 
//                __FILE__, __LINE__, __FUNCTION__, p2[0], p2[1], p2[2], p2[3], p2[4]);
//            return -1;
        }

        p2++;
    }

    //--------将整个h264文件拆分成以GOP为单位的H264碎片文件，用于定位哪一个GOP导致了解码花屏-----------
    if(outputFilenameH264 != "")
    {
        std::string outDir = m_outputDir + "/split_h264";
        ret = rtpProtocol.splitSingleH264FileToMultiFilesByIFrame(outputFilenameH264, outDir);
        RETURN_IF_FAILED(ret != 0, ret);
    }

    return ret;
}


int CRtspProtocol::splitRtspClientRequest(unsigned char *buffer, int bufferSize, RTSP_HEADER_AND_PAYLAOAD_INFO &rtsp_header_and_payload_info, int &bufferSizeUsed)
{
    int ret = 0;

    //-------------------------
    RETURN_IF_FAILED(bufferSize < 0, -1);

    unsigned char *strTemp = (unsigned char *)malloc(bufferSize + 1);
    RETURN_IF_FAILED(strTemp == NULL, -1);
    memcpy(strTemp, buffer, bufferSize);
    strTemp[bufferSize] = '\0';
    printf("%s(%d): %s: buffer: --%s---\n", __FILE__, __LINE__, __FUNCTION__, strTemp);
    free(strTemp);
    strTemp = NULL;

    //----------------------------
    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;
    unsigned char *p3 = buffer + bufferSize - 1;
    int flag = 0;

    std::vector<std::string> vecLines;
    bufferSizeUsed = bufferSize;

    ret = getHttpLines((char *)p1, bufferSize, vecLines);
    RETURN_IF_FAILED(ret != 0 || vecLines.size() <= 0, -1);

    int lineCount1 = vecLines.size();

    std::vector<std::string> vecLinesTemp;
    std::vector<std::vector<std::string>> vecTypeLines;
    RTSP_REQUEST_RESPONSE_TYPE rtspType = RTSP_REQUEST_TYPE_UNKNOWN;

    for (int i = 0; i < lineCount1; ++i)
    {
        std::vector<std::string> vecCols;
        ret = splitLineBySeparatorChar(vecLines[i], ' ', vecCols);
        RETURN_IF_FAILED(ret != 0 || vecCols.size() < 3, -1);

        if (vecCols[0] == "OPTIONS" //RTSP Client Request: OPTIONS rtsp://192.168.0.5:554/h264/ch1/main/av_stream RTSP/1.0
            || vecCols[0] == "DESCRIBE"
            || vecCols[0] == "SETUP"
            || vecCols[0] == "PLAY"
            )
        {
            if (vecLinesTemp.size() > 0)
            {
                vecTypeLines.push_back(vecLinesTemp);
                vecLinesTemp.clear();
            }
            flag = 1;
        }

        vecLinesTemp.push_back(vecLines[i]);
    }

    if(flag == 1)
    {
        if (vecLinesTemp.size() > 0)
        {
            vecTypeLines.push_back(vecLinesTemp);
            vecLinesTemp.clear();
        }
    }

    //------------RTSP Client Request Method----------------------
    for (int j = 0; j < vecTypeLines.size(); ++j)
    {
        int lineCount = vecTypeLines[j].size();
        RETURN_IF_FAILED(lineCount < 3, -1);
        
        std::vector<std::string> vecCols;
        ret = splitLineBySeparatorChar(vecTypeLines[j][0], ' ', vecCols);
        RETURN_IF_FAILED(ret != 0 || vecCols.size() < 3, -1);

        //----------------------------------------
        std::vector<std::vector<std::string>> vecLineCols;

        if (vecCols[0] == "OPTIONS") //RTSP Client Request: OPTIONS rtsp://192.168.0.5:554/h264/ch1/main/av_stream RTSP/1.0
        {
            RETURN_IF_FAILED(lineCount < 3, -1);

            rtsp_header_and_payload_info.rtsp_reuest_options.rtsp_url = vecCols[1];
            rtsp_header_and_payload_info.rtsp_reuest_options.rtsp_version = vecCols[2];

            for (int i = 1; i < lineCount; ++i)
            {
                vecCols.clear();
                ret = splitLineBySeparatorChar(vecLines[i], ':', vecCols);
                RETURN_IF_FAILED(ret != 0 || vecCols.size() < 2, -1);

                if (vecCols[0] == "CSeq") //CSeq: 1
                {
                    rtsp_header_and_payload_info.rtsp_reuest_options.cseq = vecCols[1];
                } else if (vecCols[0] == "User-Agent") //User-Agent: Lavf57.56.101
                {
                    rtsp_header_and_payload_info.rtsp_reuest_options.user_agent = vecCols[1];
                }
            }
        } else if (vecCols[0] == "DESCRIBE") //RTSP Client Request: DESCRIBE rtsp://192.168.0.5:554/h264/ch1/main/av_stream RTSP/1.0
        {
            RETURN_IF_FAILED(lineCount != 4 && lineCount != 5, -1);

            if (lineCount == 4) //[Request DESCRIBE 1]s
            {
                rtsp_header_and_payload_info.rtsp_reuest_describe1.rtsp_url = vecCols[1];
                rtsp_header_and_payload_info.rtsp_reuest_describe1.rtsp_version = vecCols[2];

                for (int i = 1; i < lineCount; ++i)
                {
                    vecCols.clear();
                    ret = splitLineBySeparatorChar(vecLines[i], ':', vecCols);
                    RETURN_IF_FAILED(ret != 0 || vecCols.size() < 2, -1);

                    if (vecCols[0] == "CSeq") //CSeq: 2
                    {
                        rtsp_header_and_payload_info.rtsp_reuest_describe1.cseq = vecCols[1];
                    } else if (vecCols[0] == "User-Agent") //User-Agent: Lavf57.56.101
                    {
                        rtsp_header_and_payload_info.rtsp_reuest_describe1.user_agent = vecCols[1];
                    } else if (vecCols[0] == "Accept") //Accept: application/sdp
                    {
                        rtsp_header_and_payload_info.rtsp_reuest_describe1.accept = vecCols[1];
                    }
                }
            } else if (lineCount == 5) //[Request DESCRIBE 2]
            {
                rtsp_header_and_payload_info.rtsp_reuest_describe2.rtsp_url = vecCols[1];
                rtsp_header_and_payload_info.rtsp_reuest_describe2.rtsp_version = vecCols[2];

                for (int i = 1; i < lineCount; ++i)
                {
                    vecCols.clear();
                    ret = splitLineBySeparatorChar(vecLines[i], ':', vecCols);
                    RETURN_IF_FAILED(ret != 0 || vecCols.size() < 2, -1);

                    if (vecCols[0] == "CSeq") //CSeq: 3
                    {
                        rtsp_header_and_payload_info.rtsp_reuest_describe2.cseq = vecCols[1];
                    } else if (vecCols[0] == "User-Agent") //User-Agent: Lavf57.56.101
                    {
                        rtsp_header_and_payload_info.rtsp_reuest_describe2.user_agent = vecCols[1];
                    } else if (vecCols[0] == "Accept") //Accept: application/sdp
                    {
                        rtsp_header_and_payload_info.rtsp_reuest_describe2.accept = vecCols[1];
                    } else if (vecCols[0] == "Authorization") //Authorization: Digest username="admin", realm="a41437c723c4", nonce="d650274caf99bd963a97f805c839b85e", uri="rtsp://192.168.0.5:554/h264/ch1/main/av_stream", response="93d40550715a217ba8edb167f987504b"
                    {
                        rtsp_header_and_payload_info.rtsp_reuest_describe2.authorization = vecCols[1];
                    }
                }
            }
        } else if (vecCols[0] == "SETUP") //RTSP Client Request: SETUP rtsp://192.168.0.5:554/h264/ch1/main/av_stream/trackID=1 RTSP/1.0
        {
            RETURN_IF_FAILED(lineCount < 5, -1);

            rtsp_header_and_payload_info.rtsp_reuest_setup.rtsp_url = vecCols[1];
            rtsp_header_and_payload_info.rtsp_reuest_setup.rtsp_version = vecCols[2];

            for (int i = 1; i < lineCount; ++i)
            {
                vecCols.clear();
                ret = splitLineBySeparatorChar(vecLines[i], ':', vecCols);
                RETURN_IF_FAILED(ret != 0 || vecCols.size() < 2, -1);

                if (vecCols[0] == "CSeq") //CSeq: 4
                {
                    rtsp_header_and_payload_info.rtsp_reuest_setup.cseq = vecCols[1];
                } else if (vecCols[0] == "User-Agent") //User-Agent: Lavf57.56.101
                {
                    rtsp_header_and_payload_info.rtsp_reuest_setup.user_agent = vecCols[1];
                } else if (vecCols[0] == "Transport") //Transport: RTP / AVP / TCP; unicast; interleaved = 0 - 1
                {
                    rtsp_header_and_payload_info.rtsp_reuest_setup.transport = vecCols[1];
                } else if (vecCols[0] == "Authorization") //Authorization: Digest username="admin", realm="a41437c723c4", nonce="d650274caf99bd963a97f805c839b85e", uri="rtsp://192.168.0.5:554/h264/ch1/main/av_stream", response="93d40550715a217ba8edb167f987504b"
                {
                    rtsp_header_and_payload_info.rtsp_reuest_setup.authorization = vecCols[1];
                }
            }
        } else if (vecCols[0] == "PLAY") //RTSP Client Request: PLAY rtsp://192.168.0.5:554/h264/ch1/main/av_stream/ RTSP/1.0
        {
            RETURN_IF_FAILED(lineCount < 5, -1);

            rtsp_header_and_payload_info.rtsp_reuest_play.rtsp_url = vecCols[1];
            rtsp_header_and_payload_info.rtsp_reuest_play.rtsp_version = vecCols[2];

            for (int i = 1; i < lineCount; ++i)
            {
                vecCols.clear();
                ret = splitLineBySeparatorChar(vecLines[i], ':', vecCols);
                RETURN_IF_FAILED(ret != 0 || vecCols.size() < 2, -1);

                if (vecCols[0] == "CSeq") //CSeq: 5
                {
                    rtsp_header_and_payload_info.rtsp_reuest_play.cseq = vecCols[1];
                } else if (vecCols[0] == "User-Agent") //User-Agent: Lavf57.56.101
                {
                    rtsp_header_and_payload_info.rtsp_reuest_play.user_agent = vecCols[1];
                } else if (vecCols[0] == "Range") //Range: npt=0.000-
                {
                    rtsp_header_and_payload_info.rtsp_reuest_play.range = vecCols[1];
                } else if (vecCols[0] == "Session") //Session: 1039078252
                {
                    rtsp_header_and_payload_info.rtsp_reuest_play.session = vecCols[1];
                } else if (vecCols[0] == "Authorization") //Authorization: Digest username="admin", realm="a41437c723c4", nonce="d650274caf99bd963a97f805c839b85e", uri="rtsp://192.168.0.5:554/h264/ch1/main/av_stream", response="93d40550715a217ba8edb167f987504b"
                {
                    rtsp_header_and_payload_info.rtsp_reuest_play.authorization = vecCols[1];
                }
            }
        } else
        {
            RETURN_IF_FAILED(-1, -1);
        }
    }

    return ret;
}


int CRtspProtocol::splitRtspSeverResponse(unsigned char *buffer, int bufferSize, RTSP_HEADER_AND_PAYLAOAD_INFO &rtsp_header_and_payload_info, int &bufferSizeUsed)
{
    int ret = 0;

    //-------------------------
    RETURN_IF_FAILED(bufferSize < 0, -1);
    
    unsigned char *strTemp = (unsigned char *)malloc(bufferSize + 1);
    RETURN_IF_FAILED(strTemp == NULL, -1);
    memcpy(strTemp, buffer, bufferSize);
    strTemp[bufferSize] = '\0';
    printf("%s(%d): %s: buffer: --%s---\n", __FILE__, __LINE__, __FUNCTION__, strTemp);
    free(strTemp);
    strTemp = NULL;
    
    //-------------------------
    unsigned char *p = buffer;
    unsigned char *p1 = p;
    unsigned char *p2 = p;
    unsigned char *p3 = buffer + bufferSize - 1;
    int flag = 0;

    std::vector<std::string> vecLines;
    bufferSizeUsed = bufferSize;

    ret = getHttpLines((char *)p1, bufferSize, vecLines);
    RETURN_IF_FAILED(ret != 0 || vecLines.size() <= 0, -1);

    int lineCount1 = vecLines.size();

    std::vector<std::string> vecLinesTemp;
    std::vector<std::vector<std::string>> vecTypeLines;
    for (int i = 0; i < lineCount1; ++i)
    {
        std::vector<std::string> vecCols;
        ret = splitLineBySeparatorChar(vecLines[i], ' ', vecCols);
//        RETURN_IF_FAILED(ret != 0 || vecCols.size() < 1, -1);
        if(ret == 0)
        {
            if (vecCols.size() > 0 && vecCols[0] == "RTSP/1.0") //RTSP Sever Response: RTSP/1.0 200 OK
            {
                if(vecLinesTemp.size() > 0)
                {
                    vecTypeLines.push_back(vecLinesTemp);
                    vecLinesTemp.clear();
                }
                flag = 1;
            }
        }

        vecLinesTemp.push_back(vecLines[i]);
    }

    if(flag == 1)
    {
        if (vecLinesTemp.size() > 0)
        {
            vecTypeLines.push_back(vecLinesTemp);
            vecLinesTemp.clear();
        }
    }

    //------------RTSP Sever Response----------------------
    for (int j = 0; j < vecTypeLines.size(); ++j)
    {
        int lineCount2 = vecTypeLines[j].size();
        RETURN_IF_FAILED(lineCount2 < 3, -1);
        
        std::vector<std::string> vecCols;
        ret = splitLineBySeparatorChar(vecTypeLines[j][0], ' ', vecCols);
        RETURN_IF_FAILED(ret != 0 || vecCols.size() < 3, -1);

        //----------------------------------------
        std::string response_code = vecCols[1];
        std::string response_code_msg = vecCols[2];

        std::vector<std::vector<std::string>> vecLineCols;
        std::string strResponseType = "";

        for (int i = 1; i < lineCount2; ++i)
        {
            vecCols.clear();
            ret = splitLineBySeparatorChar(vecTypeLines[j][i], ':', vecCols);
            if (ret != 0 || vecCols.size() < 2)
            {
                continue;
            }

            vecLineCols.push_back(vecCols);

            if (vecCols[0] == "Public")
            {
                strResponseType = "OPTIONS";
            } else if (vecCols[0] == "WWW-Authenticate" || vecCols[0] == "Proxy-Authenticate") //RFC2326 Page27
            {
                strResponseType = "DESCRIBE 1";
            } else if (vecCols[0] == "Content-Length")
            {
                strResponseType = "DESCRIBE 2";
            } else if (vecCols[0] == "Transport")
            {
                strResponseType = "SETUP";
            } else if (vecCols[0] == "RTP-Info")
            {
                strResponseType = "PLAY";
            } else if (vecCols[0] == "Range")
            {
                strResponseType = "PLAY";
            }else
            {
                printf("%s(%d): %s: Error: vecTypeLines[j][i]=%s;\n", __FILE__, __LINE__, __FUNCTION__, vecTypeLines[j][i].c_str());
            }
        }

        //---------------------
        if (strResponseType == "OPTIONS")
        {
            rtsp_header_and_payload_info.rtsp_response_options.response_code = response_code;
            rtsp_header_and_payload_info.rtsp_response_options.response_code_msg = response_code_msg;

            for (int i = 0; i < vecLineCols.size(); ++i)
            {
                RETURN_IF_FAILED(vecLineCols[i].size() < 2, -1);

                if (vecLineCols[i][0] == "CSeq")
                {
                    rtsp_header_and_payload_info.rtsp_response_options.cseq = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "Public")
                {
                    rtsp_header_and_payload_info.rtsp_response_options.public_method = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "Date")
                {
                    rtsp_header_and_payload_info.rtsp_response_options.date = vecLineCols[i][1];
                }
            }
        } else if (strResponseType == "DESCRIBE 1")
        {
            rtsp_header_and_payload_info.rtsp_response_describe1.response_code = response_code;
            rtsp_header_and_payload_info.rtsp_response_describe1.response_code_msg = response_code_msg;

            for (int i = 0; i < vecLineCols.size(); ++i)
            {
                RETURN_IF_FAILED(vecLineCols[i].size() < 2, -1);

                if (vecLineCols[i][0] == "CSeq")
                {
                    rtsp_header_and_payload_info.rtsp_response_describe1.cseq = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "WWW-Authenticate")
                {
                    if (vecLineCols[i][1].substr(0, 6) == " Basic") //WWW-Authenticate: Basic realm="a41437c723c4"
                    {
                        rtsp_header_and_payload_info.rtsp_response_describe1.authenticate_basic_realm = vecLineCols[i][1];
                    } else //WWW-Authenticate: Digest realm="a41437c723c4", nonce="d650274caf99bd963a97f805c839b85e", stale="FALSE"
                    {
                        rtsp_header_and_payload_info.rtsp_response_describe1.authenticate_digest_realm = vecLineCols[i][1];
                    }
                } else if (vecLineCols[i][0] == "Date")
                {
                    rtsp_header_and_payload_info.rtsp_response_describe1.date = vecLineCols[i][1];
                }
            }
        } else if (strResponseType == "DESCRIBE 2")
        {
            rtsp_header_and_payload_info.rtsp_response_describe2.response_code = response_code;
            rtsp_header_and_payload_info.rtsp_response_describe2.response_code_msg = response_code_msg;

            for (int i = 0; i < vecLineCols.size(); ++i)
            {
                RETURN_IF_FAILED(vecLineCols[i].size() < 2, -1);

                if (vecLineCols[i][0] == "CSeq")
                {
                    rtsp_header_and_payload_info.rtsp_response_describe2.cseq = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "Content-Type") //Content-Type: application/sdp
                {
                    rtsp_header_and_payload_info.rtsp_response_describe2.content_type = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "Content-Base") //Content-Base: rtsp://192.168.0.5:554/h264/ch1/main/av_stream/
                {
                    rtsp_header_and_payload_info.rtsp_response_describe2.content_base = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "Content-Length") //Content-Length: 477
                {
                    rtsp_header_and_payload_info.rtsp_response_describe2.content_length = atoi(vecLineCols[i][1].c_str());
                } else
                {
                    rtsp_header_and_payload_info.rtsp_response_describe2.content_strs.push_back(vecLineCols[i][1]);
                }
            }
        } else if (strResponseType == "SETUP")
        {
            rtsp_header_and_payload_info.rtsp_response_setup.response_code = response_code;
            rtsp_header_and_payload_info.rtsp_response_setup.response_code_msg = response_code_msg;

            for (int i = 0; i < vecLineCols.size(); ++i)
            {
                RETURN_IF_FAILED(vecLineCols[i].size() < 2, -1);

                if (vecLineCols[i][0] == "CSeq")
                {
                    rtsp_header_and_payload_info.rtsp_response_setup.cseq = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "Session") //Session:       1039078252;timeout=60
                {
                    rtsp_header_and_payload_info.rtsp_response_setup.session = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "Transport") //Transport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=45439e03;mode="play"
                {
                    rtsp_header_and_payload_info.rtsp_response_setup.transport = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "Date")
                {
                    rtsp_header_and_payload_info.rtsp_response_setup.date = vecLineCols[i][1];
                }
            }
        } else if (strResponseType == "PLAY")
        {
            rtsp_header_and_payload_info.rtsp_response_play.response_code = response_code;
            rtsp_header_and_payload_info.rtsp_response_play.response_code_msg = response_code_msg;

            for (int i = 0; i < vecLineCols.size(); ++i)
            {
                RETURN_IF_FAILED(vecLineCols[i].size() < 2, -1);

                if (vecLineCols[i][0] == "CSeq")
                {
                    rtsp_header_and_payload_info.rtsp_response_play.cseq = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "Session") //Session:       1039078252;timeout=60
                {
                    rtsp_header_and_payload_info.rtsp_response_play.session = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "RTP-Info") //RTP-Info: url=rtsp://192.168.0.5:554/h264/ch1/main/av_stream/trackID=1;seq=48656;rtptime=706810978
                {
                    rtsp_header_and_payload_info.rtsp_response_play.rtp_info = vecLineCols[i][1];
                } else if (vecLineCols[i][0] == "Date")
                {
                    rtsp_header_and_payload_info.rtsp_response_play.date = vecLineCols[i][1];
                }
            }
        } else //strResponseType == ""
        {
            printf("%s(%d): Error: strResponseType == \"\"\n", __FUNCTION__, __LINE__);
        }
    }

    return ret;
}


int CRtspProtocol::getHttpLines(char *buffer, int bufferSize, std::vector<std::string> &vecLines)
{
    int ret = 0;

    //-------------------------
    RETURN_IF_FAILED(bufferSize < 0, -1);

    char *p = buffer;
    char *p1 = p;
    char *p2 = p;
    char *p3 = buffer + bufferSize - 1;

    while (p1 < p3 - 1)
    {
        if (*p1 == '\r' && *(p1 + 1) == '\n')
        {
            char * pLinestart = p2;
            char * pLineEnd = p1;
            int lineLength = pLineEnd - pLinestart;
            std::string str = "";

            if (lineLength > 0)
            {
                char * lineStr = (char *)malloc(lineLength + 1);
                RETURN_IF_FAILED(lineStr == NULL, -1);

                memcpy(lineStr, pLinestart, lineLength);
                lineStr[lineLength] = '\0';
                
                str = lineStr;
                
                free(lineStr);
                lineStr = NULL;
            }
            else if (lineLength > 0)
            {
                RETURN_IF_FAILED(lineLength < 0, -1);
            }

            vecLines.push_back(str);

            p2 = p1 + 2;
            p1++;
        }
        p1++;
    }

    return ret;
}


int CRtspProtocol::splitLineBySeparatorChar(std::string lineStr, char separator, std::vector<std::string> &vecCols)
{
    int len = lineStr.length();
    if (len <= 0)
    {
        return -1;
    }

    //--------------------
    const int line_max_size = 1024;
    char strCol[line_max_size] = { 0 };

    const char *p = lineStr.c_str();
    const char *p1 = p;
    const char *p2 = p;

    while (p1 < p + len)
    {
        while (*p1 == separator && p1 < p + len) //跳过连续的空格
        {
            p1++;
        }
        p2 = p1;

        while (*p1 != separator && p1 < p + len) //跳过连续的非空格
        {
            p1++;
        }

        int len2 = p1 - p2;
        if (len2 > 0 && len2 < line_max_size)
        {
            memcpy(strCol, p2, len2);
            strCol[len2] = '\0';
            vecCols.push_back(strCol);
        }
        else
        {
            printf("%s: Warning: len2=%d <= 0 || >= line_max_size=%d;\n", __FUNCTION__, len2, line_max_size);
        }
    }

    return 0;
}


int CRtspProtocol::openFileToWrite(int channel, FILE * &fp, std::string &filename, std::string strErr)
{
    std::string outputFilename = m_outputFilename + ".channel" + std::to_string(channel) + strErr;
    filename = outputFilename;

    std::map<std::string, FILE *>::iterator it = m_hashFileHandle.find(outputFilename);
    if(it == m_hashFileHandle.end())
    {
        printf("%s\n", outputFilename.c_str());

        FILE * fp2 = fopen(outputFilename.c_str(), "wb");
        if (fp2 == NULL)
        {
            printf("%s(%d): %s: Cannot open file to write! outputFilename='%s'\n", __FILE__, __LINE__, __FUNCTION__, outputFilename.c_str());
            return -1;
        }

        m_hashFileHandle[outputFilename] = fp2;
        fp = fp2;
    }else
    {
        fp = m_hashFileHandle[outputFilename];
    }

    return 0;
}


int CRtspProtocol::closeFile()
{
    std::map<std::string, FILE *>::iterator it;
    for(it = m_hashFileHandle.begin(); it != m_hashFileHandle.end(); ++it)
    {
        printf("%s(%d): %s: channel_id=%d; fp=0x%p;\n", __FILE__, __LINE__, __FUNCTION__, it->first, it->second);

        FILE * fp = it->second;
        if(fp)
        {
            fclose(fp);
            fp = NULL;
        }
    }

    return 0;
}
