// wireshark_rtsp_over_tcp.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "WiresharkRtspOverTcp.h"


int printHelp(int argc, char *argv[])
{
    printf("Usage:\n");
    printf("  %s <parser_type|[1,2,3]> <in|rtsp_tcpdump.pcap> <in|rtsp_server_ip> <outDir|./data/h264>\n", argv[0]);
    printf("For Example:\n");
    printf("  %s 1 ./rtsp_tcpdump.pcap 192.168.3.17 ./data/h264/\n", argv[0]);
    printf("  %s 2 ./rtsp_tcpdump.pcap 192.168.3.17 ./data/h264/ 169635 175635\n", argv[0]);
    printf("  %s 3 ./test.h264 ./data/h264_split_by_start_code/\n", argv[0]);

    return 0;
}


int main1(int argc, char* argv[])
{
    if(argc != 5)
    {
        printHelp(argc, argv);
        return -1;
    }

    int ret = 0;
    int parser_type = atoi(argv[1]);
    std::string inputFilename = argv[2];
    std::string rtspServerIp = argv[3];
    std::string outputDir = argv[4];

    CWiresharkRtspOverTcp wrot;

    ret = wrot.splitRtspOverTcp(inputFilename, rtspServerIp, outputDir, 0, 0);
    if(ret != 0)
    {
        printf("Error: 1: wrot.splitRtspOverTcp() failed! ret=%d;\n", ret);
        return -1;
    }

    printf("%s: All thing is OK!\n", __FUNCTION__);

    return 0;
}


int main2(int argc, char* argv[])
{
    if(argc != 7)
    {
        printHelp(argc, argv);
        return -1;
    }

    int ret = 0;
    int parser_type = atoi(argv[1]);
    std::string inputFilename = argv[2];
    std::string rtspServerIp = argv[3];
    std::string outputDir = argv[4];
    int startFrameNumber = atoi(argv[5]);
    int endFrameNumber = atoi(argv[6]);

    if(startFrameNumber > 0 && endFrameNumber > 0 && startFrameNumber < endFrameNumber)
    {
        //do nothing
    }else
    {
        return -1;
    }

    CWiresharkRtspOverTcp wrot;

    ret = wrot.splitRtspOverTcp(inputFilename, rtspServerIp, outputDir, startFrameNumber, endFrameNumber);
    if(ret != 0)
    {
        printf("Error: 2: wrot.splitRtspOverTcp() failed! ret=%d;\n", ret);
        return -1;
    }
    
    printf("%s: All thing is OK!\n", __FUNCTION__);

    return 0;
}


int main3(int argc, char* argv[])
{
    if(argc != 4)
    {
        printHelp(argc, argv);
        return -1;
    }

    int ret = 0;
    int parser_type = atoi(argv[1]);
    std::string inputFilename = argv[2];
    std::string outputDir = argv[3];

    CRtpProtocol rptl;

    ret = rptl.splitSingleH264FileToMultiFilesByStartCode(inputFilename, outputDir);
    if(ret != 0)
    {
        printf("Error: rptl.splitSingleH264FileToMultiFilesByStartCode() failed! ret=%d;\n", ret);
        return -1;
    }
    
    printf("%s: All thing is OK!\n", __FUNCTION__);

    return 0;
}


int main(int argc, char* argv[])
{
    if(argc < 2)
    {
        printHelp(argc, argv);
        return -1;
    }

    int ret = 0;
    int parser_type = atoi(argv[1]);

    if(parser_type == 1)
    {
        ret = main1(argc, argv);
    }else if(parser_type == 2)
    {
        ret = main2(argc, argv);
    }else if(parser_type == 3)
    {
        ret = main3(argc, argv);
    }else
    {
        printHelp(argc, argv);
        return -1;
    }

    printf("All thing is Over! ret=%d;\n", ret);

    return 0;
}

