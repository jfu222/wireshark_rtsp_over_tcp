// main.cpp : 定义控制台应用程序的入口点。
//

#include "WiresharkRtspOverTcp.h"
#include "version.h"


int printHelp(int argc, char *argv[])
{
    printf("====== Wireshark-Rtsp-Over-Tcp-Parser Version: %s ======\n", VERSION_STR3(VERSION_STR));
    printf("====== Author: jfu2 ======\n");
    printf("====== Email: 386520874@qq.com ======\n");
    printf("====== Date: 2019.11.30 ======\n\n");

    printf("Usage:\n");
    printf("  %s <parser_type|[1,2,3]> <in|rtsp_tcpdump.pcap> <in|rtsp_server_ip> <in|rtsp_server_port> <outDir|./data/h264/>\n", argv[0]);
    printf("For Example:\n");
    printf("  %s 1 ./rtsp_tcpdump.pcap 192.168.3.17 554 ./data/h264/\n", argv[0]);
    printf("  %s 2 ./rtsp_tcpdump.pcap 192.168.3.17 554 ./data/h264/ 169635 175635\n", argv[0]);
    printf("  %s 3 ./test.h264 ./data/h264_split_by_start_code/\n", argv[0]);
    printf("\n", argv[0]);
    printf("Notice:\n");
    printf("  parser_type=1:     Extract H264 video data from pcap file which created by tcpdump or wireshark.\n");
    printf("                     And the pcap file contains RTSP data which over TCP.\n");
    printf("  parser_type=2:     Extract Ethernet frames data from start frame number to end frame number,\n");
    printf("                     and then save to a file.\n");
    printf("  parser_type=3:     Split a big H264 file into multi small H264 files by start code '00 00 00 01'.\n");
    printf("  input file:        Linux tcpdump pcap file format and Windows wireshark file format can be support.\n");
    printf("  rtsp_server_ip:    The RTSP server IP address used to filter data.\n");
    printf("  rtsp_server_port:  The RTSP server port.\n");
    printf("  outDir:            Used to save all result files.\n");

    return 0;
}


int main1(int argc, char* argv[])
{
    if(argc != 6)
    {
        printHelp(argc, argv);
        return -1;
    }

    int ret = 0;
    int parser_type = atoi(argv[1]);
    std::string inputFilename = argv[2];
    std::string rtspServerIp = argv[3];
    int rtspServerPort = atoi(argv[4]);
    std::string outputDir = argv[5];

    CWiresharkRtspOverTcp wrot;

    ret = wrot.splitRtspOverTcp(inputFilename, rtspServerIp, rtspServerPort, outputDir, 0, 0);
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
    if(argc != 8)
    {
        printHelp(argc, argv);
        return -1;
    }

    int ret = 0;
    int parser_type = atoi(argv[1]);
    std::string inputFilename = argv[2];
    std::string rtspServerIp = argv[3];
    int rtspServerPort = atoi(argv[4]);
    std::string outputDir = argv[5];
    int startFrameNumber = atoi(argv[6]);
    int endFrameNumber = atoi(argv[7]);

    if(startFrameNumber > 0 && endFrameNumber > 0 && startFrameNumber < endFrameNumber)
    {
        //do nothing
    }else
    {
        return -1;
    }

    CWiresharkRtspOverTcp wrot;

    ret = wrot.splitRtspOverTcp(inputFilename, rtspServerIp, rtspServerPort, outputDir, startFrameNumber, endFrameNumber);
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

