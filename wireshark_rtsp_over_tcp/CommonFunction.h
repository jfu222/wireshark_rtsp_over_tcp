#ifndef __COMMON_FUNCTION_H__
#define __COMMON_FUNCTION_H__

#include <string>
#include <vector>


typedef enum _PAYLOAD_TYPE_
{
    PAYLOAD_TYPE_UNKNOWN = 0,
    PAYLOAD_TYPE_ETHERNET_II,
    PAYLOAD_TYPE_IP,
    PAYLOAD_TYPE_TCP,
    PAYLOAD_TYPE_UDP,
    PAYLOAD_TYPE_RTSP,
    PAYLOAD_TYPE_RTP,
    PAYLOAD_TYPE_RTCP,
    PAYLOAD_TYPE_VIDEO_H264,
    PAYLOAD_TYPE_VIDEO_H265,
    PAYLOAD_TYPE_AUDIO_PCMU,
    PAYLOAD_TYPE_SDP,
    PAYLOAD_TYPE_RTMP,
    PAYLOAD_TYPE_HTTP,
    PAYLOAD_TYPE_WEBSOCKET,
}PAYLOAD_TYPE;


int getFileDirnameAndBasenameAndExtname(const char *fileName, std::string &dirName, std::string &baseName, std::string &extensionName);
int createNestedDir(const char *dir); //´´½¨Ç¶Ì×Ä¿Â¼

#endif //__COMMON_FUNCTION_H__
