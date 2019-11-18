#pragma once
#include "RtpProtocol.h"
#include <string>
#include <vector>
#include <map>


//https://tools.ietf.org/html/rfc2326 Page21 RTSP/1.0 1998
typedef enum _RTSP_SERVER_PUBLIC_OPTIONS_
{
    OPTIONS = 1,
    DESCRIBE,
    SETUP,
    PLAY,
    TEARDOWN,
    PAUSE,
    GET_PARAMETER,
    SET_PARAMETER,
    ANNOUNCE,
    RECORD,
    REDIRECT,
}RTSP_SERVER_PUBLIC_OPTIONS;


typedef enum _RTSP_REQUEST_RESPONSE_TYPE_
{
    RTSP_REQUEST_TYPE_UNKNOWN = 0,
    RTSP_RESPONSE_TYPE_UNKNOWN,
    RTSP_REQUEST_TYPE_OPTIONS,
    RTSP_RESPONSE_TYPE_OPTIONS,
    RTSP_REQUEST_TYPE_DESCRIBE1,
    RTSP_RESPONSE_TYPE_DESCRIBE1,
    RTSP_REQUEST_TYPE_DESCRIBE12,
    RTSP_RESPONSE_TYPE_DESCRIBE2,
    RTSP_REQUEST_TYPE_SETUP,
    RTSP_RESPONSE_TYPE_SETUP,
    RTSP_REQUEST_TYPE_PLAY,
    RTSP_RESPONSE_TYPE_PLAY,
    RTSP_REQUEST_TYPE_TEARDOWN,
    RTSP_RESPONSE_TYPE_TEARDOWN,
    RTSP_REQUEST_TYPE_PAUSE,
    RTSP_RESPONSE_TYPE_PAUSE,
    RTSP_REQUEST_TYPE_GET_PARAMETER,
    RTSP_RESPONSE_TYPE_GET_PARAMETER,
    RTSP_REQUEST_TYPE_SET_PARAMETER,
    RTSP_RESPONSE_TYPE_SET_PARAMETER,
    RTSP_REQUEST_TYPE_ANNOUNCE,
    RTSP_RESPONSE_TYPE_ANNOUNCE,
    RTSP_REQUEST_TYPE_RECORD,
    RTSP_RESPONSE_TYPE_RECORD,
    RTSP_REQUEST_TYPE_REDIRECT,
    RTSP_RESPONSE_TYPE_REDIRECT,
}RTSP_REQUEST_RESPONSE_TYPE;


//-------------------------step 1-----------------------------
/*
[Request OPTIONS]

OPTIONS rtsp://192.168.0.5:554/h264/ch1/main/av_stream RTSP/1.0
CSeq: 1
User-Agent: Lavf57.56.101

*/
typedef struct _RTSP_REQUEST_OPTIONS_
{
    std::string rtsp_url; //rtsp://192.168.0.5:554/h264/ch1/main/av_stream
    std::string rtsp_version; //RTSP/1.0
    std::string cseq; //1
    std::string user_agent; //Lavf57.56.101
}RTSP_REQUEST_OPTIONS;


/*
[Response OPTIONS]

RTSP/1.0 200 OK
CSeq: 1
Public: OPTIONS, DESCRIBE, PLAY, PAUSE, SETUP, TEARDOWN, SET_PARAMETER, GET_PARAMETER
Date:  Wed, Oct 23 2019 13:00:34 GMT

*/
typedef struct _RTSP_RESPONSE_OPTIONS_
{
    std::string response_code; //200
    std::string response_code_msg; //OK
    std::string cseq; //1
    std::string public_method; //OPTIONS, DESCRIBE, PLAY, PAUSE, SETUP, TEARDOWN, SET_PARAMETER, GET_PARAMETER
    std::string date; //Wed, Oct 23 2019 13:00:34 GMT
}RTSP_RESPONSE_OPTIONS;


//-------------------------step 2-----------------------------
/*
[Request DESCRIBE 1]

DESCRIBE rtsp://192.168.0.5:554/h264/ch1/main/av_stream RTSP/1.0
CSeq: 2
User-Agent: Lavf57.56.101
Accept: application/sdp

*/
typedef struct _RTSP_REQUEST_DESCRIBE1_
{
    std::string rtsp_url; //rtsp://192.168.0.5:554/h264/ch1/main/av_stream
    std::string rtsp_version; //RTSP/1.0
    std::string cseq; //2
    std::string user_agent; //Lavf57.56.101
    std::string accept; //application/sdp
}RTSP_REQUEST_DESCRIBE1;


/*
[Response DESCRIBE 1]

RTSP/1.0 401 Unauthorized
CSeq: 2
WWW-Authenticate: Digest realm="a41437c723c4", nonce="d650274caf99bd963a97f805c839b85e", stale="FALSE"
WWW-Authenticate: Basic realm="a41437c723c4"
Date:  Wed, Oct 23 2019 13:00:34 GMT

*/
typedef struct _RTSP_RESPONSE_DESCRIBE1_
{
    std::string response_code; //401
    std::string response_code_msg; //Unauthorized
    std::string cseq; //2
    std::string authenticate_digest_realm; //rtsp 摘要认证(http 1.1提出的基本认证的替代方案，其消息经过MD5哈希转换因此具有更高的安全性) 客户端需要 response = md5(md5(username:realm:password):nonce:md5(public_method:url));
    std::string authenticate_basic_realm; //rtsp 基本认证(http 1.0提出的认证方案，其消息传输不经过加密转换因此存在严重的安全隐患)，客户端需要 response = base64_encode(username:password);
    std::string date; //Wed, Oct 23 2019 13:00:34 GMT
}RTSP_RESPONSE_DESCRIBE1;


//-------------------------step 3-----------------------------
/*
[Request DESCRIBE 2]
DESCRIBE rtsp://192.168.0.5:554/h264/ch1/main/av_stream RTSP/1.0
CSeq: 3
User-Agent: Lavf57.56.101
Accept: application/sdp
Authorization: Digest username="admin", realm="a41437c723c4", nonce="d650274caf99bd963a97f805c839b85e", uri="rtsp://192.168.0.5:554/h264/ch1/main/av_stream", response="93d40550715a217ba8edb167f987504b"

*/
typedef struct _RTSP_REQUEST_DESCRIBE2_
{
    std::string rtsp_url; //rtsp://192.168.0.5:554/h264/ch1/main/av_stream
    std::string rtsp_version; //RTSP/1.0
    std::string cseq; //3
    std::string user_agent; //Lavf57.56.101
    std::string accept; //application/sdp
    std::string authorization; //Digest username="admin", realm="a41437c723c4", nonce="d650274caf99bd963a97f805c839b85e", uri="rtsp://192.168.0.5:554/h264/ch1/main/av_stream", response="93d40550715a217ba8edb167f987504b"
}RTSP_REQUEST_DESCRIBE2;


/*
[Response DESCRIBE 2]

RTSP/1.0 200 OK
CSeq: 3
Content-Type: application/sdp
Content-Base: rtsp://192.168.0.5:554/h264/ch1/main/av_stream/
Content-Length: 477

v=0
o=- 1571835634058165 1571835634058165 IN IP4 192.168.0.5
s=Media Presentation
e=NONE
b=AS:5050
t=0 0
a=control:rtsp://192.168.0.5:554/h264/ch1/main/av_stream/
m=video 0 RTP/AVP 96
c=IN IP4 0.0.0.0
b=AS:5000
a=recvonly
a=x-dimensions:1920,1080
a=control:rtsp://192.168.0.5:554/h264/ch1/main/av_stream/trackID=1
a=rtpmap:96 H265/90000
a=Media_header:MEDIAINFO=494D4B48010200000400050000000000000000000000000000000000000000000000000000000000;
a=appversion:1.0

----------------------------------------------
Session Description Protocol Version (v): 0
Owner/Creator, Session Id (o): - 1571835634058165 1571835634058165 IN IP4 192.168.0.5
Session Name (s): Media Presentation
E-mail Address (e): NONE
Bandwidth Information (b): AS:5050
Time Description, active time (t): 0 0
Session Attribute (a): control:rtsp://192.168.0.5:554/h264/ch1/main/av_stream/
Media Description, name and address (m): video 0 RTP/AVP 96
Connection Information (c): IN IP4 0.0.0.0
Bandwidth Information (b): AS:5000
Media Attribute (a): recvonly
Media Attribute (a): x-dimensions:1920,1080
Media Attribute (a): control:rtsp://192.168.0.5:554/h264/ch1/main/av_stream/trackID=1
Media Attribute (a): rtpmap:96 H265/90000
Media Attribute (a): Media_header:MEDIAINFO=494D4B48010200000400050000000000000000000000000000000000000000000000000000000000;
Media Attribute (a): appversion:1.0
*/
typedef struct _RTSP_RESPONSE_DESCRIBE2_
{
    std::string response_code; //200
    std::string response_code_msg; //OK
    std::string cseq; //3
    std::string content_type; //application/sdp
    std::string content_base; //rtsp://192.168.0.5:554/h264/ch1/main/av_stream/
    int content_length; //477
    std::vector<std::string> content_strs;
}RTSP_RESPONSE_DESCRIBE2;


//-------------------------step 4-----------------------------
/*
[Request SETUP]

SETUP rtsp://192.168.0.5:554/h264/ch1/main/av_stream/trackID=1 RTSP/1.0
CSeq: 4
User-Agent: Lavf57.56.101
Transport: RTP/AVP/TCP;unicast;interleaved=0-1
Authorization: Digest username="admin", realm="a41437c723c4", nonce="d650274caf99bd963a97f805c839b85e", uri="rtsp://192.168.0.5:554/h264/ch1/main/av_stream/trackID=1", response="65dd69647f266cbfaa0f59be932854e9"

*/
typedef struct _RTSP_REQUEST_SETUP_
{
    std::string rtsp_url; //rtsp://192.168.0.5:554/h264/ch1/main/av_stream/trackID=1
    std::string rtsp_version; //RTSP/1.0
    std::string cseq; //4
    std::string user_agent; //Lavf57.56.101
    std::string transport; //RTP/AVP/TCP;unicast;interleaved=0-1
    std::string authorization; //Digest username="admin", realm="a41437c723c4", nonce="d650274caf99bd963a97f805c839b85e", uri="rtsp://192.168.0.5:554/h264/ch1/main/av_stream", response="93d40550715a217ba8edb167f987504b"
}RTSP_REQUEST_SETUP;


/*
[Response SETUP]

RTSP/1.0 200 OK
CSeq: 4
Session:       1039078252;timeout=60
Transport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=45439e03;mode="play"
Date:  Wed, Oct 23 2019 13:00:34 GMT

*/
typedef struct _RTSP_RESPONSE_SETUP_
{
    std::string response_code; //200
    std::string response_code_msg; //OK
    std::string cseq; //4
    std::string session; //1039078252;timeout=60
    std::string transport; //RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=45439e03;mode="play"
    int public_options_size;
    std::string date; //Wed, Oct 23 2019 13:00:34 GMT
}RTSP_RESPONSE_SETUP;


//-------------------------step 5-----------------------------
/*
[Request PLAY]

PLAY rtsp://192.168.0.5:554/h264/ch1/main/av_stream/ RTSP/1.0
CSeq: 5
User-Agent: Lavf57.56.101
Range: npt=0.000-
Session: 1039078252
Authorization: Digest username="admin", realm="a41437c723c4", nonce="d650274caf99bd963a97f805c839b85e", uri="rtsp://192.168.0.5:554/h264/ch1/main/av_stream/", response="4be82df5f2de5fb154d021222c485fe2"

*/
typedef struct _RTSP_REQUEST_PLAY_
{
    std::string rtsp_url; //rtsp://192.168.0.5:554/h264/ch1/main/av_stream/
    std::string rtsp_version; //RTSP/1.0
    std::string cseq; //5
    std::string user_agent; //Lavf57.56.101
    std::string range; //npt=0.000-
    std::string session; //1039078252
    std::string authorization; //Digest username="admin", realm="a41437c723c4", nonce="d650274caf99bd963a97f805c839b85e", uri="rtsp://192.168.0.5:554/h264/ch1/main/av_stream", response="93d40550715a217ba8edb167f987504b"
}RTSP_REQUEST_PLAY;


/*
[Response PLAY]

RTSP/1.0 200 OK
CSeq: 5
Session:       1039078252
RTP-Info: url=rtsp://192.168.0.5:554/h264/ch1/main/av_stream/trackID=1;seq=48656;rtptime=706810978
Date:  Wed, Oct 23 2019 13:00:34 GMT

*/
typedef struct _RTSP_RESPONSE_PLAY_
{
    std::string response_code; //200
    std::string response_code_msg; //OK
    std::string cseq; //5
    std::string session; //1039078252
    std::string rtp_info; //url=rtsp://192.168.0.5:554/h264/ch1/main/av_stream/trackID=1;seq=48656;rtptime=706810978
    std::string date; //Wed, Oct 23 2019 13:00:34 GMT
}RTSP_RESPONSE_PLAY;


//-------------------------step 6-----------------------------
typedef struct _RTSP_INTERLEAVED_FRAME_
{
    int magic;//1byte 0x24 => '$'
    int channel; //1byte 0-1
    int rtp_length; //2bytes rtp包发送时单个包的载荷总大小（即不包含 magic、channel、rtp_length 这3个字段所占的4字节），但实际上可能超过TCP最大的1460字节
    int rtp_real_read_bytes_in_single_tcp_packet; //在单个TCP包中实际上读到的字节数目，如果该值小于rtp_length，则剩下的字节需要在下一个TCP包中读取
    unsigned char * interleaved_frame_data;
    RTP_AND_RTCP_INFO rtp_and_rtcp;
}RTSP_INTERLEAVED_FRAME;


//-------------------------rtstp info-----------------------------
typedef struct _RTSP_HEADER_AND_PAYLAOAD_INFO_
{
    RTSP_REQUEST_OPTIONS rtsp_reuest_options;
    RTSP_RESPONSE_OPTIONS rtsp_response_options;

    RTSP_REQUEST_DESCRIBE1 rtsp_reuest_describe1;
    RTSP_RESPONSE_DESCRIBE1 rtsp_response_describe1;

    RTSP_REQUEST_DESCRIBE2 rtsp_reuest_describe2;
    RTSP_RESPONSE_DESCRIBE2 rtsp_response_describe2;

    RTSP_REQUEST_SETUP rtsp_reuest_setup;
    RTSP_RESPONSE_SETUP rtsp_response_setup;

    RTSP_REQUEST_PLAY rtsp_reuest_play;
    RTSP_RESPONSE_PLAY rtsp_response_play;

    std::vector<RTSP_INTERLEAVED_FRAME> rtsp_interleaved_frame;
}RTSP_HEADER_AND_PAYLAOAD_INFO;



//------------RTSP协议 Real Time Streaming Protocol--------------
class CRtspProtocol
{
public:
    std::string m_inputFilename;
    std::string m_outputDir; //用于保存h264结果的文件目录
    std::string m_outputFilename; //输出h264文件

    std::map<std::string, FILE *> m_hashFileHandle;

public:
    CRtspProtocol();
    ~CRtspProtocol();
    
    int splitRtpPayloadFile(std::string inputFilename, std::string outputFilename);
    int splitRtspPacket(unsigned char *buffer, int bufferSize, RTSP_HEADER_AND_PAYLAOAD_INFO &rtsp_header_and_payload_info, int &bufferSizeUsed);
    int splitRtspClientRequest(unsigned char *buffer, int bufferSize, RTSP_HEADER_AND_PAYLAOAD_INFO &rtsp_header_and_payload_info, int &bufferSizeUsed);
    int splitRtspSeverResponse(unsigned char *buffer, int bufferSize, RTSP_HEADER_AND_PAYLAOAD_INFO &rtsp_header_and_payload_info, int &bufferSizeUsed);
    int getHttpLines(char *buffer, int bufferSize, std::vector<std::string> &vecLines); //HTTP协议的payload中，以"\r\n"进行换行
    int splitLineBySeparatorChar(std::string lineStr, char separator, std::vector<std::string> &vecCols);

    int openFileToWrite(int channel, FILE * &fp, std::string &filename, std::string strErr);
    int closeFile();
};

