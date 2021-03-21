# wireshark_rtsp_over_tcp
用于分析从tcpdump抓包得到的RTSP数据

## 测试数据
1. 先用vs2013编译生成F:\wireshark_rtsp_over_tcp\build\x64\Debug\wireshark_rtsp_over_tcp.exe
2. 在win7的cmd命令行中，运行 C:\wireshark_rtsp_over_tcp\build\x64\Debug\wireshark_rtsp_over_tcp.exe 1 C:\wireshark_rtsp_over_tcp\data\test.cap 172.31.25.211 554 C:\wireshark_rtsp_over_tcp\data\h264_out
3. 上面一切正常的话，会在C:\wireshark_rtsp_over_tcp\data\h264_out目录下面生成相关的h264文件
4. 目前h264文件，我一般只用VLC或ffplay播放，其他播放器没试过，其实也没必要试。如果VLC都能播，说明H264文件本身是没有问题的。

## 其他
- blog: https://blog.csdn.net/jfu22/article/details/103335427
