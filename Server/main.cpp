#include "Server.h"
#include <QtWidgets/QApplication>
#include"winsock2.h"
#include"Common.h"
#include"rtmp.h"
#include"bytestream.h"
#define PORT 5236
#define BUFFER_SIZE 1024*1024
#define RTMP_HANDSHAKE_PACKET_SIZE 1536
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
uint8_t serverdata[RTMP_HANDSHAKE_PACKET_SIZE + 1] = { 0 };
uint8_t clientdata[RTMP_HANDSHAKE_PACKET_SIZE ] = { 0 };
#include"flv.h"
#include<vector>

struct Chunk {
    int type;
    int fmt;
    int messageType;
    int messageLength;
    int streamID;
    int timeStamp;
};
static int rtmp_handshake_imprint_with_digest(uint8_t* buf)
{
    int ret, digest_pos;


    digest_pos = ff_rtmp_calc_digest_pos(buf, 8, 728, 12);

    ret = ff_rtmp_calc_digest(buf, RTMP_HANDSHAKE_PACKET_SIZE, digest_pos,
        rtmp_player_key, PLAYER_KEY_OPEN_PART_LEN,
        buf + digest_pos);
    if (ret < 0)
        return ret;

    return digest_pos;
}
void signal(uint8_t* buf) {
    uint8_t digest[32];
    int ret, digest_pos;

    digest_pos = ff_rtmp_calc_digest_pos(buf, 8, 728, 8 + 4);

    ret = ff_rtmp_calc_digest(buf, RTMP_HANDSHAKE_PACKET_SIZE, digest_pos,
        rtmp_server_key, SERVER_KEY_OPEN_PART_LEN,
        digest);
    memcpy(buf + digest_pos, digest, 32);
}
void makeS0S1() {
    memset(serverdata, RTMP_HANDSHAKE_PACKET_SIZE+1, 0);
    serverdata[0] = 3;
    serverdata[5] = 8;
    serverdata[6] = 8;
    serverdata[7] = 8;
    serverdata[8] = 8;
    AVLFG rnd;
    av_lfg_init(&rnd, 0xDEADC0DE);
    for (int i = 9; i <= RTMP_HANDSHAKE_PACKET_SIZE; i++)
        serverdata[i] = av_lfg_get(&rnd) >> 24;

    signal(serverdata + 1);

}
void makeSe(char* buf) {

    memset(clientdata, RTMP_HANDSHAKE_PACKET_SIZE, 0);

    AVLFG rnd;
    av_lfg_init(&rnd, 0xDEADC0DE);
    for (int i = 9; i <= RTMP_HANDSHAKE_PACKET_SIZE; i++)
        clientdata[i] = av_lfg_get(&rnd) >> 24;

    uint8_t digest[32], signature[32];
    int client_pos = rtmp_handshake_imprint_with_digest((uint8_t*)buf + 1);


    int ret = ff_rtmp_calc_digest((uint8_t*)buf + 1 + client_pos, 32, 0,
        rtmp_server_key, sizeof(rtmp_server_key),
        digest);
    if (ret < 0)
        return ;

    ret = ff_rtmp_calc_digest(clientdata, RTMP_HANDSHAKE_PACKET_SIZE - 32,
        0, digest, 32, signature);

    if (ret < 0)
        return ;
    memcpy(clientdata + RTMP_HANDSHAKE_PACKET_SIZE - 32, signature, 32);
    

}

ConnectObject parseConnectMessage(GetByteContext* context){
#define CSIZE 50
    ConnectObject co;
    int length = 0;
   
   
    ff_amf_read_string(context, (uint8_t*)co.id, CSIZE, &length);
    ff_amf_read_number(context, &(co.TransactionID));
    AMFDataType dt=(AMFDataType)bytestream2_get_byte(context);
    uint8_t fileName[20] = { 0 };
    ff_amf_read_field_name(context, fileName);
    ff_amf_read_string(context, (uint8_t*)co.app, CSIZE, &length);
    ff_amf_read_field_name(context, fileName);
    ff_amf_read_string(context, (uint8_t*)co.flashver, CSIZE, &length);
   /* ff_amf_read_field_name(context, fileName);
    ff_amf_read_string(context, (uint8_t*)co.swfUrl, CSIZE, &length);*/
    ff_amf_read_field_name(context, fileName);
    ff_amf_read_string(context, (uint8_t*)co.tcUrl, CSIZE, &length);
    ff_amf_read_field_name(context, fileName);
    ff_amf_read_bool(context, &co.fpad);
    ff_amf_read_field_name(context, fileName);
    ff_amf_read_number(context, &(co.capabilities));
    ff_amf_read_field_name(context, fileName);
    ff_amf_read_number(context, &(co.audioCodecs));
    ff_amf_read_field_name(context, fileName);
    ff_amf_read_number(context, &(co.videoCodecs));
    ff_amf_read_field_name(context, fileName);
    ff_amf_read_number(context, &(co.videoFunction));
    
    /*ff_amf_read_field_name(context, fileName);
    ff_amf_read_string(context, (uint8_t*)co.pageUrl, CSIZE, &length);
    ff_amf_read_field_name(context, fileName);
    ff_amf_read_number(context, &(co.objectEncoding));*/
    dt = (AMFDataType)bytestream2_get_be24(context);
    return co;
}
void sendWindowSize(int new_socket,int size) {
    RTMPPacket p;
    p.channel_id = 3;
    p.ts_field = 0;
    p.size = 4;
    p.type = RTMP_PT_WINDOW_ACK_SIZE;
    p.extra = 0;
    uint8_t* windowsize = (uint8_t*)malloc(4);
    AV_WB32(windowsize, size);
    p.data = windowsize;
    RTMPPacket* prev_pkt_ptr = NULL;
    int nb_prev_pkt = 0;
    ff_rtmp_packet_write(new_socket, &p, 128, &prev_pkt_ptr, &nb_prev_pkt);
}
void sendPeerBandwidth(int new_socket, int size) {
    RTMPPacket p;
    p.channel_id = 3;
    p.ts_field = 0;
    p.size = 4;
    p.type = RTMP_PT_SET_PEER_BW;
    p.extra = 0;
    uint8_t* bw = (uint8_t*)malloc(4);
    AV_WB32(bw, size);
    p.data = bw;
    RTMPPacket* prev_pkt_ptr = NULL;
    int nb_prev_pkt = 0;
    ff_rtmp_packet_write(new_socket, &p, 128, &prev_pkt_ptr, &nb_prev_pkt);
}
void sendUserControl(int new_socket, int data) {
    RTMPPacket p;
    p.channel_id = 3;
    p.ts_field = 0;
    p.size = 2;
    p.type = RTMP_PT_USER_CONTROL;
    p.extra = 0;
    uint8_t* bw = (uint8_t*)malloc(2);
    AV_WB16(bw, data);
    p.data = bw;
    RTMPPacket* prev_pkt_ptr = NULL;
    int nb_prev_pkt = 0;
    ff_rtmp_packet_write(new_socket, &p, 128, &prev_pkt_ptr, &nb_prev_pkt);
}

void sendPingRequest(int new_socket, int data) {
    RTMPPacket p;
    p.channel_id = 3;
    p.ts_field = 0;
    p.size = 6;
    p.type = RTMP_PT_USER_CONTROL;
    p.extra = 0;
    uint8_t* bw = (uint8_t*)malloc(6);
    memset(bw, 0, 6);
    AV_WB16(bw, data);
    
    p.data = bw;
    RTMPPacket* prev_pkt_ptr = NULL;
    int nb_prev_pkt = 0;
    ff_rtmp_packet_write(new_socket, &p, 4096, &prev_pkt_ptr, &nb_prev_pkt);
}

void sendChunkSize(int new_socket, int data) {
    RTMPPacket p;
    p.channel_id = 3;
    p.ts_field = 0;
    p.size = 4;
    p.type = RTMP_PT_CHUNK_SIZE;
    p.extra = 0;
    uint8_t* bw = (uint8_t*)malloc(4);
    AV_WB32(bw, data);
    p.data = bw;
    RTMPPacket* prev_pkt_ptr = NULL;
    int nb_prev_pkt = 0;
    ff_rtmp_packet_write(new_socket, &p, 128, &prev_pkt_ptr, &nb_prev_pkt);
}
void sendConnectReponse(int new_socket) {
    RTMPPacket p;
    p.channel_id = 3;
    p.ts_field = 0;
    p.extra = 0;
    p.timestamp = 0;
    p.size = 261;
    p.offset = 0;
    p.type = RTMP_PT_INVOKE;
    
    uint8_t* bw = (uint8_t*)malloc(261);
    for (int i = 0; i < 261; i++) {
        bw[i] = i;
    }
    p.data = bw;
    ff_amf_write_string(&bw, "_result");
    ff_amf_write_number(&bw, 1);
    
    RTMPPacket* prev_pkt_ptr = NULL;
    int nb_prev_pkt = 0;
    ff_rtmp_packet_write(new_socket, &p, 4096, &prev_pkt_ptr, &nb_prev_pkt);
}
void sendCreateStream(int new_socket) {
    RTMPPacket p;
    p.channel_id = 3;
    p.ts_field = 0;
    p.size = 29;
    p.offset = 29;
    p.timestamp = 0;
    p.type = RTMP_PT_INVOKE;
    p.extra = 0;
    uint8_t* bw = (uint8_t*)malloc(29);
    memset(bw, 0, 29);
    p.data = bw;

    std::string strbuffer = "_result";
    ff_amf_write_string(&bw, strbuffer.c_str());
    // Value 2/4: The callee reference number
    ff_amf_write_number(&bw, 2);
    // Value 3/4: Null
    ff_amf_write_null(&bw);
    // Value 4/4: The response as AMF_NUMBER
    ff_amf_write_number(&bw, 1);

    RTMPPacket* prev_pkt_ptr = NULL;
    int nb_prev_pkt = 0;
    ff_rtmp_packet_write(new_socket, &p, 4096, &prev_pkt_ptr, &nb_prev_pkt);
}
void sendGetStreamLength(int new_socket) {
    RTMPPacket p;
    p.channel_id = 3;
    p.timestamp = 0;
    p.ts_field = 0;
    p.extra = 0;
    p.size = 29;
    p.offset = 29;
    p.type = RTMP_PT_INVOKE;
    
    uint8_t* bw = (uint8_t*)malloc(29);
    p.data = bw;

    std::string strbuffer = "_result";
    ff_amf_write_string(&bw, strbuffer.c_str());
    // Value 2/4: The callee reference number
    ff_amf_write_number(&bw, 3);
    // Value 3/4: Null
    ff_amf_write_null(&bw);
    // Value 4/4: The response as AMF_NUMBER
    ff_amf_write_number(&bw, 0);

    RTMPPacket* prev_pkt_ptr = NULL;
    int nb_prev_pkt = 0;
    ff_rtmp_packet_write(new_socket, &p, 4096, &prev_pkt_ptr, &nb_prev_pkt);
}

void sendOnStatusReponse(int new_socket) {
    RTMPPacket p;
    p.channel_id = 3;
    p.ts_field = 0;
    p.extra = 0;
    p.timestamp = 0;
    p.size = 261;
    p.offset = 0;
    p.type = RTMP_PT_INVOKE;
    
    uint8_t* bw = (uint8_t*)malloc(261);
    p.data = bw;
    std::string strbuffer = "onStatus";
    ff_amf_write_string(&bw, strbuffer.c_str());
    ff_amf_write_number(&bw, 2);
    ff_amf_write_null(&bw);
    
    ff_amf_write_object_start(&bw);
    ff_amf_write_field_name(&bw, "level");
    ff_amf_write_string(&bw, "status");
    ff_amf_write_field_name(&bw, "code");
    ff_amf_write_string(&bw, "NetStream.Play.Start");

    RTMPPacket* prev_pkt_ptr = NULL;
    int nb_prev_pkt = 0;
    ff_rtmp_packet_write(new_socket, &p, 4096, &prev_pkt_ptr, &nb_prev_pkt);
}
struct VideoData {
    char* data;
    int size;
};
void sendVideoData(int new_socket, VideoData vd) {
    RTMPPacket p;
    p.channel_id = 6;
    p.ts_field = 0;
    p.size = vd.size;
    p.type = RTMP_PT_VIDEO;
    p.extra = 0;
    

    p.data =(uint8_t*)vd.data;
    RTMPPacket* prev_pkt_ptr = NULL;
    int nb_prev_pkt = 0;
    ff_rtmp_packet_write(new_socket, &p, 4096, &prev_pkt_ptr, &nb_prev_pkt);
}

int main(int argc, char *argv[])
{
    
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        printf("WSAStartup failed with error: %d\n", err);
        return 1;
    }
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char* buffer= (char* )malloc(BUFFER_SIZE);

    ;
    const char* hello = "Hello from server";

    // 创建套接字
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // 绑定IP和端口
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    err=bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    if (err < 0) {
        perror("Bind failed");
        closesocket(server_fd);
        exit(EXIT_FAILURE);
    }

    // 监听连接请求
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        closesocket(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Waiting for connections...\n");
    while (1) {
        // 接受客户端连接
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("Accept failed");
            closesocket(server_fd);
            exit(EXIT_FAILURE);
        }
        //握手流程
        {
            // 接收数据
            int valread = recv(new_socket, buffer, BUFFER_SIZE, 0);
            if (valread >= BUFFER_SIZE) {
                printf("too short\n", buffer);
            }
            //printf("Received: %s\n", buffer);
            makeS0S1();
            // 发送数据
            send(new_socket, (const char*)serverdata, 1537, 0);
            //这个跟协议中讲的不太一样 并不是s2的格式
            makeSe(buffer);
            send(new_socket, (const char*)clientdata, 1536, 0);

            //再次接收  但不知到有啥用
            int valread1 = recv(new_socket, buffer, BUFFER_SIZE, 0);

        }
        //处理消息都应该在这里处理
        {
            //while (1) {
                RTMPPacket p;
                
                RTMPPacket* prev_pkt= (RTMPPacket * )malloc(sizeof(RTMPPacket)*64);
                memset(prev_pkt, 0, sizeof(RTMPPacket) * 64);
                int* nb_prev_pkt=0;
                uint8_t hdr = 0;;
                ff_rtmp_packet_read_internal(new_socket, &p, 128,
                    &prev_pkt, nb_prev_pkt,
                    hdr);
                if (p.type == RTMP_PT_INVOKE) {
                    
                    GetByteContext context;
                    context.buffer = p.data;
                    context.buffer_start = p.data;
                    context.buffer_end = p.data+p.size;
                    char buf[45] = { 0 };
                    memcpy(buf, p.data, 45);
                    ConnectObject co=parseConnectMessage(&context);
                    sendWindowSize(new_socket, 2500000);
                    sendPeerBandwidth(new_socket, 2500000);
                    sendUserControl(new_socket, 0);
                    sendChunkSize(new_socket, 4096);
                    sendConnectReponse(new_socket);
                    
                    //处理返回来的windowsSize
                    ff_rtmp_packet_read_internal(new_socket, &p, 128,
                        &prev_pkt, nb_prev_pkt,
                        hdr);
                    int size=AV_RB32(p.data);
                    //接收createstream
                    ff_rtmp_packet_read_internal(new_socket, &p, 128,
                        &prev_pkt, nb_prev_pkt,
                        hdr);
                    Sleep(20);
                    sendCreateStream(new_socket);
                    //接收play消息
                   ff_rtmp_packet_read_internal(new_socket, &p, 128,
                        &prev_pkt, nb_prev_pkt,
                        hdr);
                   Sleep(20);
                   sendGetStreamLength(new_socket);
                   ff_rtmp_packet_read_internal(new_socket, &p, 128,
                       &prev_pkt, nb_prev_pkt,
                       hdr);
                    Sleep(20);
                    sendPingRequest(new_socket, 6);
                    Sleep(20);
                    sendOnStatusReponse(new_socket);
                    std::vector<VideoData> datas;
                    for (int i = 0; i < 351; i++) {
                        char path[200] = { 0 };
                        sprintf(path, "./data/%d.dat", i);
                        //sprintf(path, "./data/codePacket.dat");
                        FILE* file = fopen(path, "rb");
                        fseek(file,0, SEEK_END);
                        int size = ftell(file);
                        fseek(file, 0, SEEK_SET);
                        char* data =(char*) malloc(size);
                        int ret=fread(data,sizeof(char),  size, file);
                        fflush(file);
                        fclose(file);
                        VideoData vd;
                        vd.data = data;
                        vd.size = size;
                        datas.push_back(vd);
                    }
                    while (1) {
                        for (int i = 0; i < 351; i++) {
                            Sleep(30);
                            VideoData vd = datas.at(i);
                            sendVideoData(new_socket, vd);
                        }
                    }
                    
                }
            //}
            

        }

        printf("Hello message sent\n");
    }
    

    // 关闭套接字
    closesocket(new_socket);
    closesocket(server_fd);

    return 0;
}
