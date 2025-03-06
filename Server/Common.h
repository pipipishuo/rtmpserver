#pragma once
extern "C"
{
#include "libavutil/error.h"
#include "libavutil/hmac.h"
#include"libavutil/lfg.h"

}
#include"bytestream.h"
#include"rtmp.h"
#define SERVER_KEY_OPEN_PART_LEN 36   ///< length of partial key used for first server digest signing
/** Key used for RTMP server digest signing */
static const uint8_t rtmp_server_key[] = {
    'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
    'F', 'l', 'a', 's', 'h', ' ', 'M', 'e', 'd', 'i', 'a', ' ',
    'S', 'e', 'r', 'v', 'e', 'r', ' ', '0', '0', '1',

    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1, 0x02,
    0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB, 0x93, 0xB8,
    0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
};
#define PLAYER_KEY_OPEN_PART_LEN 30   ///< length of partial key used for first client digest signing
/** Client key used for digest signing */
static const uint8_t rtmp_player_key[] = {
    'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
    'F', 'l', 'a', 's', 'h', ' ', 'P', 'l', 'a', 'y', 'e', 'r', ' ', '0', '0', '1',

    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1, 0x02,
    0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB, 0x93, 0xB8,
    0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
};
static int rtmp_validate_digest(uint8_t* buf, int off);
#define CSIZE 50
struct ConnectObject {
    char id[CSIZE];
    double TransactionID;
    char app[CSIZE];
    char flashver[CSIZE];
    char swfUrl[CSIZE];
    char tcUrl[CSIZE];
    bool fpad;
    double capabilities;
    double audioCodecs;
    double videoCodecs;
    double videoFunction;
    char pageUrl[CSIZE];
    double objectEncoding;
};
typedef enum RTMPPacketType {
    RTMP_PT_CHUNK_SIZE = 1,  ///< chunk size change
    RTMP_PT_BYTES_READ = 3,  ///< number of bytes read
    RTMP_PT_USER_CONTROL,       ///< user control
    RTMP_PT_WINDOW_ACK_SIZE,    ///< window acknowledgement size
    RTMP_PT_SET_PEER_BW,        ///< peer bandwidth
    RTMP_PT_AUDIO = 8,  ///< audio packet
    RTMP_PT_VIDEO,              ///< video packet
    RTMP_PT_FLEX_STREAM = 15,  ///< Flex shared stream
    RTMP_PT_FLEX_OBJECT,        ///< Flex shared object
    RTMP_PT_FLEX_MESSAGE,       ///< Flex shared message
    RTMP_PT_NOTIFY,             ///< some notification
    RTMP_PT_SHARED_OBJ,         ///< shared object
    RTMP_PT_INVOKE,             ///< invoke some stream action
    RTMP_PT_METADATA = 22,  ///< FLV metadata
} RTMPPacketType;
enum RTMPPacketSize {
    RTMP_PS_TWELVEBYTES = 0, ///< packet has 12-byte header
    RTMP_PS_EIGHTBYTES,      ///< packet has 8-byte header
    RTMP_PS_FOURBYTES,       ///< packet has 4-byte header
    RTMP_PS_ONEBYTE          ///< packet is really a next chunk of a packet
};

typedef struct RTMPPacket {
    int            channel_id; ///< RTMP channel ID (nothing to do with audio/video channels though)
    RTMPPacketType type;       ///< packet payload type
    uint32_t       timestamp;  ///< packet full timestamp
    uint32_t       ts_field;   ///< 24-bit timestamp or increment to the previous one, in milliseconds (latter only for media packets). Clipped to a maximum of 0xFFFFFF, indicating an extended timestamp field.
    uint32_t       extra;      ///< probably an additional channel ID used during streaming data
    uint8_t* data;      ///< packet payload
    int            size;       ///< packet payload size
    int            offset;     ///< amount of data read so far
    int            read;       ///< amount read, including headers
} RTMPPacket;
void ff_amf_write_bool(uint8_t** dst, int val);
void ff_amf_write_number(uint8_t** dst, double val);

void ff_amf_write_string(uint8_t** dst, const char* str);
void ff_amf_write_string2(uint8_t** dst, const char* str1, const char* str2);

void ff_amf_write_null(uint8_t** dst);

void ff_amf_write_object_start(uint8_t** dst);
void ff_amf_write_field_name(uint8_t** dst, const char* str);

void ff_amf_write_object_end(uint8_t** dst);
void ff_amf_read_field_name(GetByteContext* dst, uint8_t* str);
int ff_amf_read_number(GetByteContext* bc, double* val);
int ff_amf_get_string(GetByteContext* bc, uint8_t* str,
    int strsize, int* length);
int ff_amf_read_string(GetByteContext* bc, uint8_t* str,
    int strsize, int* length);
void ff_amf_read_bool(GetByteContext* dst, bool* val);
int ff_amf_read_null(GetByteContext* bc);
int ff_rtmp_packet_read_internal(int socket, RTMPPacket* p, int chunk_size,
    RTMPPacket** prev_pkt, int* nb_prev_pkt,
    uint8_t hdr);
int ff_rtmp_packet_write(int h, RTMPPacket* pkt,
    int chunk_size, RTMPPacket** prev_pkt_ptr,
    int* nb_prev_pkt);