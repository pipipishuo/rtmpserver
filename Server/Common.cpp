#include "Common.h"
#include<memory>
#include"flv.h"
#include"winsock2.h"
static int rtmp_validate_digest(uint8_t* buf, int off)
{
    uint8_t digest[32];
    int ret, digest_pos;

    digest_pos = ff_rtmp_calc_digest_pos(buf, off, 728, off + 4);

    ret = ff_rtmp_calc_digest(buf, RTMP_HANDSHAKE_PACKET_SIZE, digest_pos,
        rtmp_server_key, SERVER_KEY_OPEN_PART_LEN,
        digest);
    if (ret < 0)
        return ret;

    if (!memcmp(digest, buf + digest_pos, 32))
        return digest_pos;
    return 0;
}
void ff_amf_write_bool(uint8_t** dst, int val)
{
    bytestream_put_byte(dst, AMF_DATA_TYPE_BOOL);
    bytestream_put_byte(dst, val);
}

void ff_amf_write_number(uint8_t** dst, double val)
{
    bytestream_put_byte(dst, AMF_DATA_TYPE_NUMBER);
    bytestream_put_be64(dst, av_double2int(val));
}

void ff_amf_write_string(uint8_t** dst, const char* str)
{
    bytestream_put_byte(dst, AMF_DATA_TYPE_STRING);
    bytestream_put_be16(dst, strlen(str));
    bytestream_put_buffer(dst,(uint8_t*) str, strlen(str));
}

void ff_amf_write_string2(uint8_t** dst, const char* str1, const char* str2)
{
    int len1 = 0, len2 = 0;
    if (str1)
        len1 = strlen(str1);
    if (str2)
        len2 = strlen(str2);
    bytestream_put_byte(dst, AMF_DATA_TYPE_STRING);
    bytestream_put_be16(dst, len1 + len2);
    bytestream_put_buffer(dst, (uint8_t*)str1, len1);
    bytestream_put_buffer(dst, (uint8_t*)str2, len2);
}

void ff_amf_write_null(uint8_t** dst)
{
    bytestream_put_byte(dst, AMF_DATA_TYPE_NULL);
}

void ff_amf_write_object_start(uint8_t** dst)
{
    bytestream_put_byte(dst, AMF_DATA_TYPE_OBJECT);
}

void ff_amf_write_field_name(uint8_t** dst, const char* str)
{
    bytestream_put_be16(dst, strlen(str));
    bytestream_put_buffer(dst, (uint8_t*)str, strlen(str));
}

void ff_amf_write_object_end(uint8_t** dst)
{
    /* first two bytes are field name length = 0,
     * AMF object should end with it and end marker
     */
    bytestream_put_be24(dst, AMF_DATA_TYPE_OBJECT_END);
}
void ff_amf_read_field_name(GetByteContext* dst, uint8_t* str)
{
    int len=bytestream2_get_be16(dst);
    bytestream2_get_buffer(dst, str, len);
}
int ff_amf_read_number(GetByteContext* bc, double* val)
{
    uint64_t read;
    if (bytestream2_get_byte(bc) != AMF_DATA_TYPE_NUMBER)
        return AVERROR_INVALIDDATA;
    read = bytestream2_get_be64(bc);
    *val = av_int2double(read);
    return 0;
}
void ff_amf_read_bool(GetByteContext* dst, bool* val)
{
    bytestream2_get_byte(dst);
    *val = bytestream2_get_byte(dst);
}
int ff_amf_get_string(GetByteContext* bc, uint8_t* str,
    int strsize, int* length)
{
    int stringlen = 0;
    int readsize;
    stringlen = bytestream2_get_be16(bc);
    if (stringlen + 1 > strsize)
        return AVERROR(EINVAL);
    readsize = bytestream2_get_buffer(bc, str, stringlen);
    if (readsize != stringlen) {
       ;
    }
    str[readsize] = '\0';
    *length = FFMIN(stringlen, readsize);
    return 0;
}

int ff_amf_read_string(GetByteContext* bc, uint8_t* str,
    int strsize, int* length)
{
    if (bytestream2_get_byte(bc) != AMF_DATA_TYPE_STRING)
        return AVERROR_INVALIDDATA;
    return ff_amf_get_string(bc, str, strsize, length);
}

int ff_amf_read_null(GetByteContext* bc)
{
    if (bytestream2_get_byte(bc) != AMF_DATA_TYPE_NULL)
        return AVERROR_INVALIDDATA;
    return 0;
}
int ff_rtmp_packet_create(RTMPPacket* pkt, int channel_id, RTMPPacketType type,
    int timestamp, int size)
{
    if (size) {
        pkt->data =(uint8_t*) malloc( size);
        if (!pkt->data)
            return AVERROR(ENOMEM);
    }
    pkt->size = size;
    pkt->channel_id = channel_id;
    pkt->type = type;
    pkt->timestamp = timestamp;
    pkt->extra = 0;
    pkt->ts_field = 0;

    return 0;
}

static int rtmp_packet_read_one_chunk(int socket, RTMPPacket* p,
    int chunk_size, RTMPPacket** prev_pkt_ptr,
    int* nb_prev_pkt, uint8_t hdr)
{

    uint8_t buf[16];
    int channel_id, timestamp, size;
    uint32_t ts_field; // non-extended timestamp or delta field
    uint32_t extra = 0;
    enum RTMPPacketType type;
    int written = 0;
    int ret, toread;
    RTMPPacket* prev_pkt;

    written++;
    channel_id = hdr & 0x3F;

    if (channel_id < 2) { //special case for channel number >= 64
        buf[1] = 0;
        if (recv(socket,(char*)buf, channel_id + 1,0) != channel_id + 1)
            return AVERROR(EIO);
        written += channel_id + 1;
        channel_id = AV_RL16(buf) + 64;
    }
    //ËæÊ±ÄÜ¼ÇÂ¼
    /*if ((ret = ff_rtmp_check_alloc_array(prev_pkt_ptr, nb_prev_pkt,
        channel_id)) < 0)
        return ret;*/
    prev_pkt = *prev_pkt_ptr;
    size = prev_pkt[channel_id].size;
    type = prev_pkt[channel_id].type;
    extra = prev_pkt[channel_id].extra;

    hdr >>= 6; // header size indicator
    if (hdr == RTMP_PS_ONEBYTE) {
        ts_field = prev_pkt[channel_id].ts_field;
    }
    else {
        if (recv(socket, (char*)buf, 3,0) != 3)
            return AVERROR(EIO);
        written += 3;
        ts_field = AV_RB24(buf);
        if (hdr != RTMP_PS_FOURBYTES) {
            
            if (recv(socket, (char*)buf, 3,0) != 3)
                return AVERROR(EIO);
            written += 3;
            size = AV_RB24(buf);
          
            if (recv(socket, (char*)buf, 1,0) != 1)
                return AVERROR(EIO);
            written++;
            type = (RTMPPacketType)buf[0];
            if (hdr == RTMP_PS_TWELVEBYTES) {
                if (recv(socket, (char*)buf, 4,0) != 4)
                    return AVERROR(EIO);
                
                extra = AV_RL32(buf);
               
                written += 4;
            }
        }
    }
    if (ts_field == 0xFFFFFF) {
        if (recv(socket, (char*)buf, 4,0) != 1)
            return AVERROR(EIO);
        timestamp = AV_RB32(buf);
    }
    else {
        timestamp = ts_field;
    }
    if (hdr != RTMP_PS_TWELVEBYTES)
        timestamp += prev_pkt[channel_id].timestamp;

    

    if (!prev_pkt[channel_id].read) {
        if ((ret = ff_rtmp_packet_create(p, channel_id, type, timestamp,
            size)) < 0)
            return ret;
        p->read = written;
        p->offset = 0;
        prev_pkt[channel_id].ts_field = ts_field;
        prev_pkt[channel_id].timestamp = timestamp;
    }
    else {
        // previous packet in this channel hasn't completed reading
        RTMPPacket* prev = &prev_pkt[channel_id];
        p->data = prev->data;
        p->size = prev->size;
        p->channel_id = prev->channel_id;
        p->type = prev->type;
        p->ts_field = prev->ts_field;
        p->extra = prev->extra;
        p->offset = prev->offset;
        p->read = prev->read + written;
        p->timestamp = prev->timestamp;
        prev->data = NULL;
    }
    p->extra = extra;
    // save history
    prev_pkt[channel_id].channel_id = channel_id;
    prev_pkt[channel_id].type = type;
    prev_pkt[channel_id].size = size;
    prev_pkt[channel_id].extra = extra;
    size = size - p->offset;

    toread = FFMIN(size, chunk_size);
    
    if (recv(socket, (char*)p->data + p->offset, toread,0) != toread) {
        ;
        return AVERROR(EIO);
    }
    size -= toread;
    p->read += toread;
    p->offset += toread;

    if (size > 0) {
        RTMPPacket* prev = &prev_pkt[channel_id];
        prev->data = p->data;
        prev->read = p->read;
        prev->offset = p->offset;
        p->data = NULL;
        return AVERROR(EAGAIN);
    }

    prev_pkt[channel_id].read = 0; // read complete; reset if needed
    return p->read;
}
int ff_rtmp_check_alloc_array(RTMPPacket** prev_pkt, int* nb_prev_pkt,
    int channel)
{
    int nb_alloc;
    RTMPPacket* ptr;
    if (channel < *nb_prev_pkt)
        return 0;

    nb_alloc = channel + 16;
    // This can't use the av_reallocp family of functions, since we
    // would need to free each element in the array before the array
    // itself is freed.
    ptr =(RTMPPacket*) malloc( nb_alloc*sizeof(**prev_pkt));
    if (!ptr)
        return AVERROR(ENOMEM);
    memset(ptr + *nb_prev_pkt, 0, (nb_alloc - *nb_prev_pkt) * sizeof(*ptr));
    *prev_pkt = ptr;
    *nb_prev_pkt = nb_alloc;
    return 0;
}
int ff_rtmp_packet_read_internal(int socket,RTMPPacket* p, int chunk_size,
    RTMPPacket** prev_pkt, int* nb_prev_pkt,
    uint8_t hdr)
{
    uint8_t buf[1024];
    uint8_t* data = buf;
    while (1) {
        data = buf;
        int reCount=recv(socket, (char*)data, 1, 0);
       
        hdr = data[0];
        data++;
        
        int ret = rtmp_packet_read_one_chunk(socket,p, 128, prev_pkt,
            nb_prev_pkt, hdr);
        if (ret > 0 || ret != AVERROR(EAGAIN))
            return ret;
    }
}
int ff_rtmp_packet_write(int h, RTMPPacket* pkt,
    int chunk_size, RTMPPacket** prev_pkt_ptr,
    int* nb_prev_pkt)
{
    uint8_t pkt_hdr[16], * p = pkt_hdr;
    int mode = RTMP_PS_TWELVEBYTES;
    int off = 0;
    int written = 0;
    int ret;
    RTMPPacket* prev_pkt;
    int use_delta; // flag if using timestamp delta, not RTMP_PS_TWELVEBYTES
    uint32_t timestamp; // full 32-bit timestamp or delta value

    if ((ret = ff_rtmp_check_alloc_array(prev_pkt_ptr, nb_prev_pkt,
        pkt->channel_id)) < 0)
        return ret;
    prev_pkt = *prev_pkt_ptr;

    //if channel_id = 0, this is first presentation of prev_pkt, send full hdr.
    use_delta = prev_pkt[pkt->channel_id].channel_id &&
        pkt->extra == prev_pkt[pkt->channel_id].extra &&
        pkt->timestamp >= prev_pkt[pkt->channel_id].timestamp;

    timestamp = pkt->timestamp;
    if (use_delta) {
        timestamp -= prev_pkt[pkt->channel_id].timestamp;
    }
    if (timestamp >= 0xFFFFFF) {
        pkt->ts_field = 0xFFFFFF;
    }
    else {
        pkt->ts_field = timestamp;
    }

    if (use_delta) {
        if (pkt->type == prev_pkt[pkt->channel_id].type &&
            pkt->size == prev_pkt[pkt->channel_id].size) {
            mode = RTMP_PS_FOURBYTES;
            if (pkt->ts_field == prev_pkt[pkt->channel_id].ts_field)
                mode = RTMP_PS_ONEBYTE;
        }
        else {
            mode = RTMP_PS_EIGHTBYTES;
        }
    }

    if (pkt->channel_id < 64) {
        bytestream_put_byte(&p, pkt->channel_id | (mode << 6));
    }
    else if (pkt->channel_id < 64 + 256) {
        bytestream_put_byte(&p, 0 | (mode << 6));
        bytestream_put_byte(&p, pkt->channel_id - 64);
    }
    else {
        bytestream_put_byte(&p, 1 | (mode << 6));
        bytestream_put_le16(&p, pkt->channel_id - 64);
    }
    if (mode != RTMP_PS_ONEBYTE) {
        bytestream_put_be24(&p, pkt->ts_field);
        if (mode != RTMP_PS_FOURBYTES) {
            bytestream_put_be24(&p, pkt->size);
            bytestream_put_byte(&p, pkt->type);
            if (mode == RTMP_PS_TWELVEBYTES)
                bytestream_put_le32(&p, pkt->extra);
        }
    }
    if (pkt->ts_field == 0xFFFFFF)
        bytestream_put_be32(&p, timestamp);
    // save history
    prev_pkt[pkt->channel_id].channel_id = pkt->channel_id;
    prev_pkt[pkt->channel_id].type = pkt->type;
    prev_pkt[pkt->channel_id].size = pkt->size;
    prev_pkt[pkt->channel_id].timestamp = pkt->timestamp;
    prev_pkt[pkt->channel_id].ts_field = pkt->ts_field;
    prev_pkt[pkt->channel_id].extra = pkt->extra;

    // FIXME:
    // Writing packets is currently not optimized to minimize system calls.
    // Since system calls flush on exit which we cannot change in a system-independant way.
    // We should fix this behavior and by writing packets in a single or in as few as possible system calls.
    // Protocols like TCP and RTMP should benefit from this when enabling TCP_NODELAY.
    int headerCount=(int)(p - pkt_hdr);
    if ((ret = send(h, (char*)pkt_hdr, headerCount,0)) < 0)
        return ret;
    written = p - pkt_hdr + pkt->size;
    while (off < pkt->size) {
        int towrite = FFMIN(chunk_size, pkt->size - off);
        
        if ((ret = send(h, (char*)pkt->data + off, towrite,0)) < 0)
            return ret;
        off += towrite;
        if (off < pkt->size) {
            uint8_t marker = 0xC0 | pkt->channel_id;
            if ((ret = send(h, (char*)&marker, 1,0)) < 0)
                return ret;
            written++;
            if (pkt->ts_field == 0xFFFFFF) {
                uint8_t ts_header[4];
                AV_WB32(ts_header, timestamp);
                if ((ret = send(h, (char*)ts_header, 4,0)) < 0)
                    return ret;
                written += 4;
            }
        }
    }
    return written;
}