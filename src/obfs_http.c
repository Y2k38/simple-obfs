/*
 * obfs_http.c - Implementation of http obfuscating
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the simple-obfs.
 *
 * simple-obfs is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * simple-obfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with simple-obfs; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <strings.h>
#include <ctype.h> /* isblank() */

#include "base64.h"
#include "utils.h"
#include "obfs_http.h"

// Method = GET
// URI = /
// curl/7.x.y
// key = base64(16_bytes_rand_key)
// 数据长度
static const char *http_request_template =
    "%s %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "User-Agent: curl/7.%d.%d\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: %s\r\n"
    "Content-Length: %lu\r\n"
    "\r\n";

// nginx/1.x.y
// date网络格式
// key = base64(16_bytes_rand_key)
static const char *http_response_template =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Server: nginx/1.%d.%d\r\n"
    "Date: %s\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: %s\r\n"
    "\r\n";

static int obfs_http_request(buffer_t *, size_t, obfs_t *);
static int obfs_http_response(buffer_t *, size_t, obfs_t *);
static int deobfs_http_header(buffer_t *, size_t, obfs_t *);
static int check_http_header(buffer_t *buf);
static void disable_http(obfs_t *obfs);
static int is_enable_http(obfs_t *obfs);

static int get_header(const char *, const char *, int, char **);
static int next_header(const char **, int *);

static obfs_para_t obfs_http_st = {
    .name            = "http",
    .port            = 80,
    .send_empty_response_upon_connection = true,

    .obfs_request    = &obfs_http_request,
    .obfs_response   = &obfs_http_response,
    .deobfs_request  = &deobfs_http_header,
    .deobfs_response = &deobfs_http_header,
    .check_obfs      = &check_http_header,
    .disable         = &disable_http,
    .is_enable       = &is_enable_http
};

obfs_para_t *obfs_http = &obfs_http_st;

static int
obfs_http_request(buffer_t *buf, size_t cap, obfs_t *obfs)
{

    // stage不等于0，不处理
    if (obfs == NULL || obfs->obfs_stage != 0) return 0;
    // 此时stage=1
    obfs->obfs_stage++;

    static int major_version = 0;
    static int minor_version = 0;

    // 0-50 （包含）
    major_version = major_version ? major_version : rand() % 51;
    // 0-1 （包含）
    minor_version = minor_version ? minor_version : rand() % 2;

    char host_port[256];
    char http_header[512];
    uint8_t key[16];
    char b64[64];

    // 不是默认的80
    if (obfs_http->port != 80)
        // ip:port或者domain:port
        snprintf(host_port, sizeof(host_port), "%s:%d", obfs_http->host, obfs_http->port);
    else
        // 直接是IP或者domain
        snprintf(host_port, sizeof(host_port), "%s", obfs_http->host);

    // 填充16个字节的数据
    rand_bytes(key, 16);
    // 生成base64作为key
    base64_encode(b64, 64, key, 16);

    // 生成http的请求header，websocket握手协议
    size_t obfs_len =
        snprintf(http_header, sizeof(http_header), http_request_template, obfs_http->method,
                 obfs_http->uri, host_port, major_version, minor_version, b64, buf->len);
    size_t buf_len = buf->len; // 记录下当前的数据长度

    // 重新调整缓冲区，header+数据的总长度
    brealloc(buf, obfs_len + buf_len, cap);

    // 把数据往后挪
    memmove(buf->data + obfs_len, buf->data, buf_len);
    // header放到最前面
    memcpy(buf->data, http_header, obfs_len);

    // 更新长度
    buf->len = obfs_len + buf_len;

    // 最终长度
    return buf->len;
}

static int
obfs_http_response(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    // stage不等于0，不处理
    if (obfs == NULL || obfs->obfs_stage != 0) return 0;
    // 此时stage=1
    obfs->obfs_stage++;

    static int major_version = 0;
    static int minor_version = 0;

    // 0-10 （包含）
    major_version = major_version ? major_version : rand() % 11;
    // 0-11 （包含）
    minor_version = minor_version ? minor_version : rand() % 12;

    char http_header[512];
    char datetime[64];
    uint8_t key[16];
    char b64[64];

    time_t now;
    struct tm *tm_now;

    // Unix 时间戳
    time(&now);
    // 转换为本地时区的 tm 结构体
    tm_now = localtime(&now);
    // Tue, 02 Jun 2026 19:33:50 GMT
    strftime(datetime, 64, "%a, %d %b %Y %H:%M:%S GMT", tm_now);

    // 填充16个字节的数据
    rand_bytes(key, 16);
    // 生成base64作为key
    base64_encode(b64, 64, key, 16);

    // 记录下当前的数据长度
    size_t buf_len  = buf->len;
    // 生成http的响应header，websocket握手协议
    size_t obfs_len =
        snprintf(http_header, sizeof(http_header), http_response_template,
                 major_version, minor_version, datetime, b64);

    // 重新调整缓冲区，header+数据的总长度
    brealloc(buf, obfs_len + buf_len, cap);

    // 把数据往后挪
    memmove(buf->data + obfs_len, buf->data, buf_len);
    // header放到最前面
    memcpy(buf->data, http_header, obfs_len);

    // 更新长度
    buf->len = obfs_len + buf_len;

    // 最终长度
    return buf->len;
}

static int
deobfs_http_header(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    // stage不等于0，不处理
    if (obfs == NULL || obfs->deobfs_stage != 0) return 0;

    char *data = buf->data;
    int len    = buf->len;
    int err    = -1;

    // Allow empty content
    while (len >= 4) {
        // 找到最终的换行符
        if (data[0] == '\r' && data[1] == '\n'
            && data[2] == '\r' && data[3] == '\n') {
            // 数据长度-4
            len  -= 4;
            // 指针往后挪动4步
            data += 4;
            // 表示找到数据了
            err   = 0;
            break;
        }
        // 从头往后一直扫描
        // 数据长度-1
        len--;
        // 指针往后挪动一步
        data++;
    }

    // err=0，表示进入了while循环过，len>=4，有找到最终的换行符号
    if (!err) {
        // 把数据往前挪动
        memmove(buf->data, data, len);
        // 记录尾部未知
        buf->len = len;
        // 此时stage=1
        obfs->deobfs_stage++;
    }

    // 没找到数据
    return err;
}

// server端调用
static int
check_http_header(buffer_t *buf)
{
    // 记录指针跟长度
    char *data = buf->data;
    int len    = buf->len;

    // 找到第一个换行符位置 => 有没有完整的一行
    char *lfpos= strchr(data, '\n');
    // 没找到，数据不足
    if (lfpos == NULL) return OBFS_NEED_MORE;
    // 数据量小于15，异常 => 有完整的一行，那么数据长度符不符合预期
    if (len < 15) return OBFS_ERROR;
    // 没找到HTTP/1.1，异常
    if (strncasecmp(lfpos - 9, "HTTP/1.1", 8) != 0) return OBFS_ERROR;
    // method对不上，异常
    if ( obfs_http->method != NULL && strncasecmp(data, obfs_http->method, strlen(obfs_http->method)) != 0)
        return OBFS_ERROR;

    {
        char *protocol;
        // 找到upgrade数据
        int result = get_header("Upgrade:", data, len, &protocol);
        if (result < 0) {
            // 数据不足
            if (result == -1)
                return OBFS_NEED_MORE;
            else
                // 开辟内存失败，或者没找到
                return OBFS_ERROR;
        }
        // 不是websocket，异常
        if (strncmp(protocol, "websocket", result) != 0) {
            free(protocol);
            return OBFS_ERROR;
        } else {
            free(protocol);
        }
    }

    // 有设置host（一般都有）
    if (obfs_http->host != NULL) {
        char *hostname;
        int i;

        // 找到host数据
        int result = get_header("Host:", data, len, &hostname);
        if (result < 0) {
            // 数据不足
            if (result == -1)
                return OBFS_NEED_MORE;
            else
                // 开辟内存失败，或者没找到
                return OBFS_ERROR;
        }

        /*
         *  if the user specifies the port in the request, it is included here.
         *  Host: example.com:80
         *  so we trim off port portion
         */
        // 从后面往前面查找
        for (i = result - 1; i >= 0; i--)
            // 找到分隔符
            if ((hostname)[i] == ':') {
                // 直接换成字符串终止符
                (hostname)[i] = '\0';
                // 更新长度
                result         = i;
                break;
            }

        // 先设置为异常
        result = OBFS_ERROR;
        // 匹配字符串
        if (strncasecmp(hostname, obfs_http->host, len) == 0) {
            // 匹配成功
            result = OBFS_OK;
        }
        // 匹配失败，异常
        free(hostname);
        return result;
    }

    return OBFS_OK;
}

static int
get_header(const char *header, const char *data, int data_len, char **value)
{
    int len, header_len;

    // 需要匹配的数据长度
    header_len = strlen(header);

    // 找到下一个header的长度
    /* loop through headers stopping at first blank line */
    while ((len = next_header(&data, &data_len)) != 0)
        // 一行的长度足够覆盖要查找的字符串 且 完全匹配
        if (len > header_len && strncasecmp(header, data, header_len) == 0) {
            /* Eat leading whitespace */
            // 跳过空白字符
            while (header_len < len && isblank((unsigned char)data[header_len]))
                header_len++;

            // 开辟一段内存空间，专门用来存储后面的数据
            *value = malloc(len - header_len + 1);
            // 失败
            if (*value == NULL)
                return -4;

            // 复制数据
            strncpy(*value, data + header_len, len - header_len);
            // 字符串增加换行符
            (*value)[len - header_len] = '\0';

            // 数据长度
            return len - header_len;
        }

    // 数据不足
    /* If there is no data left after reading all the headers then we do not
     * have a complete HTTP request, there must be a blank line */
    if (data_len == 0)
        return -1;

    // 没找到
    return -2;
}

// 找到下一个header的长度
static int
next_header(const char **data, int *len)
{
    int header_len;

    /* perhaps we can optimize this to reuse the value of header_len, rather
     * than scanning twice.
     * Walk our data stream until the end of the header */
    // 从头往后一直扫描查找
    while (*len > 2 && (*data)[0] != '\r' && (*data)[1] != '\n') {
        (*len)--;
        (*data)++;
    }

    /* advanced past the <CR><LF> pair */
    *data += 2;
    *len  -= 2;

    /* Find the length of the next header */
    header_len = 0;
    while (*len > header_len + 1
           && (*data)[header_len] != '\r'
           && (*data)[header_len + 1] != '\n')
        header_len++;

    return header_len;
}

static void
disable_http(obfs_t *obfs)
{
    // -1为禁用
    obfs->obfs_stage = -1;
    obfs->deobfs_stage = -1;
}

static int
is_enable_http(obfs_t *obfs)
{
    // 两个都不能是-1
    return obfs->obfs_stage != -1 && obfs->deobfs_stage != -1;
}
