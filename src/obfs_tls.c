/*
 * obfs_tls.c - Implementation of tls obfuscating
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
 * <tls://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <strings.h>

#include <libcork/core.h>

#define CT_HTONS(n) CORK_UINT16_HOST_TO_BIG(n)
#define CT_NTOHS(n) CORK_UINT16_BIG_TO_HOST(n)
#define CT_HTONL(n) CORK_UINT32_HOST_TO_BIG(n)
#define CT_NTOHL(n) CORK_UINT32_BIG_TO_HOST(n)

#include "base64.h"
#include "utils.h"
#include "obfs_tls.h"

static const struct tls_client_hello
tls_client_hello_template = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0301),
    .len = 0,

    .handshake_type = 1,
    .handshake_len_1 = 0,
    .handshake_len_2 = 0,
    .handshake_version = CT_HTONS(0x0303),

    .random_unix_time = 0,
    .random_bytes = { 0 },

    .session_id_len = 32,
    .session_id = { 0 },

    .cipher_suites_len = CT_HTONS(56),
    .cipher_suites = {
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
        0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
        0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
        0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff
    },

    .comp_methods_len = 1,
    .comp_methods = { 0 },

    .ext_len = 0,
};

static const struct tls_ext_server_name
tls_ext_server_name_template = {
    .ext_type = 0,
    .ext_len = 0,
    .server_name_list_len = 0,
    .server_name_type = 0,
    .server_name_len = 0,
    // char server_name[server_name_len];
};

static const struct tls_ext_session_ticket
tls_ext_session_ticket_template = {
    .session_ticket_type = CT_HTONS(0x0023),
    .session_ticket_ext_len = 0,
    // char  session_ticket[session_ticket_ext_len];
};

static const struct tls_ext_others
tls_ext_others_template = {
    .ec_point_formats_ext_type = CT_HTONS(0x000B),
    .ec_point_formats_ext_len = CT_HTONS(4),
    .ec_point_formats_len = 3,
    .ec_point_formats = { 0x01, 0x00, 0x02 },

    .elliptic_curves_type = CT_HTONS(0x000a),
    .elliptic_curves_ext_len = CT_HTONS(10),
    .elliptic_curves_len = CT_HTONS(8),
    .elliptic_curves = { 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18 },

    .sig_algos_type = CT_HTONS(0x000d),
    .sig_algos_ext_len = CT_HTONS(32),
    .sig_algos_len = CT_HTONS(30),
    .sig_algos = {
        0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02,
        0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03
    },

    .encrypt_then_mac_type = CT_HTONS(0x0016),
    .encrypt_then_mac_ext_len = 0,

    .extended_master_secret_type = CT_HTONS(0x0017),
    .extended_master_secret_ext_len = 0,
};

static const struct tls_server_hello
tls_server_hello_template = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0301),
    .len = CT_HTONS(91),

    .handshake_type = 2,
    .handshake_len_1 = 0,
    .handshake_len_2 = CT_HTONS(87),
    .handshake_version = CT_HTONS(0x0303),

    .random_unix_time = 0,
    .random_bytes = { 0 },

    .session_id_len = 32,
    .session_id = { 0 },

    .cipher_suite = CT_HTONS(0xCCA8),
    .comp_method = 0,
    .ext_len = 0,

    .ext_renego_info_type = CT_HTONS(0xFF01),
    .ext_renego_info_ext_len = CT_HTONS(1),
    .ext_renego_info_len = 0,

    .extended_master_secret_type = CT_HTONS(0x0017),
    .extended_master_secret_ext_len = 0,

    .ec_point_formats_ext_type = CT_HTONS(0x000B),
    .ec_point_formats_ext_len = CT_HTONS(2),
    .ec_point_formats_len = 1,
    .ec_point_formats = { 0 },
};

static const struct tls_change_cipher_spec
tls_change_cipher_spec_template = {
    .content_type = 0x14,
    .version = CT_HTONS(0x0303),
    .len = CT_HTONS(1),
    .msg = 0x01,
};

static const struct tls_encrypted_handshake
tls_encrypted_handshake_template = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0303),
    .len = 0,
    // char  msg[len];
};

const char tls_data_header[3] = {0x17, 0x03, 0x03};

static int obfs_tls_request(buffer_t *, size_t, obfs_t *);
static int obfs_tls_response(buffer_t *, size_t, obfs_t *);
static int deobfs_tls_request(buffer_t *, size_t, obfs_t *);
static int deobfs_tls_response(buffer_t *, size_t, obfs_t *);
static int obfs_app_data(buffer_t *, size_t, obfs_t *);
static int deobfs_app_data(buffer_t *, size_t, obfs_t *);
static int check_tls_request(buffer_t *buf);
static void disable_tls(obfs_t *obfs);
static int is_enable_tls(obfs_t *obfs);

static obfs_para_t obfs_tls_st = {
    .name            = "tls",
    .port            = 443,
    .send_empty_response_upon_connection = false,

    .obfs_request    = &obfs_tls_request,
    .obfs_response   = &obfs_tls_response,
    .deobfs_request  = &deobfs_tls_request,
    .deobfs_response = &deobfs_tls_response,
    .check_obfs      = &check_tls_request,
    .disable         = &disable_tls,
    .is_enable       = &is_enable_tls
};

obfs_para_t *obfs_tls = &obfs_tls_st;

// 数据加混淆
static int
obfs_app_data(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    // 数据长度
    size_t buf_len = buf->len;

    // 增加5个字节
    brealloc(buf, buf_len + 5, cap);
    // 原始数据往后挪
    memmove(buf->data + 5, buf->data, buf_len);
    // 最开始3个字节：0x17, 0x03, 0x03
    memcpy(buf->data, tls_data_header, 3);

    // 后面的两个字节表示长度
    *(uint16_t*)(buf->data + 3) = CT_HTONS(buf_len);
    // 更新buf的长度
    buf->len = buf_len + 5;

    return 0;
}

static int
deobfs_app_data(buffer_t *buf, size_t idx, obfs_t *obfs)
{
    // idx为0或者原始数据的长度
    int bidx = idx, bofst = idx;

    // 索引2字节 + 长度2字节 + 缓冲区2字节 = 一共6个字节
    frame_t *frame = (frame_t *)obfs->extra;

    // bidx => 固定往后走的指针
    while (bidx < buf->len) {
        // 当frame->len一般为0
        // 解析数据获取len后就不执行这部分了
        if (frame->len == 0) {
            // 检查前面3个字节是否匹配
            if (frame->idx >= 0 && frame->idx < 3
                    && buf->data[bidx] != tls_data_header[frame->idx]) {
                return OBFS_ERROR;
            } else if (frame->idx >= 3 && frame->idx < 5) { 
                // 复制长度数据，一共两位，每次一位
                memcpy(frame->buf + frame->idx - 3, buf->data + bidx, 1);
            } else if (frame->idx < 0) {
                // 数据不足
                bofst++;
            }
            // 往后挪动
            frame->idx++;
            bidx++;
            if (frame->idx == 5) {
                // 更新长度
                frame->len = CT_NTOHS(*(uint16_t *)(frame->buf));
                // 重置为0
                frame->idx = 0; 
            }
            continue;
        }

        // 当frame->len不为0，表示已经去掉header获取的真实的数据长度

        // 模拟tls载荷，不能超过16kb，否则异常
        if (frame->len > 16384)
            return OBFS_ERROR;

        // buffer剩余的长度
        int left_len = buf->len - bidx;

        // 有额外数据
        if (left_len > frame->len) {
            // 真实数据移动到指定位置
            memmove(buf->data + bofst, buf->data + bidx, frame->len);
            // 挪动bidx指针到下一个frame
            bidx  += frame->len;
            // 下一个写入真实数据的位置
            bofst += frame->len;
            // 重置为0，从新开解析header
            frame->len = 0;
        } else {
            // 数据刚好，或不够
            // 真实数据挪动到指定位置
            memmove(buf->data + bofst, buf->data + bidx, left_len);
            // 到末尾
            bidx  = buf->len;
            // 下一个写入真实数据的位置
            bofst += left_len;
            // 记录len，可能是0，也可能是一小部分数据，跟着下一个frame一起解析
            frame->len -= left_len;
        }
    }

    // 真实数据末尾
    buf->len = bofst;

    return OBFS_OK;
}


static int
obfs_tls_request(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    // 负数表示禁用，不处理
    if (obfs == NULL || obfs->obfs_stage < 0) return 0;

    // 初始化临时缓冲区
    // idx=0，len=0，cap=0，指针=null
    static buffer_t tmp = { 0, 0, 0, NULL };

    // 第一次处理
    if (obfs->obfs_stage == 0) {

        size_t buf_len = buf->len;                                  // 原始数据长度
        size_t hello_len = sizeof(struct tls_client_hello);         // client hello的头部大小
        size_t server_name_len = sizeof(struct tls_ext_server_name);// server name的头部大小
        size_t host_len = strlen(obfs_tls->host);                   // host的长度
        size_t ticket_len = sizeof(struct tls_ext_session_ticket);  // session ticket的头部大小
        size_t other_ext_len = sizeof(struct tls_ext_others);       // others的头部大小
        size_t tls_len = buf_len + hello_len + server_name_len
            + host_len + ticket_len + other_ext_len;                // 加密后的总大小

        // 扩容临时缓冲区
        brealloc(&tmp, buf_len, cap);
        // 扩容buffer，最终结果
        brealloc(buf,  tls_len, cap);

        // 把原始数据放在tmp
        memcpy(tmp.data, buf->data, buf_len);

        /* Client Hello Header */
        // 复制模板
        struct tls_client_hello *hello = (struct tls_client_hello *) buf->data;
        memcpy(hello, &tls_client_hello_template, hello_len);
        // 长度=总长度-5个字节（content_type+version+len）
        hello->len = CT_HTONS(tls_len - 5);
        // 长度=总长度-5个字节-4个字节（handshake_type+handshake_len_1+handshake_len_2）
        hello->handshake_len_2 = CT_HTONS(tls_len - 9);
        // unix时间戳
        hello->random_unix_time = CT_HTONL((uint32_t)time(NULL));
        // 28字节随机数
        rand_bytes(hello->random_bytes, 28);
        // 32字节随机数
        rand_bytes(hello->session_id, 32);
        // 长度=server name的头部大小 + host的长度 + session ticket的头部大小 + 数据大小 + others的头部大小
        hello->ext_len = CT_HTONS(server_name_len + host_len + ticket_len + buf_len + other_ext_len);

        /* Session Ticket */
        // 复制模板
        struct tls_ext_session_ticket *ticket =
            (struct tls_ext_session_ticket *)((char *)hello + hello_len);
        memcpy(ticket, &tls_ext_session_ticket_template, sizeof(struct tls_ext_session_ticket));
        // 记录为数据长度
        ticket->session_ticket_ext_len = CT_HTONS(buf_len);
        // 把原始数据放到这里（ticket后面）
        memcpy((char *)ticket + ticket_len, tmp.data, buf_len);

        /* SNI */
        // 复制模板
        struct tls_ext_server_name *server_name =
            (struct tls_ext_server_name *)((char *)ticket + ticket_len + buf_len);
        memcpy(server_name, &tls_ext_server_name_template, server_name_len);
        // 剩下的数据长度=host长度+3+2 （server_name_list_len+server_name_type+server_name_len）
        server_name->ext_len = CT_HTONS(host_len + 3 + 2);
        // =host长度+3（server_name_type+server_name_len）
        server_name->server_name_list_len = CT_HTONS(host_len + 3);
        // =host长度
        server_name->server_name_len = CT_HTONS(host_len);
        // 把host放在最后面
        memcpy((char *)server_name + server_name_len, obfs_tls->host, host_len);

        /* Other Extensions */
        // 把剩下的others模板复制到最后
        memcpy((char *)server_name + server_name_len + host_len, &tls_ext_others_template,
                other_ext_len);

        // 记录总长度
        buf->len = tls_len;

        // 此时stage=1
        obfs->obfs_stage++;

    } else if (obfs->obfs_stage == 1) {
        // 第2+处理
        obfs_app_data(buf, cap, obfs);

    }

    // 不管stage为0还是1，都会返回缓冲区长度
    return buf->len;
}

static int
obfs_tls_response(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    // 负数表示禁用，不处理
    if (obfs == NULL || obfs->obfs_stage < 0) return 0;

    // 初始化临时缓冲区
    // idx=0，len=0，cap=0，指针=null
    static buffer_t tmp = { 0, 0, 0, NULL };

    // 第一次处理
    if (obfs->obfs_stage == 0) {

        // 原始数据长度
        size_t buf_len = buf->len;
        // sever hello的头部大小
        size_t hello_len = sizeof(struct tls_server_hello);
        // change cipher的头部大小
        size_t change_cipher_spec_len = sizeof(struct tls_change_cipher_spec);
        // encrypted handshake的头部大小
        size_t encrypted_handshake_len = sizeof(struct tls_encrypted_handshake);
        // 加密后的总大小
        size_t tls_len = hello_len + change_cipher_spec_len + encrypted_handshake_len + buf_len;

        // 扩容临时缓冲区
        brealloc(&tmp, buf_len, cap);
        // 扩容buffer，最终结果
        brealloc(buf,  tls_len, cap);

        // 把原始数据放在tmp
        memcpy(tmp.data, buf->data, buf_len);

        /* Server Hello */
        // 复制模板
        memcpy(buf->data, &tls_server_hello_template, hello_len);
        struct tls_server_hello *hello = (struct tls_server_hello *)buf->data;
        // unix时间戳
        hello->random_unix_time = CT_HTONL((uint32_t)time(NULL));
        // 28字节随机数
        rand_bytes(hello->random_bytes, 28);

        // 一个特殊的缓冲区
        if (obfs->buf != NULL) {
            // 从缓冲区复制session id
            memcpy(hello->session_id, obfs->buf->data, 32);
        } else {
            // 没有就自己生成一个
            rand_bytes(hello->session_id, 32);
        }

        /* Change Cipher Spec */
        // 复制模板
        memcpy(buf->data + hello_len, &tls_change_cipher_spec_template, change_cipher_spec_len);

        /* Encrypted Handshake */
        // 复制模板
        memcpy(buf->data + hello_len + change_cipher_spec_len, &tls_encrypted_handshake_template,
                encrypted_handshake_len);
        // 把原始数据放到这里（handshake后面）
        memcpy(buf->data + hello_len + change_cipher_spec_len + encrypted_handshake_len,
                tmp.data, buf_len);

        struct tls_encrypted_handshake *encrypted_handshake =
            (struct tls_encrypted_handshake *)(buf->data + hello_len + change_cipher_spec_len);
        // 修改长度为原始数据的大小
        encrypted_handshake->len = CT_HTONS(buf_len);

        // 改为总大小
        buf->len = tls_len;

        // 此时stage=1
        obfs->obfs_stage++;

    } else if (obfs->obfs_stage == 1) {
        // 第2+次处理
        obfs_app_data(buf, cap, obfs);

    }

    // 不管stage为0还是1，都会返回缓冲区长度
    return buf->len;
}

static int
deobfs_tls_request(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    // 负数表示禁用，不处理
    if (obfs == NULL || obfs->deobfs_stage < 0) return 0;

    // 解混淆阶段，初始化extra，结构为frame_t，一共6个字节，全部设置为0或NULL
    if (obfs->extra == NULL) {
        obfs->extra = ss_malloc(sizeof(frame_t));
        memset(obfs->extra, 0, sizeof(frame_t));
    }

    // 一个特殊缓冲区，专门记录session id
    // 初始：idx=0，len=0，cap=0，指针=null
    // 更新：idx=0，len=32，cap=32，指针指向一片内存区域
    if (obfs->buf == NULL) {
        obfs->buf = (buffer_t *)ss_malloc(sizeof(buffer_t));
        balloc(obfs->buf, 32);
        obfs->buf->len = 32;
    }

    // 第一次处理
    if (obfs->deobfs_stage == 0) {
        // 记录数据长度
        int len = buf->len;

        // 数据不足不处理
        len -= sizeof(struct tls_client_hello);
        if (len <= 0) return OBFS_NEED_MORE;

        // 一次性映射hello结构体
        struct tls_client_hello *hello = (struct tls_client_hello *) buf->data;
        // 检查content_type是否一致 => 0x16
        if (hello->content_type != tls_client_hello_template.content_type)
            return OBFS_ERROR; // 不一致，异常

        // hello_len的长度=记录长度+5个字节（content_type+version+len）
        size_t hello_len = CT_NTOHS(hello->len) + 5;

        // memcpy(目标地址, 源地址, 长度)
        // session id 从网络数据拷贝到特殊缓冲区
        memcpy(obfs->buf->data, hello->session_id, 32);

        // 数据不足不处理
        len -= sizeof(struct tls_ext_session_ticket);
        if (len <= 0) return OBFS_NEED_MORE;

        // 一次性映射ticket结构体
        struct tls_ext_session_ticket *ticket =
            (struct tls_ext_session_ticket *)(buf->data + sizeof(struct tls_client_hello));
        // 对比下session_ticket_type是否一致 => 0x0023
        if (ticket->session_ticket_type != tls_ext_session_ticket_template.session_ticket_type)
            return OBFS_ERROR;

        // 原始数据就藏在这里
        size_t ticket_len = CT_NTOHS(ticket->session_ticket_ext_len);
        // 原始数据不足，这里保证数据刚好或者有溢出
        if (len < ticket_len)
            return OBFS_NEED_MORE;

        // 把原始数据挪到最前面
        memmove(buf->data, (char *)ticket + sizeof(struct tls_ext_session_ticket), ticket_len);

        // 有多余的数据
        if (buf->len > hello_len) {
            // 把多余的数据拼到原始数据的后面
            memmove(buf->data + ticket_len, buf->data + hello_len, buf->len - hello_len);
        }

        // 总长度更新
        // 原始数据+额外数据
        buf->len = ticket_len + buf->len - hello_len;

        // 此时stage=1
        obfs->deobfs_stage++;

        // 有额外数据
        if (buf->len > ticket_len) {
            // 
            return deobfs_app_data(buf, ticket_len, obfs);
        } else {
            // 数据量刚刚好
            // idx + len + buf[2]
            // 2字节+2字节+2字节
            // 这里结果必定为0（上游拦截了<0，if分支处理了>0）
            ((frame_t*)obfs->extra)->idx = buf->len - ticket_len;
        }

    } else if (obfs->deobfs_stage == 1) {
        // 第2+处理
        return deobfs_app_data(buf, 0, obfs);

    }

    // 返回处理结果
    return 0;
}

static int
deobfs_tls_response(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    // 负数表示禁用，不处理
    if (obfs == NULL || obfs->deobfs_stage < 0) return 0;

    // 解混淆阶段，初始化extra，结构为frame_t，一共6个字节，全部设置为0或NULL
    if (obfs->extra == NULL) {
        obfs->extra = ss_malloc(sizeof(frame_t));
        memset(obfs->extra, 0, sizeof(frame_t));
    }

    // 第一次处理
    if (obfs->deobfs_stage == 0) {
        // server hello结构体大小
        size_t hello_len = sizeof(struct tls_server_hello);

        // 建立一个变量存储指针跟大小
        char *data = buf->data;
        int len    = buf->len;

        // 数据量不足不处理
        len -= hello_len;
        if (len <= 0) return OBFS_NEED_MORE;

        // 一次性映射hello结构体
        struct tls_server_hello *hello = (struct tls_server_hello*) data;
        // 检查content_type是否一致 => 0x16
        if (hello->content_type != tls_server_hello_template.content_type)
            return OBFS_ERROR;

        // change cipher的结构体大小
        size_t change_cipher_spec_len = sizeof(struct tls_change_cipher_spec);
        // encrypted handshake的结构体大小
        size_t encrypted_handshake_len = sizeof(struct tls_encrypted_handshake);

        // 数据量不足不处理
        len -= change_cipher_spec_len + encrypted_handshake_len;
        if (len <= 0) return OBFS_NEED_MORE;

        // 多余的头部大小，需要丢弃掉
        size_t tls_len = hello_len + change_cipher_spec_len + encrypted_handshake_len;
        // 一次性映射encrypted handshake
        struct tls_encrypted_handshake *encrypted_handshake =
            (struct tls_encrypted_handshake *)(buf->data + hello_len + change_cipher_spec_len);
        // 获取原始数据的大小
        size_t msg_len = CT_NTOHS(encrypted_handshake->len);

        // 把原始数据挪到最前面
        memmove(buf->data, buf->data + tls_len, buf->len - tls_len);

        // 更新总大小
        buf->len = buf->len - tls_len;

        // 此时stage=1
        obfs->deobfs_stage++;

        // 有额外数据
        if (buf->len > msg_len) {
            return deobfs_app_data(buf, msg_len, obfs);
        } else {
            // 数据量刚刚好或者不足
            // idx <= 0，负数表示不足的部分
            ((frame_t*)obfs->extra)->idx = buf->len - msg_len;
        }

    } else if (obfs->deobfs_stage == 1) {
        // 第2+处理
        return deobfs_app_data(buf, 0, obfs);

    }

    // 返回处理结果
    return 0;
}

// 检查前面11个字节的数据
static int
check_tls_request(buffer_t *buf)
{
    char *data = buf->data;
    int len    = buf->len;

    // 小于11个字节，数据量不足
    if (len < 11)
        return OBFS_NEED_MORE;

    // content_type = 0x16
    // version = CT_HTONS(0x0301)
    // handshake_type = 1
    // handshake_version = CT_HTONS(0x0303)
    if (data[0] == 0x16
        && data[1] == 0x03
        && data[2] == 0x01
        && data[5] == 0x01
        && data[9] == 0x03
        && data[10] == 0x03)
        return OBFS_OK;
    else
        return OBFS_ERROR;
}

static void
disable_tls(obfs_t *obfs)
{
    // -1表示禁用
    obfs->obfs_stage = -1;
    obfs->deobfs_stage = -1;
}

static int
is_enable_tls(obfs_t *obfs)
{
    // 两个都不能是-1
    return obfs->obfs_stage != -1 && obfs->deobfs_stage != -1;
}
