/*
 * local.h - Define the client's buffers and callbacks
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

#ifndef _LOCAL_H
#define _LOCAL_H

#include <ev.h>
#include <libcork/ds.h>

#ifdef __MINGW32__
#include "win32.h"
#endif

#include "encrypt.h"
#include "jconf.h"

#include "common.h"

typedef struct listen_ctx {
    ev_io io;
    char *iface; // 网卡
    int remote_num; // remote数量
    int method; // method
    int timeout; // 超时
    int fd; // conn
    int mptcp; // mptcp
    struct sockaddr **remote_addr; // remote_addr
} listen_ctx_t;

typedef struct server_ctx {
    ev_io io;
    int connected; // 是否已连接
    struct server *server; // 双向绑定
} server_ctx_t;

typedef struct server {
    int fd; // conn
    int stage; // 阶段

    obfs_t *obfs; // 状态

    struct server_ctx *recv_ctx; // 接收上下文 - 是否已连接
    struct server_ctx *send_ctx; // 发送上下文 - 是否已连接
    struct listen_ctx *listener; // 
    struct remote *remote; // remote

    buffer_t *buf; // 缓冲区

    struct cork_dllist_item entries; // 钩子
} server_t;

typedef struct remote_ctx {
    ev_io io;
    ev_timer watcher; // 超时定时器

    int connected; // 是否已连接
    struct remote *remote; // 双向绑定
} remote_ctx_t;

typedef struct remote {
    int fd; // conn
    int direct; // 默认为0
    int addr_len; // 长度
    uint32_t counter; // 计数器
#ifdef TCP_FASTOPEN_WINSOCK
    OVERLAPPED olap; // 
    int connect_ex_done; // 
#endif

    buffer_t *buf; // 缓冲区
    struct remote_ctx *recv_ctx; // 接收上下文 - 是否已连接/超时
    struct remote_ctx *send_ctx; // 发送上下文 - 是否已连接/超时
    struct server *server; // 双向绑定
    struct sockaddr_storage addr; // 地址
} remote_t;

#endif // _LOCAL_H
