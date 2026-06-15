/*
 * obfs.h - Interfaces of obfuscating function
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

#ifndef OBFS_H
#define OBFS_H

#include <stdbool.h>
#include "encrypt.h"

#define OBFS_OK         0 // 成功
#define OBFS_NEED_MORE -1 // 数据不足
#define OBFS_ERROR     -2 // 异常

// 状态机，每个连接一个
typedef struct obfs {
    int obfs_stage;   // 混淆阶段
    int deobfs_stage; // 解混淆阶段
    buffer_t *buf;    // 缓冲区，注意，tls会直接操作缓冲区
    void *extra;      // 额外数据，tls模式使用
} obfs_t;

// 混淆器，全局唯一
typedef struct obfs_para {
    const char *name;   // http或者tls
    const char *host;   // 默认为"cloudfront.net"
    const char *uri;    // local端使用，默认为 "/"
    const char *method; // method，默认为GET
    uint16_t port;      // local端使用，http为80，tls为443
    bool send_empty_response_upon_connection; // server端使用，http为false，tls为true

    int(*const obfs_request)(buffer_t *, size_t, obfs_t *);
    int(*const obfs_response)(buffer_t *, size_t, obfs_t *);
    int(*const deobfs_request)(buffer_t *, size_t, obfs_t *);
    int(*const deobfs_response)(buffer_t *, size_t, obfs_t *);
    int(*const check_obfs)(buffer_t *); // server端调用
    void(*const disable)(obfs_t *);
    int(*const is_enable)(obfs_t *);
} obfs_para_t;


#endif
