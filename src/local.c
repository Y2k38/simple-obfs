/*
 * local.c - Setup a tunneling proxy through remote simple-obfs server
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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>

#ifndef __MINGW32__
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include <libcork/core.h>

#include "netutils.h"
#include "utils.h"
#include "obfs_http.h"
#include "obfs_tls.h"
#include "options.h"
#include "local.h"

#ifdef __APPLE__
#include <AvailabilityMacros.h>
#if defined(MAC_OS_X_VERSION_10_10) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_10
#include <launch.h>
#define HAVE_LAUNCHD
#endif
#endif

// 在早期不同的 Unix 版本中，有的系统使用 EAGAIN 来表示“重试”，有的使用 EWOULDBLOCK 来表示“阻塞”
#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

// 缓冲区设置为2k
#ifndef BUF_SIZE
#define BUF_SIZE 2048
#endif

// 不打印详细信息
int verbose        = 0;
// 
int keep_resolving = 1;

#ifdef ANDROID
int vpn        = 0; // 标志位，通常用于判断 VPN 服务是否已启动或作为 VPN 文件描述符（File Descriptor）的句柄
uint64_t tx    = 0; // 记录了通过 VPN 发送的数据总量（单位通常是字节）
uint64_t rx    = 0; // 记录了通过 VPN 接收的数据总量
ev_tstamp last = 0; // 时间戳（通常来自于 libev 库）。它记录了上一次更新流量统计的时间，用于计算当前的“瞬时网速”或判定连接是否超时
#endif

// ipv6优先
static int ipv6first = 0;
// fast-open
static int fast_open = 0;

static obfs_para_t *obfs_para  = NULL;

#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif

static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void signal_cb(EV_P_ ev_signal *w, int revents);

static int create_and_bind(const char *addr, const char *port);
#ifdef HAVE_LAUNCHD
static int launch_or_create(const char *addr, const char *port);
#endif
static remote_t *create_remote(listen_ctx_t *listener, struct sockaddr *addr);
static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

static remote_t *new_remote(int fd, int timeout);
static server_t *new_server(int fd);

// 连接
static struct cork_dllist connections;

#ifndef __MINGW32__
// 非windows，设置为非阻塞
int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// 当发现当前进程的父进程发生变更时，主动退出程序
static void
parent_watcher_cb(EV_P_ ev_timer *watcher, int revents)
{
    static int ppid = -1;

    int cur_ppid = getppid();
    if (ppid != -1) {
        if (ppid != cur_ppid) {
            keep_resolving = 0; // 停止业务逻辑
            ev_unloop(EV_A_ EVUNLOOP_ALL); // 通知 libev 事件循环停止运行
        }
    }

    ppid = cur_ppid;
}
#endif

int
create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    // ipv4+ipv6 + tcp
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    // 地址转换
    s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0) {
        LOGE("getaddrinfo (%s:%s), error %s", addr, port, gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        // 创建socket
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        int opt = 1;
        // 地址复用 程序重启时，可以立即使用处于 TIME_WAIT 状态的端口
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        // 防止程序因“向已关闭的连接写入数据”而收到 SIGPIPE 信号导致崩溃的保护措施
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        // 端口复用 允许多个进程绑定到同一个 IP 和端口
        int err = set_reuseport(listen_sock);
        if (err == 0) {
            LOGI("tcp port reuse enabled");
        }

        // 程序与特定的端口绑定在一起
        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            // 成功，退出循环
            /* We managed to bind successfully! */
            break;
        } else {
            // 失败
            ERROR("bind");
        }

        close(listen_sock);
    }

    // 循环到最后都没有能绑定的
    if (rp == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    // 回收内存
    freeaddrinfo(result);

    // 返回socket
    return listen_sock;
}

#ifdef HAVE_LAUNCHD
int
launch_or_create(const char *addr, const char *port)
{
    int *fds;
    size_t cnt;
    int error = launch_activate_socket("Listeners", &fds, &cnt);
    if (error == 0) { 
        // launchd启动的程序
        // 函数直接返回那个已经建立好的 Socket fd
        if (cnt == 1) {
            return fds[0];
        } else {
            FATAL("please don't specify multi entry");
        }
    } else if (error == ESRCH || error == ENOENT) {
        /* ESRCH:  The calling process is not managed by launchd(8).
         * ENOENT: The socket name specified does not exist
         *          in the caller's launchd.plist(5).
         */
        if (port == NULL) {
            usage();
            exit(EXIT_FAILURE);
        }
        // 手动
        // 回退到传统方式
        return create_and_bind(addr, port);
    } else {
        FATAL("launch_activate_socket() error");
    }
    return -1;
}
#endif

// 遍历双向链表，回收连接
static void
free_connections(struct ev_loop *loop)
{
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach_void(&connections, curr, next) {
        server_t *server = cork_container_of(curr, server_t, entries);
        remote_t *remote = server->remote;
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
    }
}

// 客户端->服务端
static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    buffer_t *buf;
    ssize_t r;

    if (remote == NULL) { // init阶段
        // 第一次接收数据，复制到server的buf，然后手动复制到remote的buf
        buf = server->buf;
    } else { // stream阶段
        // 直接复制到remote的buf
        buf = remote->buf;
    }

    // 0 => 使用默认行为
    // 读取数据到buf
    r = recv(server->fd, buf->data + buf->len, BUF_SIZE - buf->len, 0);

    // 对方已经关闭了连接（EOF）
    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) { // 发生了错误
        // 内核缓冲区已满/已空
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            // 异常
            if (verbose)
                ERROR("server_recv_cb_recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    // 成功接收到的字节数
    buf->len += r;

    while (1) {
        // local socks5 server
        if (server->stage == STAGE_STREAM) {
            // 连接已经建立

            // 没有remote，异常
            if (remote == NULL) {
                LOGE("invalid remote");
                close_and_free_server(EV_A_ server);
                return;
            }

#ifdef ANDROID
            // 计数器，已发送数据量
            tx += remote->buf->len;
#endif
            // 混淆
            if (obfs_para)
                // 混淆请求
                // 缓冲区
                // 2kb的容量
                // http或tls
                obfs_para->obfs_request(remote->buf, BUF_SIZE, server->obfs);

            // 未连接
            if (!remote->send_ctx->connected) {
#ifdef ANDROID
                // 检查程序是否运行在 VPN 模式下
                if (vpn) {
                    int not_protect = 0;
                    if (remote->addr.ss_family == AF_INET) {
                        struct sockaddr_in *s = (struct sockaddr_in *)&remote->addr;
                        if (s->sin_addr.s_addr == inet_addr("127.0.0.1"))
                            not_protect = 1;
                    }
                    if (!not_protect) {
                        // 将这个 Socket 从 VPN 的流量接管名单中剔除，让其直接走物理网卡（如移动网络或 Wi-Fi）发送，不进入 VPN 隧道
                        if (protect_socket(remote->fd) == -1) {
                            ERROR("protect_socket");
                            close_and_free_remote(EV_A_ remote);
                            close_and_free_server(EV_A_ server);
                            return;
                        }
                    }
                }
#endif
                // 从头开始算
                remote->buf->idx = 0;

                // 不是fast-open
                if (!fast_open) {
                    // connecting, wait until connected
                    // 连接
                    int r = connect(remote->fd, (struct sockaddr *)&(remote->addr), remote->addr_len);

                    // 连接失败
                    if (r == -1 && errno != CONNECT_IN_PROGRESS) {
                        ERROR("connect");
                        close_and_free_remote(EV_A_ remote);
                        close_and_free_server(EV_A_ server);
                        return;
                    }

                    // wait on remote connected event
                    // 先暂停server recv事件
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    // 开启remote send事件
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                    // 开启watcher
                    ev_timer_start(EV_A_ & remote->send_ctx->watcher);
                } else {
#ifdef TCP_FASTOPEN
#ifdef __APPLE__
                    ((struct sockaddr_in *)&(remote->addr))->sin_len = sizeof(struct sockaddr_in);
                    sa_endpoints_t endpoints;
                    memset((char *)&endpoints, 0, sizeof(endpoints));
                    endpoints.sae_dstaddr    = (struct sockaddr *)&(remote->addr);
                    endpoints.sae_dstaddrlen = remote->addr_len;

                    int s = connectx(remote->fd, &endpoints, SAE_ASSOCID_ANY,
                                     CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
                                     NULL, 0, NULL, NULL);
                    if (s == 0) {
                        s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
                    }
#elif defined(TCP_FASTOPEN_WINSOCK)
                    DWORD s = -1;
                    DWORD err = 0;
                    do {
                        int optval = 1;
                        // Set fast open option
                        if (setsockopt(remote->fd, IPPROTO_TCP, TCP_FASTOPEN,
                                       &optval, sizeof(optval)) != 0) {
                            ERROR("setsockopt");
                            break;
                        }
                        // Load ConnectEx function
                        LPFN_CONNECTEX ConnectEx = winsock_getconnectex();
                        if (ConnectEx == NULL) {
                            LOGE("Cannot load ConnectEx() function");
                            err = WSAENOPROTOOPT;
                            break;
                        }
                        // ConnectEx requires a bound socket
                        if (winsock_dummybind(remote->fd,
                                              (struct sockaddr *)&(remote->addr)) != 0) {
                            ERROR("bind");
                            break;
                        }
                        // Call ConnectEx to send data
                        memset(&remote->olap, 0, sizeof(remote->olap));
                        remote->connect_ex_done = 0;
                        if (ConnectEx(remote->fd, (const struct sockaddr *)&(remote->addr),
                                      remote->addr_len, remote->buf->data, remote->buf->len,
                                      &s, &remote->olap)) {
                            remote->connect_ex_done = 1;
                            break;
                        };
                        // XXX: ConnectEx pending, check later in remote_send
                        if (WSAGetLastError() == ERROR_IO_PENDING) {
                            err = CONNECT_IN_PROGRESS;
                            break;
                        }
                        ERROR("ConnectEx");
                    } while(0);
                    // Set error number
                    if (err) {
                        SetLastError(err);
                    }
#else
                    // 发送到远端
                    int s = sendto(remote->fd, remote->buf->data, remote->buf->len, MSG_FASTOPEN,
                                   (struct sockaddr *)&(remote->addr), remote->addr_len);
#endif
                    // 失败
                    if (s == -1) {
                        // 连接正在进行中
                        if (errno == CONNECT_IN_PROGRESS) {
                            // in progress, wait until connected
                            remote->buf->idx = 0;
                            // 不接收app数据
                            ev_io_stop(EV_A_ & server_recv_ctx->io);
                            // 也不发送数据到远端
                            ev_io_start(EV_A_ & remote->send_ctx->io);
                            return;
                        } else {
                            // 异常
                            ERROR("sendto");
                            // Socket 未连接
                            if (errno == ENOTCONN) {
                                LOGE("fast open is not supported on this platform");
                                // just turn it off
                                fast_open = 0;
                            }
                            close_and_free_remote(EV_A_ remote);
                            close_and_free_server(EV_A_ server);
                            return;
                        }
                    } else if (s < (int)(remote->buf->len)) { // 部分发送
                        // 更正idx
                        remote->buf->len -= s;
                        remote->buf->idx  = s;

                        // 先不接收app数据
                        ev_io_stop(EV_A_ & server_recv_ctx->io);
                        // 继续开启发送
                        ev_io_start(EV_A_ & remote->send_ctx->io);
                        // 开启watcher
                        ev_timer_start(EV_A_ & remote->send_ctx->watcher);
                        return;
                    } else { // 全部发送
                        // Just connected
                        // 更新idx跟len
                        remote->buf->idx = 0;
                        remote->buf->len = 0;
#if defined(__APPLE__) || defined(__MINGW32__)
                        ev_io_stop(EV_A_ & server_recv_ctx->io);
                        ev_io_start(EV_A_ & remote->send_ctx->io);
                        ev_timer_start(EV_A_ & remote->send_ctx->watcher);
#else
                        // 已发送
                        remote->send_ctx->connected = 1;
                        // 停止send watcher
                        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
                        // 开启定时器，remote接收，10s超时
                        ev_timer_start(EV_A_ & remote->recv_ctx->watcher);
                        // 监听服务端发送回来的数据
                        ev_io_start(EV_A_ & remote->recv_ctx->io);
                        return;
#endif
                    }
#else
                    // if TCP_FASTOPEN is not defined, fast_open will always be 0
                    FATAL("can't come here");
#endif
                }
            } else { // remote已连接
                // 发送数据到remote
                int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
                // 失败
                if (s == -1) {
                    // 内核缓冲区已满/已空
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // 重置idx
                        // no data, wait for send
                        remote->buf->idx = 0;
                        // 服务端不再接收数据
                        ev_io_stop(EV_A_ & server_recv_ctx->io);
                        // remote开启发送数据
                        ev_io_start(EV_A_ & remote->send_ctx->io);
                        return;
                    } else {
                        // 异常
                        ERROR("server_recv_cb_send");
                        close_and_free_remote(EV_A_ remote);
                        close_and_free_server(EV_A_ server);
                        return;
                    }
                } else if (s < (int)(remote->buf->len)) { // 部分发送
                    remote->buf->len -= s;
                    remote->buf->idx  = s;
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                    return;
                } else { // 全部发送
                    remote->buf->idx = 0;
                    remote->buf->len = 0;
                }
            }

            // all processed
            return;

        } else if (server->stage == STAGE_INIT) {
            // 第一次执行
            // 修改状态
            server->stage = STAGE_STREAM;

            // 创建remote
            remote = create_remote(server->listener, NULL);

            // 失败
            if (remote == NULL) {
                LOGE("invalid remote addr");
                close_and_free_server(EV_A_ server);
                return;
            }

            // 复制到remote的buf
            if (buf->len > 0) {
                memcpy(remote->buf->data, buf->data, buf->len);
                remote->buf->len = buf->len;
            }

            // 双向绑定
            server->remote = remote;
            remote->server = server;
        }
    }
}

// 服务端->客户端 remote_recv_cb里设置调用
static void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;
    // 没数据
    if (server->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        // 写数据
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        // 有错误
        if (s == -1) {
            // 内核缓冲区已满/已空
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_cb_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < (ssize_t)(server->buf->len)) { // 部分发送
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            // 不用再调整libev事件，因为remote_recv_cb 已经做了这件事
            return;
        } else { // 全部发送
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            ev_io_start(EV_A_ & remote->recv_ctx->io);
            return;
        }
    }
}

// 10s超时了
static void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    // 上下文
    remote_ctx_t *remote_ctx
        = cork_container_of(watcher, remote_ctx_t, watcher);

    // remote
    remote_t *remote = remote_ctx->remote;
    // server
    server_t *server = remote->server;

    // 打日志
    if (verbose) {
        LOGI("TCP connection timeout");
    }

    // 关闭连接
    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

// remote -> server
static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    // 上下文
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    // remote
    remote_t *remote              = remote_recv_ctx->remote;
    // server
    server_t *server              = remote->server;

    // 重新设置定时器
    ev_timer_again(EV_A_ & remote->recv_ctx->watcher);

    // 读取数据
    ssize_t r = recv(remote->fd, server->buf->data, BUF_SIZE, 0);

    // 对方已经关闭了连接（EOF）
    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) { // 错误
        // 内核缓冲区已满/已空
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else { // 异常
            ERROR("remote_recv_cb_recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    // 数据量
    server->buf->len = r;

    // 默认为0
    if (!remote->direct) {
#ifdef ANDROID
        // 更新计数器
        rx += server->buf->len;
#endif
        // 解混淆
        if (obfs_para) {
            if (obfs_para->deobfs_response(server->buf, BUF_SIZE, server->obfs)) {
                // 失败
                LOGE("invalid obfuscating");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }

    // 把数据直接发送给客户端
    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    // 失败
    if (s == -1) {
        // 内核缓冲区已满/已空
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            // 不接受远端数据
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            // 开启server_send_cb
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else { // 异常
            ERROR("remote_recv_cb_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < (int)(server->buf->len)) { // 部分发送
        server->buf->len -= s;
        server->buf->idx  = s;
        // 不接受远端数据
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        // 开启server_send_cb
        ev_io_start(EV_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    // 当 remote 接收到了第一个响应并通过了混淆验证，发送给客户端后，就意味着这层“混淆隧道”的握手正式成功，接下来的时间全部都是大块的数据流（Stream）传输。
    if (!remote->recv_ctx->connected) {
        int opt = 0;
        // 关闭 TCP_NODELAY（实际上是重新开启 Nagle 算法，允许合并小包）
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        // 关闭 TCP_NODELAY
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        // 标记
        remote->recv_ctx->connected = 1;
    }
}

// server -> remote
static void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
    // 上下文
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    // remote
    remote_t *remote              = remote_send_ctx->remote;
    // server
    server_t *server              = remote->server;

    // 第一次发送
    if (!remote_send_ctx->connected) {
#ifdef TCP_FASTOPEN_WINSOCK
        if (fast_open) {
            // Check if ConnectEx is done
            if (!remote->connect_ex_done) {
                DWORD numBytes;
                DWORD flags;
                // Non-blocking way to fetch ConnectEx result
                if (WSAGetOverlappedResult(remote->fd, &remote->olap,
                                           &numBytes, FALSE, &flags)) {
                    remote->buf->len -= numBytes;
                    remote->buf->idx  = numBytes;
                    remote->connect_ex_done = 1;
                } else if (WSAGetLastError() == WSA_IO_INCOMPLETE) {
                    // XXX: ConnectEx still not connected, wait for next time
                    return;
                } else {
                    ERROR("WSAGetOverlappedResult");
                    // not connected
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                };
            }

            // Make getpeername work
            if (setsockopt(remote->fd, SOL_SOCKET,
                           SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
                ERROR("setsockopt");
            }
        }
#endif
        // 获取与指定的 Socket（remote->fd）相连的那个“远端”机器的 IP 地址和端口号。
        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r         = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) { // 查询成功，addr 中存着对端的详细地址信息
            // 更新标志位
            remote_send_ctx->connected = 1;
            // 超时
            ev_timer_stop(EV_A_ & remote_send_ctx->watcher);
            ev_timer_start(EV_A_ & remote->recv_ctx->watcher);
            // 启动接收
            ev_io_start(EV_A_ & remote->recv_ctx->io);

            // no need to send any data
            // 没数据
            if (remote->buf->len == 0) {
                // 停止发送remote
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                // 启动接收client
                ev_io_start(EV_A_ & server->recv_ctx->io);
                return;
            }
            //有数据，往下看
        } else {
            // 出错了（比如 Socket 已经关闭，或者地址无效）
            // not connected
            ERROR("getpeername");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    // 异常
    if (remote->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        // 发送数据
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        // 失败
        if (s == -1) {
            // 内核缓冲区已满/已空
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_cb_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < (ssize_t)(remote->buf->len)) { // 部分发送
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            // 为什么没更新IO事件？因为目前正处于 remote_send_cb 回调中，
            // 意味着 ev_io 里的 remote_send_ctx->io 早已是 start 状态（被别人开启过）。
            // 只要它保持开启，libev 发现缓冲区又有空位时，就会再次调用当前函数。
            // 同时 server_recv 肯定在别处被停掉了（否则不会积压数据进这个函数的缓冲区）。
            return;
        } else { // 全部发送
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            ev_io_start(EV_A_ & server->recv_ctx->io);
        }
    }
}

// server -> remote
static remote_t *
new_remote(int fd, int timeout)
{
    // 状态机
    remote_t *remote;
    remote = ss_malloc(sizeof(remote_t));

    memset(remote, 0, sizeof(remote_t));

    // 缓冲区
    remote->buf      = ss_malloc(sizeof(buffer_t));
    // 接收
    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    // 发送
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    // 2k大小
    balloc(remote->buf, BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    // 未连接
    remote->recv_ctx->connected = 0;
    remote->send_ctx->connected = 0;
    // conn
    remote->fd                  = fd;
    // 绑定
    remote->recv_ctx->remote    = remote;
    remote->send_ctx->remote    = remote;

    // 注册事件
    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    // 10s超时，发送/接收
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT, timeout), 0);
    ev_timer_init(&remote->recv_ctx->watcher, remote_timeout_cb,
                  timeout, timeout);

    return remote;
}

static void
free_remote(remote_t *remote)
{
    // 解绑
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    // 释放缓冲区
    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    // 上下文
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void
close_and_free_remote(EV_P_ remote_t *remote)
{
    if (remote != NULL) {
        // 停止定时器
        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
        ev_timer_stop(EV_A_ & remote->recv_ctx->watcher);
        // 停止io
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        // 关闭conn
        close(remote->fd);
        // 释放内存
        free_remote(remote);
    }
}

// 处理app的数据
static server_t *
new_server(int fd)
{
    server_t *server;
    server = ss_malloc(sizeof(server_t));

    memset(server, 0, sizeof(server_t));

    // 读写上下文、缓冲区
    server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(server_ctx_t));
    server->buf      = ss_malloc(sizeof(buffer_t));
    // 初始化
    // 缓冲区设置为2k
    balloc(server->buf, BUF_SIZE);
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    // stage为init
    server->stage               = STAGE_INIT;
    // 未连接
    server->recv_ctx->connected = 0;
    server->send_ctx->connected = 0;
    // conn
    server->fd                  = fd;
    // 双向绑定？
    server->recv_ctx->server    = server;
    server->send_ctx->server    = server;

    // 初始化状态机，记录server连接状态
    if (obfs_para != NULL) {
        server->obfs = (obfs_t *)ss_malloc(sizeof(obfs_t));
        memset(server->obfs, 0, sizeof(obfs_t));
    }

    // 读写回调函数
    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

    cork_dllist_add(&connections, &server->entries);

    return server;
}

static void
free_server(server_t *server)
{
    // 把server从连接池移除
    cork_dllist_remove(&server->entries);

    // 状态机
    if (server->obfs != NULL) {
        // 缓冲区
        bfree(server->obfs->buf);
        // tls帧状态机
        if (server->obfs->extra != NULL)
            ss_free(server->obfs->extra);
        ss_free(server->obfs);
    }
    // 解除绑定
    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    // 释放缓冲区
    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }
    // 上下文
    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void
close_and_free_server(EV_P_ server_t *server)
{
    if (server != NULL) {
        // 停止io
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        // 关闭conn
        close(server->fd);
        // 回收内存
        free_server(server);
    }
}

static remote_t *
create_remote(listen_ctx_t *listener,
              struct sockaddr *addr)
{
    struct sockaddr *remote_addr;

    // 随机索引
    int index = rand() % listener->remote_num;
    // 为空
    if (addr == NULL) {
        // 随机选一个
        remote_addr = listener->remote_addr[index];
    } else {
        // 应该不会进入这里
        remote_addr = addr;
    }

    // 创建socket
    int remotefd = socket(remote_addr->sa_family, SOCK_STREAM, IPPROTO_TCP);

    if (remotefd == -1) {
        ERROR("socket");
        return NULL;
    }

    int opt = 1;
    // 禁用nagle算法
    // 在代理和远端刚开始建立连接的阶段，会有 TLS 的握手包（比如 Client Hello, Server Hello 等）。这些包非常关键且对延迟极其敏感。如果等待 Nagle 算法拼凑小包，会导致握手时间被严重拉长（特别是在高延迟跨国线路上）。
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    // no sig pipe
    // 防止程序因“向已关闭的连接写入数据”而收到 SIGPIPE 信号导致崩溃的保护措施
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // mptcp
    if (listener->mptcp == 1) {
        // 42？
        int err = setsockopt(remotefd, SOL_TCP, MPTCP_ENABLED, &opt, sizeof(opt));
        if (err == -1) {
            ERROR("failed to enable multipath TCP");
        }
    }

    // Setup
    // 非阻塞
    setnonblocking(remotefd);
#ifdef SET_INTERFACE
    // 出口网卡
    if (listener->iface) {
        if (setinterface(remotefd, listener->iface) == -1)
            ERROR("setinterface");
    }
#endif

    // 
    remote_t *remote = new_remote(remotefd, listener->timeout);
    // 如果本身是IPv4/IPv6，直接返回socket结构，否则通过dns解析后返回
    remote->addr_len = get_sockaddr_len(remote_addr);
    memcpy(&(remote->addr), remote_addr, remote->addr_len);

    return remote;
}

static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
        case SIGINT: // 用户在终端按下 Ctrl+C 时产生的信号
        case SIGTERM: // 系统发出的正常终止请求信号（比如通过 kill 命令）
#ifndef __MINGW32__
        case SIGUSR1: // Windows不支持，剔除
#endif
            keep_resolving = 0; // 停止业务逻辑
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

// 接收到app的数据
void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    // accept
    int serverfd           = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }
    // 非阻塞
    setnonblocking(serverfd);
    int opt = 1;
    // 关闭Nagle算法
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    // 防止程序因“向已关闭的连接写入数据”而收到 SIGPIPE 信号导致崩溃的保护措施
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // 创建server
    server_t *server = new_server(serverfd);
    server->listener = listener;

    // 监听client写入
    ev_io_start(EV_A_ & server->recv_ctx->io);
}

int
main(int argc, char **argv)
{
    int i, c;
    int pid_flags    = 0;
    int mptcp        = 0;
    char *user       = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *timeout    = NULL;
    char *pid_path   = NULL;
    char *conf_path  = NULL;
    char *iface      = NULL;
    char *obfs_host  = NULL;
    char *obfs_uri   = NULL;
    char *http_method= NULL;

    // 随机数种子
    srand(time(NULL));

    int remote_num = 0;
    // 最多10个地址
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;

    char *ss_remote_host = getenv("SS_REMOTE_HOST");
    char *ss_remote_port = getenv("SS_REMOTE_PORT");
    char *ss_local_host  = getenv("SS_LOCAL_HOST");
    char *ss_local_port  = getenv("SS_LOCAL_PORT");
    char *ss_plugin_opts = getenv("SS_PLUGIN_OPTIONS");

    // obfs-server的地址
    // 按 "|" 分割字符串，放入remote_addr数组
    if (ss_remote_host != NULL) {
        ss_remote_host = strdup(ss_remote_host);
        char *delim = "|";
        char *p = strtok(ss_remote_host, delim);
        do {
            remote_addr[remote_num].host = p;
            remote_addr[remote_num++].port = NULL;
        } while ((p = strtok(NULL, delim)));
    }

    // obfs-server的端口 
    if (ss_remote_port != NULL) {
        remote_port = ss_remote_port;
    }

    // 自己监听的地址
    if (ss_local_host != NULL) {
        local_addr = ss_local_host;
    }

    // 自己监听的端口
    if (ss_local_port != NULL) {
        local_port = ss_local_port;
    }

    // 其他参数
    if (ss_plugin_opts != NULL) {
        ss_plugin_opts = strdup(ss_plugin_opts);
        options_t opts;
        int opt_num = parse_options(ss_plugin_opts,
                strlen(ss_plugin_opts), &opts);
        // 遍历所有参数
        for (i = 0; i < opt_num; i++) {
            char *key = opts.keys[i];
            char *value = opts.values[i];
            // 空的跳过
            if (key == NULL) continue;
            size_t key_len = strlen(key);
            // 一样是空的
            if (key_len == 0) continue;
            // 短参数
            if (key_len == 1) {
                char c = key[0];
                switch (c) {
                    case 't': // 超时
                        timeout = value;
                        break;
                    case 'c': // json配置文件路径
                        conf_path = value;
                        break;
                    case 'i': // 网卡
                        iface = value;
                        break;
                    case 'a': // 以此用户身份执行
                        user = value;
                        break;
                    case 'v': // 输出详情
                        verbose = 1;
                        break;
#ifdef ANDROID
                    case 'V': // 未知（新）
                        vpn = 1;
                        break;
#endif
                    case '6': // ipv6
                        ipv6first = 1;
                        break;
                    }
            } else {
                // 长参数
                if (strcmp(key, "fast-open") == 0) { // fast-open
                    fast_open = 1;
                } else if (strcmp(key, "obfs") == 0) { // http还是tls混淆
                    if (strcmp(value, obfs_http->name) == 0)
                        obfs_para = obfs_http;
                    else if (strcmp(value, obfs_tls->name) == 0)
                        obfs_para = obfs_tls;
                } else if (strcmp(key, "obfs-host") == 0) { // host
                    obfs_host = value;
                } else if (strcmp(key, "obfs-uri") == 0) { // uri（新）
                    obfs_uri = value;
                } else if (strcmp(key, "http-method") == 0) { // method
                    http_method = value;
#ifdef __linux__
                } else if (strcmp(key, "mptcp") == 0) { // 多路径
                    mptcp = 1;
                    LOGI("enable multipath TCP");
#endif
                }
            }
        }
    }

    int option_index = 0;

    static struct option long_options[] = {
        { "fast-open", no_argument,       0, 0 },
        { "mptcp",     no_argument,       0, 0 },
        { "obfs",      required_argument, 0, 0 },
        { "obfs-host", required_argument, 0, 0 },
        { "obfs-uri",  required_argument, 0, 0 },
        { "http-method",required_argument,0, 0 },
        { "help",      no_argument,       0, 0 },
        { 0,           0,                 0, 0 }
    };

    opterr = 0;

    USE_TTY();

#ifdef ANDROID
    while ((c = getopt_long(argc, argv, "f:s:p:l:t:i:c:b:a:n:hvV6",
                            long_options, &option_index)) != -1) {
#else
    while ((c = getopt_long(argc, argv, "f:s:p:l:t:i:c:b:a:n:hv6",
                            long_options, &option_index)) != -1) {
#endif
        switch (c) {
        case 0:
            if (option_index == 0) { // fast-open
                fast_open = 1;
            } else if (option_index == 1) { // 多路径
                mptcp = 1;
                LOGI("enable multipath TCP");
            } else if (option_index == 2) { // http还是tls
                if (strcmp(optarg, obfs_http->name) == 0)
                    obfs_para = obfs_http;
                else if (strcmp(optarg, obfs_tls->name) == 0)
                    obfs_para = obfs_tls;
            } else if (option_index == 3) { // host
                obfs_host = optarg;
            } else if (option_index == 4) { // uri
                obfs_uri = optarg;
            } else if (option_index == 5) { // method
                http_method = optarg;
            } else if (option_index == 6) { // 打印详情
                usage();
                exit(EXIT_SUCCESS);
            }
            break;
        case 's': // remote_addr
            if (remote_num < MAX_REMOTE_NUM) {
                remote_addr[remote_num].host   = optarg;
                remote_addr[remote_num++].port = NULL;
            }
            break;
        case 'p': // remote_port
            remote_port = optarg;
            break;
        case 'l': // local_port
            local_port = optarg;
            break;
        case 'f': // pid路径
            pid_flags = 1;
            pid_path  = optarg;
            break;
        case 't': // 超时
            timeout = optarg;
            break;
        case 'c': // json配置路径
            conf_path = optarg;
            break;
        case 'i': // 网卡
            iface = optarg;
            break;
        case 'b': // local_addr
            local_addr = optarg;
            break;
        case 'a': // 用户
            user = optarg;
            break;
#ifdef HAVE_SETRLIMIT
        case 'n': // 文件数量
            nofile = atoi(optarg);
            break;
#endif
        case 'v': // 打印日志
            verbose = 1;
            break;
        case 'h': // 打印详情
            usage();
            exit(EXIT_SUCCESS);
        case '6': // ipv6优先
            ipv6first = 1;
            break;
#ifdef ANDROID
        case 'V': // 未知
            vpn = 1;
            break;
#endif
        case '?': // 
            // The option character is not recognized.
            LOGE("Unrecognized option: %s", optarg);
            opterr = 1;
            break;
        }
    }

    // 解析错误
    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    // 解析json文件
    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        // 如果remote_addr为空
        if (remote_num == 0) {
            // 总数量
            remote_num = conf->remote_num;
            // 加入数组
            for (i = 0; i < remote_num; i++)
                remote_addr[i] = conf->remote_addr[i];
        }
        // 如果remote_port为空
        if (remote_port == NULL) {
            remote_port = conf->remote_port;
        }
        // 如果local_addr为空
        if (local_addr == NULL) {
            local_addr = conf->local_addr;
        }
        // 如果local_port为空
        if (local_port == NULL) {
            local_port = conf->local_port;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
        if (obfs_para == NULL && conf->obfs != NULL) {
            if (strcmp(conf->obfs, obfs_http->name) == 0)
                obfs_para = obfs_http;
            else if (strcmp(conf->obfs, obfs_tls->name) == 0)
                obfs_para = obfs_tls;
        }
        if (obfs_host == NULL) {
            obfs_host = conf->obfs_host;
        }
        if (obfs_uri == NULL) {
            obfs_uri = conf->obfs_uri;
        }
        if (http_method == NULL) {
            http_method = conf->http_method;
        }
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
    }

    // 核心参数没有，退出
    if (remote_num == 0 || remote_port == NULL ||
#ifndef HAVE_LAUNCHD
        local_port == NULL ||
#endif
        obfs_para == NULL) {
        usage();
        exit(EXIT_FAILURE);
    }

    // 默认600s超时
    if (timeout == NULL) {
        timeout = "600";
    }

#ifdef HAVE_SETRLIMIT
    /*
     * no need to check the return value here since we will show
     * the user an error message if setrlimit(2) fails
     */
    // 最大文件打开数量
    if (nofile > 1024) {
        if (verbose) {
            LOGI("setting NOFILE to %d", nofile);
        }
        set_nofile(nofile);
    }
#endif

    // 默认127.0.0.1
    if (local_addr == NULL) {
        local_addr = "127.0.0.1";
    }

    // pid文件路径
    if (pid_flags) {
        USE_SYSLOG(argv[0]);
        daemonize(pid_path);
    }

    // 支持就打印日志，不支持就关闭
    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    // 打印日志
    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

    // 覆盖参数
    if (obfs_para) {
        if (obfs_host != NULL)
            obfs_para->host = obfs_host;
        else
            obfs_para->host = "cloudfront.net";
        if (obfs_uri == NULL) obfs_para->uri = "/";
        else obfs_para->uri = obfs_uri;
        if (http_method == NULL) obfs_para->method = "GET";
        else obfs_para->method = http_method;
        obfs_para->port = atoi(remote_port);
        LOGI("obfuscating enabled");
        LOGI("obfuscation http method: %s", obfs_para->method);
        if (obfs_host)
            LOGI("obfuscating hostname: %s", obfs_host);
        if (obfs_uri) LOGI("obfuscation uri path: %s", obfs_uri);
    }

    // 信号处理
#ifdef __MINGW32__
    winsock_init();
#else
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN); // 忽略掉这个信号，重要
    signal(SIGABRT, SIG_IGN); // 忽略掉这个信号，重要
#endif

    // Setup proxy context
    listen_ctx_t listen_ctx;
    listen_ctx.remote_num  = remote_num;
    listen_ctx.remote_addr = ss_malloc(sizeof(struct sockaddr *) * remote_num);
    memset(listen_ctx.remote_addr, 0, sizeof(struct sockaddr *) * remote_num);
    // 所有的remote_addr
    for (i = 0; i < remote_num; i++) {
        char *host = remote_addr[i].host;
        char *port = remote_addr[i].port == NULL ? remote_port :
                     remote_addr[i].port;
        struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
        memset(storage, 0, sizeof(struct sockaddr_storage));
        // 如果本身是IPv4/IPv6，直接返回socket结构，否则通过dns解析后返回
        if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        listen_ctx.remote_addr[i] = (struct sockaddr *)storage;
    }
    listen_ctx.timeout = atoi(timeout);
    listen_ctx.iface   = iface;
    listen_ctx.mptcp   = mptcp;

    // 设置信号处理器
    // Setup signal handler
    struct ev_signal sigint_watcher;
    struct ev_signal sigterm_watcher;
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

#ifndef __MINGW32__
    // 非windows

    ev_timer parent_watcher;
    // 5s
    ev_timer_init(&parent_watcher, parent_watcher_cb, 0, UPDATE_INTERVAL);
    ev_timer_start(EV_DEFAULT, &parent_watcher);
#endif

    struct ev_loop *loop = EV_DEFAULT;

    // 创建local socket
    // Setup socket
    int listenfd;
#ifdef HAVE_LAUNCHD
    listenfd = launch_or_create(local_addr, local_port);
#else
    listenfd = create_and_bind(local_addr, local_port);
#endif
    // bind失败
    if (listenfd == -1) {
        FATAL("bind() error");
    }
    // 4k个连接
    if (listen(listenfd, SOMAXCONN) == -1) {
        FATAL("listen() error");
    }
    // 非阻塞
    setnonblocking(listenfd);

    // 记录fd
    listen_ctx.fd = listenfd;

    // 启用libev监听
    ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
    ev_io_start(loop, &listen_ctx.io);

#ifdef HAVE_LAUNCHD
    if (local_port == NULL)
        LOGI("listening through launchd");
    else
#endif
    // ipv6地址
    if (strcmp(local_addr, ":") > 0)
        LOGI("listening at [%s]:%s", local_addr, local_port);
    else
        LOGI("listening at %s:%s", local_addr, local_port);

    // 以该用户身份运行
    // setuid
    if (user != NULL && !run_as(user)) {
        FATAL("failed to switch user");
    }

#ifndef __MINGW32__
    if (geteuid() == 0) {
        LOGI("running from root user");
    }
#endif

    // Init connections
    // 初始化连接池
    cork_dllist_init(&connections);

    // Enter the loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    ev_io_stop(loop, &listen_ctx.io);
    // 清理连接池
    free_connections(loop);

    for (i = 0; i < remote_num; i++)
        ss_free(listen_ctx.remote_addr[i]);
    ss_free(listen_ctx.remote_addr);

#ifdef __MINGW32__
    winsock_cleanup();
#else
    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
#endif

    return 0;
}
