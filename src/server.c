/*
 * server.c - Provide simple-obfs service
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
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>

#ifndef __MINGW32__
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/un.h>
#endif

#include <libcork/core.h>

#ifdef __MINGW32__
#include "win32.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "netutils.h"
#include "utils.h"
#include "obfs_http.h"
#include "obfs_tls.h"
#include "options.h"
#include "server.h"

// 这两个都是代表同一个意思，缓冲区满了/空了
#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

// buf大小为16k
#ifndef BUF_SIZE
#define BUF_SIZE 16384
#endif

// 最大连接数1k
#ifndef SSMAXCONN
#define SSMAXCONN 1024
#endif

static void signal_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);
static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents);

static void perform_handshake(EV_P_ server_t *server);
static remote_t *new_remote(int fd);
static server_t *new_server(int fd, listen_ctx_t *listener);
static remote_t *connect_to_remote(EV_P_ struct addrinfo *res,
                                   server_t *server);

static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

int verbose = 0;

static int ipv6first = 0;
static int reverse_proxy = 0;
static int fast_open = 0;

static obfs_para_t *obfs_para = NULL;

#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif
static int remote_conn = 0; // 连接数
static int server_conn = 0; // 连接数

static char *bind_address    = NULL;
static char *server_port     = NULL;
uint64_t tx                  = 0; // 计数器
uint64_t rx                  = 0; // 计数器

static struct cork_dllist connections;

// 当发现当前进程的父进程发生变更时，主动退出程序
#ifndef __MINGW32__
static void
parent_watcher_cb(EV_P_ ev_timer *watcher, int revents)
{
    static int ppid = -1;

    int cur_ppid = getppid();
    if (ppid != -1) {
        if (ppid != cur_ppid) {
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }

    ppid = cur_ppid;
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

int
setfastopen(int fd)
{
    int s = 0;
// 如果支持fastopen
#ifdef TCP_FASTOPEN
    if (fast_open) {
#if defined(__APPLE__) || defined(__MINGW32__)
        int opt = 1; // backlog
#else
        int opt = 5; // backlog
#endif
        s = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &opt, sizeof(opt));

        // 失败
        if (s == -1) {
            // 协议不支持 或 协议选项不可用
            if (errno == EPROTONOSUPPORT || errno == ENOPROTOOPT) {
                LOGE("fast open is not supported on this platform");
                fast_open = 0;
            } else {
                ERROR("setsockopt");
            }
        }
    }
#endif
    return s;
}

// 非windows，设置为非阻塞
#ifndef __MINGW32__
int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#endif

int
create_and_bind(const char *host, const char *port, int mptcp)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp, *ipv4v6bindall;
    int s, listen_sock;

    // ipv4+ipv6 + tcp
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;               /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM;             /* We want a TCP socket */
    hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_TCP;

    // 最多尝试8次
    for (int i = 1; i < 8; i++) {
        // 地址转换
        s = getaddrinfo(host, port, &hints, &result);
        if (s == 0) {
            break;
        } else {
            // 间隔一段时间
            sleep(pow(2, i));
            LOGE("failed to resolve server name, wait %.0f seconds", pow(2, i));
        }
    }

    // 异常
    if (s != 0) {
        LOGE("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    // 结果链表
    rp = result;

    /*
     * On Linux, with net.ipv6.bindv6only = 0 (the default), getaddrinfo(NULL) with
     * AI_PASSIVE returns 0.0.0.0 and :: (in this order). AI_PASSIVE was meant to
     * return a list of addresses to listen on, but it is impossible to listen on
     * 0.0.0.0 and :: at the same time, if :: implies dualstack mode.
     */
    // 如果host为NULL，查找第一个IPv6地址
    if (!host) { // 如果用户要监听本地所有网卡
        // 指向链表开头
        ipv4v6bindall = result; // 从链表头开始找

        /* Loop over all address infos found until a IPV6 address is found. */
        while (ipv4v6bindall) {
            if (ipv4v6bindall->ai_family == AF_INET6) { // 强行跳过前面的 IPv4
                // 只要一看到 IPv6 (::)，就立刻截获它！
                rp = ipv4v6bindall; /* Take first IPV6 address available */
                break;
            }
            ipv4v6bindall = ipv4v6bindall->ai_next; /* Get next address info, if any */
        }
    }

    for (/*rp = result*/; rp != NULL; rp = rp->ai_next) {
        // 建立socket
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        // 失败，换一个地址
        if (listen_sock == -1) {
            continue;
        }

        // ipv6
        if (rp->ai_family == AF_INET6) {
            // 如果host为null，那么使用使用双栈，否则指定为ipv6
            int ipv6only = host ? 1 : 0;
            setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
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

        // mptcp
        if (mptcp == 1) {
            int err = setsockopt(listen_sock, SOL_TCP, MPTCP_ENABLED, &opt, sizeof(opt));
            if (err == -1) {
                ERROR("failed to enable multipath TCP");
            }
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

static remote_t *
connect_to_remote(EV_P_ struct addrinfo *res,
                  server_t *server)
{
    int sockfd;
#ifdef SET_INTERFACE
    // 出口网卡
    const char *iface = server->listen_ctx->iface;
#endif

    // initialize remote socks
    // 创建socket
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        ERROR("socket");
        close(sockfd);
        return NULL;
    }

    int opt = 1;
    // 关闭Nagle算法
    setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
     // 防止程序因“向已关闭的连接写入数据”而收到 SIGPIPE 信号导致崩溃的保护措施
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    // 地址复用 程序重启时，可以立即使用处于 TIME_WAIT 状态的端口
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // setup remote socks

    // 非阻塞
    if (setnonblocking(sockfd) == -1)
        ERROR("setnonblocking");

    // 绑定出口地址？
    if (bind_address != NULL)
        if (bind_to_address(sockfd, bind_address) == -1) {
            ERROR("bind_to_address");
            close(sockfd);
            return NULL;
        }

#ifdef SET_INTERFACE
    // 绑定出口网卡
    if (iface) {
        if (setinterface(sockfd, iface) == -1) {
            ERROR("setinterface");
            close(sockfd);
            return NULL;
        }
    }
#endif

    // 
    remote_t *remote = new_remote(sockfd);

#ifdef TCP_FASTOPEN
    if (fast_open) {
#ifdef __APPLE__
        // 历史问题，需要填写长度
        ((struct sockaddr_in *)(res->ai_addr))->sin_len = sizeof(struct sockaddr_in);
        // 要连接的远程地址
        sa_endpoints_t endpoints;
        memset((char *)&endpoints, 0, sizeof(endpoints));
        endpoints.sae_dstaddr    = res->ai_addr;
        endpoints.sae_dstaddrlen = res->ai_addrlen;

        // buffer缓冲区
        struct iovec iov;
        iov.iov_base = server->buf->data + server->buf->idx;
        iov.iov_len  = server->buf->len;
        size_t len;
        // 调用connect，sync的同时把数据发出去
        int s = connectx(sockfd, &endpoints, SAE_ASSOCID_ANY, CONNECT_DATA_IDEMPOTENT,
                         &iov, 1, &len, NULL);
        if (s == 0) {
            s = len; // 实际数据量
        }
#elif defined(TCP_FASTOPEN_WINSOCK)
        DWORD s = -1;
        DWORD err = 0;
        do {
            // 开启TFO
            int optval = 1;
            // Set fast open option
            if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN,
                           &optval, sizeof(optval)) != 0) {
                ERROR("setsockopt");
                break;
            }
            // 加载微软特有的动态指针
            // Load ConnectEx function
            LPFN_CONNECTEX ConnectEx = winsock_getconnectex();
            if (ConnectEx == NULL) {
                LOGE("Cannot load ConnectEx() function");
                err = WSAENOPROTOOPT;
                break;
            }
            // 如果你敢调 ConnectEx，你就必须在调用前手动调用 bind 绑定本地 IP 和端口
            // ConnectEx requires a bound socket
            if (winsock_dummybind(sockfd, res->ai_addr) != 0) {
                ERROR("bind");
                break;
            }
            // Call ConnectEx to send data
            memset(&remote->olap, 0, sizeof(remote->olap));
            remote->connect_ex_done = 0;
            // 异步把数据和握手一起扔出去
            if (ConnectEx(sockfd, res->ai_addr, res->ai_addrlen,
                          server->buf->data, server->buf->len,
                          &s, &remote->olap)) {
                remote->connect_ex_done = 1;
                break;
            };
            // 正在处理中（ERROR_IO_PENDING）
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
        // linux
        // 发送到远端
        ssize_t s = sendto(sockfd, server->buf->data + server->buf->idx,
                           server->buf->len, MSG_FASTOPEN, res->ai_addr,
                           res->ai_addrlen);
#endif
        // 错误
        if (s == -1) {
            // 连接正在进行中 或 内核缓冲区已满/已空
            if (errno == CONNECT_IN_PROGRESS || errno == EAGAIN
                || errno == EWOULDBLOCK) {
                // The remote server doesn't support tfo or it's the first connection to the server.
                // It will automatically fall back to conventional TCP.
            } else if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                       errno == ENOPROTOOPT) {
                // 系统不支持：协议不支持 或 协议选项不可用 或 操作不支持
                // Disable fast open as it's not supported
                fast_open = 0;
                LOGE("fast open is not supported on this platform");
            } else {
                ERROR("sendto");
            }
        } else if (s <= server->buf->len) { // 部分发送
            server->buf->idx += s;
            server->buf->len -= s;
        } else { // 全部发送
            server->buf->idx = 0;
            server->buf->len = 0;
        }
    }
#endif

    // 不支持fast_open
    if (!fast_open) {
        // 连接远程
        int r = connect(sockfd, res->ai_addr, res->ai_addrlen);

        // 异常
        if (r == -1 && errno != CONNECT_IN_PROGRESS) {
            ERROR("connect");
            close_and_free_remote(EV_A_ remote);
            return NULL;
        }
    }

    return remote;
}

static void
perform_handshake(EV_P_ server_t *server)
{
    // Copy back the saved first packet
    // 从header_buf移动到buf => 客户端发过来的数据
    server->buf->len = server->header_buf->len;
    server->buf->idx = server->header_buf->idx;
    memcpy(server->buf->data, server->header_buf->data, server->header_buf->len);
    // 清空
    server->header_buf->idx = server->header_buf->len = 0;

    struct addrinfo info;
    struct sockaddr_storage storage;
    memset(&info, 0, sizeof(struct addrinfo));
    memset(&storage, 0, sizeof(struct sockaddr_storage));

    // Domain name
    // 目标地址
    size_t name_len = strlen(server->listen_ctx->dst_addr->host);
    char *host = server->listen_ctx->dst_addr->host;
    uint16_t port = htons((uint16_t)atoi(server->listen_ctx->dst_addr->port));

    // 如果obfs被禁用，使用故障转移地址
    if (obfs_para == NULL || !obfs_para->is_enable(server->obfs)) {
        // 故障转移的地址不为空
        // failover
        if (server->listen_ctx->failover->host != NULL
                && server->listen_ctx->failover->port != NULL) {
            name_len = strlen(server->listen_ctx->failover->host);
            host = server->listen_ctx->failover->host;
            port = htons((uint16_t)atoi(server->listen_ctx->failover->port));
        }
    }

    struct cork_ip ip;
    if (cork_ip_init(&ip, host) != -1) { // 单纯的IP地址
        if (ip.version == 4) { // ipv4
            struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
            inet_pton(AF_INET, host, &(addr->sin_addr));
            addr->sin_port   = port;
            addr->sin_family = AF_INET;
        } else if (ip.version == 6) { // ipv6
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
            inet_pton(AF_INET6, host, &(addr->sin6_addr));
            addr->sin6_port   = port;
            addr->sin6_family = AF_INET6;
        }
    } else { // 域名解析
        // 检查
        // 防止恶意输入导致 getaddrinfo 崩溃（拒绝服务攻击）
        // 提前拦截，提升性能，防止“被动等待”
        if (!validate_hostname(host, name_len)) {
            LOGE("invalid host name");
            close_and_free_server(EV_A_ server);
            return;
        }
        char tmp_port[16];
        snprintf(tmp_port, 16, "%d", ntohs(port));
        // 如果本身是IPv4/IPv6，直接返回socket结构，否则通过dns解析后返回
        if (get_sockaddr(host, tmp_port, &storage, 0, ipv6first) == -1) {
            LOGE("failed to resolve the provided hostname");
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    info.ai_socktype = SOCK_STREAM;
    info.ai_protocol = IPPROTO_TCP;

    if (storage.ss_family == AF_INET) { // ipv4
        info.ai_family   = AF_INET;
        info.ai_addrlen  = sizeof(struct sockaddr_in);
        info.ai_addr     = (struct sockaddr *)&storage;
    } else if (storage.ss_family == AF_INET6) { // ipv6
        info.ai_family   = AF_INET6;
        info.ai_addrlen  = sizeof(struct sockaddr_in6);
        info.ai_addr     = (struct sockaddr *)&storage;
    } else { // 异常
        LOGE("failed to resolve the provided hostname");
        close_and_free_server(EV_A_ server);
        return;
    }

    if (verbose) {
        LOGI("connect to %s:%d", host, ntohs(port));
    }

    // 连接远程
    remote_t *remote = connect_to_remote(EV_A_ & info, server);

    // 失败
    if (remote == NULL) {
        LOGE("connect error");
        close_and_free_server(EV_A_ server);
        return;
    } else { // 成功
        // 双向绑定
        server->remote = remote;
        remote->server = server;

        // XXX: should handle buffer carefully
        // server的buffer有数据
        if (server->buf->len > 0) {
            // 把server数据复制到remote的buffer
            memcpy(remote->buf->data, server->buf->data, server->buf->len);
            remote->buf->len = server->buf->len;
            remote->buf->idx = 0;
            server->buf->len = 0;
            server->buf->idx = 0;
        }

        // waiting on remote connected event
        // 监听远程发送事件
        ev_io_start(EV_A_ & remote->send_ctx->io);
    }

    return;
}

// 客户端->服务端
static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = NULL;

    // 已有数据
    int len       = server->buf->len;
    // 缓冲区
    buffer_t *buf = server->buf;

    // 已解析域名或已经在传输了
    if (server->stage > STAGE_PARSE) {
        remote = server->remote;
        buf    = remote->buf; // 把数据读到remote的buffer
        len    = 0;

        // 再次注册接收超时，看门狗定时器，只要一段时间没数据就断开连接
        ev_timer_again(EV_A_ & server->recv_ctx->watcher);
    }

    // 超过16k
    if (len > BUF_SIZE) { // 异常
        ERROR("out of recv buffer");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    // 从客户端读取数据，不超过16k
    ssize_t r = recv(server->fd, buf->data + len, BUF_SIZE - len, 0);

    // 对方关闭了连接
    if (r == 0) {
        // connection closed
        if (verbose) {
            LOGI("server_recv close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) { // 失败
        // 内核缓冲区已满/已空
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else { // 真异常
            ERROR("server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    // 其他阶段，如初始化、握手、解析、域名解析、数据传输阶段

    // 计数器
    tx += r;

    // handle incomplete header part 1
    // 初始阶段
    if (server->stage == STAGE_INIT) {
        buf->len += r; // 累加

        // obfs解混淆 且 enable中 => 尝试解混淆，如果失败，可能是gfw的恶意攻击
        if (obfs_para && obfs_para->is_enable(server->obfs)) {
            // 检查header
            int ret = obfs_para->check_obfs(buf);
            if (ret == OBFS_NEED_MORE) {// 数据不足
                return;
            } else if (ret == OBFS_OK) { // 检查正常
                // obfs is enabled
                // 解混淆
                ret = obfs_para->deobfs_request(buf, BUF_SIZE, server->obfs);
                if (ret == OBFS_NEED_MORE) // 数据不足
                    return;
                else if (ret == OBFS_ERROR) // 异常
                    obfs_para->disable(server->obfs); // 禁用obfs
            } else { // 异常
                obfs_para->disable(server->obfs); // 禁用obfs
            }
        }

        // 进入handshake阶段
        server->stage = STAGE_HANDSHAKE;
        // 停止接收客户端数据
        ev_io_stop(EV_A_ & server->recv_ctx->io);

        // Copy the first packet to the currently unused header_buf.
        // 解析出来的数据 或 没解析成功的数据 复制到header_buf
        server->header_buf->len = server->buf->len - server->buf->idx;
        server->header_buf->idx = 0;
        memcpy(server->header_buf->data, server->buf->data + server->buf->idx, server->header_buf->len);

        // 如果是 反向代理模式 以及 http方式的混淆 => 假装自己是nginx
        if (reverse_proxy && obfs_para->send_empty_response_upon_connection) {
            // Clear the buffer to make an empty packet.
            server->buf->len = 0;

            // http混淆，websocket升级
            if (obfs_para) {
                obfs_para->obfs_response(server->buf, BUF_SIZE, server->obfs);
            }

            // 发送给客户端
            // 直通快车道（Fast Path），不会触发server_send_cb
            int s = send(server->fd, server->buf->data, server->buf->len, 0);

            // 失败
            if (s == -1) {
                // 内核缓冲区已满/已空
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // no data, wait for send
                    server->buf->idx = 0;
                    ev_io_start(EV_A_ & server->send_ctx->io);
                    return;
                } else { // 异常
                    ERROR("send_inital_response");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            } else if (s < server->buf->len) { // 部分发送
                server->buf->len -= s;
                server->buf->idx  = s;
                ev_io_start(EV_A_ & server->send_ctx->io);
                return;
            } else { // 全部发送
                server->buf->len = 0;
                server->buf->idx = 0;
            }
        }

        // 不管是合法还是不合法，继续执行握手 => 发到shadowsocks还是failover地址
        perform_handshake(EV_A_ server);
        return;
    } else { // 其他阶段，如握手、解析、域名解析、数据传输阶段
        buf->len = r; // 总长度设置为r
        if (obfs_para) { // obfs解混淆
            // 解析请求数据，16kb
            int ret = obfs_para->deobfs_request(buf, BUF_SIZE, server->obfs);
            // 解析失败，可能是数据不足或异常，出于健壮性跟混淆的目的，不退出，只记录错误
            if (ret) LOGE("invalid obfuscating");
        }
    }

    // 其他阶段，如握手、解析、域名解析、数据传输阶段
    // 解析成功或失败

    // 传输数据阶段
    // handshake and transmit data
    if (server->stage == STAGE_STREAM) {

        // 发送到远程
        int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
        // 失败
        if (s == -1) {
            // 内核缓冲区已满/已空
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data, wait for send
                remote->buf->idx = 0;
                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
            } else { // 异常
                ERROR("server_recv_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
        } else if (s < remote->buf->len) { // 部分发送
            remote->buf->len -= s;
            remote->buf->idx  = s;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
        return;

    }
    // 不应该走到这里
    // should not reach here
    FATAL("server context error");
}

// 服务端->客户端
static void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;

    // remote都没有了
    if (remote == NULL) {
        LOGE("invalid server");
        close_and_free_server(EV_A_ server);
        return;
    }

    // 没数据
    if (server->buf->len == 0) {
        // close and free
        if (verbose) {
            LOGI("server_send close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else { // 有数据
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        // 失败
        if (s == -1) {
            // 异常
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < server->buf->len) { // 部分发送
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

            // If handshaking
            if (server->stage == STAGE_HANDSHAKE) {
                perform_handshake(EV_A_ server); // 握手
                return;
            } else { // If streaming
                if (remote != NULL) { // 监听远端发回的数据
                    ev_io_start(EV_A_ & remote->recv_ctx->io);
                    return;
                } else { // remote为null，异常，他妈的无语了，最开始已经做了guard，这里又写，真的是屎山了
                    LOGE("invalid remote");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }
        }
    }
}

// 长时间收不到客户端的数据则关闭连接
static void
server_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    server_ctx_t *server_ctx
        = cork_container_of(watcher, server_ctx_t, watcher);
    server_t *server = server_ctx->server;
    remote_t *remote = server->remote;

    if (verbose) {
        LOGI("TCP connection timeout");
    }

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

// remote -> server
static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;

    // 异常
    if (server == NULL) {
        LOGE("invalid server");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    // 再次注册接收超时
    ev_timer_again(EV_A_ & server->recv_ctx->watcher);

    // 接收数据
    ssize_t r = recv(remote->fd, server->buf->data, BUF_SIZE, 0);

    // 对端已关闭
    if (r == 0) {
        // connection closed
        if (verbose) {
            LOGI("remote_recv close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) { // 异常
        // 内核缓冲区已满/已空
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else { // 真异常
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    // 计数器
    rx += r;

    // 更新buffer
    server->buf->len = r;

    // obfs
    if (obfs_para) {
        // 加混淆
        obfs_para->obfs_response(server->buf, BUF_SIZE, server->obfs);
    }

    // 发送给客户端
    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    // 失败
    if (s == -1) {
        // 内核缓冲区已满/已空
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io); // 不读remote
            ev_io_start(EV_A_ & server->send_ctx->io); // 开启发送
        } else { // 真异常
            ERROR("remote_recv_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < server->buf->len) { // 部分发送
        server->buf->len -= s;
        server->buf->idx  = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io); // 不读remote
        ev_io_start(EV_A_ & server->send_ctx->io); // 开启发送
    }

    // 全部发送
    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected) { // 第一次收到remote的数据
        // 链路已打通，开启nagle算法
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        remote->recv_ctx->connected = 1;
    }
}

// server -> remote
static void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;

    // server为null，异常
    if (server == NULL) {
        LOGE("invalid server");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    // 第一次发送
    if (!remote_send_ctx->connected) {
#ifdef TCP_FASTOPEN_WINSOCK
        if (fast_open) {
            // Check if ConnectEx is done
            if (!remote->connect_ex_done) {
                DWORD numBytes; // 实际塞进 SYN 包并发出去的字节数
                DWORD flags;
                // 因为 ConnectEx 是异步的，代码走到这里时，需要确认连接到底建好没有
                // “非阻塞检查”。如果还没发完，别让我在这死等，立刻告诉我
                // Non-blocking way to fetch ConnectEx result
                if (WSAGetOverlappedResult(remote->fd, &remote->olap,
                                           &numBytes, FALSE, &flags)) {
                    // 挪动指针
                    remote->buf->len -= numBytes;
                    remote->buf->idx  = numBytes;
                    remote->connect_ex_done = 1;
                } else if (WSAGetLastError() == WSA_IO_INCOMPLETE) {
                    // 数据还没发完？继续等
                    // XXX: ConnectEx still not connected, wait for next time
                    return;
                } else {
                    // 彻底崩了：双杀连接
                    ERROR("WSAGetOverlappedResult");
                    // not connected
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                };
            }

            // 更新连接上下文
            // Make getpeername work
            if (setsockopt(remote->fd, SOL_SOCKET,
                           SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
                ERROR("setsockopt");
            }
        }
#endif
        // 获取与指定的 Socket（remote->fd）相连的那个“远端”机器的 IP 地址和端口号。
        struct sockaddr_storage addr;
        socklen_t len = sizeof(struct sockaddr_storage);
        memset(&addr, 0, len);
        int r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) { // 查询成功，addr 中存着对端的详细地址信息
            if (verbose) {
                LOGI("remote connected");
            }
            // 更新标志位
            remote_send_ctx->connected = 1;

            // 没数据
            if (remote->buf->len == 0) {
                // 从handshake进入stream状态
                server->stage = STAGE_STREAM;
                // 停止发送remote
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                // 开启接收client
                ev_io_start(EV_A_ & server->recv_ctx->io);
                // 开启接收remote
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            }
            // 有数据，往下看
        } else { 
            // 出错了（比如 Socket 已经关闭，或者地址无效）
            ERROR("getpeername");
            // not connected
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    // 异常
    if (remote->buf->len == 0) {
        // close and free
        if (verbose) {
            LOGI("remote_send close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        // 发送数据
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1) { // 失败
            // 异常
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < remote->buf->len) { // 部分发送
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else { // 全部发送
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            // 停止发送remote
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            if (server != NULL) {
                // 开启接收客户端数据
                ev_io_start(EV_A_ & server->recv_ctx->io);
                // 转到stream阶段
                if (server->stage != STAGE_STREAM) {
                    // 从handshake进入stream状态
                    server->stage = STAGE_STREAM;
                    // 开启接收remote
                    ev_io_start(EV_A_ & remote->recv_ctx->io);
                }
            } else { // 又是屎山
                LOGE("invalid server");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        }
    }
}

// server -> remote
static remote_t *
new_remote(int fd)
{
    // 记录连接数
    if (verbose) {
        remote_conn++;
    }

    remote_t *remote = ss_malloc(sizeof(remote_t));
    memset(remote, 0, sizeof(remote_t));

    // 缓冲区
    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    // 接收
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    // 发送
    remote->buf      = ss_malloc(sizeof(buffer_t));
    // 16k大小
    balloc(remote->buf, BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    // conn
    remote->fd                  = fd;
    // 绑定
    remote->recv_ctx->remote    = remote;
    remote->recv_ctx->connected = 0; // 未连接
    remote->send_ctx->remote    = remote;
    remote->send_ctx->connected = 0; // 未连接
    remote->server              = NULL;

    // 读写事件注册
    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);

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
        // 停止io
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        // 关闭conn
        close(remote->fd);
        // 释放内存
        free_remote(remote);
        // 计数器
        if (verbose) {
            remote_conn--;
            LOGI("current remote connection: %d", remote_conn);
        }
    }
}

static server_t *
new_server(int fd, listen_ctx_t *listener)
{
    // 计数器
    if (verbose) {
        server_conn++;
    }

    server_t *server;
    server = ss_malloc(sizeof(server_t));

    memset(server, 0, sizeof(server_t));

    // 上下文
    server->recv_ctx   = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx   = ss_malloc(sizeof(server_ctx_t));
    // 缓冲区 16k
    server->buf        = ss_malloc(sizeof(buffer_t));
    // 缓冲区 16k
    server->header_buf = ss_malloc(sizeof(buffer_t));
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    balloc(server->buf, BUF_SIZE);
    balloc(server->header_buf, BUF_SIZE);
    // conn
    server->fd                  = fd;
    // 双向绑定
    server->recv_ctx->server    = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server    = server;
    server->send_ctx->connected = 0;
    // 初始状态
    server->stage               = STAGE_INIT;
    server->listen_ctx          = listener;
    server->remote              = NULL;

    // 混淆，全局唯一
    if (obfs_para != NULL) {
        server->obfs = (obfs_t *)ss_malloc(sizeof(obfs_t));
        memset(server->obfs, 0, sizeof(obfs_t));
    }

    // 超时 = min(60, timeout + rand) => rand = [0-59]
    int request_timeout = min(MAX_REQUEST_TIMEOUT, listener->timeout)
                          + rand() % MAX_REQUEST_TIMEOUT;

    // 注册io事件
    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
    // 服务器接收超时设置 => 关闭连接
    ev_timer_init(&server->recv_ctx->watcher, server_timeout_cb,
                  request_timeout, listener->timeout);

    cork_dllist_add(&connections, &server->entries);

    return server;
}

static void
free_server(server_t *server)
{
    cork_dllist_remove(&server->entries);

    // 释放obfs相关内衬
    if (server->obfs != NULL) {
        bfree(server->obfs->buf);
        // tls相关
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
    // header_buf缓冲区
    if (server->header_buf != NULL) {
        bfree(server->header_buf);
        ss_free(server->header_buf);
    }

    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void
close_and_free_server(EV_P_ server_t *server)
{
    if (server != NULL) {
        // 停止接收/发送客户端数据
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        // 停止接收定时器
        ev_timer_stop(EV_A_ & server->recv_ctx->watcher);
        // 关闭conn
        close(server->fd);
        // 回收内存
        free_server(server);
        if (verbose) {
            server_conn--;
            LOGI("current server connection: %d", server_conn);
        }
    }
}

static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
        case SIGINT: // 用户在终端按下 Ctrl+C 时产生的信号
        case SIGTERM: // 系统发出的正常终止请求信号（比如通过 kill 命令）
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

// 接收到app的数据
static void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    // accept
    int serverfd           = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }

    int opt = 1;
    // 关闭Nagle算法
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    // 防止程序因“向已关闭的连接写入数据”而收到 SIGPIPE 信号导致崩溃的保护措施
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    // 非阻塞
    setnonblocking(serverfd);

    if (verbose) {
        LOGI("accept a connection");
    }

    server_t *server = new_server(serverfd, listener);
    // 开启接收客户端写入
    ev_io_start(EV_A_ & server->recv_ctx->io);
    // 超时设置
    ev_timer_start(EV_A_ & server->recv_ctx->watcher);
}

int
main(int argc, char **argv)
{
    int i, c;
    int pid_flags   = 0;
    int mptcp       = 0;
    char *user      = NULL;
    char *timeout   = NULL;
    char *pid_path  = NULL;
    char *conf_path = NULL;
    char *iface     = NULL;

    int server_num = 0;
    // 最多10个地址
    const char *server_host[MAX_REMOTE_NUM];

    // 这东西压根就没用到，死代码
    char *nameservers = NULL;

    // 目标
    ss_addr_t dst_addr = { .host = NULL, .port = NULL };
    char *dst_addr_str = NULL;
    // 故障转移
    ss_addr_t failover = { .host = NULL, .port = NULL };
    char *failover_str = NULL;
    char *obfs_host = NULL;
    char *http_method = NULL;

    // 参数与local一致
    char *ss_remote_host = getenv("SS_REMOTE_HOST");
    char *ss_remote_port = getenv("SS_REMOTE_PORT");
    char *ss_local_host  = getenv("SS_LOCAL_HOST");
    char *ss_local_port  = getenv("SS_LOCAL_PORT");
    char *ss_plugin_opts = getenv("SS_PLUGIN_OPTIONS");

    // 
    // 按 "|" 分割字符串，放入server_host数组
    if (ss_remote_host != NULL) {
        ss_remote_host = strdup(ss_remote_host);
        char *delim = "|";
        char *p = strtok(ss_remote_host, delim);
        do {
            server_host[server_num++] = p;
        } while ((p = strtok(NULL, delim)));
    }

    // 
    if (ss_remote_port != NULL) {
        server_port = ss_remote_port;
    }

    // 
    if (ss_local_host != NULL) {
        dst_addr.host = ss_local_host;
    }

    // 
    if (ss_local_port != NULL) {
        dst_addr.port =  ss_local_port;
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
                    case 'b': // 绑定地址（新）
                        bind_address = value;
                        break;
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
                } else if (strcmp(key, "http-method") == 0) { // method
                    http_method = value;
                } else if (strcmp(key, "failover") == 0) {
                    failover_str = value;
                } else if (strcmp(key, "reverse_proxy") == 0) { // 未知（新）
                    reverse_proxy = 1;
#ifdef __linux__
                } else if (strcmp(key, "mptcp") == 0) { // 多路径
                    mptcp = 1;
                    LOGI("enable multipath TCP");
#endif
                }
            }
        }
    }

    int option_index                    = 0;
    static struct option long_options[] = {
        { "fast-open",       no_argument,       0, 0 },
        { "help",            no_argument,       0, 0 },
        { "obfs",            required_argument, 0, 0 },
        { "obfs-host",       required_argument, 0, 0 },
        { "http-method",     required_argument, 0, 0 },
        { "failover",        required_argument, 0, 0 },
#ifdef __linux__
        { "mptcp",           no_argument,       0, 0 },
#endif
        { "reverse_proxy",   no_argument,       0, 0 },
        { 0,                 0,                 0, 0 }
    };

    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, "f:s:p:l:t:b:c:i:d:r:a:n:hv6",
                            long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            if (option_index == 0) { // fast-open
                fast_open = 1;
            } else if (option_index == 1) { // 打印详情
                usage();
                exit(EXIT_SUCCESS);
            } else if (option_index == 2) { // http还是tls
                if (strcmp(optarg, obfs_http->name) == 0)
                    obfs_para = obfs_http;
                else if (strcmp(optarg, obfs_tls->name) == 0)
                    obfs_para = obfs_tls;
            } else if (option_index == 3) { // host
                obfs_host = optarg;
            } else if (option_index == 4) { // method
                http_method = optarg;
            } else if (option_index == 5) { // failover
                failover_str = optarg;
            } else if (option_index == 6) { // 多路径
                mptcp = 1;
                LOGI("enable multipath TCP");
            } else if (option_index == 7) { // reverse_proxy
                reverse_proxy = 1;
                LOGI("enable reverse proxy");
            }
            break;
        case 's': // server_host
            if (server_num < MAX_REMOTE_NUM) {
                server_host[server_num++] = optarg;
            }
            break;
        case 'b': // bind_address
            bind_address = optarg;
            break;
        case 'p': // server_port
            server_port = optarg;
            break;
        case 'r': // 
            dst_addr_str = optarg;
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
        case 'd': // dns
            nameservers = optarg;
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
        case '?':
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
        // 如果server_host为空
        if (server_num == 0) {
            // 总数量
            server_num = conf->remote_num;
            // 加入数组
            for (i = 0; i < server_num; i++)
                server_host[i] = conf->remote_addr[i].host;
        }
        // 如果server_port为空
        if (server_port == NULL) {
            server_port = conf->remote_port;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
        // dst_addr
        if (dst_addr_str == NULL) {
            dst_addr_str = conf->dst_addr;
        }
        // failover
        if (failover_str == NULL) {
            failover_str = conf->failover;
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
        if (http_method == NULL) http_method = conf->http_method;
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
#ifdef TCP_FASTOPEN
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
#endif
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
        // 服务端的几个参数
        if (nameservers == NULL) {
            nameservers = conf->nameserver;
        }
        if (ipv6first == 0) {
            ipv6first = conf->ipv6_first;
        }
        if (reverse_proxy == 0) {
            reverse_proxy = conf->reverse_proxy;
        }
    }

    // 没数据？
    if (server_num == 0) {
        server_host[server_num++] = NULL;
    }

    // 打印usage，退出
    if (server_num == 0 || server_port == NULL) {
        usage();
        exit(EXIT_FAILURE);
    }

    // 转成socket地址
    if (dst_addr_str != NULL) {
        // parse dst addr
        parse_addr(dst_addr_str, &dst_addr);
    }

    // 失败 => local_host, local_port
    if (dst_addr.host == NULL || dst_addr.port == NULL) {
        FATAL("forwarding destination is not defined");
    }

    // 转成socket地址
    if (failover_str != NULL) {
        // parse failover addr
        parse_addr(failover_str, &failover);
    }

    // 默认600s超时，同obfs-local
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

    // pid文件路径
    if (pid_flags) {
        USE_SYSLOG(argv[0]);
        daemonize(pid_path);
    }

    // 打印日志
    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
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

    // 覆盖参数
    if (obfs_para) {
        obfs_para->host = obfs_host;
        obfs_para->method = http_method;
        LOGI("obfuscating enabled");
        if (http_method) LOGI("obfuscation http method: %s", obfs_para->method);
        if (obfs_host)
            LOGI("obfuscating hostname: %s", obfs_host);
    }

#ifdef __MINGW32__
    winsock_init();
#else
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN); // 忽略掉这个信号，重要
    signal(SIGCHLD, SIG_IGN); // 忽略掉这个信号，重要
    signal(SIGABRT, SIG_IGN); // 忽略掉这个信号，重要
#endif

    // 设置信号处理器
    struct ev_signal sigint_watcher;
    struct ev_signal sigterm_watcher;
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    // initialize ev loop
    struct ev_loop *loop = EV_DEFAULT;

    // dns
    if (nameservers != NULL)
        LOGI("using nameserver: %s", nameservers);

    // 监听地址
    // initialize listen context
    listen_ctx_t listen_ctx_list[server_num];

    // bind to each interface
    while (server_num > 0) {
        // 从后往前扫描
        int index        = --server_num;
        const char *host = server_host[index];

        // Bind to port
        int listenfd;
        // 创建socket
        listenfd = create_and_bind(host, server_port, mptcp);
        // 失败
        if (listenfd == -1) {
            // 退出
            FATAL("bind() error");
        }
        // backlog设置为1024
        if (listen(listenfd, SSMAXCONN) == -1) {
            // 退出
            FATAL("listen() error");
        }
        // fast_open
        setfastopen(listenfd);
        // 非阻塞
        setnonblocking(listenfd);
        // 记录到数组
        listen_ctx_t *listen_ctx = &listen_ctx_list[index];

        // Setup proxy context
        listen_ctx->timeout = atoi(timeout);
        listen_ctx->fd      = listenfd;
        listen_ctx->iface   = iface;
        listen_ctx->loop    = loop;

        listen_ctx->dst_addr = &dst_addr; // 目标地址
        listen_ctx->failover = &failover; // 故障转移

        // 监听accept
        ev_io_init(&listen_ctx->io, accept_cb, listenfd, EV_READ);
        ev_io_start(loop, &listen_ctx->io);

        // ipv6
        if (host && strcmp(host, ":") > 0)
            LOGI("listening at [%s]:%s", host, server_port);
        else
            LOGI("listening at %s:%s", host ? host : "*", server_port);
    }

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

#ifndef __MINGW32__
    // 5s
    ev_timer parent_watcher;
    ev_timer_init(&parent_watcher, parent_watcher_cb, 0, UPDATE_INTERVAL);
    ev_timer_start(EV_DEFAULT, &parent_watcher);
#endif

    // start ev loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    for (int i = 0; i <= server_num; i++) {
        listen_ctx_t *listen_ctx = &listen_ctx_list[i];
        ev_io_stop(loop, &listen_ctx->io);
        close(listen_ctx->fd);
    }

    free_connections(loop);

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);

    return 0;
}
