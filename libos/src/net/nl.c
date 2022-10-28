/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

/*
 * Implementation of Netlink sockets.
 * For such sockets `handle->info.sock.pal_handle` is always set, hence does not need atomicity on
 * accesses.
 */

#include "libos_fs.h"
#include "libos_socket.h"
#include "pal.h"
#include "socket_utils.h"

static int verify_sockaddr(int expected_family, void* addr, size_t* addrlen) {
    unsigned short family;
    switch (expected_family) {
        case AF_NETLINK:
            if (*addrlen < sizeof(struct sockaddr_nl)) {
                return -EINVAL;
            }
            memcpy(&family, (char*)addr + offsetof(struct sockaddr_nl, nl_family), sizeof(family));
            if (family != AF_NETLINK) {
                return -EAFNOSUPPORT;
            }
            /* Cap the address at the maximal possible size - rest of the input buffer (if any) is
             * ignored. */
            *addrlen = sizeof(struct sockaddr_nl);
            break;
        default:
            BUG();
    }
    return 0;
}

static int create(struct libos_handle* handle) {
    assert(handle->info.sock.domain == AF_NETLINK);
    assert(handle->info.sock.type == SOCK_RAW || handle->info.sock.type == SOCK_DGRAM);

    enum pal_socket_domain pal_domain;
    switch (handle->info.sock.domain) {
        case AF_NETLINK:
            pal_domain = PAL_NL;
            break;
        default:
            BUG();
    }

    enum pal_socket_type pal_type;
    switch (handle->info.sock.type) {
        case SOCK_DGRAM:
        case SOCK_RAW:
            pal_type = PAL_SOCKET_NL;
            /* Netlink sockets are ready for communication instantly. */
            handle->info.sock.can_be_read = true;
            handle->info.sock.can_be_written = true;
            break;
        default:
            BUG();
    }

    int protocol = handle->info.sock.protocol;
    if (protocol < 0 || protocol >= MAX_LINKS) {
        return -EPROTONOSUPPORT;
    }

    /* We don't need to take the lock - handle was just created. */
    pal_stream_options_t options = handle->flags & O_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
    PAL_HANDLE pal_handle = NULL;
    int ret = PalSocketCreate(pal_domain, pal_type, protocol, options, &pal_handle);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    handle->info.sock.pal_handle = pal_handle;
    return 0;
}

static int bind(struct libos_handle* handle, void* addr, size_t addrlen) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    int ret = verify_sockaddr(sock->domain, addr, &addrlen);
    if (ret < 0) {
        return ret;
    }

    struct pal_socket_addr pal_nl_addr;
    linux_to_pal_sockaddr(addr, &pal_nl_addr);

    ret = PalSocketBind(sock->pal_handle, &pal_nl_addr);
    if (ret < 0) {
        return (ret == -PAL_ERROR_STREAMEXIST) ? -EADDRINUSE : pal_to_unix_errno(ret);
    }

    pal_to_linux_sockaddr(&pal_nl_addr, &sock->local_addr, &sock->local_addrlen);
    return 0;
}

static int connect(struct libos_handle* handle, void* addr, size_t addrlen) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    int ret = verify_sockaddr(sock->domain, addr, &addrlen);
    if (ret < 0) {
        return ret;
    }

    struct pal_socket_addr pal_remote_addr;
    linux_to_pal_sockaddr(addr, &pal_remote_addr);
    struct pal_socket_addr pal_local_addr;

    /* XXX: this connect is always blocking (regardless of actual setting of nonblockingness on
     * `sock->pal_handle`. See also the comment in netlink connect implementation in Linux PAL. */
    ret = PalSocketConnect(sock->pal_handle, &pal_remote_addr, &pal_local_addr);
    if (ret < 0) {
        return ret == -PAL_ERROR_CONNFAILED ? -ECONNREFUSED : pal_to_unix_errno(ret);
    }

    memcpy(&sock->remote_addr, addr, addrlen);
    sock->remote_addrlen = addrlen;
    if (sock->state != SOCK_BOUND) {
        assert(sock->state == SOCK_NEW);
        assert(!sock->was_bound);
        pal_to_linux_sockaddr(&pal_local_addr, &sock->local_addr, &sock->local_addrlen);
    }
    return 0;
}

static int disconnect(struct libos_handle* handle) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    struct pal_socket_addr pal_nl_addr = {
        .domain = PAL_DISCONNECT,
    };
    int ret = PalSocketConnect(sock->pal_handle, &pal_nl_addr, /*local_addr=*/NULL);
    return pal_to_unix_errno(ret);
}

static int setsockopt(struct libos_handle* handle, int level, int optname, void* optval,
                      size_t len) {
    /* Nothing to do here. */
    __UNUSED(handle);
    __UNUSED(level);
    __UNUSED(optname);
    __UNUSED(optval);
    __UNUSED(len);
    return -ENOPROTOOPT;
}

static int getsockopt(struct libos_handle* handle, int level, int optname, void* optval,
                      size_t* len) {
    /* Nothing to do here. */
    __UNUSED(handle);
    __UNUSED(level);
    __UNUSED(optname);
    __UNUSED(optval);
    __UNUSED(len);
    return -ENOPROTOOPT;
}

static int send(struct libos_handle* handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                void* addr, size_t addrlen, bool force_nonblocking) {
    assert(handle->type == TYPE_SOCK);

    struct libos_sock_handle* sock = &handle->info.sock;
    struct sockaddr_storage sock_addr;

    switch (sock->type) {
        case SOCK_DGRAM:
        case SOCK_RAW:
            if (!addr) {
                lock(&sock->lock);
                if (sock->remote_addr.ss_family == AF_UNSPEC) {
                    /* Not connected. */
                    unlock(&sock->lock);
                    return -ENOTCONN;
                }
                addrlen = sock->remote_addrlen;
                assert(addrlen <= sizeof(sock_addr));
                memcpy(&sock_addr, &sock->remote_addr, addrlen);
                addr = &sock_addr;
                unlock(&sock->lock);
            }
            break;
        default:
            __builtin_unreachable();
    }

    struct pal_socket_addr pal_sockaddr;
    if (addr) {
        int ret = verify_sockaddr(sock->domain, addr, &addrlen);
        if (ret < 0) {
            return ret;
        }
        linux_to_pal_sockaddr(addr, &pal_sockaddr);
    }

    int ret = PalSocketSend(sock->pal_handle, iov, iov_len, out_size, addr ? &pal_sockaddr : NULL,
                            force_nonblocking);
    ret = (ret == -PAL_ERROR_TOOLONG) ? -EMSGSIZE : pal_to_unix_errno(ret);
    return ret;
}

static int recv(struct libos_handle* handle, struct iovec* iov, size_t iov_len,
                size_t* out_total_size, void* addr, size_t* addrlen, bool force_nonblocking) {
    assert(handle->type == TYPE_SOCK);

    switch (handle->info.sock.type) {
        case SOCK_DGRAM:
        case SOCK_RAW:
            break;
        default:
            __builtin_unreachable();
    }

    struct pal_socket_addr pal_sockaddr;
    int ret = PalSocketRecv(handle->info.sock.pal_handle, iov, iov_len, out_total_size,
                            addr ? &pal_sockaddr : NULL, force_nonblocking);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    if (addr) {
        struct sockaddr_storage linux_addr;
        size_t linux_addr_len = sizeof(linux_addr);
        pal_to_linux_sockaddr(&pal_sockaddr, &linux_addr, &linux_addr_len);
        /* If the user provided buffer is too small, the address is truncated, but we report
         * the actual address size in `addrlen`. */
        memcpy(addr, &linux_addr, MIN(*addrlen, linux_addr_len));
        *addrlen = linux_addr_len;
    }
    return 0;
}

struct libos_sock_ops sock_nl_ops = {
    .create = create,
    .bind = bind,
    .connect = connect,
    .disconnect = disconnect,
    .getsockopt = getsockopt,
    .setsockopt = setsockopt,
    .send = send,
    .recv = recv,
};
