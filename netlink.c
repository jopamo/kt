// netlink.c

#include "netlink.h"

#include <errno.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

u16 netlink_attr_put(struct nlmsghdr *nlh, u16 nla_type, const void *data, u16 data_len)
{
  nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len);
  struct nlattr *attr = (void *) ((char *) nlh + nlh->nlmsg_len);

  attr->nla_type = nla_type;
  attr->nla_len = NLA_HDRLEN + data_len;
  memcpy((char *) attr + NLA_HDRLEN, data, data_len);

  nlh->nlmsg_len += attr->nla_len;
  return attr->nla_len;
}

u16 netlink_attr_append(struct nlattr *attr, u16 nla_type, const void *data, u16 data_len)
{
  attr->nla_len = NLMSG_ALIGN(attr->nla_len);
  struct nlattr *a = (void *) ((char *) attr + attr->nla_len);

  a->nla_type = nla_type;
  a->nla_len = NLA_HDRLEN + data_len;
  memcpy((char *) a + NLA_HDRLEN, data, data_len);

  attr->nla_len += a->nla_len;
  return a->nla_len;
}

struct nlattr *netlink_nest_begin(struct nlmsghdr *nlh, u16 nla_type)
{
  nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len);
  struct nlattr *attr = (void *) ((char *) nlh + nlh->nlmsg_len);

  attr->nla_type = nla_type | NLA_F_NESTED;
  attr->nla_len = NLA_HDRLEN;

  return attr;
}

u16 netlink_nest_end(struct nlmsghdr *nlh, struct nlattr *attr)
{
  nlh->nlmsg_len += attr->nla_len;
  return attr->nla_len;
}

struct nlattr *netlink_attr_nest_begin(struct nlattr *attr, u16 nla_type)
{
  attr->nla_len = NLMSG_ALIGN(attr->nla_len);
  struct nlattr *child = (void *) ((char *) attr + attr->nla_len);

  child->nla_type = nla_type | NLA_F_NESTED;
  child->nla_len = NLA_HDRLEN;

  return child;
}

u16 netlink_attr_nest_end(struct nlattr *parent, struct nlattr *inner)
{
  parent->nla_len += inner->nla_len;
  return inner->nla_len;
}

int __netlink_send(int fd, const void *nlh, size_t size)
{
  struct iovec iov = {
    .iov_base = (void *) nlh,
    .iov_len = size,
  };
  struct msghdr msg = {
    .msg_name = NULL,
    .msg_namelen = 0,
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = NULL,
    .msg_controllen = 0,
    .msg_flags = 0,
  };

  if (sendmsg(fd, &msg, 0) < 0) {
    perror("sendmsg()");
    return -1;
  }
  return 0;
}

int netlink_recv(int fd, void *nlh, size_t size)
{
  struct iovec iov = { .iov_base = (void *) nlh, .iov_len = 0 };
  struct msghdr msg = {
    .msg_name = NULL,
    .msg_namelen = 0,
    .msg_iov = NULL,
    .msg_iovlen = 0,
    .msg_control = NULL,
    .msg_controllen = 0,
    .msg_flags = MSG_TRUNC,
  };

  memset(nlh, 0, size);

  iov.iov_len = recvmsg(fd, &msg, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
  if ((ssize_t) iov.iov_len < 0) {
    if (errno == EAGAIN) {
      return 0;
    }
    perror("recvmsg()");
    return -1;
  }
  if (iov.iov_len > size) {
    fprintf(stderr, "message too large: %zu > %zu\n", iov.iov_len, size);
    return -1;
  }

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  return recvmsg(fd, &msg, 0);
}

int netlink_errno(const struct nlmsghdr *nlh)
{
  if (nlh->nlmsg_len == 0) {
    return 0;
  }
  if (nlh->nlmsg_type != NLMSG_ERROR) {
    fprintf(stderr, "warning: not a netlink error message: %hu\n", nlh->nlmsg_type);
    return 0;
  }
  struct nlmsgerr *e = (struct nlmsgerr *) NLMSG_DATA(nlh);
  if (e->error != 0) {
    errno = -e->error;
  }
  return e->error;
}

int netlink_open(int proto)
{
  struct sockaddr_nl addr;
  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;

  int s = socket(AF_NETLINK, SOCK_RAW, proto);
  if (s < 0) {
    perror("socket()");
    return s;
  }
  if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
    perror("bind()");
    close(s);
    return -1;
  }
  return s;
}

void netlink_close(int fd)
{
  close(fd);
}
