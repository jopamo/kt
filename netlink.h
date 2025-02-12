#ifndef __H_NETLINK
#define __H_NETLINK

#include <linux/netlink.h>
#include <stddef.h>
#include <stdint.h>

typedef uint16_t u16;

static inline void *nlmsg_end(struct nlmsghdr *nlh)
{
  return (char *) (nlh) + NLMSG_ALIGN(nlh->nlmsg_len);
}
static inline void *nlattr_end(struct nlattr *attr)
{
  return (char *) (attr) + NLMSG_ALIGN(attr->nla_len);
}

void netlink_close(int fd);

int netlink_open(int proto);
int netlink_recv(int fd, void *nlh, size_t size);
int __netlink_send(int fd, const void *nlh, size_t size);
static inline int netlink_send(int fd, const struct nlmsghdr *nlh)
{
  return __netlink_send(fd, nlh, nlh->nlmsg_len);
}
int netlink_errno(const struct nlmsghdr *nlh);

u16 netlink_attr_put(struct nlmsghdr *nlh, u16 nla_type, const void *data, u16 data_len);
struct nlattr *netlink_nest_begin(struct nlmsghdr *nlh, u16 nla_type);
u16 netlink_nest_end(struct nlmsghdr *nlh, struct nlattr *attr);
struct nlattr *netlink_attr_nest_begin(struct nlattr *attr, u16 nla_type);
u16 netlink_attr_nest_end(struct nlattr *parent, struct nlattr *inner);
u16 netlink_attr_append(struct nlattr *attr, u16 nla_type, const void *data, u16 data_len);

#endif
