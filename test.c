#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <errno.h>
#include <stdio.h>

// libnl
#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "minuteman.h"

int main() {
  struct nl_sock *sk = nl_socket_alloc();
  if (!sk) {
    fprintf(stderr, "Could not allocate socket\n");
    exit(1);
  }
  int ret;
  int family;
  ret = genl_connect(sk);
  if (ret) {
    fprintf(stderr, "Could not connect socket\n");
    goto fail;
  }
  family = genl_ctrl_resolve(sk, "MINUTEMAN");
  if (family < 0) {
    fprintf(stderr, "Could not resolve family\n");
    goto fail;
  }

  ret = genl_send_simple(sk, family, MINUTEMAN_CMD_NOOP, 1, NLM_F_DUMP);
  printf("Status: %d\n", ret);

  ret = genl_send_simple(sk, family, MINUTEMAN_CMD_ADD_VIP, 1, NLM_F_DUMP);
  printf("Status: %d\n", ret);
  nl_socket_free(sk);
  return 0;
  fail:
  nl_socket_free(sk);
  exit(1);
}

