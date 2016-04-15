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
static int parse_cb(struct nl_msg *msg, void *arg)
{
  printf("pants\n");
}

int main() {
  int err;
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

/*
  ret = genl_send_simple(sk, family, MINUTEMAN_CMD_NOOP, 1, NLM_F_DUMP);
  printf("Status: %d\n", ret);

  ret = genl_send_simple(sk, family, MINUTEMAN_CMD_ADD_VIP, 1, NLM_F_DUMP);
  printf("Status: %d\n", ret);
*/
  struct nl_msg *msg;
  if (!(msg = nlmsg_alloc()))
    exit(1);

  void *hdr;
  hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0, MINUTEMAN_CMD_ADD_VIP, 1);
  if (!hdr)
    exit(1);
  struct in_addr addr;
  inet_aton("1.2.3.4", &addr);

  nla_put_u32(msg, MINUTEMAN_ATTR_VIP_IP, addr.s_addr);
  nla_put_u16(msg, MINUTEMAN_ATTR_VIP_PORT, htons(1111));
  nl_send_auto_complete(sk, msg);

  if ((err = nl_recvmsgs_default(sk)) < 0)
                fprintf(stderr, "Unable to receive message: %s", nl_geterror(err));

  ret = genl_send_simple(sk, family, MINUTEMAN_CMD_NOOP, 1, 0);
  printf("Status: %d\n", ret);

  nl_socket_free(sk);


  return 0;
  fail:
  nl_socket_free(sk);
  exit(1);
}

