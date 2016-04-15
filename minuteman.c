#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <net/tcp.h>
#include <linux/idr.h>
#include <linux/net.h>
#include <linux/utsname.h>
#include <linux/filter.h>

#include <uapi/linux/ip.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/seqlock.h>

#include "minuteman.h"

// For semi-awful reasons, we don't need to lock here because of genl_lock -- the only API here is the genl API
// and all accesses are serialized :(
#define VIP_HASH_BITS 3
#define BE_HASH_BITS 8

static DEFINE_HASHTABLE(vip_table, VIP_HASH_BITS);
static DEFINE_HASHTABLE(be_table, BE_HASH_BITS);

static DEFINE_PER_CPU(__u32, minuteman_seqnum);

struct ip_port {
  __be32  ip;
  __be16  port;
};
struct vip {
  struct hlist_node hash_list;
  struct list_head backend_containers;
  struct ip_port  vip;
};
struct backend {
  struct hlist_node hash_list;
  struct ip_port  backend;
  bool    available;
};
struct backend_container {
  struct list_head list;
  struct backend *backend;
};

static struct genl_family minuteman_family = {
  .id = GENL_ID_GENERATE,
  .hdrsize = 0,
  .name = "MINUTEMAN",
  .version = 1,
  .maxattr = MINUTEMAN_ATTR_MAX,
};

static u64 hash_ip_port(__be32 ip, __be32 port) {
  return (ip << 16) | port;
}
static int prepare_reply(struct genl_info *info, u8 cmd, struct sk_buff **skbp) {
        struct sk_buff *skb;
        void *reply;

        /*
         * If new attributes are added, please revisit this allocation
         */
        skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
        if (!skb)
                return -ENOMEM;

        if (!info) {
                int seq = this_cpu_inc_return(minuteman_seqnum) - 1;

                reply = genlmsg_put(skb, 0, seq, &minuteman_family, 0, cmd);
        } else
                reply = genlmsg_put_reply(skb, info, &minuteman_family, 0, cmd);
        if (reply == NULL) {
                nlmsg_free(skb);
                return -EINVAL;
        }

        *skbp = skb;
        return 0;
}
static int send_reply(struct sk_buff *skb, struct genl_info *info)
{
        struct genlmsghdr *genlhdr = nlmsg_data(nlmsg_hdr(skb));
        void *reply = genlmsg_data(genlhdr);

        genlmsg_end(skb, reply);

        return genlmsg_reply(skb, info);
}


static int minuteman_nl_dump(struct sk_buff *skb, struct netlink_callback *cb) {
  return 0;
}
static int minuteman_nl_cmd_noop(struct sk_buff *skb, struct genl_info *info)
{
  struct sk_buff *msg;
  void *hdr;
  int err;

  printk(KERN_INFO "NOOPING\n");

  msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
  if (!msg)
    return -ENOMEM;
  hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
                    &minuteman_family, 0, MINUTEMAN_CMD_NOOP);
  if (!hdr) {
    err = -EMSGSIZE;
    goto err_msg_put;
  }

  genlmsg_end(msg, hdr);

  return genlmsg_unicast(genl_info_net(info), msg, info->snd_portid);

  err_msg_put:
    nlmsg_free(msg);

  return err;
}

static int minuteman_nl_cmd_add_vip(struct sk_buff *skb, struct genl_info *info) {
  int rc = 0;
  struct sk_buff *reply_skb;
  __be32 ip;
  __be16 port;
  struct vip *v;

  if (!info) return -EINVAL;
  if (!(info->attrs[MINUTEMAN_ATTR_VIP_IP])) {
    return -EINVAL;
  }
  if (!(info->attrs[MINUTEMAN_ATTR_VIP_PORT])) {
    return -EINVAL;
  }
  ip = nla_get_u32(info->attrs[MINUTEMAN_ATTR_VIP_IP]);
  port = nla_get_u16(info->attrs[MINUTEMAN_ATTR_VIP_PORT]);

  // Check that we don't already have this VIP
  hash_for_each_possible_rcu(vip_table, v, hash_list, hash_ip_port(ip, port)) {
    if(v->vip.ip == ip && v->vip.port == port) {
      return -EINVAL;
    }
  }

  v = kmalloc(sizeof(*v), GFP_KERNEL);
  if (!v)
    return -ENOMEM;

  INIT_LIST_HEAD(&v->backend_containers);
  v->vip.ip = ip;
  v->vip.port = port;

  hash_add_rcu(vip_table, &v->hash_list, hash_ip_port(ip, port));

  rc = prepare_reply(info, MINUTEMAN_CMD_ADD_VIP, &reply_skb);
  if (rc < 0)
    goto error;

  rc = send_reply(reply_skb, info);

  error:
  return rc;
}
static int minuteman_nl_cmd_del_vip(struct sk_buff *skb, struct genl_info *info) {
}
static int minuteman_nl_cmd_set_be(struct sk_buff *skb, struct genl_info *info) {
}
static int minuteman_nl_cmd_add_be(struct sk_buff *skb, struct genl_info *info) {
}
static int minuteman_nl_cmd_del_be(struct sk_buff *skb, struct genl_info *info) {
}


static const struct genl_ops minuteman_ops[] = {
  {
    .cmd = MINUTEMAN_CMD_NOOP,
    .flags = GENL_ADMIN_PERM,
    .doit = minuteman_nl_cmd_noop,
    .dumpit = minuteman_nl_dump,
    .policy = minuteman_policy,
  },
  {
    .cmd = MINUTEMAN_CMD_ADD_VIP,
    .flags = GENL_ADMIN_PERM,
    .doit = minuteman_nl_cmd_add_vip,
    .policy = minuteman_policy,
  },
  {
    .cmd = MINUTEMAN_CMD_DEL_VIP,
    .flags = GENL_ADMIN_PERM,
    .doit = minuteman_nl_cmd_del_vip,
    .policy = minuteman_policy,
  },
  {
    .cmd = MINUTEMAN_CMD_SET_BE,
    .flags = GENL_ADMIN_PERM,
    .doit = minuteman_nl_cmd_set_be,
    .policy = minuteman_policy,
  },
  {
    .cmd = MINUTEMAN_CMD_ADD_BE,
    .flags = GENL_ADMIN_PERM,
    .doit = minuteman_nl_cmd_add_be,
    .policy = minuteman_policy,
  },
  {
    .cmd = MINUTEMAN_CMD_DEL_BE,
    .flags = GENL_ADMIN_PERM,
    .doit = minuteman_nl_cmd_del_be,
    .policy = minuteman_policy,
  },
};

static int minuteman_nl_setup(void) {
  return genl_register_family_with_ops(&minuteman_family, minuteman_ops);
}
static int minuteman_nl_unsetup(void) {
  return genl_unregister_family(&minuteman_family);
}





/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
  .symbol_name  = "tcp_init_sock",
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
  /* A dump_stack() here will give a stack backtrace */
  return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
  printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
  /* Return 0 because we don't handle the fault. */
  return 0;
}
static int __init kprobe_init(void)
{
  int ret;
  ret = minuteman_nl_setup();
  if (ret < 0) {
    printk(KERN_INFO "minuteman_nl_setup failed, returned %d\n", ret);
    return ret;
  }
  ret = register_kprobe(&kp);
  if (ret < 0) {
    minuteman_nl_unsetup();
    printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
    return ret;
  }
  printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
  return 0;
}

static void __exit kprobe_exit(void)
{
  unregister_kprobe(&kp);
  printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
  minuteman_nl_unsetup();
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");

