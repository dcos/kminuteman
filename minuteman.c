#include <linux/kernel.h>
#include <linux/types.h>
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

// TODO: Initialize seed on startup
#define SEED  42

// For semi-awful reasons, we don't need to lock here because of genl_lock -- the only API here is the genl API
// and all accesses are serialized :(
#define VIP_HASH_BITS 3
#define BE_HASH_BITS 8

static DEFINE_HASHTABLE(vip_table, VIP_HASH_BITS);
static DEFINE_HASHTABLE(be_table, BE_HASH_BITS);

static DEFINE_PER_CPU(__u32, minuteman_seqnum);

struct vip {
  struct hlist_node   hash_list;
  struct list_head    backend_containers;
  struct sockaddr_in  vip;
};
struct backend {
  atomic_t            refcnt;
  struct  hlist_node  hash_list;
  struct  sockaddr_in backend;
  bool    available;
};
struct backend_container {
  struct list_head  list;
  struct backend    *backend;
};

static struct genl_family minuteman_family = {
  .id = GENL_ID_GENERATE,
  .hdrsize = 0,
  .name = "MINUTEMAN",
  .version = 1,
  .maxattr = MINUTEMAN_ATTR_MAX,
};

static int hash_sockaddr(struct sockaddr_in *addr) {
  // We don't support not AF_INET
  // Also, this only works because of the way the struct is laid out
  // TODO: We should probably make this better
  return jhash(addr, sizeof(addr->sin_family) + sizeof(addr->sin_port) + sizeof(addr->sin_addr), SEED);
}
static struct vip* get_vip(struct sockaddr_in *addr) {
  struct vip *v;
  int hash;
  hash = hash_sockaddr(addr);
  hash_for_each_possible_rcu(vip_table, v, hash_list, hash) {
    if(v->vip.sin_family == addr->sin_family &&
      v->vip.sin_addr.s_addr == addr->sin_addr.s_addr &&
      v->vip.sin_port == addr->sin_port) {
      return v;
    }
  }
  return NULL;
}
static struct backend* get_be(struct sockaddr_in *addr) {
  struct backend *b;
  int hash;
  hash = hash_sockaddr(addr);
  hash_for_each_possible_rcu(be_table, b, hash_list, hash) {
    if(b->backend.sin_family == addr->sin_family && b->backend.sin_addr.s_addr == addr->sin_addr.s_addr && b->backend.sin_port == addr->sin_port) {
      return b;
    }
  }
  return NULL;
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
static int minuteman_nl_cmd_noop(struct sk_buff *skb, struct genl_info *info) {
  struct sk_buff *msg;
  void *hdr;
  int err;
  struct vip *v;
  int bkt;
  struct backend_container *be_container;
  struct backend *be;

  rcu_read_lock();
  hash_for_each_rcu(vip_table, bkt, v, hash_list) {
    printk(KERN_INFO "VIP: %pISpc\n", &v->vip);
    list_for_each_entry_rcu(be_container, &v->backend_containers, list) {
      be = rcu_dereference(be_container->backend);
      printk(KERN_INFO "\tBackend: %pISpc\n", &be->backend);
    }
  }
  rcu_read_unlock();
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
  struct vip *v;
  int hash;
  struct sockaddr_in addr;

  if (!info) return -EINVAL;
  if (!(info->attrs[MINUTEMAN_ATTR_VIP_IP])) {
    return -EINVAL;
  }
  if (!(info->attrs[MINUTEMAN_ATTR_VIP_PORT])) {
    return -EINVAL;
  }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = nla_get_u32(info->attrs[MINUTEMAN_ATTR_VIP_IP]);
  addr.sin_port = nla_get_u16(info->attrs[MINUTEMAN_ATTR_VIP_PORT]);
  hash = hash_sockaddr(&addr);
  // No need to RCU read lock here because we're the only ones writing
  // Check that we don't already have this VIP
  if (get_vip(&addr)) {
    rc = -EINVAL;
    goto fail;
  }

  v = kmalloc(sizeof(*v), GFP_KERNEL);
  if (!v) {
    rc = -ENOMEM;
    goto fail;
  }

  INIT_LIST_HEAD(&v->backend_containers);
  memcpy(&v->vip, &addr, sizeof(addr));

  hash_add_rcu(vip_table, &v->hash_list, hash);

  rc = prepare_reply(info, MINUTEMAN_CMD_ADD_VIP, &reply_skb);
  if (rc < 0)
    goto fail;

  rc = send_reply(reply_skb, info);

  fail:
  return rc;
}
static int minuteman_nl_cmd_del_vip(struct sk_buff *skb, struct genl_info *info) {
}
static int minuteman_nl_cmd_set_be(struct sk_buff *skb, struct genl_info *info) {
}
static int minuteman_nl_cmd_add_be(struct sk_buff *skb, struct genl_info *info) {
  int rc = 0;
  struct sk_buff *reply_skb;
  struct vip *v;
  struct backend *be, *maybe_be;
  struct backend_container *be_container;
  int hash;
  struct sockaddr_in be_addr, vip_addr;

  if (!info) return -EINVAL;
  if (!(info->attrs[MINUTEMAN_ATTR_VIP_IP])) {
    return -EINVAL;
  }
  if (!(info->attrs[MINUTEMAN_ATTR_VIP_PORT])) {
    return -EINVAL;
  }
  if (!(info->attrs[MINUTEMAN_ATTR_BE_IP])) {
    return -EINVAL;
  }
  if (!(info->attrs[MINUTEMAN_ATTR_BE_PORT])) {
    return -EINVAL;
  }

  vip_addr.sin_family = AF_INET;
  vip_addr.sin_addr.s_addr = nla_get_u32(info->attrs[MINUTEMAN_ATTR_VIP_IP]);
  vip_addr.sin_port = nla_get_u16(info->attrs[MINUTEMAN_ATTR_VIP_PORT]);

  be_addr.sin_family = AF_INET;
  be_addr.sin_addr.s_addr = nla_get_u32(info->attrs[MINUTEMAN_ATTR_BE_IP]);
  be_addr.sin_port = nla_get_u16(info->attrs[MINUTEMAN_ATTR_BE_PORT]);

  rcu_read_lock();
  v = get_vip(&vip_addr);
  if (!v) {
    rc = -EINVAL;
    goto fail;
  }
  // Now we check if the BE already exists
  be = get_be(&be_addr);
  if (be) {
    // First check if the BE is already in the VIP
    list_for_each_entry_rcu(be_container, &v->backend_containers, list) {
      maybe_be = rcu_dereference(be_container->backend);
      if (maybe_be == be) {
        rc = -EINVAL;
        goto fail;
      }
    }
    be_container = kmalloc(sizeof(*be_container), GFP_KERNEL);
    if (!be_container) {
      rc = -ENOMEM;
      goto fail;
    }
    rcu_read_unlock();
    synchronize_rcu();
    atomic_inc(&be->refcnt);
  } else {
    be_container = kmalloc(sizeof(*be_container), GFP_KERNEL);
    if (!be_container) {
      rc = -ENOMEM;
      goto fail;
    }

    be = kmalloc(sizeof(*be), GFP_KERNEL);
    if (!be) {
      kfree(be_container);
      rc = -ENOMEM;
      goto fail;
    }
    rcu_read_unlock();

    memcpy(&be->backend, &be_addr, sizeof(be_addr));
    atomic_set(&be->refcnt, 1);
    be->available = false;

    hash = hash_sockaddr(&be_addr);
    synchronize_rcu();
    hash_add_rcu(be_table, &be->hash_list, hash);
  }

  be_container->backend = be;
  // We don't need to lock around this because all netlink operations are serialized
  list_add_rcu(&be_container->list, &v->backend_containers);

  rc = prepare_reply(info, MINUTEMAN_CMD_ADD_BE, &reply_skb);
  if (rc < 0)
    return rc;

  rc = send_reply(reply_skb, info);

  return rc;

  fail:
  rcu_read_unlock();
  return rc;
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





/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
  struct socket *sock;
  struct sockaddr *uaddr;
  struct sockaddr_in *addr_in;
  struct vip *v;
  int addr_len;

  sock = (struct socket*) regs->di;
  uaddr = (struct sockaddr*) regs->si;
  addr_len = (int)regs->dx;

  rcu_read_lock();
  if (uaddr->sa_family == AF_INET) {
    addr_in = (struct sockaddr_in*)uaddr;
    v = get_vip(addr_in);
    if (v) {
      printk(KERN_INFO "Raver\n");
    }
  }
  rcu_read_unlock();
  printk(KERN_INFO "Connecting to: %pISpc\n", uaddr);
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

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
  .pre_handler = handler_pre,
  .symbol_name  = "inet_stream_connect",
};


/* per-instance private data */
struct my_data {
        ktime_t entry_stamp;
};

/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        struct my_data *data;

        if (!current->mm)
                return 1;       /* Skip kernel threads */

        data = (struct my_data *)ri->data;
        data->entry_stamp = ktime_get();
        return 0;
}

/*
 * Return-probe handler: Log the return value and duration. Duration may turn
 * out to be zero consistently, depending upon the granularity of time
 * accounting on the platform.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        int retval = regs_return_value(regs);
        struct my_data *data = (struct my_data *)ri->data;
        s64 delta;
        ktime_t now;

        now = ktime_get();
        delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
        printk(KERN_INFO "returned %d and took %lld ns to execute\n", retval, (long long)delta);
        return 0;
}

static struct kretprobe my_kretprobe = {
  .handler                = ret_handler,
  .entry_handler          = entry_handler,
  .data_size              = sizeof(struct my_data),
  .maxactive              = 1024,
  .kp = {
    .symbol_name = "sys_connect",
  },
};


static int __init minuteman_init(void)
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

  ret = register_kretprobe(&my_kretprobe);
  if (ret < 0) {
                printk(KERN_INFO "register_kretprobe failed, returned %d\n",
                                ret);
  }
  return 0;
}

static void __exit minuteman_exit(void)
{
  unregister_kprobe(&kp);
  printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
  minuteman_nl_unsetup();
  unregister_kretprobe(&my_kretprobe);
}

module_init(minuteman_init)
module_exit(minuteman_exit)
MODULE_LICENSE("GPL");

