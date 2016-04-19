#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <net/tcp.h>
#include <linux/idr.h>
#include <linux/net.h>
#include <uapi/linux/ip.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/seqlock.h>
#include <linux/errno.h>
#include "minuteman.h"

// TODO: Initialize seed on startup
#define SEED  42
#define MAX_BACKENDS 1024

// For semi-awful reasons, we don't need to lock here because of genl_lock -- the only API here is the genl API
// and all accesses are serialized :(
#define VIP_HASH_BITS 8
#define BE_HASH_BITS 8

static DEFINE_HASHTABLE(vip_table, VIP_HASH_BITS);
static DEFINE_HASHTABLE(be_table, BE_HASH_BITS);


struct backend;
struct backend_vector;
struct vip;

struct backend_vector {
	long						backend_count;
	struct backend	*backends[];
};
struct vip {
	struct sockaddr_in vip; // The VIP itself
	struct hlist_node hash_list;
	struct backend_vector *be_vector;
};

struct backend {
	struct sockaddr_in backend_addr;
	struct hlist_node hash_list;
	atomic_t refcnt;
	int available;
	int reachable;
};


static struct genl_family minuteman_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "MINUTEMAN",
	.version = 1,
	.maxattr = MINUTEMAN_ATTR_MAX,
};

static int hash_sockaddr(struct sockaddr_in *addr) {
	// We only support AF_INET
	// Also, this only works because of the way the struct is laid out
	// TODO: We should probably make this better
	return jhash(addr, sizeof (addr->sin_family) + sizeof (addr->sin_port) + sizeof (addr->sin_addr), SEED);
}

static struct vip* get_vip(struct sockaddr_in *addr) {
	struct vip *v;
	int hash;
	hash = hash_sockaddr(addr);

	hash_for_each_possible_rcu(vip_table, v, hash_list, hash) {
		if (v->vip.sin_family == addr->sin_family &&
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
		if (b->backend_addr.sin_family == addr->sin_family && 
				b->backend_addr.sin_addr.s_addr == addr->sin_addr.s_addr && 
				b->backend_addr.sin_port == addr->sin_port) {
			return b;
		}
	}
	return NULL;
}

static int prepare_reply(struct genl_info *info, u8 cmd, struct sk_buff **skbp) {
	struct sk_buff *skb;
	void *hdr;
	int err;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	hdr = genlmsg_put(skb, info->snd_portid, info->snd_seq,
										&minuteman_family, 0, cmd);
	if (!hdr) {
		err = -EMSGSIZE;
		nlmsg_free(skb);
		return err;
	}

	*skbp = skb;
	return 0;
}

static int send_reply(struct sk_buff *skb, struct genl_info *info) {
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
	struct vip *vip;
	int bkt;
	int i;
	struct backend_vector *be_vector;
	struct backend *be;
	
	printk(KERN_INFO "NOOPING\n");
	hash_for_each(vip_table, bkt, vip, hash_list) {
		printk(KERN_INFO "VIP: %pISpc\n", &vip->vip);
		be_vector = rcu_dereference(vip->be_vector);
		if (be_vector != NULL) {
			for (i = 0; i < be_vector->backend_count; i++) {
				be = be_vector->backends[i];
				printk(KERN_INFO "\tBackend: %pISpc\n", &be->backend_addr);
			}
		}
	}

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
		rc = -EEXIST;
		goto fail;
	}

	v = kmalloc(sizeof (*v), GFP_KERNEL);
	if (!v) {
		rc = -ENOMEM;
		goto fail;
	}

	memcpy(&v->vip, &addr, sizeof (addr));
	v->be_vector = NULL;
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
static int validate_minuteman_nl_cmd_add_be(struct genl_info *info) {
	if (!info) {
		return -EINVAL;
	}
	if (!(info->attrs[MINUTEMAN_ATTR_BE_IP])) {
		return -EINVAL;
	}
	if (!(info->attrs[MINUTEMAN_ATTR_BE_PORT])) {
		return -EINVAL;
	}
	return 0;
}

// We don't need to lock around this because all netlink operations are serialized
static int minuteman_nl_cmd_add_be(struct sk_buff *skb, struct genl_info *info) {
	int rc = 0;
	struct sk_buff *reply_skb;
	struct backend *be;
	int hash;
	struct sockaddr_in be_addr;

	rc = validate_minuteman_nl_cmd_add_be(info);
	if (rc != 0) {
		return rc;
	}
	
	be_addr.sin_family = AF_INET;
	be_addr.sin_addr.s_addr = nla_get_u32(info->attrs[MINUTEMAN_ATTR_BE_IP]);
	be_addr.sin_port = nla_get_u16(info->attrs[MINUTEMAN_ATTR_BE_PORT]);
	
	// Now we check if the BE already exists
	be = get_be(&be_addr);
	if (be) {
		rc = -EEXIST;
		goto fail;
	}
	be = kmalloc(sizeof (*be), GFP_KERNEL);
	if (!be) {
		rc = -ENOMEM;
		goto fail;
	}
	memcpy(&be->backend_addr, &be_addr, sizeof (be_addr));
	atomic_set(&be->refcnt, 1);
	be->available = false;
	hash = hash_sockaddr(&be_addr);
	hash_add_rcu(be_table, &be->hash_list, hash);
	

	rc = prepare_reply(info, MINUTEMAN_CMD_ADD_BE, &reply_skb);
	if (rc < 0)
		return rc;

	rc = send_reply(reply_skb, info);

fail:
	return rc;
}

static int minuteman_nl_cmd_del_be(struct sk_buff *skb, struct genl_info *info) {
}

static int validate_minuteman_nl_cmd_attach_be(struct genl_info *info) {
	int rc = 0;
	if (!info) {
		rc = -EINVAL;
		goto end;
	}
	if (!(info->attrs[MINUTEMAN_ATTR_VIP_IP])) {
		rc = -EINVAL;
		goto end;
	}
	if (!(info->attrs[MINUTEMAN_ATTR_VIP_PORT])) {
		rc = -EINVAL;
		goto end;
	}
	if (!(info->attrs[MINUTEMAN_ATTR_BE_IP])) {
		rc = -EINVAL;
		goto end;
	}
	if (!(info->attrs[MINUTEMAN_ATTR_BE_PORT])) {
		rc = -EINVAL;
		goto end;
	}
	end:
	return rc; 
}
static int minuteman_nl_cmd_attach_be(struct sk_buff *skb, struct genl_info *info) {
	int rc = 0;
	int i;
	struct sk_buff *reply_skb;
	struct vip *vip;
	struct backend *be;
	struct sockaddr_in be_addr, vip_addr;
	struct backend_vector	*new_be_vector, *old_be_vector;
	int new_backend_count;

	rc = validate_minuteman_nl_cmd_attach_be(info);
	if (rc != 0) {
		goto fail;
	}
	
	be_addr.sin_family = AF_INET;
	be_addr.sin_addr.s_addr = nla_get_u32(info->attrs[MINUTEMAN_ATTR_BE_IP]);
	be_addr.sin_port = nla_get_u16(info->attrs[MINUTEMAN_ATTR_BE_PORT]);
	
	vip_addr.sin_family = AF_INET;
	vip_addr.sin_addr.s_addr = nla_get_u32(info->attrs[MINUTEMAN_ATTR_VIP_IP]);
	vip_addr.sin_port = nla_get_u16(info->attrs[MINUTEMAN_ATTR_VIP_PORT]);
	
	
	// Now we check if the BE already exists
	be = get_be(&be_addr);
	if (!be) {
		rc = -ENONET;
		goto fail;
	}
	vip = get_vip(&vip_addr);
	if (!vip) {
		rc = -ENONET;
		goto fail;
	}
	old_be_vector = rcu_dereference(vip->be_vector);
	if (old_be_vector == NULL) {
		new_be_vector = kmalloc(sizeof(struct backend_vector) + sizeof(void*) * 1, GFP_KERNEL);
		if (new_be_vector == NULL) {
			rc = -ENOMEM;
			goto fail;
		}
		new_be_vector->backend_count = 1;
		new_be_vector->backends[0] = be;
		rcu_assign_pointer(vip->be_vector, new_be_vector);
	} else {
		for(i = 0; i < old_be_vector->backend_count; i++) {
			if (old_be_vector->backends[i] == be) {
				rc = -EEXIST;
				goto fail;
			}
		}
		new_backend_count = old_be_vector->backend_count + 1;
		new_be_vector = kmalloc(sizeof(struct backend_vector) + sizeof(void*) * new_backend_count, GFP_KERNEL);
		if (new_be_vector == NULL) {
			rc = -ENOMEM;
			goto fail;
		}
		new_be_vector->backend_count = new_backend_count;
		memcpy(&new_be_vector->backends, &old_be_vector->backends, sizeof(void*) * (old_be_vector->backend_count));
		new_be_vector->backends[old_be_vector->backend_count] = be;
		rcu_assign_pointer(vip->be_vector, new_be_vector);
		synchronize_rcu();
		kfree(old_be_vector);
	}
	atomic_inc(&be->refcnt);
	
	rc = prepare_reply(info, MINUTEMAN_CMD_ATTACH_BE, &reply_skb);
	
	if (rc < 0)
		return rc;

	rc = send_reply(reply_skb, info);
fail:
	return rc;
}

static int minuteman_nl_cmd_detach_be(struct sk_buff *skb, struct genl_info *info) {
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
	{
		.cmd = MINUTEMAN_CMD_SET_BE,
		.flags = GENL_ADMIN_PERM,
		.doit = minuteman_nl_cmd_set_be,
		.policy = minuteman_policy,
	},
	{
		.cmd = MINUTEMAN_CMD_ATTACH_BE,
		.flags = GENL_ADMIN_PERM,
		.doit = minuteman_nl_cmd_attach_be,
		.policy = minuteman_policy,
	},
	{
		.cmd = MINUTEMAN_CMD_DETACH_BE,
		.flags = GENL_ADMIN_PERM,
		.doit = minuteman_nl_cmd_detach_be,
		.policy = minuteman_policy,
	},
};

static int minuteman_nl_setup(void) {
	return genl_register_family_with_ops(&minuteman_family, minuteman_ops);
}

static int minuteman_nl_unsetup(void) {
	return genl_unregister_family(&minuteman_family);
}

// Begins to return random numbers [0, maxnum) if idx > maxnum
static int randomize_up_to(int idx, int maxnum) {
	int i;
	if (idx < maxnum) {
		return idx;
	} else {
		get_random_bytes(&i, sizeof(i));
		return i % maxnum;
	}
}
// These array sizes are tiny for two reasons:
	// 1. To encourage "mixing" 
	// 2. To not blow up the stack

// Calculate a backend based on the given sockaddr
// Should happen in an rcu_read_lock
static struct backend * get_backend(struct vip *vip) {
	return NULL;
}
static void remap_backend(struct vip *vip, struct sockaddr_in *addr_in) {
	struct backend *be = get_backend(vip);
	if (be == NULL) {
		// TODO: Then we must remap to some logical backend that traps the connection
		return;
	}
		
}

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
	struct socket *sock;
	struct sockaddr *uaddr;
	struct sockaddr_in *addr_in;
	struct vip *v;
	int addr_len;

	sock = (struct socket*) regs->di;
	uaddr = (struct sockaddr*) regs->si;
	addr_len = (int) regs->dx;

	rcu_read_lock();
	if (uaddr->sa_family == AF_INET) {
		addr_in = (struct sockaddr_in*) uaddr;
		v = get_vip(addr_in);
		if (v) {
			// Marks the connection with 1024
			sock->sk->sk_mark |= (1<<10);
			remap_backend(v, addr_in);
		}
	}
	rcu_read_unlock();
	printk(KERN_INFO "Connecting to: %pISpc\n", uaddr);
	/* A dump_stack() here will give a stack backtrace */

	return 0;
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr) {
	printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.pre_handler = handler_pre,
	.fault_handler = handler_fault,
	.symbol_name = "inet_stream_connect",
};

static int __init minuteman_init(void) {
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

static void __exit minuteman_exit(void) {
	unregister_kprobe(&kp);
	printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
	minuteman_nl_unsetup();
}

module_init(minuteman_init)
module_exit(minuteman_exit)
MODULE_LICENSE("GPL");

