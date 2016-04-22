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
#include <linux/fs.h>
#include <net/route.h>

#include "minuteman.h"

#ifdef DEBUG
# define DEBUG_PRINT(fmt, args...) DEBUG_PRINT()
#else
# define DEBUG_PRINT(fmt, args...) do {} while (0)
#endif

#define MIN(a,b) ((a)<(b) ? (a):(b))

#define TCP_FAILED_THRESHOLD 5
#define TCP_FAILED_BACKEND_BACKOFF_PERIOD 30
#define TCP_FAILED_BACKEND_BACKOFF_PERIOD_JIFFIES TCP_FAILED_BACKEND_BACKOFF_PERIOD * HZ

// TODO: Initialize seed on startup
#define SEED  42
#define MAX_BACKENDS_PER_VIP 16384

// For semi-awful reasons, we don't need to lock here because of genl_lock -- the only API here is the genl API
// and all accesses are serialized :(
#define VIP_HASH_BITS 8
#define BE_HASH_BITS 8

enum {
	BACKEND_UP = 1,
	BACKEND_MAYBE_UP,
	BACKEND_DOWN
};

static DEFINE_HASHTABLE(vip_table, VIP_HASH_BITS);
static DEFINE_HASHTABLE(be_table, BE_HASH_BITS);

struct sockaddr_in blackhole;

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
	spinlock_t lock;
	atomic_t reachable; // Did lashup decide it was reachable
	atomic_t refcnt;
	atomic64_t last_failure;
	atomic_t consecutive_failures;
	atomic_t total_successes;
	atomic_t total_failures;
	atomic_t pending;
};

struct lb_scratch {
	DECLARE_BITMAP(up_backends, MAX_BACKENDS_PER_VIP);
	DECLARE_BITMAP(maybe_up_backends, MAX_BACKENDS_PER_VIP);
	DECLARE_BITMAP(down_backends, MAX_BACKENDS_PER_VIP);

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

static int minuteman_nl_fill_be(struct sk_buff *skb, struct backend *be) {
	struct nlattr *nla;
	int rc;
	nla = nla_nest_start(skb, MINUTEMAN_ATTR_BE);
	if (!nla)
		return -EMSGSIZE;
	rc = nla_put_u32(skb, MINUTEMAN_ATTR_BE_IP, be->backend_addr.sin_addr.s_addr);
	if (rc < 0)
		return rc;
	rc = nla_put_u16(skb, MINUTEMAN_ATTR_BE_PORT, be->backend_addr.sin_port);
	if (rc < 0)
		return rc;
	rc = nla_put_u64(skb, MINUTEMAN_ATTR_BE_CONSECUTIVE_FAILURES, atomic_read(&be->consecutive_failures));
	if (rc < 0)
		return rc;
	rc = nla_put_u64(skb, MINUTEMAN_ATTR_BE_LAST_FAILURE, (unsigned long int) atomic_read(&be->consecutive_failures));
	if (rc < 0)
		return rc;
	rc = nla_put_u64(skb, MINUTEMAN_ATTR_BE_CONSECUTIVE_FAILURES, atomic_read(&be->consecutive_failures));
	if (rc < 0)
		return rc;
	rc = nla_put_u64(skb, MINUTEMAN_ATTR_BE_PENDING, atomic_read(&be->pending));
	if (rc < 0)
		return rc;
	rc = nla_put_u64(skb, MINUTEMAN_ATTR_BE_TOTAL_FAILURES, atomic_read(&be->total_failures));
	if (rc < 0)
		return rc;
	rc = nla_put_u64(skb, MINUTEMAN_ATTR_BE_TOTAL_SUCCESSES, atomic_read(&be->total_successes));
	nla_nest_end(skb, nla);
	return 0;
}
static int minuteman_nl_dump_be(struct sk_buff *skb, struct backend *be, struct netlink_callback *cb) {
	void *hdr;
	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq, &minuteman_family, NLM_F_MULTI, MINUTEMAN_CMD_NOOP);
	if (minuteman_nl_fill_be(skb, be) < 0)
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;
	nla_put_failure:
		genlmsg_cancel(skb, hdr);
		return -EMSGSIZE;
}
static int minuteman_nl_fill_vip_be(struct sk_buff *skb, struct vip *vip, struct backend *be) {
	struct nlattr *nla;
	int rc;
	nla = nla_nest_start(skb, MINUTEMAN_ATTR_VIP_BE);
	if (!nla)
		return -EMSGSIZE;
	rc = nla_put_u32(skb, MINUTEMAN_ATTR_VIP_IP, vip->vip.sin_addr.s_addr);
	if (rc < 0) 
		return rc;
	rc = nla_put_u16(skb, MINUTEMAN_ATTR_VIP_PORT, vip->vip.sin_port);
	if (rc < 0) 
		return rc;
	rc = nla_put_u32(skb, MINUTEMAN_ATTR_BE_IP, be->backend_addr.sin_addr.s_addr);
	if (rc < 0)
		return rc;
	rc = nla_put_u16(skb, MINUTEMAN_ATTR_BE_PORT, be->backend_addr.sin_port);
	if (rc < 0)
		return rc;
	nla_nest_end(skb, nla);
	return 0;
	
}
static int minuteman_nl_dump_vip_be(struct sk_buff *skb, struct vip *vip, struct backend *be, struct netlink_callback *cb) {
	void *hdr;
	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq, &minuteman_family, NLM_F_MULTI, MINUTEMAN_CMD_NOOP);
	if (!hdr)
		return -EMSGSIZE;
	if (minuteman_nl_fill_vip_be(skb, vip, be) < 0)
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;
	nla_put_failure:
		genlmsg_cancel(skb, hdr);
		return -EMSGSIZE;
}
static int minuteman_nl_fill_vip(struct sk_buff *skb, struct vip *vip) {
	struct nlattr *nla;
	int rc;
	nla = nla_nest_start(skb, MINUTEMAN_ATTR_VIP);
	if (!nla)
		return -EMSGSIZE;
	rc = nla_put_u32(skb, MINUTEMAN_ATTR_VIP_IP, vip->vip.sin_addr.s_addr);
	if (rc < 0) 
		return rc;
	rc = nla_put_u16(skb, MINUTEMAN_ATTR_VIP_PORT, vip->vip.sin_port);
	if (rc < 0) 
		return rc;
	nla_nest_end(skb, nla);
	return 0;
}
static int minuteman_nl_dump_vip(struct sk_buff *skb, struct vip *vip, struct netlink_callback *cb) {
	void *hdr;
	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq, &minuteman_family, NLM_F_MULTI, MINUTEMAN_CMD_NOOP);
	if (!hdr)
		return -EMSGSIZE;
	if (minuteman_nl_fill_vip(skb, vip) < 0)
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;
	nla_put_failure:
		genlmsg_cancel(skb, hdr);
		return -EMSGSIZE;
}
static int minuteman_nl_dump_noop(struct sk_buff *skb, struct netlink_callback *cb) {
	int rc = 0, x = 0, y;
	struct vip *vip;
	int bkt;
	struct backend_vector *be_vector;
	struct backend *be;
	int vip_idx = 0, be_idx = 0;
	rcu_read_lock();
	
	hash_for_each(vip_table, bkt, vip, hash_list) {
		if (vip_idx++ < cb->args[0])
			continue;
		
		// Only dump on the first "go-around"
		if (cb->args[1] == 0) {
			rc = minuteman_nl_dump_vip(skb, vip, cb);
			if (rc  < 0) {
				goto error;
			}
		}
		be_vector = vip->be_vector;
		for (y = 0; y < be_vector->backend_count; y++) {
			printk("Dumping BE %d, %d for VIP %d\n", x, y, vip_idx);
			if (x++ < cb->args[1]) 
				continue;
			be = be_vector->backends[y];
			rc = minuteman_nl_dump_vip_be(skb, vip, be, cb);
			if (rc  < 0) {
				goto error;
			}
			cb->args[1] = x;
			goto jump_out;
		}
		cb->args[0] = vip_idx;
		cb->args[1] = 0;
	}
	hash_for_each(be_table, bkt, be, hash_list) {
		if (be_idx++ < cb->args[2])
			continue;
		rc = minuteman_nl_dump_be(skb, be, cb);
		if (rc  < 0) {
			goto error;
		}
	}
	jump_out:
	cb->args[2] = be_idx;
	rcu_read_unlock();
	return skb->len;
	
	error:
	rcu_read_unlock();
	return rc;
}
static int validate_minuteman_nl_cmd_add_vip(struct genl_info *info) { 
	if (!info) return -EINVAL;
	if (!(info->attrs[MINUTEMAN_ATTR_VIP_IP])) {
		return -EINVAL;
	}
	if (!(info->attrs[MINUTEMAN_ATTR_VIP_PORT])) {
		return -EINVAL;
	}
	return 0;
}
static int minuteman_nl_cmd_add_vip(struct sk_buff *skb, struct genl_info *info) {
	int rc = 0;
	struct vip *v;
	int hash;
	struct sockaddr_in addr;

	rc = validate_minuteman_nl_cmd_add_vip(info);
	if (rc != 0) {
		return rc;
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
	atomic_set(&be->refcnt, 0);
	atomic_set(&be->consecutive_failures, 0);
	atomic_set(&be->pending, 0);
	atomic_set(&be->total_failures, 0);
	atomic_set(&be->total_successes, 0);
	atomic_set(&be->reachable, 0);
	spin_lock_init(&be->lock);
	
	hash = hash_sockaddr(&be_addr);
	hash_add_rcu(be_table, &be->hash_list, hash);
	
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
fail:
	return rc;
}

static int minuteman_nl_cmd_detach_be(struct sk_buff *skb, struct genl_info *info) {
}

static const struct genl_ops minuteman_ops[] = {
	{
		.cmd = MINUTEMAN_CMD_NOOP,
		.flags = GENL_ADMIN_PERM,
		.dumpit = minuteman_nl_dump_noop,
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

// Although % doesn't result in "perfect" rnd, good enough
static int rnd(unsigned int maxnum) {
	unsigned int i;
	get_random_bytes(&i, sizeof(i));
	return i % maxnum;
}

// max_n = total number of set bits
// bitsize = how big the bitset is
static void choose_two(int bitsize, int max_n, const unsigned long *addr, int *ret1, int *ret2) {
	int n1, n2, found_bits, tries, i, curbitidx;
	tries = 0;
	curbitidx = -1;
	found_bits = 0;

	n1 = rnd(max_n);
	do {
		n2 = rnd(max_n);
		tries++;
	} while (n1 == n2 && tries < 20);
	
	for (i = 0; i < max_n; i++) {
		curbitidx++;
		curbitidx = find_next_bit(addr, max_n, curbitidx);
		if (i == n1) {
			*ret1 = curbitidx;
		} 
		if (i == n2) {
			*ret2 = curbitidx;
		}
	}
}

int is_open(struct backend *be) {
	int reachable;
	int consecutive_failures;
	long int last_failure;
	reachable = atomic_read(&be->reachable);
	spin_lock(&be->lock);
	consecutive_failures = atomic_read(&be->consecutive_failures);
	last_failure = atomic64_read(&be->last_failure);
	spin_unlock(&be->lock);

	if ((consecutive_failures > TCP_FAILED_THRESHOLD) && 
		 (((signed long int)jiffies - last_failure) < TCP_FAILED_BACKEND_BACKOFF_PERIOD_JIFFIES)) {
		return BACKEND_DOWN;
	} else if (reachable == 1) {
		return BACKEND_UP;
	} else {
		return BACKEND_MAYBE_UP; 
	}
}

static int be_cost(struct backend *be) {
	return atomic_read(&be->pending);
}

static struct backend * get_backend(struct lb_scratch *scratch_space, struct vip *vip) {
	struct backend_vector *be_vector;
	struct backend *be, *be1, *be2;
	int i, state;
	int total_backend_cnt;
	
	int n1 = 0;
	int n2 = 0;

	// Backends that haven't had recent failures and have been marked up by Lashup
	int up_backends_cnt = 0;
	// Backends that haven't had recent failures and have not been marked up by Lashup
	int maybe_up_backends_cnt = 0;
	// Down backends
	int down_backends_cnt = 0;
	
	be_vector = vip->be_vector;
	
	total_backend_cnt = MIN(be_vector->backend_count, MAX_BACKENDS_PER_VIP);
	if (total_backend_cnt == 0) {
		return NULL;
	} else if (total_backend_cnt == 1) {
		return be_vector->backends[0];
	}
	bitmap_zero((long unsigned int *)&scratch_space->up_backends, MAX_BACKENDS_PER_VIP);
	bitmap_zero((long unsigned int *)&scratch_space->maybe_up_backends, MAX_BACKENDS_PER_VIP);
	bitmap_zero((long unsigned int *)&scratch_space->down_backends, MAX_BACKENDS_PER_VIP);
	
	
	for (i = 0; i < total_backend_cnt; i++) {
		be = be_vector->backends[i];
		state = is_open(be);
		DEBUG_PRINT(KERN_INFO "Backend (%pISpc) status: %d\n", &be->backend_addr, state);

		if (state == BACKEND_DOWN) {
			set_bit(i, (long unsigned int *)&scratch_space->down_backends);
			down_backends_cnt++;
		} else if (state == BACKEND_MAYBE_UP) {
			set_bit(i, (long unsigned int *)&scratch_space->maybe_up_backends);
			maybe_up_backends_cnt++;
		} else if (state == BACKEND_UP) {
			set_bit(i, (long unsigned int *)&scratch_space->up_backends);
			up_backends_cnt++;
		}
	}
	
	// 1. Check up backends
	// 2. Check maybe_up backends
	// 3. Check other backends 
	// 4. Check down backends
	if (up_backends_cnt == 1) {
		i = find_first_bit((const long unsigned int *)&scratch_space->up_backends, MAX_BACKENDS_PER_VIP);
		return be_vector->backends[i];
	} else if (up_backends_cnt > 0) {
		choose_two(MAX_BACKENDS_PER_VIP, up_backends_cnt, 
							 (const long unsigned int *)&scratch_space->up_backends, &n1, &n2);
	} else if (maybe_up_backends_cnt == 1) {
		i = find_first_bit((const long unsigned int *)&scratch_space->maybe_up_backends, MAX_BACKENDS_PER_VIP);
		return be_vector->backends[i];
	} else if (maybe_up_backends_cnt > 0) {
		choose_two(MAX_BACKENDS_PER_VIP, maybe_up_backends_cnt, 
							 (const long unsigned int *)&scratch_space->maybe_up_backends, &n1, &n2);
	} else if (down_backends_cnt == 1) {
		i = find_first_bit((const long unsigned int *)&scratch_space->down_backends, MAX_BACKENDS_PER_VIP);
		return be_vector->backends[i];
	} else if (down_backends_cnt > 0) {
		choose_two(MAX_BACKENDS_PER_VIP, down_backends_cnt, 
							 (const long unsigned int *)&scratch_space->down_backends, &n1, &n2);
	}
	be1 = be_vector->backends[n1];
	be2 = be_vector->backends[n2];
	be = (be_cost(be1) > be_cost(be2) ? be2 : be1);
	return be;
}

// Something went wrong
static void remap_backend_to_failure(struct vip *vip, struct sockaddr_in *addr_in) {
	memcpy(addr_in, &blackhole, sizeof(blackhole));
}
static void remap_backend(struct lb_scratch *scratch_space, struct vip *vip, struct sockaddr_in *addr_in) {
	struct backend *be = get_backend(scratch_space, vip);
	if (be == NULL) {
		printk(KERN_INFO "Unable to map backend\n");
		remap_backend_to_failure(vip, addr_in);
	} else {
		// TODO: Then we must remap to some logical backend that traps the connection
		DEBUG_PRINT(KERN_INFO "Remapping connection to backend: %pISpc\n", &be->backend_addr);
		memcpy(addr_in, &be->backend_addr, sizeof(struct sockaddr_in));
	}
		
}
static int tcp_set_state_handler_pre(struct kprobe *p, struct pt_regs *regs) {
	
	struct sock *sk;
	struct socket *sock;
	struct inet_sock *inet;
	int state, oldstate;
	struct backend *be;
	struct sockaddr_in addr;

	state = (int)(regs->si);
	sk = (struct sock*) (regs->di);
	
	if (!sk) {
		return 0;
	}
	if (sk->sk_family != AF_INET) {
		return 0;
	}
	
	inet = inet_sk(sk);

	sock = sk->sk_socket;
	
	oldstate = sk->sk_state;
	addr.sin_family = AF_INET;
	addr.sin_port = inet->inet_dport;
	addr.sin_addr.s_addr = inet->inet_daddr;
	
	DEBUG_PRINT(KERN_INFO "Introspecting state change %pISpc - %d -> %d\n", &addr, oldstate, state);
	if (state == oldstate) {
		return 0;
	}
	be = get_be(&addr);
	if (be) {
		spin_lock(&be->lock);
	}
	rcu_read_unlock();
	if (!be) {
		return 0;
	}
	if (state == TCP_SYN_SENT) {
		atomic_inc(&be->pending);
	} else if (state == TCP_ESTABLISHED) {
		atomic_dec(&be->pending);
		atomic_set(&be->consecutive_failures, 0);
		atomic_inc(&be->total_successes);
	} else if ((oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV) && state == TCP_CLOSE) {
		atomic_dec(&be->pending);
		atomic_inc(&be->total_failures);
		atomic_inc(&be->consecutive_failures);
		atomic64_set(&be->last_failure, (signed long)jiffies);
	}
	spin_unlock(&be->lock);
	return 0;
}
/* kprobe pre_handler: called just before the probed instruction is executed */
static int inet_stream_connect_handler_pre(struct kprobe *p, struct pt_regs *regs) {
	struct socket *sock;
	struct sockaddr *uaddr;
	struct sockaddr_in *addr_in;
	struct vip *v;
	struct lb_scratch *scratch_space;
	int addr_len;
	

	sock = (struct socket*) regs->di;
	uaddr = (struct sockaddr*) regs->si;
	addr_len = (int) regs->dx;

	rcu_read_lock();
	if (uaddr->sa_family == AF_INET) {
		addr_in = (struct sockaddr_in*) uaddr;
		v = get_vip(addr_in);
		if (v) {
			// Maybe we should use a more clever allocator
			// from my understanding kprobes are singletons
			// so maybe we could make this part of the datastructure itself
			scratch_space = kmalloc(sizeof(struct lb_scratch), GFP_KERNEL);
			// Marks the connection with 1024
			sock->sk->sk_mark |= (1<<10);
			if (scratch_space != NULL) {
				remap_backend(scratch_space, v, addr_in);
				kfree(scratch_space);
			} else {
				remap_backend_to_failure(v, addr_in);
			}
		}
	}
	rcu_read_unlock();
	DEBUG_PRINT(KERN_INFO "Connecting to: %pISpc\n", uaddr);
	/* A dump_stack() here will give a stack backtrace */

	return 0;
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr) {
	DEBUG_PRINT(KERN_WARNING "fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.pre_handler = inet_stream_connect_handler_pre,
	.fault_handler = handler_fault,
	.symbol_name = "inet_stream_connect",
};

/* For each probe you need to allocate a kprobe structure */
static struct kprobe tcp_set_state_kp = {
	.pre_handler = tcp_set_state_handler_pre,
	.fault_handler = handler_fault,
	.symbol_name = "tcp_set_state",
};
static int __init minuteman_init(void) {
	int ret;
	memset(&blackhole, 0, sizeof(blackhole));
	
	blackhole.sin_port = 0;
	// 127.6.6.6
	blackhole.sin_addr.s_addr = 0x7f060606;
	ret = minuteman_nl_setup();
	if (ret < 0) {
		printk(KERN_ERR "minuteman_nl_setup failed, returned %d\n", ret);
		return ret;
	}
	ret = register_kprobe(&kp);
	if (ret < 0) {
		printk(KERN_ERR "register_kprobe failed, returned %d\n", ret);
		minuteman_nl_unsetup();
		return ret;
	}
	
	ret = register_kprobe(&tcp_set_state_kp);
	if (ret < 0) {
		printk(KERN_ERR "register_kprobe failed, returned %d\n", ret);
		unregister_kprobe(&kp);
		minuteman_nl_unsetup();
		return ret;
	}
	printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);

	return 0;
}

static void __exit minuteman_exit(void) {
	unregister_kprobe(&kp);
	printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
	unregister_kprobe(&tcp_set_state_kp);
	printk(KERN_INFO "kprobe at %p unregistered\n", tcp_set_state_kp.addr);
	minuteman_nl_unsetup();
}

module_init(minuteman_init)
module_exit(minuteman_exit)
MODULE_LICENSE("GPL and additional rights");

