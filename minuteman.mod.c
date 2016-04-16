#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x6c15661c, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x638fe045, __VMLINUX_SYMBOL_STR(unregister_kprobe) },
	{ 0xc027dd22, __VMLINUX_SYMBOL_STR(genl_unregister_family) },
	{ 0x512b1d19, __VMLINUX_SYMBOL_STR(register_kprobe) },
	{ 0xe863c844, __VMLINUX_SYMBOL_STR(__genl_register_family) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xb4f22726, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x3a40aaab, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x7e900f6f, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0x99f1da57, __VMLINUX_SYMBOL_STR(netlink_unicast) },
	{ 0x19439f53, __VMLINUX_SYMBOL_STR(genlmsg_put) },
	{ 0xe3682c94, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "900BE2E9F06497B8CF54CB6");
