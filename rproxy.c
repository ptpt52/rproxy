/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 19 Dec 2012 09:52:21 +0800
 */
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
static inline int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	return nf_register_net_hooks(&init_net, reg, n);
}

static inline void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	nf_unregister_net_hooks(&init_net, reg, n);
}
#endif


#define MODULE_NAME "rproxy"
#define RPROXY_VERSION "0.0.1"

#define RPROXY_println(fmt, ...) \
	do { \
		printk(KERN_DEFAULT "{" MODULE_NAME "}:%s(): " pr_fmt(fmt) "\n", __FUNCTION__, ##__VA_ARGS__); \
	} while (0)

static int rproxy_major = 0;
static int rproxy_minor = 0;
static int number_of_devices = 1;
static struct cdev rproxy_cdev;
const char *rproxy_dev_name = "rproxy_ctl";
static struct class *rproxy_class;
static struct device *rproxy_dev;

static char rproxy_ctl_buffer[PAGE_SIZE];
static void *rproxy_start(struct seq_file *m, loff_t *pos)
{
	int n = 0;

	if ((*pos) == 0) {
		n = snprintf(rproxy_ctl_buffer,
				sizeof(rproxy_ctl_buffer) - 1,
				"# Usage:\n"
				"#\n"
				"# Info:\n"
				"#    ...\n"
				"#\n"
				"# Reload cmd:\n"
				"\n"
				"\n");
		rproxy_ctl_buffer[n] = 0;
		return rproxy_ctl_buffer;
	}

	return NULL;
}

static void *rproxy_next(struct seq_file *m, void *v, loff_t *pos)
{
	return NULL;
}

static void rproxy_stop(struct seq_file *m, void *v)
{
}

static int rproxy_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

const struct seq_operations rproxy_seq_ops = {
	.start = rproxy_start,
	.next = rproxy_next,
	.stop = rproxy_stop,
	.show = rproxy_show,
};

static ssize_t rproxy_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
{
	return seq_read(file, buf, buf_len, offset);
}

static ssize_t rproxy_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	int err = 0;
	int n, l;
	int cnt = 256;
	static char data[256];
	static int data_left = 0;

	cnt -= data_left;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data + data_left, buf, cnt) != 0)
		return -EACCES;

	n = 0;
	while(n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t')) n++;
	if (n) {
		*offset += n;
		data_left = 0;
		return n;
	}

	//make sure line ended with '\n' and line len <=256
	l = 0;
	while (l < cnt && data[l + data_left] != '\n') l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= 256) {
			RPROXY_println("err: too long a line");
			data_left = 0;
			return -EINVAL;
		}
		goto done;
	} else {
		data[l + data_left] = '\0';
		data_left = 0;
		l++;
	}

	RPROXY_println("ignoring line[%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
}

static int rproxy_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &rproxy_seq_ops);
	if (ret)
		return ret;
	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	return 0;
}

static int rproxy_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

static struct file_operations rproxy_fops = {
	.owner = THIS_MODULE,
	.open = rproxy_open,
	.release = rproxy_release,
	.read = rproxy_read,
	.write = rproxy_write,
	.llseek  = seq_lseek,
};

int skb_rcsum_tcpudp(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	int len = ntohs(iph->tot_len);

	if (skb->len < len) {
		return -1;
	} else if (len < (iph->ihl * 4)) {
		return -1;
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl*4);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			tcph->check = 0;
			tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_TCP, 0);
			skb->csum_start = (unsigned char *)tcph - skb->head;
			skb->csum_offset = offsetof(struct tcphdr, check);
		} else {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			skb->csum = 0;
			tcph->check = 0;
			skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
			tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);
			if (skb->ip_summed == CHECKSUM_COMPLETE) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = (struct udphdr *)((void *)iph + iph->ihl*4);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			udph->check = 0;
			udph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_UDP, 0);
			skb->csum_start = (unsigned char *)udph - skb->head;
			skb->csum_offset = offsetof(struct udphdr, check);
		} else {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			if (udph->check) {
				skb->csum = 0;
				udph->check = 0;
				skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
				udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);
				if (udph->check == 0)
					udph->check = CSUM_MANGLED_0;
			}
			if (skb->ip_summed == CHECKSUM_COMPLETE) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
		}
	} else {
		return -1;
	}

	return 0;
}

#define TCPH(t) ((struct tcphdr *)(t))

#define RPROXY_UA1 "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36 Edge/12.0"
#define RPROXY_UA2 "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Edge/12.0"
#define RPROXY_UA3 "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/12.0"
#define RPROXY_UA4 "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)"
#define RPROXY_UA5 "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36"
#define RPROXY_UA6 "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64)"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned rproxy_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int rproxy_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	//unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int rproxy_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
#else
static unsigned int rproxy_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	unsigned char *data;
	int data_len;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}

	//rewrite set ttl to 64
	iph = ip_hdr(skb);
	csum_replace2(&iph->check, htons(iph->ttl << 8), htons(64 << 8));
	iph->ttl = 64;

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}

	if (iph->protocol != IPPROTO_TCP) {
		return NF_ACCEPT;
	}

	l4 = (void *)iph + iph->ihl * 4;

	data = skb->data + (iph->ihl << 2) + (TCPH(l4)->doff << 2);
	data_len = ntohs(iph->tot_len) - ((iph->ihl << 2) + (TCPH(l4)->doff << 2));
	if (data_len > 24 &&
			((data[0] >= 'a' && data[0] <= 'z') || (data[0] >= 'A' && data[0] <= 'Z')) &&
			((data[1] >= 'a' && data[1] <= 'z') || (data[1] >= 'A' && data[1] <= 'Z'))) {
		//TODO
		int p_len = 0;
		unsigned char *p = data;
		do {
			while (p - data < data_len && *p++ != '\n') ;
			if (p + 23 - data >= data_len) break;

			if (strncasecmp(p, "User-Agent: Mozilla/5.0", 23) == 0) {
				while (p + p_len - data < data_len && *(p + p_len) != '\n') p_len++;
				if (*(p + p_len) == '\n' && p_len > 0) {
					*(p + p_len) = '\0';
					//printk("get %s\n", p);
					memset(p + 23, ' ', p_len);
					if (strlen(RPROXY_UA1) <= p_len) {
						memcpy(p, RPROXY_UA1, strlen(RPROXY_UA1));
					} else if (strlen(RPROXY_UA2) <= p_len) {
						memcpy(p, RPROXY_UA2, strlen(RPROXY_UA2));
					} else if (strlen(RPROXY_UA3) <= p_len) {
						memcpy(p, RPROXY_UA3, strlen(RPROXY_UA3));
					} else if (strlen(RPROXY_UA4) <= p_len) {
						memcpy(p, RPROXY_UA4, strlen(RPROXY_UA4));
					} else if (strlen(RPROXY_UA5) <= p_len) {
						memcpy(p, RPROXY_UA5, strlen(RPROXY_UA5));
					} else if (strlen(RPROXY_UA6) <= p_len) {
						memcpy(p, RPROXY_UA6, strlen(RPROXY_UA6));
					}
					*(p + p_len) = '\n';
					skb_rcsum_tcpudp(skb);
					break;
				}
			}
		} while (p - data < data_len);
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops rproxy_hooks[] = {
	{    
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = rproxy_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 10,
	},
};

static int __init rproxy_init(void) {
	int retval = 0;
	dev_t devno;

	RPROXY_println("version: " RPROXY_VERSION "");

	if (rproxy_major>0) {
		devno = MKDEV(rproxy_major, rproxy_minor);
		retval = register_chrdev_region(devno, number_of_devices, rproxy_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, rproxy_minor, number_of_devices, rproxy_dev_name);
	}
	if (retval < 0) {
		RPROXY_println("alloc_chrdev_region failed!");
		return retval;
	}
	rproxy_major = MAJOR(devno);
	rproxy_minor = MINOR(devno);
	RPROXY_println("rproxy_major=%d, rproxy_minor=%d", rproxy_major, rproxy_minor);

	cdev_init(&rproxy_cdev, &rproxy_fops);
	rproxy_cdev.owner = THIS_MODULE;
	rproxy_cdev.ops = &rproxy_fops;

	retval = cdev_add(&rproxy_cdev, devno, 1);
	if (retval) {
		RPROXY_println("adding chardev, error=%d", retval);
		goto cdev_add_failed;
	}

	rproxy_class = class_create(THIS_MODULE,"rproxy_class");
	if (IS_ERR(rproxy_class)) {
		RPROXY_println("failed in creating class");
		retval = -EINVAL;
		goto class_create_failed;
	}

	rproxy_dev = device_create(rproxy_class, NULL, devno, NULL, rproxy_dev_name);
	if (!rproxy_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	retval = nf_register_hooks(rproxy_hooks, ARRAY_SIZE(rproxy_hooks));
	if (retval) {
		goto err0;
	}

	return 0;

	//nf_unregister_hooks(rproxy_hooks, ARRAY_SIZE(rproxy_hooks));
err0:
	device_destroy(rproxy_class, devno);
device_create_failed:
	class_destroy(rproxy_class);
class_create_failed:
	cdev_del(&rproxy_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, number_of_devices);

	return retval;
}

static void __exit rproxy_exit(void) {
	dev_t devno;

	RPROXY_println("removing");

	nf_unregister_hooks(rproxy_hooks, ARRAY_SIZE(rproxy_hooks));

	devno = MKDEV(rproxy_major, rproxy_minor);
	device_destroy(rproxy_class, devno);
	class_destroy(rproxy_class);
	cdev_del(&rproxy_cdev);
	unregister_chrdev_region(devno, number_of_devices);
	RPROXY_println("done");
	return;
}

module_init(rproxy_init);
module_exit(rproxy_exit);

MODULE_AUTHOR("Q2hlbiBNaW5xaWFuZyA8cHRwdDUyQGdtYWlsLmNvbT4=");
MODULE_VERSION(RPROXY_VERSION);
MODULE_DESCRIPTION("rproxy to replace user-agent for HTTP request");
MODULE_LICENSE("GPL");
