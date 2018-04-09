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

#define MODULE_NAME "hstshack"
#define HSTSHACK_VERSION "5.0.0"

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

#define HSTSHACK_println(fmt, ...) \
	do { \
		printk(KERN_DEFAULT "{" MODULE_NAME "}:%s(): " pr_fmt(fmt) "\n", __FUNCTION__, ##__VA_ARGS__); \
	} while (0)

char hsts_host[64] = "router-sh.ptpt52.com";

#define HSTS_RSP_FMT "" \
		"HTTP/1.1 307 Internal Redirect\r\n" \
		"Connection: close\r\n" \
		"Cache-Control: no-cache\r\n" \
		"Content-Type: text/html; charset=UTF-8\r\n" \
		"Location: https://%s/\r\n" \
		"Content-Security-Policy: upgrade-insecure-requests\r\n" \
		"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" \
		"Content-Length: 0\r\n" \
		"\r\n"

char hsts_rsp[1024];

static int hstshack_major = 0;
static int hstshack_minor = 0;
static int number_of_devices = 1;
static struct cdev hstshack_cdev;
const char *hstshack_dev_name = "hstshack_ctl";
static struct class *hstshack_class;
static struct device *hstshack_dev;

static char hstshack_ctl_buffer[PAGE_SIZE];
static void *hstshack_start(struct seq_file *m, loff_t *pos)
{
	int n = 0;

	if ((*pos) == 0) {
		n = snprintf(hstshack_ctl_buffer,
				sizeof(hstshack_ctl_buffer) - 1,
				"# Usage:\n"
				"#    hsts_host=hostname -- set hostname\n"
				"#\n"
				"# Info:\n"
				"#    ...\n"
				"#\n"
				"# Reload cmd:\n"
				"\n"
				"hsts_host=%s\n"
				"\n",
				hsts_host);
		hstshack_ctl_buffer[n] = 0;
		return hstshack_ctl_buffer;
	}

	return NULL;
}

static void *hstshack_next(struct seq_file *m, void *v, loff_t *pos)
{
	return NULL;
}

static void hstshack_stop(struct seq_file *m, void *v)
{
}

static int hstshack_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

const struct seq_operations hstshack_seq_ops = {
	.start = hstshack_start,
	.next = hstshack_next,
	.stop = hstshack_stop,
	.show = hstshack_show,
};

static ssize_t hstshack_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
{
	return seq_read(file, buf, buf_len, offset);
}

static ssize_t hstshack_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
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
			HSTSHACK_println("err: too long a line");
			data_left = 0;
			return -EINVAL;
		}
		goto done;
	} else {
		data[l + data_left] = '\0';
		data_left = 0;
		l++;
	}

	if (strncmp(data, "hsts_host=", 10) == 0) {
		char *tmp = NULL;
		tmp = kmalloc(1024, GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;
		n = sscanf(data, "hsts_host=%s\n", tmp);
		tmp[1023] = 0;
		if (n == 1 && strlen(tmp) <= 63) {
			strcpy(hsts_host, tmp);
			sprintf(hsts_rsp, HSTS_RSP_FMT, hsts_host);
			kfree(tmp);
			goto done;
		}
		kfree(tmp);
	}

	HSTSHACK_println("ignoring line[%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
}

static int hstshack_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &hstshack_seq_ops);
	if (ret)
		return ret;
	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	return 0;
}

static int hstshack_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

static struct file_operations hstshack_fops = {
	.owner = THIS_MODULE,
	.open = hstshack_open,
	.release = hstshack_release,
	.read = hstshack_read,
	.write = hstshack_write,
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

static inline void hstshack_reply(struct sk_buff *oskb, const struct net_device *dev)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int offset, header_len;
	unsigned int seq = jiffies;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	/*stage 1: send syn-ack */
	do {
		offset = sizeof(struct iphdr) + sizeof(struct tcphdr) - oskb->len;
		header_len = offset < 0 ? 0 : offset;
		nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
		if (!nskb) {
			printk("alloc_skb fail\n");
			return;
		}

		if (offset <= 0) {
			if (pskb_trim(nskb, nskb->len + offset)) {
				printk("pskb_trim fail: len=%d, offset=%d\n", nskb->len, offset);
				consume_skb(nskb);
				return;
			}
		} else {
			nskb->len += offset;
			nskb->tail += offset;
		}

		neth = eth_hdr(nskb);
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);

		niph = ip_hdr(nskb);
		memset(niph, 0, sizeof(struct iphdr));
		niph->saddr = oiph->daddr;
		niph->daddr = oiph->saddr;
		niph->version = oiph->version;
		niph->ihl = 5;
		niph->tos = 0;
		niph->tot_len = htons(nskb->len);
		niph->ttl = 0x80;
		niph->protocol = IPPROTO_TCP;
		niph->id = __constant_htons(0xDEAD);
		niph->frag_off = 0x0;

		ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
		ntcph->source = otcph->dest;
		ntcph->dest = otcph->source;
		ntcph->seq = htonl(seq);
		ntcph->ack_seq = htonl(ntohl(otcph->seq) + 1);
		ntcph->res1 = 0;
		ntcph->doff = 5;
		ntcph->syn = 1;
		ntcph->rst = 0;
		ntcph->psh = 0;
		ntcph->ack = 1;
		ntcph->fin = 0;
		ntcph->urg = 0;
		ntcph->ece = 0;

		nskb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_rcsum_tcpudp(nskb);

		skb_push(nskb, (char *)niph - (char *)neth);
		nskb->dev = (struct net_device *)dev;

		dev_queue_xmit(nskb);
	} while (0);

	/*stage 2: send ack and payload */
	do {
		char *data;
		const char *payload = hsts_rsp;
		int payload_len = strlen(hsts_rsp);

		offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len - oskb->len;
		header_len = offset < 0 ? 0 : offset;
		nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
		if (!nskb) {
			printk("alloc_skb fail\n");
			return;
		}

		if (offset <= 0) {
			if (pskb_trim(nskb, nskb->len + offset)) {
				printk("pskb_trim fail: len=%d, offset=%d\n", nskb->len, offset);
				consume_skb(nskb);
				return;
			}
		} else {
			nskb->len += offset;
			nskb->tail += offset;
		}

		neth = eth_hdr(nskb);
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);

		niph = ip_hdr(nskb);
		memset(niph, 0, sizeof(struct iphdr));
		niph->saddr = oiph->daddr;
		niph->daddr = oiph->saddr;
		niph->version = oiph->version;
		niph->ihl = 5;
		niph->tos = 0;
		niph->tot_len = htons(nskb->len);
		niph->ttl = 0x80;
		niph->protocol = IPPROTO_TCP;
		niph->id = __constant_htons(0xDEAD);
		niph->frag_off = 0x0;

		ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
		ntcph->source = otcph->dest;
		ntcph->dest = otcph->source;
		data = (char *)ntcph + sizeof(struct tcphdr);
		memcpy(data, payload, payload_len);
		ntcph->seq = htonl(seq + 1);
		ntcph->ack_seq = htonl(ntohl(otcph->seq) + 1);
		ntcph->res1 = 0;
		ntcph->doff = 5;
		ntcph->syn = 0;
		ntcph->rst = 0;
		ntcph->psh = 0;
		ntcph->ack = 1;
		ntcph->fin = 1;
		ntcph->urg = 0;
		ntcph->ece = 0;

		nskb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_rcsum_tcpudp(nskb);

		skb_push(nskb, (char *)niph - (char *)neth);
		nskb->dev = (struct net_device *)dev;

		dev_queue_xmit(nskb);
	} while (0);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned hstshack_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int hstshack_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	//unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int hstshack_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
#else
static unsigned int hstshack_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
#endif
	struct iphdr *iph;
	void *l4;
	__be32 dst = 0;
	struct in_device *indev;
	struct in_ifaddr *ifa;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP) {
		return NF_ACCEPT;
	}

	l4 = (void *)iph + iph->ihl * 4;
	if (TCPH(l4)->dest != __constant_htons(80)) {
		return NF_ACCEPT;
	}

	if (!(TCPH(l4)->syn && !TCPH(l4)->ack)) {
		return NF_ACCEPT;
	}

	rcu_read_lock();
	indev = __in_dev_get_rcu(in);
	if (indev && indev->ifa_list) {
		ifa = indev->ifa_list;
		dst = ifa->ifa_local;
	}
	rcu_read_unlock();

	if (iph->daddr != dst) {
		return NF_ACCEPT;
	}

	hstshack_reply(skb, in);

	return NF_DROP;
}

static struct nf_hook_ops hstshack_hooks[] = {
	{    
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = hstshack_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK - 10,
	},
};

static int __init hstshack_init(void) {
	int retval = 0;
	dev_t devno;

	HSTSHACK_println("version: " HSTSHACK_VERSION "");

	if (hstshack_major>0) {
		devno = MKDEV(hstshack_major, hstshack_minor);
		retval = register_chrdev_region(devno, number_of_devices, hstshack_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, hstshack_minor, number_of_devices, hstshack_dev_name);
	}
	if (retval < 0) {
		HSTSHACK_println("alloc_chrdev_region failed!");
		return retval;
	}
	hstshack_major = MAJOR(devno);
	hstshack_minor = MINOR(devno);
	HSTSHACK_println("hstshack_major=%d, hstshack_minor=%d", hstshack_major, hstshack_minor);

	cdev_init(&hstshack_cdev, &hstshack_fops);
	hstshack_cdev.owner = THIS_MODULE;
	hstshack_cdev.ops = &hstshack_fops;

	retval = cdev_add(&hstshack_cdev, devno, 1);
	if (retval) {
		HSTSHACK_println("adding chardev, error=%d", retval);
		goto cdev_add_failed;
	}

	hstshack_class = class_create(THIS_MODULE,"hstshack_class");
	if (IS_ERR(hstshack_class)) {
		HSTSHACK_println("failed in creating class");
		retval = -EINVAL;
		goto class_create_failed;
	}

	hstshack_dev = device_create(hstshack_class, NULL, devno, NULL, hstshack_dev_name);
	if (!hstshack_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	sprintf(hsts_rsp, HSTS_RSP_FMT, hsts_host);

	retval = nf_register_hooks(hstshack_hooks, ARRAY_SIZE(hstshack_hooks));
	if (retval) {
		goto err0;
	}

	return 0;

	//nf_unregister_hooks(hstshack_hooks, ARRAY_SIZE(hstshack_hooks));
err0:
	device_destroy(hstshack_class, devno);
device_create_failed:
	class_destroy(hstshack_class);
class_create_failed:
	cdev_del(&hstshack_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, number_of_devices);

	return retval;
}

static void __exit hstshack_exit(void) {
	dev_t devno;

	HSTSHACK_println("removing");

	nf_unregister_hooks(hstshack_hooks, ARRAY_SIZE(hstshack_hooks));

	devno = MKDEV(hstshack_major, hstshack_minor);
	device_destroy(hstshack_class, devno);
	class_destroy(hstshack_class);
	cdev_del(&hstshack_cdev);
	unregister_chrdev_region(devno, number_of_devices);
	HSTSHACK_println("done");
	return;
}

module_init(hstshack_init);
module_exit(hstshack_exit);

MODULE_AUTHOR("Q2hlbiBNaW5xaWFuZyA8cHRwdDUyQGdtYWlsLmNvbT4=");
MODULE_VERSION(HSTSHACK_VERSION);
MODULE_DESCRIPTION("HSTS Hack for fast bypass http to https");
MODULE_LICENSE("GPL");
