#include <linux/module.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/net_namespace.h>
#include <net/inet_common.h>

int udp_sock_create4(struct net *net, struct udp_port_cfg *cfg,
		     struct sock **skp)
{
	int err;
	struct sock *sk = NULL;
	struct sockaddr_in udp_addr;

	sk = sk_alloc(net, PF_INET, GFP_KERNEL, &udp_prot);
	if (!sk)
		goto error;
	sock_init_data(NULL, sk);

	udp_addr.sin_family = AF_INET;
	udp_addr.sin_addr = cfg->local_ip;
	udp_addr.sin_port = cfg->local_udp_port;
	err = inet_bind_sk(sk, (struct sockaddr *)&udp_addr, sizeof(udp_addr));
	if (err < 0)
		goto error;

	if (cfg->peer_udp_port) {
		udp_addr.sin_family = AF_INET;
		udp_addr.sin_addr = cfg->peer_ip;
		udp_addr.sin_port = cfg->peer_udp_port;
		err = inet_dgram_connect_sk(sk, (struct sockaddr *)&udp_addr,
					    sizeof(udp_addr), 0);
		if (err < 0)
			goto error;
	}

	sk->sk_no_check_tx = !cfg->use_udp_checksums;

	*skp = sk;
	return 0;

error:
	if (sk)
		udp_tunnel_sock_release(sk);
	*skp = NULL;
	return err;
}
EXPORT_SYMBOL(udp_sock_create4);

void setup_udp_tunnel_sock(struct net *net, struct sock *sk,
			   struct udp_tunnel_sock_cfg *cfg)
{
	/* Disable multicast loopback */
	inet_sk(sk)->mc_loop = 0;

	/* Enable CHECKSUM_UNNECESSARY to CHECKSUM_COMPLETE conversion */
	inet_inc_convert_csum(sk);

	rcu_assign_sk_user_data(sk, cfg->sk_user_data);

	udp_sk(sk)->encap_type = cfg->encap_type;
	udp_sk(sk)->encap_rcv = cfg->encap_rcv;
	udp_sk(sk)->encap_destroy = cfg->encap_destroy;

	udp_tunnel_encap_enable(sk);
}
EXPORT_SYMBOL_GPL(setup_udp_tunnel_sock);

int udp_tunnel_xmit_skb(struct rtable *rt, struct sock *sk, struct sk_buff *skb,
			__be32 src, __be32 dst, __u8 tos, __u8 ttl,
			__be16 df, __be16 src_port, __be16 dst_port,
			bool xnet, bool nocheck)
{
	struct udphdr *uh;

	__skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);

	uh->dest = dst_port;
	uh->source = src_port;
	uh->len = htons(skb->len);

	udp_set_csum(nocheck, skb, src, dst, skb->len);

	return iptunnel_xmit(sk, rt, skb, src, dst, IPPROTO_UDP,
			     tos, ttl, df, xnet);
}
EXPORT_SYMBOL_GPL(udp_tunnel_xmit_skb);

void udp_tunnel_sock_release(struct sock *sk)
{
	inet_shutdown_sk(sk, SHUT_RDWR, NULL);
	sk_release_kernel(sk);
}
EXPORT_SYMBOL_GPL(udp_tunnel_sock_release);

MODULE_LICENSE("GPL");
