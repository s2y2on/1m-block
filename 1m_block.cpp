#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <libnet.h> 
#include <map>
#include <string>
#include <iostream>

using namespace std;

map<string, int> mymap;

char target_str[100] = { "Host: " }; 
int block;

void usage(void)
{
	printf("Wrong usage!\n");
	printf("syntax: ./1m_block <site lisy file>\n");
	printf("sample: ./1m_block top-1m.txt\n");

	return;
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

uint8_t custom_compare(unsigned char* arr, uint8_t num) {

	int ret = 0;
	for (int i = 0; i<strlen(target_str); i++) {
		if (arr[i + num] == target_str[i])
			ret += 1;
	}
	if (ret == strlen(target_str))
		return 0;
	else
		return 1;
}

uint8_t map_find(map<string, int> &m, string str) {
	if (m.count(str)) {
		return 1; // exist
	}
	else {
		return 0; // not exist
	}
}

static u_int32_t print_pkt(struct nfq_data *tb, struct nfq_q_handle *qh)

{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);

	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);

	if (hwph) {

		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");

		for (i = 0; i < hlen - 1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen - 1]);
	}

	mark = nfq_get_nfmark(tb);

	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);

	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);

	if (ifi)
		printf("outdev=%u ", ifi);

	ifi = nfq_get_physindev(tb);

	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);

	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);

	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	u_int32_t  filter = 0;
	block = 0;
	for (auto it = mymap.begin(); it != mymap.end(); it++) {
		strcat(target_str, it->first.c_str()) ;


		for (int i = 0; i<ret - strlen(target_str); i++) {
			if (!custom_compare(data, i)) {
				int t = 0;
				char arr[100];
				while (data[i + t + 6] != '.') {
					arr[t] = data[i + t + 6];
					t++;
				}
				arr[t + 1] = 0;
				printf("\n*********************************************************\n");
				if (map_find(mymap, arr))
					block = 1;
				printf("\n*********************************************************\n");
				break;
			}
		}
	}

	return id;

}





static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,

	struct nfq_data *nfa, void *data)

{

	u_int32_t id = print_pkt(nfa, qh);

	if (block != 0) {
		printf("This is bad site!\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}

	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);


}

int read_csv(char * filename) {
	char str_tmp[1024];
	FILE *pFile = NULL;
	pFile = fopen(filename, "r");
	if (pFile == NULL) {
		printf("file open error\n");
		return -1;
	}

	if (pFile != NULL) {
		while (!feof(pFile)) {
			fscanf(pFile, "%s\n", str_tmp);
			char *tok = strtok(str_tmp, ",");
			tok = strtok(NULL, ",");
			mymap.insert(make_pair(tok, 0));
		}
	}
	/*

	*/
	fclose(pFile);
}

int main(int argc, char * argv[])

{
	read_csv(argv[1]);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;

	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));



	if (argc != 2) {
		usage();
		return -1;
	}


	printf("opening library handle\n");
	h = nfq_open();

	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");

	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");

	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);

	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {

		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		/* if your application is too slow to digest the packets that
		* are sent from kernel-space, the socket buffer that we use
		* to enqueue packets may fill up returning ENOBUFS. Depending
		* on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		* the doxygen documentation of this library on how to improve
		* this situation.
		*/

		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}

		perror("recv failed");
		break;

	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);




#ifdef INSANE

	/* normally, applications SHOULD NOT issue this command, since
	* it detaches other programs/sockets from AF_INET, too ! */

	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);

#endif

	printf("closing library handle\n");
	nfq_close(h);
	exit(0);

}