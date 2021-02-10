#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/filter.h>

#define ARRAY_SIZE(arr) \
    (sizeof(arr) / sizeof((arr)[0]) \
     + sizeof(typeof(int[1 - 2 * \
           !!__builtin_types_compatible_p(typeof(arr), \
                 typeof(&arr[0]))])) * 0)

#define ETH_A_FORMAT        "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETH_A_FROM_PTR(p)   *(p+0), *(p+1), *(p+2), *(p+3), *(p+4), *(p+5)

// filter is generated with: tcpdump -dd "udp port 67"
static const struct sock_filter dhcp_filter[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 6, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 15, 0x00000011 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 12, 0, 0x00000043 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 10, 11, 0x00000043 },
    { 0x15, 0, 10, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 8, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00000043 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00000043 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};

static const struct sock_fprog bpf = {
        .len = ARRAY_SIZE(dhcp_filter),
        .filter = dhcp_filter,
};

#define DHCP_CHADDR_MAX 16

struct dhcp_packet {
  uint8_t op, htype, hlen, hops;
  uint32_t xid;
  uint16_t secs, flags;
  struct in_addr ciaddr, yiaddr, siaddr, giaddr;
  uint8_t chaddr[DHCP_CHADDR_MAX], sname[64], file[128];
  uint8_t options[312];
};

void hexdump(const void *data, size_t len)
{
    const uint8_t *ptr = data;

    while(len >= 16)
    {
        printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
            ptr[0],
            ptr[1],
            ptr[2],
            ptr[3],
            ptr[4],
            ptr[5],
            ptr[6],
            ptr[7],
            ptr[8],
            ptr[9],
            ptr[10],
            ptr[11],
            ptr[12],
            ptr[13],
            ptr[14],
            ptr[15]);
        len -= 16;
        ptr += 16;
    }

    while (len--)
    {
        printf("%02x ", *ptr++);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    int sock_raw = socket(AF_PACKET, SOCK_RAW , htons(ETH_P_ALL));

    if (sock_raw < 0)
    {
        printf("Errno %d, could not open a packet socket: %s\n", errno, strerror(errno));
        return errno;
    }

    int ret = setsockopt(sock_raw, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    if (ret < 0)
    {
        printf("Errno %d, could not attack the packet filter: %s\n", errno, strerror(errno));
        return errno;
    }

    char buffer[4096];

    while(1)
    {
        ret = read(sock_raw, buffer, sizeof(buffer));

        // Ethernet header
        struct ether_header *ether_hdr = (struct ether_header *) buffer;


        if (ntohs(ether_hdr->ether_type) == ETH_P_IP)
        {
            // IP header
            struct iphdr *ip_hdr = (struct iphdr*)(buffer + sizeof(struct ether_header));

            size_t ip_hdr_length = ip_hdr->ihl * sizeof(uint32_t);

            if (ip_hdr->protocol == IPPROTO_UDP)
            {
                // UDP header
                struct udphdr *udp_hdr = (struct udphdr*)(buffer + sizeof(struct ether_header) + ip_hdr_length);

                printf("ret=%d\n", ret);

                printf("ETH " ETH_A_FORMAT " -> " ETH_A_FORMAT"\n", ETH_A_FROM_PTR(ether_hdr->ether_shost), ETH_A_FROM_PTR(ether_hdr->ether_dhost));
                printf("UDP %d -> %d\n", ntohs(udp_hdr->source), ntohs(udp_hdr->dest));

                const uint8_t *dhcp_payload = (uint8_t*)(udp_hdr) + sizeof(struct udphdr);
                hexdump(dhcp_payload, ntohs(udp_hdr->len));

                const struct dhcp_packet *dhcp = (struct dhcp_packet*) dhcp_payload;

                printf("DHCP chaddr: " ETH_A_FORMAT "\n", ETH_A_FROM_PTR(dhcp->chaddr));

                return 0;
            }
        }
    }
}

