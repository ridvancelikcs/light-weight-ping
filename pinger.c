#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <fcntl.h>

#define BUF_SIZE		64
#define RECV_TIMEOUT	1                                                          // timeout value for SO_RCVTIMEO in sec
#define ECHO_MESSAGE	"This is your captain speaking.	Give me a nice echo dude"  // 56 bytes with null terminator

typedef struct ping_pckt_send
{
	struct icmphdr	icmp_hdr;
	char			msg[BUF_SIZE - sizeof(struct icmphdr)];
} x_ping_pckt_t;

typedef struct ping_pckt_recv
{
	struct iphdr	ip_hdr;										// Kernel adds an extra iphdr into received packet
	struct icmphdr	icmp_hdr;
	char			msg[BUF_SIZE - sizeof(struct icmphdr)];
} r_ping_pckt_t;

unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

// success: returns rtt in usec
// error: returns zero 
int send_ping(char *ip)
{
	struct sockaddr_in ping_addr;
	ping_addr.sin_family = AF_INET;
	ping_addr.sin_port = htons(0);
	memset(ping_addr.sin_zero, 0x0, sizeof(ping_addr.sin_zero));
	if (inet_pton(AF_INET, ip, &(ping_addr.sin_addr)) != 1)
	{
		printf("No valid address to PING: %s!!\n", ip);
		return (0);
	}
	
	int ping_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (ping_sock_fd < 0)
	{
		printf("Socket file descriptor not received!!\n");
		return 0;
	}

	int ttl_val = 128;
	if (setsockopt(ping_sock_fd, SOL_IP, IP_TTL, &ttl_val, sizeof(int)) != 0)
	{
		printf("Set socket option TTL failed! value: %d\n", ttl_val);
		close(ping_sock_fd);
		return 0;
	}
	
	struct timeval tv_out;
	tv_out.tv_sec = RECV_TIMEOUT;
	tv_out.tv_usec = 0;
	if (setsockopt(ping_sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_out, sizeof(struct timeval)) != 0)
	{
		printf("Set socket option TIMEOUT failed! value: %ld\n", tv_out.tv_sec);
		close(ping_sock_fd);
		return 0;
	}

	// fill packet
	x_ping_pckt_t		x_pckt;
	struct timespec		time_start;
	struct timespec		time_end;
	static int			msg_count;
	
	memset(&x_pckt, 0x0, sizeof(x_ping_pckt_t));	
	x_pckt.icmp_hdr.type = ICMP_ECHO;			// 8
	x_pckt.icmp_hdr.un.echo.id = getpid();
	x_pckt.icmp_hdr.un.echo.sequence = ++msg_count;	
	strncpy(x_pckt.msg, ECHO_MESSAGE, sizeof(x_pckt.msg));		
	x_pckt.icmp_hdr.checksum = csum((unsigned short *)&x_pckt, sizeof(x_ping_pckt_t) / 2);

	// send packet
	clock_gettime(CLOCK_MONOTONIC, &time_start);
	if (sendto(ping_sock_fd, &x_pckt, sizeof(x_ping_pckt_t), 0, (struct sockaddr *)&ping_addr, sizeof(struct sockaddr_in)) <= 0)
	{
		printf("Packet Sending Failed!\n");
		close(ping_sock_fd);
		return (0);
	}

	// receive packet
	r_ping_pckt_t	r_pckt;
	memset(&r_pckt, 0x0, sizeof(r_ping_pckt_t));
	
	struct sockaddr_in r_addr;
	unsigned int addr_len = sizeof(struct sockaddr_in);
	int recv_ret = recvfrom(ping_sock_fd, &r_pckt, sizeof(r_ping_pckt_t), 0, NULL, NULL);
	
	clock_gettime(CLOCK_MONOTONIC, &time_end);
	double elapsed_in_usec = ((double)(time_end.tv_nsec - time_start.tv_nsec)) / 1000.0;
	elapsed_in_usec += (time_end.tv_sec - time_start.tv_sec) * 1000000.0;
	
	if (recv_ret <= 0) 
	{
		printf("Packet receive failed!\n");
		close(ping_sock_fd);
		return (0);
	}
	else if (r_pckt.icmp_hdr.type != ICMP_ECHOREPLY || strcmp(ECHO_MESSAGE, r_pckt.msg))
	{
		printf("Error: ICMP Type: %d, Code: %d, Message: %s", r_pckt.icmp_hdr.code, r_pckt.icmp_hdr.type, r_pckt.msg);
		close(ping_sock_fd);
		return (0);
	}
	printf("%d bytes form %s msg_seq=%d ttl=%d time=%f usec.\n", recv_ret, ip, msg_count, ttl_val, elapsed_in_usec);
	close(ping_sock_fd);
	return (int)elapsed_in_usec;
}

// Driver Code
int main()
{
	printf("returns: %d\n", send_ping("192.168.1.1"));
	sleep(5);
	printf("returns: %d\n", send_ping("192.168.1.1"));
	sleep(5);
	printf("returns: %d\n", send_ping("192.168.1.1"));
	sleep(5);
	printf("returns: %d\n", send_ping("asdfasdfasdf"));
	sleep(5);
	printf("returns: %d\n", send_ping("192.168.1.2"));
	sleep(5);
	printf("returns: %d\n", send_ping("192.168.1.2"));
	return (0);
}
