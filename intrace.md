
```
# ./intrace --h www.freescale.com
InTrace 1.4.3 -- R: 192.88.156.10/0 (0) L: 0.0.0.0/0
Payload Size: 1 bytes, Seq: 0x00000000, Ack: 0x00000000
Status: Sniffing for connection packets
```

> 
---


> Establish a TCP connection:
> 
---

```
    localhost$ nc www.freescale.com 80
    GET / HTTP/1.0
```
> 
---


> Take a look at the InTrace output:
> 
---

```
InTrace 1.4.3 -- R: 192.88.156.10/80 (0) L: 194.55.39.1/50049
Payload Size: 1 bytes, Seq: 0xede67714, Ack: 0x8164047b
Status: Press ENTER
```
> 
---


> Do as it says!.. ;)
> 
---

```
  #  [src addr]         [icmp src addr]    [pkt type]
 1.  [194.55.39.1    ]  [192.88.156.10  ]  [ICMP_TIMXCEED]
 2.  [194.29.3.254   ]  [192.88.156.10  ]  [ICMP_TIMXCEED]
 3.  [62.179.116.149 ]  [192.88.156.10  ]  [ICMP_TIMXCEED]
 4.  [213.46.171.42  ]  [192.88.156.10  ]  [ICMP_TIMXCEED]
 5.  [89.149.182.49  ]  [192.88.156.10  ]  [ICMP_TIMXCEED]
 6.  [77.67.94.74    ]  [192.88.156.10  ]  [ICMP_TIMXCEED]
 7.  [69.25.168.65   ]  [192.88.156.10  ]  [ICMP_TIMXCEED]
 8.  [69.25.127.90   ]  [192.88.156.10  ]  [ICMP_TIMXCEED]
 9.  [192.88.158.250 ]  [192.88.156.10  ]  [ICMP_TIMXCEED]
10.  [192.88.156.10  ]  [192.88.156.10  ]  [ICMP_TIMXCEED NAT]
11.  [192.88.156.10  ]  [      ***      ]  [TCP]
```
> 
---


> And so discovered a NAT appliance at IP: 192.88.156.10

> Another try, this time with www.paypal.com -> 216.113.188.65/80 TCP reveals details of PayPal's internal network structure.
> 
---

```
     1.    217.17.45.185     [ICMP TTL-EXCEEDED]
     2.    193.111.37.5      [ICMP TTL-EXCEEDED]
     3.    212.73.253.129    [ICMP TTL-EXCEEDED]
     4.         ---             [NO RESPONSE]
     5.    64.159.1.113      [ICMP TTL-EXCEEDED]
     6.    4.68.107.2        [ICMP TTL-EXCEEDED]
     7.    64.156.40.98      [ICMP TTL-EXCEEDED]
     8.    10.1.1.162        [ICMP TTL-EXCEEDED] <-- PayPal's
     9.    10.1.1.110        [ICMP TTL-EXCEEDED] <-- internal
    10.         ---             [NO RESPONSE]    <-- network
    11.    216.113.188.65        [TCP REPLY]
```
> 
---


> ## Remotely initiated TCP connection ##

> Take a look at remotely established TCP connections in your system's
> TCP tables and pick one (i.e. use netstat)
> 
---

```
    localhost#	netstat -tanp
    Active Internet connections (servers and established)
    Proto R-Q S-Q Local Address   Foreign Address  State  PID/Program name
    ...
    tcp   0   0  212.76.62.233:22 217.17.34.18:23203 ESTABLISHED 6321/sshd
    ...
```
> 
---


> Run InTrace ...
> 
---

```
    localhost# ./intrace -i eth0 -h 217.17.34.18
```
> 
---


> ... wait for a couple of packets (being exchanged within that connection), then
> press ENTER.
> 
---

```
    InTrace 1.2 (C)2007 Robert Swiecki <robert@swiecki.net>
    R: 217.17.34.18/ANY (23203)  L: 212.76.62.233/22
    Last rcvd SEQ: 209707007, ACK: 29305148
    Press ENTER to start sending packets

     1.    212.76.43.254     [ICMP TTL-EXCEEDED]
     2.         ---             [NO RESPONSE]
     3.         ---             [NO RESPONSE]
     4.    212.76.35.50      [ICMP TTL-EXCEEDED]
     5.    212.76.35.25      [ICMP TTL-EXCEEDED]
     6.    195.85.195.8      [ICMP TTL-EXCEEDED]
     7.    85.232.232.65     [ICMP TTL-EXCEEDED]
     8.    85.232.232.62     [ICMP TTL-EXCEEDED]
     9.    217.17.34.18      [ICMP TTL-EXCEEDED]  [NAT]
    10.         ---             [NO RESPONSE]
    11.    217.17.34.18          [TCP REPLY]
```
> 
---


> So, we've discovered that the TCP connection is actually initiated from
> behind the NAT appliance (hop # 9), and there is one more IP hop behind that
> (hop # 10) one, unfortunately not responding with icmp time-exceeded packet.

> ## Feedback ##

> If you have any suggestions or comments, don't hesitate to contact!
> The address is: Robert Swiecki <robert@swiecki.net>

> ## Credits ##

> Michal Zalewski <lcamtuf@dione.ids.pl> (http://lcamtuf.coredump.cx) - initial
> concept and the first implementation.
> http://archives.neohapsis.com/archives/fulldisclosure/2007-01/0145.html