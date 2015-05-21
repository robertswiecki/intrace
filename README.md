
                                   InTrace
                                   -------

                           http://www.swiecki.net
            (C) Copyright 2007 Robert Swiecki <robert@swiecki.net>


### 1. What is that?
====================================

  InTrace is traceroute-like application that enables users to enumerate IP hops using existing TCP connections, both initiated from local network (local system) or from remote hosts. It could be useful for network reconnaissance and firewall bypassing.

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 */

### 2. Locally initiated TCP connections
===================================

  Start intrace:
```
    localhost# ./intrace -i eth0 -h www.freescale.com
    InTrace 1.2 (C)2007 Robert Swiecki <robert@swiecki.net>
    R: 192.88.156.10/ANY (0)  L: 0.0.0.0/0
    Last rcvd SEQ: 0, ACK: 0
    Waiting to acquire enough packets
```

  Establish a TCP connection:
```
    localhost$ nc www.freescale.com 80
    GET / HTTP/1.0
```

  Press ENTER in the inteace console window:
```
    InTrace 1.2 (C)2007 Robert Swiecki <robert@swiecki.net>
    R: 192.88.156.10/ANY (80)  L: 192.168.0.5/40005
    Last rcvd SEQ: 1400545495, ACK: 3344758762
    Press ENTER to start sending packets
```

Now, enjoy the output
```
     1.    192.158.0.1       [ICMP TTL-EXCEEDED]
     2.    212.76.62.233     [ICMP TTL-EXCEEDED]
     3.         ---             [NO RESPONSE]
     4.    212.76.35.70      [ICMP TTL-EXCEEDED]
     5.    212.76.35.173     [ICMP TTL-EXCEEDED]
     6.    213.248.77.201    [ICMP TTL-EXCEEDED]
     7.         ---             [NO RESPONSE]
     8.    213.248.96.25     [ICMP TTL-EXCEEDED]
     9.    80.91.249.137     [ICMP TTL-EXCEEDED]
    10.    213.248.77.182    [ICMP TTL-EXCEEDED]
    11.    67.17.68.22       [ICMP TTL-EXCEEDED]
    12.    64.212.225.214    [ICMP TTL-EXCEEDED]
    13.    69.25.168.1       [ICMP TTL-EXCEEDED]
    14.    69.25.127.90      [ICMP TTL-EXCEEDED]
    15.    191.83.158.250    [ICMP TTL-EXCEEDED]
    16.    192.88.156.10     [ICMP TTL-EXCEEDED]  [NAT]
    17.    192.88.156.10         [TCP REPLY]
```

  So, we have probably found a NAT appliance as the 192.88.156.10 hop

  One more try with www.paypal.com -> 216.113.188.65/80 TCP
  reveals some details of PayPal's internal network structure.
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

#### . Remotely initiated TCP connections
====================================

  Take a look at the routing table of remotely established TCP connections in your system, and pick one of the TCP connections
```
    localhost#	netstat -tanp
    Active Internet connections (servers and established)
    Proto R-Q S-Q Local Address   Foreign Address  State  PID/Program name
    ...
    tcp   0   0  212.76.62.233:22 217.17.34.18:23203 ESTABLISHED 6321/sshd
    ...
```

  Now, start InTrace ...
```
    localhost# ./intrace -i eth0 -h 217.17.34.18
```

  ... wait for few packets (exchanged within the connection), then
  press ENTER.
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

  So, now we know that the TCP connection is actually initiated from behind a NAT appliance (hop # 9), and there is one more IP hop behind this one (hop # 10), unfortunately not responding with icmp time-exceeded.

4. Feedback
====================================

  If you have any suggestions or comments, don't hesitate to contact me!
  The address is: Robert Swiecki <robert@swiecki.net>

5. Credits
====================================

  Michal Zalewski <lcamtuf@dione.ids.pl> (http://lcamtuf.coredump.cx) - the concept and the original implementation of the tool
