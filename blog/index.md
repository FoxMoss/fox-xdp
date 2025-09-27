## How I Block All 26 Million Of Your Curl Requests

I recently went down a rabbit hole, packet filtering and analysis is a facinating field. I don't run
a large high traffc webserver, at least I hope I dont at the time you're reading this blog. There's
just something in my body that likes writing software at a scale that's bigger then it'll ever be
used. So how do you handle network requests fast? Well, write an operating system and custom network
drivers specifically optimized for spped. We won't be doing that today, but we can get closer to the
bare metal fairly easily without sacrificing the Linux ecosystem. [XDP - Express Data
Path](https://en.wikipedia.org/wiki/Express_Data_Path) that way of getting closer to your network
device. And according to some benchmarks Wikipedia cites you can drop 26 million packets per second
on consumer hardware. Both Linux and suprisingly Windows support XDP, but we're just going to be
focusing on Linux because thats what I have, and that's what you're going to read.

### So how do we actually write this?

XDP works on eBPF - Extended Berkly Packet Filter. We can just load our eBPF filter, on to our
network device with some XDP utilities and our filter will start logging all inbound requests. If we
want we can get our eBPF to pass our request back into the program that loaded it and do additional
proccessing. This turns out to be ~400 lines of boilerplate in C which you can read
[here](https://github.com/FoxMoss/fox-xdp). This isn't a tutorial, you can figure things out. Thats
not the real intresting bit, the magic happens on the filter. 

8 billion devices run Java, at least like a billion probably run eBPFs. eBPF is a tiny virtual
machine that hides in your kernel. It compiles down to something that looks pretty low level, you
have your jumps and your registers and things you would expect, no SIMD, no x86 bloat but it's
enough to have a decent C implementation for the target.

So lets start to parse things out in a EBF filter:

```c
// headers here

SEC("prog") int xdp_sock_prog(struct xdp_md *ctx) {
  uint8_t *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

There's a couple oddities there'll that I'll explain. The kenel won't load the program if it's not
GPL, so thats required at the bottom. The data start and data_end variable just point to the start
and end of your packet, starting with the ethernet packet. The OSI model you relucantly learned in
college, is actually going to come in handy here because we have to write our own network parser.
The other weird thing is that we're grabbing the data end, why? Because we need to validate our
program. One of the benifits for this all running on a reduced instruction set is that we can easily
validate if the program can accidently cause a segmentaion fault given any arbitrary input, because
your network driver crashing while trying to filter bad packets seems like a pretty easy attack
vector especially since most of these things are written in C.


```c
#define OVER(x, d) (x + 1 > (typeof(x))d)
  
// ..
  struct ethhdr *eth = data;

  struct iphdr *ip = (struct iphdr *)(eth + 1);

  if (OVER(ip, data_end))
    return XDP_PASS;

  // routers often drop packets with ip extensions too
  if (ip->ihl > 5)
    return XDP_PASS;

// ...
```

To make the kernel shut up about the program not being valid we have to make sure any pointer we
dereference is below data_end, and we get by 90% of the checks that the kernel has. Hooray!

So to fingerprint the client and detmine wether or not a client is coming from curl we need to parse the TLS
packets. So once we just make sure everything looks good in TCP land, then if the packet starts with the
TLS handshake and the version we care about we can then start to verify it.

```c
// ...
    void *start_payload = ((uint8_t *)tcp) + (tcp->doff * 4);

    if (OVER(start_payload, data_end)) {
      return XDP_PASS;
    }

    if (OVER(start_payload + 120, data_end)) {
      return XDP_PASS;
    }

    if (!(((uint8_t *)start_payload)[0] == 0x16 &&
          ((uint8_t *)start_payload)[1] == 0x03 &&
          ((uint8_t *)start_payload)[2] == 0x01)) {
      return XDP_PASS;
    }
// ...
```

### Act 2: How do you fingerprint a TLS connection

I for the longest time was unaware of TLS fingerprinting, it's probably that way intentionally
because once lots of people know about it, it's not hard to get arround it, but I have nothing to
hide so let me breakdown how we do this.

The modern standard for TLS fingerprint is [JA4](https://github.com/FoxIO-LLC/ja4), not an acronymn
thats just what they wanted to call it. The JA4 is just a string of some basic details about the TLS
connection, but it's able to be traced back to your browser pretty easily. Here's the full image
that FoxIO provides:

What you may notice in particular is that JA4 needs a SHA256 hash to work, if we're going to
calculate this entirely in eBPF we're going to need to introduce a ton of compexity. Because what I
found out pretty quickly when I starting implementing SHA256 in a filter is that it's hard to get it
all to fit into the 512 stack space.


512
