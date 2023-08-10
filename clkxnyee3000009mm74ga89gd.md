---
title: "Traverse TryHackMe CTF: Exploit Weak API Security for Privileged Access"
datePublished: Sat Aug 05 2023 06:58:32 GMT+0000 (Coordinated Universal Time)
cuid: clkxnyee3000009mm74ga89gd
slug: traverse
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1691628530569/c66e5969-8763-4e61-a2ff-e9831ede5e94.png
tags: ctf, penetration-testing, 2articles1week, tryhackme, ctf-writeup

---

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217314605/c51d57ed-187d-4f7e-9e14-42d688d94db2.png align="center")

This walkthrough will go over the [**Traverse**](https://tryhackme.com/room/traverse) room found on [**TryHackMe**](https://tryhackme.com/). This box aims to test your knowledge of secure software principles while introducing you to API endpoints and ways to manipulate parameters to obtain critical information. Additionally, you're presented with an opportunity to tailor HTTP requests in order to POST commands to further enumerate the backend server.

### What type of encoding is used by the hackers to obfuscate the JavaScript file?

Looking at the source code reveals a custom JavaScript file on line `14`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217498338/da01fb1f-8a61-4e10-9c47-3357f406b5ca.png align="center")

At first glance, this looks like `HEX`. Let's confirm it and decrypt it using [CyberChef](https://gchq.github.io/CyberChef).

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217516887/5d424aaf-c096-4bf1-b48c-29ca95a6b372.png align="center")

Decrypted:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217625567/1c68fc80-bfe6-41d1-8204-b760f69f1fb0.jpeg align="center")

### What is the flag value after deobfuscating the file?

Decrypting further with `JavaScript Minify` reveals the flag.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217760825/184b998c-d606-4d44-a3c3-3e60075284bd.jpeg align="center")

### Logging is an important aspect. What is the name of the file containing email dumps?

Going back to the source code on lines `25` and `26` reveals a directory. Let's check it out.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217794590/5588bd15-946c-4716-a448-b27a66efa068.png align="center")

Sure enough, there's our `email_dump.txt` file. Let's see what it contains.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217812834/11245032-63ef-4d65-9a94-8dfa23f957fa.png align="center")

### The logs folder contains email logs and has a message for the software team lead. What is the name of the directory that Bob has created?

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217860898/68be6a58-6b59-43e4-842a-baf80cfe5f8c.jpeg align="center")

Hmmm... So the directory is named after the first phase of the SDLC, `planning`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217877886/1a25efc5-ac93-4f97-acfa-389e9c393fef.png align="center")

### What is the key file for opening the directory that Bob has created for Mark?

Going back to the content found in the `email_dump.txt` file reveals the key for opening the directory. Putting the key we obtained into the form brings us to our API content.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217923122/f93622c0-c8c7-4778-938f-43911117b5ad.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217929428/46736201-6863-4374-bf30-189c83a550ee.png align="center")

### What is the email address for ID 5 using the leaked API endpoint?

Taking API endpoint syntax and plugging it into our base URL displays raw data in JSON format.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691217981087/1dec3fe2-fc67-48b7-bfab-0d581279070e.jpeg align="center")

### What is the ID for the user with admin privileges?

Playing around with the `id` numbers reveals our admin user.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691218111820/ea241689-af33-4f95-9850-759d547f3025.jpeg align="center")

### What is the endpoint for logging in as the **admin**? Mention the last endpoint instead of the URL. For example, if the answer is URL is [tryhackme.com/admin](http://tryhackme.com/admin) - Just write **/admin**.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691218191933/6d6892c8-4bbc-4334-a24a-361ce0fb52f0.jpeg align="center")

### The attacker uploaded a web shell and renamed a file used for managing the server. Can you find the name of the web shell that the attacker has uploaded?

First, we need to log in to track down this web shell. We can use the credentials obtained through the API endpoint.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691218254693/0fe4be65-8fe0-4a50-b891-cb727dfc8ce9.jpeg align="center")

Logging in brings us to this Admin Page.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691218272433/dac85bae-a079-412e-850d-8c5b611f4d71.png align="center")

Intercepting the `POST` request through `Burp Suite` allows us to manipulate the command beyond what was intended.

We can accomplish this in 4 simple steps:

1. Launch `Burp Suite`.
    
2. Route traffic from our browser via `FoxyProxy` (my preferred way).
    
3. `Right-Click` Intercepted request and send to `Repeater`.
    
4. Change `commands` variable from `whoami` to `ls` to view content in the current working directory and gain more information.
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691218348768/f2e2e4b1-b0a6-44cd-983f-33065343c760.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691218386299/12ad8d03-563e-449f-a19c-a0101a825d45.jpeg align="center")

### What is the name of the file renamed by the attacker for managing the web server?

This can be retrieved from the response to our tailored `Burp Suite` request.

### Can you use the file manager to restore the original website by removing the "**FINALLY HACKED**" message? What is the flag value after restoring the main website?

We can do this by going to `/realadmin/REDACTED_****_*****er.php` and typing in our discovered password.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691218486766/eb5db8ab-bcd5-4400-b85a-1353663e5f43.png align="center")

File Manager:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691218500505/d4084179-b54d-432d-91ab-6f2d6da5f910.png align="center")

Clicking into `index.php` and selecting the Advanced Editor gives us the ability to remove the "Finally Hacked" message as well as retrieve our final flag.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691255712971/c34bca4e-59d3-4175-a4ec-d7c79f455b66.jpeg align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691255797347/6867a80e-e604-4449-8946-410d814aa0c1.jpeg align="center")