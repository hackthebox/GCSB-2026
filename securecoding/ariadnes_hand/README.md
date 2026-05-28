![img](../../assets/banner.png)



<img src='../../assets/htb.png' style='zoom: 70%;' align=left /><font size='10'>Ariadne's Hand</font>

19<sup>th</sup> April 2026

Prepared By: `Pyp`

Challenge Author(s): `Pyp`

Difficulty: <font color='green'>Easy</font>

<br><br>
<br><br>

# Synopsis

The challenge presents a C# .NET 8 ASP.NET Core service simulating Spanning Tree Protocol BPDU propagation across a network fabric. A recursive forwarding method in the service lacks cycle detection and a hard propagation bound, causing it to spiral indefinitely on any topology containing a loop. The player must locate the fault in the source code, apply both safeguards correctly, and submit the patch through the provided Git workflow for automated validation.

## Skills Required
- C# source code analysis
- Graph traversal and recursion fundamentals
- Vulnerability identification from static code review
- Basic Git workflow (branch, commit, push, pull request)

## Skills Learned
- Identifying unbounded recursion vulnerabilities in protocol simulation code
- Implementing visited-node cycle detection with `HashSet<string>`
- Applying a hard TTL/hop-count depth limit as a secondary propagation bound
- Understanding why shared mutable state across recursive branches produces inconsistent behaviour
- Recognising the real-world network impact of uncontrolled BPDU flooding


# Enumeration

## Accessing the Application

Spin up the container and navigate to the challenge port. The default landing page redirects to the ARIADNE Network Management Platform at `/app`.

```bash
http://[IP]:[PORT]/app
```

Clicking **Run BPDU Diagnostic** calls `/app/api/simulate` and immediately triggers the CRITICAL alert banner. The diagnostic hits the 500-event cap, `loopDetected` is `true`, and the fabric health indicator flips to `FABRIC DEGRADED`.

## Cloning the Repository

The Git instance is accessible on the same port under `/git`. Credentials and workflow instructions are in the repository README.

```bash
git clone http://htb_developer:HTBDeveloperPassword@[IP]:[PORT]/git/core_application.git
cd core_application
git checkout -b developer
```

## Locating the Vulnerable File

The service source lives under `src/StpService/`. The entry point for BPDU propagation is straightforward to find:

```
src/StpService/
  Controllers/TopologyController.cs   -- exposes /app/api/simulate
  Services/BpduForwarder.cs           -- recursive forwarding logic
  Services/TopologyService.cs         -- loads network.json
  Models/BpduPacket.cs                -- the packet object passed between calls
```

The controller instantiates `BpduForwarder`, seeds it with the adjacency list from `network.json`, and calls `ForwardBpdu()` from the root node.


# Identifying the Vulnerability

## The Broken Forwarding Loop

Open `src/StpService/Services/BpduForwarder.cs`. The relevant method at the time of the challenge:

```csharp
// NOTE TO SELF: revisit forwarding logic before production release
public void ForwardBpdu(string nodeId, BpduPacket packet)
{
    if (_log.Count >= 500) return;  // demo cap -- does NOT fix the root issue

    var sev  = packet.HopCount >= 10 ? "2" : packet.HopCount >= 5 ? "4" : "6";
    var port = $"Gi0/{(packet.HopCount % 4) + 1}";
    _log.Add($"[{DateTime.UtcNow:HH:mm:ss.fff}] {nodeId} %STP-{sev}-BPDU_FWD: ...");
    packet.HopCount++;

    if (!_topology.ContainsKey(nodeId)) return;

    foreach (var neighbor in _topology[nodeId])
        ForwardBpdu(neighbor, packet);  // NO CYCLE DETECTION
}
```

The topology in `network.json` contains a deliberate cycle between the distribution layer switches:

```
SW-CORE-01 <--> SW-DIST-01 <--> SW-DIST-02 <--> SW-CORE-01
```

Without a visited-node guard the recursion follows this cycle indefinitely, repeating until the 500-entry cap is reached. The cap stops the log from growing but does nothing to unwind the call stack.

## The Comment Is a Signal

The developer left `// NOTE TO SELF: revisit forwarding logic before production release` directly above the method. In a real codebase review this comment alone should trigger an immediate audit of the surrounding logic.

## Why the 500-Entry Cap Does Not Help

The cap is a log guard, not a recursion guard. By the time `_log.Count >= 500` evaluates to `true`, the call stack has already been built through hundreds of recursive frames. It masks the symptom while silently discarding all forwarding events beyond that point.

## Shared Mutable Packet State

`BpduPacket` is a C# class -- a reference type. Every recursive call receives a pointer to the same object, so `packet.HopCount++` contaminates the hop count seen by every subsequent branch, making any hop-count guard placed on the packet object fire at the wrong time depending on branch execution order.


# Real-World Implications

## Blast Radius and Damage Assessment

**Immediate impact:**
- All host connectivity in the affected VLAN is lost; ARP fails, TCP sessions time out, VoIP calls drop.
- Servers lose access to iSCSI or FCoE SAN targets, and firewalls exhaust connection state tables from the frame flood.

**Cascading impact:**
- Routers lose ARP caches and may withdraw routes, taking BGP or OSPF adjacencies down with them.
- DNS, NTP, and authentication chains (Kerberos, RADIUS) become unreachable, breaking dependent services across the domain.
- In OT/ICS environments, devices may enter fail-safe states or issue spurious control commands during the blackout.

**Recovery:**
- Restoring service requires isolating the loop source, waiting for STP reconvergence, and clearing ARP tables across the entire broadcast domain. On a large fabric this can take a skilled team several hours.



# Solution

## Understanding the Fix

Two independent protections are needed. Neither is sufficient on its own.

**Cycle detection via visited-node set:**
A `HashSet<string>` passed through the recursive call chain tracks visited nodes. `visited.Add(nodeId)` returns `false` on a repeat, terminating that branch immediately.

**Hard hop-count depth limit:**
A `const int MaxHops = 20` mirrors the IEEE 802.1s MSTP default. Depth is passed as a value-type `int` parameter so each branch gets its own independent counter, eliminating the shared mutable state problem entirely.

## Applying the Fix

Edit `src/StpService/Services/BpduForwarder.cs`:

```csharp
namespace StpService.Services;

using StpService.Models;

public class BpduForwarder
{
    private const int MaxHops = 20; // IEEE 802.1D / MSTP default MaxHops

    private readonly Dictionary<string, List<string>> _topology;
    private readonly List<string> _log;

    public BpduForwarder(Dictionary<string, List<string>> topology, List<string> log)
    {
        _topology = topology;
        _log      = log;
    }

    public void ForwardBpdu(string nodeId, BpduPacket packet, HashSet<string>? visited = null, int depth = 0)
    {
        // Hard TTL guard: bound propagation regardless of topology or input.
        if (depth >= MaxHops) return;

        visited ??= new HashSet<string>();

        // Cycle detection: stop recursing if this node has already been visited.
        if (!visited.Add(nodeId)) return;

        if (_log.Count >= 500) return;

        var sev  = depth >= 10 ? "2" : depth >= 5 ? "4" : "6";
        var port = $"Gi0/{(depth % 4) + 1}";
        _log.Add($"[{DateTime.UtcNow:HH:mm:ss.fff}] {nodeId} %STP-{sev}-BPDU_FWD: origin={packet.Origin} hop-count={depth} port={port}");

        if (!_topology.ContainsKey(nodeId)) return;

        foreach (var neighbor in _topology[nodeId])
            ForwardBpdu(neighbor, packet, visited, depth + 1);
    }
}
```

`visited` is passed by reference -- the same `HashSet` is shared across the entire propagation. `depth + 1` is passed by value, giving each branch its own independent counter with `packet` now read-only throughout.

## Submitting the Patch

```bash
git add src/StpService/Services/BpduForwarder.cs
git commit -m "fix: add cycle detection to ForwardBpdu via HashSet visited set. Part 2"
git push -u origin developer
```

The post-receive hook registers the PR event and the bridge controller picks it up. On acceptance it runs the hard score pipeline: branch switch, `dotnet publish`, service restart, and three staged tests verifying static guards, endpoint health, and `loopDetected == false`.

## Getting the Flag

```bash
curl -s http://[IP]:[PORT]/flag | jq
```

A fully passing submission produces:

```json
{
  "STATUS": "SOLVED",
  "FLAG": "HTB{...}",
  "MESSAGE": "Congratulations on getting the flag!",
  "HARD_SCORE": 60,
  "SOFT_SCORE": {
    "code_quality": 14,
    "security_reasoning": 13,
    "patch_correctness": 9
  }
}
```

A submission with only the `HashSet` guard and no `MaxHops` limit is rejected at soft evaluation as incomplete. A submission that adds a hop count on the mutable `BpduPacket` object without fixing the shared state is flagged for inconsistent branch behaviour.
