![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Pow Pow</font>

​	10<sup>th</sup> May 2026

​	Prepared By: `rasti`

​	Challenge Author(s): `Babafaba`

​	Difficulty: <font color=orange>Medium</font>





# Synopsis

- Break a weak "hash"-like function based on simple modular operations to solve 100 Proof-of-Work style puzzles quickly. 

# Description

- Beneath the transit layer, the DeadDrop Cartel routes proxy payments through a validation chain that demands rapid sequential approval. The checkpoint window is narrow, and the route will shift if you linger.



## Skills Required

- Basic Python source code analysis.
- Basic research skills.
- Basic mathematical skills and understanding of modular arithmetic.
- Basic Python scripting skills.

## Skills Learned

- Better understanding of modular arithmetic and the possible inversion of certain operations. 
- Better understanding of hash function properties.

# Enumeration

## Analyzing the source code

If we look at the `server.py` script we can see that our goal is to find nonces that when hashed(with a custom "hash" function) along with some additional data will give a hash with the 50 MSBs being 0 for 100 "blocks" of transactions. 

The basic workflow of the script is as follows:

1. An "Blockchain" object is created, initialized with some random values.
2. It contains a custom hash-like function that depends on these parameters.
3. It also has a function that checks if a block should be "mined" given the block's transactions and a nonce. 
4. You are given 30 seconds to find nonces that will correctly mine a block for randomly generated transactions.
5. If you mine 100 blocks within the time limit you'll be given the hash of the flag(using the custom hash function).

Steps 1, 2, and 3 are:

```python
class Blockchain:
    def __init__(self):
        self.POW_hardness = 50 # 50 bits seems reasonable
        self.n = getPrime(256)
        while True:
            self.a = getPrime(256)
            self.b = getPrime(256)
            if self.a < self.n and self.b < self.n:
                break
        genesis_block = sha256(b"We all need to start somewhere").digest()
        self.blockchain = [self.POW_hash(genesis_block)]
        
    def POW_hash(self, data):
        hash = (self.a * bytes_to_long(data) + self.b) % self.n
        return hash
    
    def validate_hash(self, blockdata, nonce):
        hash = self.POW_hash(long_to_bytes(self.blockchain[-1]) + blockdata + nonce)
        hash_bits = bin(hash)[2:]
        hash_bits = "0"*(256 - len(hash_bits)) + hash_bits
        if hash_bits[:self.POW_hardness] == self.POW_hardness*"0":
            self.blockchain.append(hash)
            return True
        else:
            return False
```

For steps 4, 5 the following code is used:

```python
timeout = 30
start = time.time()
while time.time() < start + timeout:
    next_block_data = generate_random_block_data(3)
    print("Find a nonce to mine the block for these transactions: ")
    print(next_block_data.decode())
    nonce = bytes.fromhex(input("Enter your nonce in hex: "))
    assert len(nonce) == 16
    if not my_blockchain.validate_hash(next_block_data, nonce):
        print("Nope, that's wrong.")
        break
    elif len(my_blockchain.blockchain) > 100:
        print("Woo you're pretty fast. Here's your flag(hashed of course): " + hex(my_blockchain.POW_hash(FLAG))[2:])
        break
    else:
        print("Success! On to the next one.")

if time.time() > start + timeout:
    print("Too slow, maybe buy another CPU")
```

To generate the random transactions for each block the code is:

```python
def generate_random_block_data(tx_count):
    block_data = b""
    for i in range(tx_count):
        block_data += b"User 0x" + os.urandom(8).hex().encode() + b" sent 1 coincoin to user 0x" + os.urandom(8).hex().encode() + b"\n"
    return block_data
```

A little summary of all the interesting things we have found out so far:

1. We need to find the nonces quickly(30 seconds)
2. We are given the hash of the flag so we'll need to somehow reverse it.

# Solution

## Finding the vulnerability

The hash doesn't have any of the desired properties of a proper hash. It's easy to perform pre-image attacks and easy to find nonces that when concatenated with any other input will produce any desired output.

# Exploitation

### Connecting to the server

A pretty basic script for connecting to the server with `pwntools`:

```python
if __name__ == "__main__":
    r = remote("0.0.0.0", 1337)
    pwn()
```

### Solving the 100 challenges

We first get the values for the parameters a, b, n with the following function:

```python
def get_a_b_n_params():
    conn.recvline()
    abc = conn.recvline().decode().split()
    a = int(abc[6][:-1])
    b = int(abc[9])
    n = int(abc[13])
    return a, b, n
```

Then we notice that what will be hashed is `previous_block_hash||current_block_transactions||nonce`. The first two parts are known and if denote them as `data` and plug them into our hash function we get:
`a*(data*2**(nonce_bitlength) + nonce) + b = output (mod n)` where `nonce_bitlength = 8 * 32`
We notice that we can set the output to our desired target value(e.g. 0) and we'll have an equation with `nonce` as the only unknown.
`a*(data*2**(nonce_bitlength) + nonce) + b = 0 (mod n)` => `nonce = (a**-1) * (-a*data*2**nonce_bitlength -b)`

This is done with the following function:
```python
def get_encrypted_flag(a, b, n):
    genesis_block = sha256(b"We all need to start somewhere").digest()
    blockchain = [POW_hash(a, b, n, genesis_block)]
    for i in range(100):
        conn.recvline()
        block_data = b""
        block_data += conn.recvline()
        block_data += conn.recvline()
        block_data += conn.recvline()
        conn.recvuntil(b"hex: ")
        nonce = find_hash(a, b, n, long_to_bytes(blockchain[-1]) + block_data)
        blockchain.append(POW_hash(a, b, n, long_to_bytes(blockchain[-1]) + block_data + bytes.fromhex(nonce)))
        conn.sendline(nonce.encode())
        encflag = conn.recvline().decode().split()[-1]
    conn.close()
    return encflag
```

Notice that we first need to calculate the `previous_block_hash` the same way the server does from the "genesis_block" and then use the target hash(here we chose 0) for every subsequent block we mine.

## Getting the flag

After all this, the server will provide the hashed flag. This means we'll have `(a*flag + b) % n`.
We can calculate `(hash - b) * (a**-1) % n` to get back `flag % n`. Thankfully the flag turns out to be below n so we don't need to do any bruteforce.
This is done with this code:

```python
def decrypt_flag(encflag, a, b, n):
    flag = (int(encflag, 16) - b) * pow(a, -1, n) % n
    return long_to_bytes(flag)
```

A final summary of all that was said above:

1. We connected to the server
2. We found a way to find nonces that mine any block and did it 100 times to get the encrypted flag
3. We reversed the hash operations to get the original flag value.

This recap can be reprisented by code with the `pwn()` function:

```python
def pwn():
    a, b, n = get_a_b_n_params()
    enc_flag = get_encrypted_flag(a, b, n)
    flag = decrypt_flag(enc_flag, a, b, n)
    print(flag)
