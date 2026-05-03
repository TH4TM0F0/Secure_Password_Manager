import requests


ORACLE_URL   = "http://cbc-ctf.westeurope.azurecontainer.io:5000/oracle"
CIPHERTEXT   = "b248f0e8f4e3548b995d2215f54b72bd5d3b211b522b7a5ea25c5763e7425447e440e4d85933807e1385d11cd1959975"
BLOCK_SIZE   = 16


def is_valid_padding(ct_bytes: bytes) -> bool:
    """Returns True if server reports valid padding."""
    r = requests.post(ORACLE_URL, json={"ciphertext_hex": ct_bytes.hex()}, timeout=10)
    return r.json().get("valid_padding", False)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def decrypt_block(prev_block: bytes, curr_block: bytes, block_num: int) -> bytes:
    """
    CBC Padding Oracle: recover plaintext of curr_block.

    For each byte position i (right to left):
      pad_val = BLOCK_SIZE - i            (target padding byte)
      We try all 256 guesses for crafted[i].
      When oracle returns True:
        intermediate[i] = guess XOR pad_val
        plaintext[i]    = intermediate[i] XOR prev_block[i]
    """
    intermediate = bytearray(BLOCK_SIZE)

    for i in range(BLOCK_SIZE - 1, -1, -1):
        pad_val = BLOCK_SIZE - i          # padding byte we're targeting

        # Build the suffix of crafted_prev so bytes i+1..15 produce pad_val
        crafted = bytearray(BLOCK_SIZE)
        for k in range(i + 1, BLOCK_SIZE):
            crafted[k] = intermediate[k] ^ pad_val

        found = False
        for guess in range(256):
            crafted[i] = guess
            test_ct = bytes(crafted) + curr_block

            if is_valid_padding(test_ct):
                # False-positive guard for the rightmost byte:
                # flip the byte to the left and re-check.
                if i > 0:
                    guard = bytearray(crafted)
                    guard[i - 1] ^= 0x01
                    if not is_valid_padding(bytes(guard) + curr_block):
                        continue          # was a multi-byte pad fluke so skip this guess

                intermediate[i] = guess ^ pad_val
                pt_byte = intermediate[i] ^ prev_block[i]
                char = chr(pt_byte) if 32 <= pt_byte < 127 else '.'
                print(f"Block {block_num} --> byte {i:02d} "
                      f"intermediate=0x{intermediate[i]:02x}  "
                      f"plain=0x{pt_byte:02x} '{char}'")
                found = True
                break

        if not found:
            print(f"Block {block_num} --> byte {i:02d} -->  NOT FOUND ")

    return xor_bytes(intermediate, prev_block)


def pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    if pad < 1 or pad > BLOCK_SIZE:
        return data
    if data[-pad:] == bytes([pad] * pad):
        return data[:-pad]
    return data


def main():
    ct = bytes.fromhex(CIPHERTEXT)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    # blocks[0] = IV, blocks[1..n] = ciphertext blocks
    print(f"IV : {blocks[0].hex()}")
    for idx, b in enumerate(blocks[1:], 1):
        print(f"C{idx} : {b.hex()}")
    print()

    plaintext = b""
    for idx in range(1, len(blocks)):
        prev  = blocks[idx - 1]
        curr  = blocks[idx]
        print(f"Decrypting block {idx}")
        pt_block = decrypt_block(prev, curr, idx)
        plaintext += pt_block
        print(f"raw block : {pt_block}\n")

    plaintext = pkcs7_unpad(plaintext)
    print(f"Flag = {plaintext.decode('utf-8', errors='replace')}")



if __name__ == "__main__":
    main()