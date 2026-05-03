import math
from sympy import factorint
# Given values
n = 143991606075158483660871570161405209117
e = 65537
ciphertext = 34130411904650996210426832018051041635

# Factord n to find p and q
# used: https://www.alpertron.com.ar/ECM.HTM
# can also use factorint()
[p_calculated , q_calculated] = factorint(n) 
p = 11607228028223627369
q = 12405339649142310293

assert p * q == n, "Factorization failed"  

# Compute φ(n)
phi_n = (p - 1) * (q - 1)

def mod_inverse(a, m):
    """Compute the modular inverse of a mod m using Extended Euclidean Algorithm."""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

d = mod_inverse(e, phi_n)

# Decrypt the ciphertext
plaintext_int = pow(ciphertext, d, n)
# Convert the plaintext integer to bytes
plaintext_bytes = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big')
# Decode bytes to string
plaintext = plaintext_bytes.decode('utf-8')
print(f"Decrypted plaintext: {plaintext}")