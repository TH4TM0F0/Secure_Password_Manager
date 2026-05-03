import skimage.io as io

def extract_bits(img) -> str:
    bits = []
    for r in range(img.shape[0]):
        for c in range(img.shape[1]):
            bits.append(str(img[r, c] & 1)) 
    return ''.join(bits)

def decode_bits(extracted_bits: str) -> str:
    result = []
    for i in range(0, len(extracted_bits), 8):
        byte = extracted_bits[i : i+8]
        char = chr(int(byte, 2))

        if char == '\0':
            break

        result.append(char)
    return ''.join(result)

def decode(img) -> str:
    return decode_bits(extract_bits(img))

stego_img = io.imread('CTF_DATA/CTF4/stego.png')
print(decode_bits(extract_bits(stego_img)))