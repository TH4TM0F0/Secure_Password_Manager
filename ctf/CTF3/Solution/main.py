def decode_bits(shifted_values: list) -> str:
    flag = ''
    for value in shifted_values:
        flag += chr(int(value) // 2)
    return flag

txt_file_path = 'CTF_DATA/CTF3/shifted.txt'
shifted_values = []

try:
    with open(txt_file_path, 'r') as f:
        shifted_values = f.readline().split()
except FileNotFoundError as e:
    print(f'File not found: {e}')


if shifted_values:
    print(decode_bits(shifted_values))
else:
    print("No values found to decode.")