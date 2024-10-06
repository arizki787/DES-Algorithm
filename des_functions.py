import os
from config import *

# Helper function to convert hex to binary
def hex_to_bin(hex_string):
    return bin(int(hex_string, 16))[2:].zfill(64)

# Helper function to convert binary to hex
def bin_to_hex(bin_string):
    return hex(int(bin_string, 2))[2:].upper().zfill(16)

# Helper function to convert decimal to binary
def dec_to_bin(decimal_string):
    return bin(int(decimal_string))[2:].zfill(64)

# Convert text to binary (ensures 64-bit blocks)
def text_to_bin(text):
    return ''.join(format(ord(c), '08b') for c in text).ljust((len(text) + 7) // 8 * 8 * 8, '0')

# Convert binary back to text
def bin_to_text(binary_data):
    text = ''.join(chr(int(binary_data[i:i + 8], 2)) for i in range(0, len(binary_data), 8))
    return text

# Apply the initial permutation
def initial_permutation(block):
    return ''.join([block[i - 1] for i in IP_TABLE])

# Apply the final permutation
def final_permutation(block):
    return ''.join([block[i - 1] for i in FP_TABLE])

# Key scheduling to generate 16 round keys
def key_schedule(key_64bit):
    # Apply PC-1 to get the 56-bit key
    permuted_key = ''.join([key_64bit[i - 1] for i in PC1_TABLE])
    # Split into left (C) and right (D) halves
    left, right = permuted_key[:28], permuted_key[28:]

    round_keys = []
    for round_number in range(16):
        # Perform left shifts
        left = left_shift(left, LEFT_SHIFT_TABLE[round_number])
        right = left_shift(right, LEFT_SHIFT_TABLE[round_number])
        combined_key = left + right
        # Apply PC-2 to get the round key
        round_key = ''.join([combined_key[i - 1] for i in PC2_TABLE])
        round_keys.append(round_key)

    return round_keys

# Left shift function for key scheduling
def left_shift(bits, shift_count):
    return bits[shift_count:] + bits[:shift_count]

# DES round function (Feistel structure)
def feistel_function(right_half, round_key):
    expanded_right = ''.join([right_half[i - 1] for i in EXPANSION_TABLE])  # Apply expansion
    xored = xor(expanded_right, round_key)  # XOR with the round key

    sbox_output = ''
    for i in range(8):
        sbox_input = xored[i * 6:(i + 1) * 6]
        row = int(sbox_input[0] + sbox_input[5], 2)  # Row is determined by the outer bits
        col = int(sbox_input[1:5], 2)  # Column is determined by the middle 4 bits
        sbox_value = S_BOXES[i][row][col]
        sbox_output += format(sbox_value, '04b')  # Convert the S-box output to binary

    return ''.join([sbox_output[i - 1] for i in P_TABLE])  # Apply permutation P

# XOR two binary strings
def xor(bin1, bin2):
    return ''.join(['0' if b1 == b2 else '1' for b1, b2 in zip(bin1, bin2)])

# Encrypt a single 64-bit block
def des_encrypt_block(block, round_keys):
    block = initial_permutation(block)  # Apply initial permutation
    left, right = block[:32], block[32:]

    for i in range(16):
        new_right = xor(left, feistel_function(right, round_keys[i]))
        left = right
        right = new_right

    combined = right + left  # Swap halves after the 16 rounds
    return final_permutation(combined)  # Apply final permutation

# Decrypt a single 64-bit block (same as encryption but with reversed round keys)
def des_decrypt_block(block, round_keys):
    block = initial_permutation(block)  # Apply initial permutation
    left, right = block[:32], block[32:]

    for i in range(15, -1, -1):  # Reverse order of round keys for decryption
        new_right = xor(left, feistel_function(right, round_keys[i]))
        left = right
        right = new_right

    combined = right + left  # Swap halves
    return final_permutation(combined)  # Apply final permutation

# Pad the text to ensure it fits into 64-bit blocks
def pad_text(text):
    padding_length = 8 - (len(text) % 8)
    return text + (chr(padding_length) * padding_length)

# Unpad the decrypted text to get the original message
def unpad_text(text):
    padding_length = ord(text[-1])
    return text[:-padding_length]

# DES encryption on a file
def des_encrypt_file(key, input_file, output_file):
    key_64bit = hex_to_bin(key) if len(key) == 16 else dec_to_bin(key)
    round_keys = key_schedule(key_64bit)  # Generate round keys

    with open(input_file, 'r') as f:
        plaintext = f.read()

    padded_plaintext = pad_text(plaintext)
    binary_plaintext = text_to_bin(padded_plaintext)

    cipher_binary = ''
    for i in range(0, len(binary_plaintext), 64):
        block = binary_plaintext[i:i + 64]
        cipher_binary += des_encrypt_block(block, round_keys)

    cipher_hex = bin_to_hex(cipher_binary)

    with open(output_file, 'w') as f:
        f.write(cipher_hex)

    print(f"Encryption complete. Ciphertext written to {output_file}")

# DES decryption on a file
def des_decrypt_file(key, input_file, output_file):
    key_64bit = hex_to_bin(key) if len(key) == 16 else dec_to_bin(key)
    round_keys = key_schedule(key_64bit)  # Generate round keys

    with open(input_file, 'r') as f:
        cipher_hex = f.read().strip()

    cipher_binary = hex_to_bin(cipher_hex)  # Convert hex to binary

    decrypted_binary = ''
    for i in range(0, len(cipher_binary), 64):
        block = cipher_binary[i:i + 64]
        decrypted_binary += des_decrypt_block(block, round_keys)

    decrypted_text = bin_to_text(decrypted_binary)
    unpadded_text = unpad_text(decrypted_text)

    with open(output_file, 'w') as f:
        f.write(unpadded_text)

    print(f"Decryption complete. Plaintext written to {output_file}")


def get_mode():
    while True:
        print("\nSelect Operation:")
        print("1. Encrypt")
        print("2. Decrypt")
        mode = input("Please choose an option (1 or 2): ").strip()
        if mode in ['1', '2']:
            return mode
        print("Invalid input. Please enter '1' for Encrypt or '2' for Decrypt.")

def get_key_format():
    while True:
        print("\nSelect Key Format:")
        print("1. Hexadecimal")
        print("2. Decimal")
        key_format = input("Please choose an option (1 or 2): ").strip()
        if key_format in ['1', '2']:
            return key_format
        print("Invalid input. Please enter '1' for Hexadecimal or '2' for Decimal.")

def get_key(key_format):
    while True:
        key = input(f"\nEnter 64-bit {'hexadecimal' if key_format == '1' else 'decimal'} key: ").strip()
        if len(key) == 16 and key_format == '1':  # 16 hex digits for 64 bits
            return key
        elif len(key) == 20 and key_format == '2':  # 64-bit decimal key should have 20 digits max
            return key
        print("Invalid key length. Please enter a valid 64-bit key.")

def list_files():
    print("\nAvailable files in the current directory:")
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    for index, file in enumerate(files, start=1):
        print(f"{index}. {file}")
    return files

def get_file_names():
    files = list_files()
    print("\nEnter the number of the file you want to use, or type the full file name:")
    choice = input("Your choice: ").strip()
    
    if choice.isdigit() and 1 <= int(choice) <= len(files):
        input_file = files[int(choice) - 1]
    else:
        input_file = choice  # User entered a file name

    output_file = input("Enter output file name: ").strip()
    return input_file, output_file