from des_functions import *

# Main function
if __name__ == '__main__':
    mode = get_mode()
    key_format = get_key_format()
    key = get_key(key_format)
    input_file, output_file = get_file_names()

    if mode == '1':
        des_encrypt_file(key, input_file, output_file)
    elif mode == '2':
        des_decrypt_file(key, input_file, output_file)

    print("\nOperation completed successfully.")