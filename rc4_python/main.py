from rc4_cipher import Rc4Cipher


def main():
    rc4 = Rc4Cipher('dafaq')
    input_text = str(input('input_text: '))
    encode_text = rc4.encode(input_text)
    print("encoded_text: ", encode_text)
    deocde_text = rc4.decode(encode_text)
    print("decoded_text:", deocde_text)


if __name__ == '__main__':
    main()
