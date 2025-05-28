import builtins


def ecb_encrypt(
    block_cipher: str,
    plaintext: bytes | str,
    key: bytes,
    padding_type: str = 'pkcs7'
):
    if padding_type != 'pkcs7':
        raise ValueError(f"Unsupported padding type: {padding_type}")

    match type(plaintext):
        case builtins.str:
            msg_bytes = plaintext.encode("utf-8")  # type: ignore
        case builtins.bytes:
            msg_bytes = plaintext
        case _:
            raise ValueError(f"Invalid type: {type}")

    match block_cipher:
        case 'sm4':
            from .sm4 import encrypt

            # 若消息长度刚好符合块长度，则添加一个填充块
            # pkcs7 padding
            nPadding = 16 - (len(msg_bytes) & 0xF)
            msg_bytes += nPadding * nPadding.to_bytes() # type: ignore

            ciphertext = b''
            for i in range(0, len(msg_bytes), 16):
                ciphertext += encrypt(msg_bytes[i:i + 16], key)
            return ciphertext

        case _:
            raise ValueError(f"Invalid block_cipher: {block_cipher}")

def ecb_decrypt(
    block_cipher: str,
    ciphertext: bytes,
    key: bytes,
    padding_type: str = 'pkcs7'
):
    if padding_type != 'pkcs7':
        raise ValueError(f"Unsupported padding type: {padding_type}")
    
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes.")

    match block_cipher:
        case 'sm4':
            from .sm4 import decrypt

            plaintext = b''
            for i in range(0, len(ciphertext), 16):
                plaintext += decrypt(ciphertext[i:i + 16], key)

            return plaintext[0:-plaintext[-1]]  # Remove padding

        case _:
            raise ValueError(f"Invalid block_cipher: {block_cipher}")