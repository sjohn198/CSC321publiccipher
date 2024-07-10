from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import random
import math

def pad_str(text):
    pad_len = 16 - len(text) % 16
    padding = chr(pad_len) * pad_len
    return text + padding

def encrypt_dh(key, msg):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg_padded = pad_str(msg)
    ct = cipher.encrypt(msg_padded.encode())
    return ct, iv

def decrypt_dh(key, ciphertext, iv):
    cipher2 = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher2.decrypt(ciphertext)
    pt_unpad = unpad(pt, 16)
    return pt_unpad.decode('utf-8')

def gen_key_mallory(q, alpha):
    user_a_priv = math.floor(random.randint(1, q - 1))
    user_b_priv = math.floor(random.randint(1, q - 1))

    user_a_pub = pow(alpha, user_a_priv, q)
    user_b_pub = pow(alpha, user_b_priv, q)

    # mallory intercepts 
    # modifies YA and YB to q
    user_a_pub = q
    user_b_pub = q

    secret_key_a = pow(user_b_pub, user_a_priv, q)
    secret_key_b = pow(user_a_pub, user_b_priv, q)
    
    print(secret_key_a == secret_key_b)
    print(secret_key_a)
    return secret_key_a

def communicate_mallory(msg):
    hex_q = """B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
    9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
    13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
    98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
    A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
    DF1FB2BC 2E4A4371"""
    hex_q = hex_q.replace(" ", "").replace("\n", "")
    hex_a = """A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
    D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
    160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
    909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
    D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
    855E6EEB 22B3B2E5"""
    hex_a = hex_a.replace(" ", "").replace("\n", "")
    q = int(hex_q, 16)
    alpha = int(hex_a, 16)
    
    key = gen_key_mallory(q, alpha)
    num_bytes = (key.bit_length() + 7) // 8 
    sym_key = SHA256.new(key.to_bytes(num_bytes, byteorder="big")).digest()[:16]
    
    ct, iv = encrypt_dh(sym_key, msg)
    result = decrypt_dh(sym_key, ct, iv)
    return result

print("Message after tampering with YA and YB:")
print(communicate_mallory("Hi Bob!"))
print(communicate_mallory("Hi Alice!"))

def gen_key_mallory_alpha(q, alpha):
    user_a_priv = math.floor(random.randint(1, q - 1))
    user_b_priv = math.floor(random.randint(1, q - 1))

    user_a_pub = pow(alpha, user_a_priv, q)
    user_b_pub = pow(alpha, user_b_priv, q)

    # Mallory sets alpha to 1, q, or q-1
    for mal_alpha in [1, q, q-1]:
        secret_key_a = pow(mal_alpha, user_a_priv * user_b_priv, q)
        secret_key_b = pow(mal_alpha, user_a_priv * user_b_priv, q)
        
        print(f"Mallory's alpha {mal_alpha} - Secret keys equal: {secret_key_a == secret_key_b}")
        print(secret_key_a)
    return secret_key_a

def communicate_mallory_alpha(msg):
    hex_q = """B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
    9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
    13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
    98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
    A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
    DF1FB2BC 2E4A4371"""
    hex_q = hex_q.replace(" ", "").replace("\n", "")
    hex_a = """A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
    D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
    160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
    909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
    D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
    855E6EEB 22B3B2E5"""
    hex_a = hex_a.replace(" ", "").replace("\n", "")
    q = int(hex_q, 16)
    alpha = int(hex_a, 16)
    
    key = gen_key_mallory_alpha(q, alpha)
    num_bytes = (key.bit_length() + 7) // 8 
    sym_key = SHA256.new(key.to_bytes(num_bytes, byteorder="big")).digest()[:16]
    
    ct, iv = encrypt_dh(sym_key, msg)
    result = decrypt_dh(sym_key, ct, iv)
    return result

print("Message after tampering with α:")
print(communicate_mallory_alpha("Hi Bob!"))
print(communicate_mallory_alpha("Hi Alice!"))
