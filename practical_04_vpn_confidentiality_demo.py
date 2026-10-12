"""
Practical 04: VPN Confidentiality & Symmetric Stream Cipher Demo
Subject: Threat Intelligence and Network Security

Aim:
    To demonstrate how Virtual Private Networks (VPNs) protect data in transit:
      1. Plaintext message generation
      2. Encryption into ciphertext using a shared symmetric key
      3. Network eavesdropping simulation (packet capture in transit)
      4. Decryption back to original plaintext by the authorized peer
      5. Educational explanation of stream-cipher mechanics vs production VPN protocols

Important Academic Disclaimer:
    This program implements an educational symmetric stream cipher (PRNG-based keystream
    with byte-wise XOR) to illustrate confidentiality principles in a classroom setting.
    Production VPNs (e.g., WireGuard, IPsec, OpenVPN) use robust authenticated encryption
    ciphers such as AES-256-GCM or ChaCha20-Poly1305 with Ephemeral Diffie-Hellman key exchange.
"""

import hashlib
import sys


def generate_keystream(key: str, length: int) -> bytes:
    """
    Generates a deterministic pseudorandom keystream of specified length
    derived from the shared secret key using iterative SHA-256 hashing.
    """
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        # Seed hash with shared key + block counter
        block = hashlib.sha256(f"{key}:{counter}".encode("utf-8")).digest()
        keystream.extend(block)
        counter += 1
    return bytes(keystream[:length])


def stream_cipher_encrypt(plaintext: str, key: str) -> tuple:
    """
    Encrypts plaintext by XORing each byte with keystream byte.
    Returns (ciphertext_bytes, keystream_bytes).
    """
    p_bytes = plaintext.encode("utf-8")
    k_bytes = generate_keystream(key, len(p_bytes))
    c_bytes = bytes([p ^ k for p, k in zip(p_bytes, k_bytes)])
    return c_bytes, k_bytes


def stream_cipher_decrypt(ciphertext: bytes, key: str) -> str:
    """
    Decrypts ciphertext by reapplying identical keystream with XOR:
    (Ciphertext XOR Keystream = (Plaintext XOR Keystream) XOR Keystream = Plaintext)
    """
    k_bytes = generate_keystream(key, len(ciphertext))
    p_bytes = bytes([c ^ k for c, k in zip(ciphertext, k_bytes)])
    return p_bytes.decode("utf-8", errors="replace")


def simulate_network_transmission(plaintext: str, shared_key: str, wrong_key: str = "WrongAttackerKey999"):
    """Simulates an insecure network vs an encrypted VPN tunnel."""
    print("\n" + "=" * 75)
    print("         VPN DATA CONFIDENTIALITY & STREAM CIPHER SIMULATION")
    print("=" * 75)

    print(f"[1] SENDER (Alice - Client Node):")
    print(f"    Original Plaintext Message : \"{plaintext}\"")
    print(f"    Pre-Shared Secret Key      : \"{shared_key}\"")
    print(f"    Message Length             : {len(plaintext)} characters ({len(plaintext.encode('utf-8'))} bytes)")

    # Step 2: Encryption
    ciphertext, keystream = stream_cipher_encrypt(plaintext, shared_key)
    print("\n[2] ENCRYPTION PROCESS (Tunnel Ingress):")
    print(f"    Derived Keystream (Hex)    : {keystream[:16].hex()}... (matched length)")
    print(f"    Ciphertext Output (Hex)    : {ciphertext.hex()}")
    print(f"    Ciphertext Base64          : {ciphertext.hex().upper()}")

    # Step 3: Network Transmission & Eavesdropping
    print("\n[3] NETWORK IN-TRANSIT CAPTURE (Simulating Wireshark / Sniffer):")
    print("    --- Scenario A: Transmission WITHOUT VPN (Cleartext) ---")
    print(f"    [ATTACKER SEES] Raw Payload: \"{plaintext}\"")
    print("    [RESULT] CONFIDENTIALITY COMPROMISED! Passwords, PII, and tokens exposed.")
    print("\n    --- Scenario B: Transmission WITH VPN Tunnel (Encrypted) ---")
    print(f"    [ATTACKER SEES] Raw Payload: <{ciphertext.hex()}>")
    print("    [RESULT] CONFIDENTIALITY PRESERVED! Unintelligible high-entropy ciphertext.")

    # Attacker attempts decryption with wrong key
    unauthorized_attempt = stream_cipher_decrypt(ciphertext, wrong_key)
    safe_preview = unauthorized_attempt[:30].encode("ascii", "backslashreplace").decode("ascii")
    print(f"    [Attacker Decrypt with guess key] -> \"{safe_preview}...\" (Gibberish)")

    # Step 4: Authorized Decryption
    print("\n[4] RECIPIENT (Bob - VPN Gateway):")
    print(f"    Authorized Shared Key      : \"{shared_key}\"")
    decrypted_plaintext = stream_cipher_decrypt(ciphertext, shared_key)
    print(f"    Decrypted Plaintext Output : \"{decrypted_plaintext}\"")

    # Integrity verification
    match = (plaintext == decrypted_plaintext)
    print(f"    Integrity & Confidentiality Check: {'PASSED (Plaintext Restored 100%)' if match else 'FAILED'}")

    # Educational notes
    print("\n" + "-" * 75)
    print("EDUCATIONAL ARCHITECTURE NOTES:")
    print("  * Stream Cipher Logic: C_i = P_i XOR K_i ; Decryption: P_i = C_i XOR K_i.")
    print("  * Why this is educational only:")
    print("    - Real VPNs (IPsec ESP / WireGuard / OpenVPN) provide NOT ONLY confidentiality,")
    print("      but also DATA INTEGRITY and ANTI-REPLAY protection via HMAC/Poly1305.")
    print("    - Real VPNs negotiate dynamic ephemeral keys via Diffie-Hellman / ECDH,")
    print("      ensuring Perfect Forward Secrecy (PFS) unlike static pre-shared XOR.")
    print("=" * 75 + "\n")


def main():
    print("======================================================================")
    print("  Cybersecurity Lab - Practical 04: VPN Confidentiality Demo")
    print("======================================================================")

    default_message = "CONFIDENTIAL: Transfer $2,500,000 from Account-4091 to Reserve-Vault."
    default_key = "CorporateVpnSecret2026!"

    try:
        user_msg = input("Enter confidential message (or press Enter for default): ").strip()
    except (EOFError, KeyboardInterrupt):
        user_msg = ""
    message = user_msg if user_msg else default_message

    try:
        user_key = input(f"Enter shared key (Default '{default_key}'): ").strip()
    except (EOFError, KeyboardInterrupt):
        user_key = ""
    key = user_key if user_key else default_key

    simulate_network_transmission(message, key)


if __name__ == "__main__":
    main()
