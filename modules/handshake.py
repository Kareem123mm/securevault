import os
import elgamal
import rc6
import time
from elgamal_utils import derive_session_key


def perform_handshake(client_name, client_cert, client_x,
                      server_cert, server_x, ca_instance):
    """
    Simulates an 8-step TLS-style handshake to establish a shared session key.

    Returns:
        A tuple (session_key_bytes, chosen_cipher_string).
    """
    print(f"\n{'='*55}")
    print(f"TLS HANDSHAKE: {client_name} <-> {server_cert['owner']}")
    print(f"{'='*55}")

    # STEP 1 — CLIENT HELLO
    client_nonce = os.urandom(16)
    print(f"[STEP 1] Client Hello — nonce: {client_nonce.hex()[:16]}...")

    # STEP 2 — SERVER HELLO
    server_nonce = os.urandom(16)
    chosen_cipher = "RC6"
    print(f"[STEP 2] Server Hello — cipher: {chosen_cipher}, nonce: {server_nonce.hex()[:16]}...")

    # STEP 3 — CLIENT VALIDATES SERVER CERT
    valid, reason = ca_instance.validate_certificate(server_cert)
    if not valid:
        raise Exception(f"[STEP 3] HANDSHAKE FAILED: Server certificate invalid: {reason}")
    print(f"[STEP 3] Server certificate validated: {reason}")

    # STEP 4 — CLIENT KEY EXCHANGE
    srv_pub = server_cert["public_key"]
    p = srv_pub['p']
    # The pre-master secret must be an integer less than the prime 'p'.
    # We generate 16-byte secrets until one satisfies this condition.
    while True:
        pre_master_secret = os.urandom(16)
        pms_int = int.from_bytes(pre_master_secret, 'big')
        if 0 < pms_int < p:
            break
    
    c1, c2 = elgamal.encrypt(pms_int, p, srv_pub['g'], srv_pub['y'])
    print(f"[STEP 4] Pre-master secret generated and encrypted with server public key")
    print(f"         c1 = {str(c1)[:20]}...")

    # STEP 5 — SERVER DECRYPTS PMS
    recovered_int = elgamal.decrypt(c1, c2, server_x, p)
    # The recovered integer must be converted back to *exactly* 16 bytes.
    recovered_pms = recovered_int.to_bytes(16, 'big')
    
    # This assertion now correctly compares the original 16-byte secret with the
    # reconstructed 16-byte secret.
    assert recovered_pms == pre_master_secret, "Pre-master secret mismatch after decryption!"
    print(f"[STEP 5] Server decrypted pre-master secret: OK")

    # STEP 6 — BOTH SIDES DERIVE SESSION KEY (same function, same inputs)
    client_sk = derive_session_key(pre_master_secret, client_nonce, server_nonce)
    server_sk = derive_session_key(recovered_pms,     client_nonce, server_nonce)
    assert client_sk == server_sk, "Session key mismatch after derivation!"
    print(f"[STEP 6] Session key derived: {client_sk.hex()}")

    # STEP 7 — CLIENT FINISHED
    summary = f"{client_name}|{server_cert['owner']}|{chosen_cipher}|FINISHED"
    encrypted_fin = rc6.encrypt_data(summary.encode(), client_sk)
    print(f"[STEP 7] Client Finished sent (RC6 encrypted handshake summary)")

    # STEP 8 — SERVER FINISHED
    decrypted_fin = rc6.decrypt_data(encrypted_fin, server_sk)
    assert decrypted_fin == summary.encode(), "Client Finished message verification failed!"
    print(f"[STEP 8] Server verified Client Finished: OK")

    print(f"{'='*55}")
    print(f"SECURE CHANNEL ESTABLISHED")
    print(f"Session key: {client_sk.hex()}")
    print(f"Cipher: {chosen_cipher}")
    print(f"{'='*55}\n")

    return client_sk, chosen_cipher


if __name__ == "__main__":
    import ca as ca_module

    ca_inst = ca_module.CertificateAuthority()

    p1, g1, x1, y1 = elgamal.generate_keypair()
    p2, g2, x2, y2 = elgamal.generate_keypair()
    cert_doctor = ca_inst.issue_certificate("dr_alice",        "doctor", p1, g1, y1)
    cert_server = ca_inst.issue_certificate("hospital_server", "server", p2, g2, y2)

    t0 = time.time()
    try:
        sk, cipher = perform_handshake(
            "dr_alice", cert_doctor, x1,
            cert_server, x2, ca_inst
        )
        print(f"Handshake completed in {round((time.time() - t0) * 1000, 2)} ms")
    except Exception as e:
        print(f"Handshake failed: {e}")