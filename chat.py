import argparse
import json
import re
import secrets
import select
import socket
import sys
import threading
from getpass import getpass

from aes_adapter import decrypt_message, encrypt_message, ensure_available


KDC_PORT = 5001
BOB_PORT = 5000
MAX_PACKET_SIZE = 1_000_000
MAX_CHAT_SIZE = 4096
ID_A = "Alice"
ID_B = "Bob"
SESSION_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Koneksi terputus.")
        data.extend(chunk)
    return bytes(data)


def send_packet(sock, data):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_PACKET_SIZE:
        raise ValueError("Ukuran paket tidak valid.")
    sock.sendall(len(data).to_bytes(4, "big") + data)


def receive_packet(sock):
    length = int.from_bytes(receive_exact(sock, 4), "big")
    if not 0 < length <= MAX_PACKET_SIZE:
        raise ValueError("Ukuran paket tidak valid.")
    return receive_exact(sock, length)


def dump_ascii(obj):
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def send_message(sock, message):
    send_packet(sock, dump_ascii(message))


def receive_message(sock, expected_type=None, fields=None):
    try:
        message = json.loads(receive_packet(sock).decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Format pesan tidak valid.") from error
    if not isinstance(message, dict) or not isinstance(message.get("type"), str):
        raise ValueError("Format pesan tidak valid.")
    if expected_type is not None and message["type"] != expected_type:
        raise ValueError("Urutan pesan tidak valid.")
    if fields is not None and set(message) != {"type", *fields}:
        raise ValueError("Field pesan tidak valid.")
    return message


def check_fields(data, fields):
    if not isinstance(data, dict) or set(data) != set(fields):
        raise ValueError("Isi pesan tidak valid.")


def check_nonce(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("Nonce tidak valid.")


def check_key_text(value):
    if not isinstance(value, str) or len(value) != 16 or not value.isascii():
        raise ValueError("Key harus 16 karakter ASCII.")
    return value.encode("ascii")


def check_envelope(envelope):
    check_fields(envelope, ("iv", "ciphertext"))
    iv_hex, cipher_hex = envelope["iv"], envelope["ciphertext"]
    if (not isinstance(iv_hex, str) or not isinstance(cipher_hex, str) or
            not re.fullmatch(r"[0-9a-fA-F]{32}", iv_hex) or
            not re.fullmatch(r"(?:[0-9a-fA-F]{32})+", cipher_hex) or
            len(cipher_hex) > MAX_PACKET_SIZE * 2):
        raise ValueError("Payload enkripsi tidak valid.")
    return bytes.fromhex(iv_hex), bytes.fromhex(cipher_hex)


def encrypt_data(data, key):
    try:
        iv, ciphertext = encrypt_message(dump_ascii(data), key)
    except NotImplementedError:
        raise
    except Exception as error:
        raise ValueError("Enkripsi gagal.") from error
    return {"iv": iv.hex(), "ciphertext": ciphertext.hex()}


def decrypt_data(envelope, key, fields):
    iv, ciphertext = check_envelope(envelope)
    try:
        data = json.loads(decrypt_message(iv, ciphertext, key).decode("ascii"))
    except NotImplementedError:
        raise
    except Exception as error:
        raise ValueError("Dekripsi gagal.") from error
    check_fields(data, fields)
    return data


def send_encrypted(sock, key, msg_type, data):
    envelope = encrypt_data(data, key)
    send_message(sock, {"type": msg_type, **envelope})
    return envelope


def receive_encrypted(sock, key, msg_type, fields):
    message = receive_message(sock, msg_type, ("iv", "ciphertext"))
    return decrypt_data({"iv": message["iv"], "ciphertext": message["ciphertext"]}, key, fields)


def new_session_key():
    return "".join(secrets.choice(SESSION_ALPHABET) for _ in range(16))


def check_alice_part(data, n1):
    check_fields(data, ("ks", "id_a", "id_b", "n1"))
    check_nonce(data["n1"])
    if data["id_a"] != ID_A or data["id_b"] != ID_B or data["n1"] != n1:
        raise ValueError("Identitas atau N1 tidak cocok.")
    return check_key_text(data["ks"])


def check_n2_answer(data, n2):
    check_fields(data, ("n2_minus_one",))
    if type(data["n2_minus_one"]) is not int or data["n2_minus_one"] != n2 - 1:
        raise ValueError("Jawaban N2 tidak cocok.")


def handle_kdc_connection(sock, ka, kb):
    request = receive_message(sock, "key_request", ("id_a", "id_b", "n1"))
    if request["id_a"] != ID_A or request["id_b"] != ID_B:
        raise ValueError("Identitas tidak valid.")
    check_nonce(request["n1"])
    ks = new_session_key()
    for_alice = encrypt_data({"ks": ks, "id_a": ID_A, "id_b": ID_B, "n1": request["n1"]}, ka)
    ticket = encrypt_data({"ks": ks, "id_a": ID_A}, kb)
    send_message(sock, {"type": "key_reply", "for_alice": for_alice, "ticket": ticket})


def request_session_key(kdc_ip, kdc_port, ka):
    n1 = secrets.randbits(64)
    with socket.create_connection((kdc_ip, kdc_port), timeout=10) as sock:
        sock.settimeout(10)
        send_message(sock, {"type": "key_request", "id_a": ID_A, "id_b": ID_B, "n1": n1})
        reply = receive_message(sock, "key_reply", ("for_alice", "ticket"))
    ks = check_alice_part(decrypt_data(reply["for_alice"], ka, ("ks", "id_a", "id_b", "n1")), n1)
    check_envelope(reply["ticket"])
    return ks, reply["ticket"]


def alice_handshake(sock, ks, ticket):
    send_message(sock, {"type": "ticket", "ticket": ticket})
    data = receive_encrypted(sock, ks, "challenge", ("n2",))
    check_nonce(data["n2"])
    if data["n2"] == 0:
        raise ValueError("N2 tidak valid.")
    send_encrypted(sock, ks, "challenge_reply", {"n2_minus_one": data["n2"] - 1})
    if receive_encrypted(sock, ks, "ready", ("status",))["status"] != "ok":
        raise ValueError("Konfirmasi Bob tidak valid.")


def bob_handshake(sock, kb):
    message = receive_message(sock, "ticket", ("ticket",))
    ticket = decrypt_data(message["ticket"], kb, ("ks", "id_a"))
    if ticket["id_a"] != ID_A:
        raise ValueError("Identitas Alice tidak valid.")
    ks = check_key_text(ticket["ks"])
    n2 = secrets.randbelow(2**64 - 1) + 1
    send_encrypted(sock, ks, "challenge", {"n2": n2})
    check_n2_answer(receive_encrypted(sock, ks, "challenge_reply", ("n2_minus_one",)), n2)
    send_encrypted(sock, ks, "ready", {"status": "ok"})
    return ks


def receive_messages(sock, key, stopped):
    try:
        while not stopped.is_set():
            message = receive_message(sock)
            if message["type"] == "close":
                check_fields(message, ("type",))
                print("\nLawan mengakhiri sesi.")
                break
            if message["type"] != "chat":
                raise ValueError("Urutan pesan tidak valid.")
            check_fields(message, ("type", "iv", "ciphertext"))
            data = decrypt_data({"iv": message["iv"], "ciphertext": message["ciphertext"]}, key, ("text",))
            text = data["text"]
            if not isinstance(text, str) or not text.isascii() or not 0 < len(text) <= MAX_CHAT_SIZE:
                raise ValueError("Teks chat tidak valid.")
            print(f"\nLawan: {text}\n> ", end="", flush=True)
    except (ConnectionError, OSError, ValueError, NotImplementedError) as error:
        if not stopped.is_set():
            print(f"\nSesi berakhir: {error}")
    finally:
        stopped.set()


def chat(sock, key):
    sock.settimeout(None)
    stopped = threading.Event()
    receiver = threading.Thread(target=receive_messages, args=(sock, key, stopped))
    receiver.start()
    print("Chat aktif. /keluar untuk selesai.")
    print("> ", end="", flush=True)
    try:
        while not stopped.is_set():
            readable, _, _ = select.select([sys.stdin], [], [], 0.2)
            if not readable:
                continue
            line = sys.stdin.readline()
            if not line:
                break
            message = line.rstrip("\r\n")
            if message == "/keluar":
                send_message(sock, {"type": "close"})
                break
            if not message:
                pass
            elif not message.isascii():
                print("Pesan harus ASCII.")
            elif len(message) > MAX_CHAT_SIZE:
                print("Pesan terlalu panjang.")
            else:
                envelope = send_encrypted(sock, key, "chat", {"text": message})
                print(f"Ciphertext: {envelope['ciphertext']}")
            print("> ", end="", flush=True)
    except (OSError, ValueError, KeyboardInterrupt) as error:
        if not isinstance(error, KeyboardInterrupt):
            print(f"\nSesi berakhir: {error}")
    finally:
        stopped.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        receiver.join()


def open_server(bind_ip, port, backlog):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_ip, port))
    server.listen(backlog)
    return server


def wait_for_connection(server):
    # Enter di stdin => kembali ke menu (None); koneksi masuk => socket.
    while True:
        readable, _, _ = select.select([server, sys.stdin], [], [])
        if sys.stdin in readable:
            sys.stdin.readline()
            return None
        if server in readable:
            return server.accept()[0]


def run_kdc(bind_ip, port, ka, kb):
    with open_server(bind_ip, port, 5) as server:
        print(f"KDC di {bind_ip}:{port}. Enter untuk menu.")
        while True:
            sock = wait_for_connection(server)
            if sock is None:
                return
            with sock:
                sock.settimeout(10)
                try:
                    handle_kdc_connection(sock, ka, kb)
                    print("Session key dikirim.")
                except (ConnectionError, OSError, ValueError) as error:
                    print(f"Permintaan ditolak: {error}")


def run_bob(bind_ip, port, kb):
    with open_server(bind_ip, port, 1) as server:
        print(f"Bob di {bind_ip}:{port}. Enter untuk menu.")
        sock = wait_for_connection(server)
        if sock is None:
            return
        with sock:
            sock.settimeout(10)
            try:
                chat(sock, bob_handshake(sock, kb))
            except (ConnectionError, OSError, ValueError) as error:
                print(f"Sesi ditolak: {error}")


def run_alice(kdc_ip, kdc_port, bob_ip, bob_port, ka):
    ks, ticket = request_session_key(kdc_ip, kdc_port, ka)
    with socket.create_connection((bob_ip, bob_port), timeout=10) as sock:
        sock.settimeout(10)
        alice_handshake(sock, ks, ticket)
        chat(sock, ks)


def read_key(label):
    while True:
        try:
            return check_key_text(getpass(f"{label} (16 ASCII): "))
        except ValueError as error:
            print(error)


def read_keys(role):
    if role == "kdc":
        return {"ka": read_key("Ka"), "kb": read_key("Kb")}
    return {"ka": read_key("Ka")} if role == "alice" else {"kb": read_key("Kb")}


def main():
    parser = argparse.ArgumentParser(description="Chat KDC dengan AES-128-CBC")
    parser.add_argument("role", choices=("kdc", "alice", "bob"))
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int)
    parser.add_argument("--kdc-ip")
    parser.add_argument("--kdc-port", type=int, default=KDC_PORT)
    parser.add_argument("--bob-ip")
    parser.add_argument("--bob-port", type=int, default=BOB_PORT)
    args = parser.parse_args()
    if any(port is not None and not 1 <= port <= 65535 for port in (args.port, args.kdc_port, args.bob_port)):
        parser.error("Port harus 1-65535.")

    keys = read_keys(args.role)
    if args.role == "alice":
        kdc_ip = args.kdc_ip or input("IP KDC: ").strip()
        bob_ip = args.bob_ip or input("IP Bob: ").strip()

    while True:
        try:
            choice = input("1 sesi, 2 ganti key, 3 keluar: ").strip()
            if choice == "3":
                return
            if choice == "2":
                keys = read_keys(args.role)
                continue
            if choice != "1":
                print("Pilihan tidak valid.")
                continue
            ensure_available()
            if args.role == "kdc":
                run_kdc(args.bind, args.port or KDC_PORT, keys["ka"], keys["kb"])
            elif args.role == "bob":
                run_bob(args.bind, args.port or BOB_PORT, keys["kb"])
            else:
                run_alice(kdc_ip, args.kdc_port, bob_ip, args.bob_port, keys["ka"])
        except (ConnectionError, OSError, ValueError, NotImplementedError) as error:
            print(error)
        except (KeyboardInterrupt, EOFError):
            print()
            return


if __name__ == "__main__":
    main()
