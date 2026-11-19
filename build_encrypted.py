#!/usr/bin/env python3
"""data.json -> data.enc.json / data-enc.js  (비밀번호 암호화 잠금용 번들)

- PBKDF2-HMAC-SHA256 (310,000회, 16바이트 salt) -> 32바이트 키
- AES-256-GCM (12바이트 IV) 으로 data.json 전체를 암호화
- 결과 JSON에는 salt, iv, iterations, ciphertext 만 들어갑니다. (비밀번호·평문 없음)

비밀번호는 저장소 밖 로컬 파일에서만 읽습니다.
  기본 경로: /workspace/work/my-todo/.board-pass  (권한 600, .gitignore 대상)
  바꾸려면: MYTODO_PASS_FILE=/path/to/file python3 build_encrypted.py

salt 는 데이터를 새로 암호화해도 그대로 두어야 브라우저에 저장된 복호화 키가 계속 쓸 수 있습니다.
  기본 경로: 비밀번호 파일과 같은 폴더의 .board-salt (없으면 새로 만들고 재사용)

사용: python3 build_encrypted.py
"""
import base64
import hashlib
import json
import os
import pathlib
import secrets
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 310_000
SALT_BYTES = 16
IV_BYTES = 12
KEY_BYTES = 32

HERE = pathlib.Path(__file__).resolve().parent
DATA_PATH = HERE / "data.json"
ENC_JSON = HERE / "data.enc.json"
ENC_JS = HERE / "data-enc.js"

PASS_FILE = pathlib.Path(os.environ.get(
    "MYTODO_PASS_FILE", "/workspace/work/my-todo/.board-pass"))
SALT_FILE = pathlib.Path(os.environ.get(
    "MYTODO_SALT_FILE", str(PASS_FILE.parent / ".board-salt")))
META_FILE = pathlib.Path(os.environ.get(
    "MYTODO_META_FILE", str(PASS_FILE.parent / ".board-enc-meta")))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def read_password() -> bytes:
    if not PASS_FILE.exists():
        sys.exit(f"비밀번호 파일이 없습니다: {PASS_FILE}")
    pw = PASS_FILE.read_text(encoding="utf-8").strip()
    if not pw:
        sys.exit(f"비밀번호 파일이 비어 있습니다: {PASS_FILE}")
    return pw.encode("utf-8")


def read_salt() -> bytes:
    if SALT_FILE.exists():
        raw = base64.b64decode(SALT_FILE.read_text(encoding="utf-8").strip())
        if len(raw) == SALT_BYTES:
            return raw
        sys.exit(f"salt 파일이 손상되었습니다: {SALT_FILE}")
    salt = secrets.token_bytes(SALT_BYTES)
    SALT_FILE.parent.mkdir(parents=True, exist_ok=True)
    SALT_FILE.write_text(b64(salt), encoding="utf-8")
    try:
        SALT_FILE.chmod(0o600)
    except OSError:
        pass
    return salt


def derive(password: bytes, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=ITERATIONS,
    ).derive(password)


def main() -> None:
    if not DATA_PATH.exists():
        sys.exit(f"원본이 없습니다: {DATA_PATH}")
    plaintext = DATA_PATH.read_bytes()
    json.loads(plaintext.decode("utf-8"))  # JSON 인지 확인

    password = read_password()
    salt = read_salt()

    # 원본·salt·비밀번호가 그대로면 기존 암호문을 그대로 둡니다. (불필요한 커밋 방지)
    fingerprint = hashlib.sha256(
        b"\x00".join([plaintext, salt, password, str(ITERATIONS).encode()])
    ).hexdigest()
    if META_FILE.exists() and ENC_JSON.exists() and ENC_JS.exists():
        try:
            meta = json.loads(META_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            meta = {}
        if meta.get("fingerprint") == fingerprint:
            print("변경 없음 — 기존 data.enc.json / data-enc.js 를 그대로 둡니다")
            return

    key = derive(password, salt)
    iv = secrets.token_bytes(IV_BYTES)
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)

    payload = {
        "salt": b64(salt),
        "iv": b64(iv),
        "iterations": ITERATIONS,
        "ciphertext": b64(ciphertext),
    }
    assert set(payload) == {"salt", "iv", "iterations", "ciphertext"}

    ENC_JSON.write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n",
                        encoding="utf-8")
    ENC_JS.write_text(
        "/* 자동 생성 파일: build_encrypted.py — 암호문만 들어 있습니다 */\n"
        "window.MY_TODO_ENC = "
        + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        + ";\n",
        encoding="utf-8")

    # 되돌려 풀리는지 스스로 확인
    check = AESGCM(key).decrypt(iv, ciphertext, None)
    assert check == plaintext, "복호화 검증 실패"

    META_FILE.write_text(json.dumps({"fingerprint": fingerprint}), encoding="utf-8")
    try:
        META_FILE.chmod(0o600)
    except OSError:
        pass

    print(f"data.enc.json / data-enc.js 생성 완료 "
          f"({len(plaintext)}B -> {len(ciphertext)}B, PBKDF2 {ITERATIONS:,}회)")


if __name__ == "__main__":
    main()
