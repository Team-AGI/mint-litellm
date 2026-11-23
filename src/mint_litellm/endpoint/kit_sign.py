"""단말 키트 서명 갱신의 서버 쪽: Ed25519 서명(표준 라이브러리만)과 갱신 묶음 만들기.

서명 키 씨앗은 설치 때 한 번 만들어 ``.env``의 ``MINT_KIT_SIGNING_KEY``(base64url 32바이트)에
둔다. 공개 키는 설치 묶음의 ``kit.json``에 들어가 단말에 고정된다. 단말의 검증 코드는
``kit/mint_kit.py``에 따로 있다(단말은 이 패키지를 쓸 수 없다). 키 회전·되돌리기는 없다.
"""

from __future__ import annotations

import base64
import hashlib
import os
import zlib
from collections.abc import Mapping
from functools import lru_cache

from mint_litellm.endpoint import kit_build

ENV = "MINT_KIT_SIGNING_KEY"
UPDATE_FILES = ("mint_agent.py", "mint_kit.py")  # 단말에 설치되는 프로그램 파일

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _add(a: tuple, b: tuple) -> tuple:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    p, q = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    c, d = 2 * t1 * t2 * _D % _P, 2 * z1 * z2 % _P
    e, f, g, h = q - p, d - c, d + c, q + p
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, point: tuple) -> tuple:
    out = (0, 1, 1, 0)
    while s:
        if s & 1:
            out = _add(out, point)
        point = _add(point, point)
        s >>= 1
    return out


def _x(y: int, sign: int) -> int | None:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    if (x * x - xx) % _P:
        return None
    return _P - x if x & 1 != sign else x


def _encode(point: tuple) -> bytes:
    inv = pow(point[2], _P - 2, _P)
    return (point[1] * inv % _P | (point[0] * inv % _P & 1) << 255).to_bytes(32, "little")


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _secret(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    return (int.from_bytes(digest[:32], "little") & ((1 << 254) - 8)) | (1 << 254), digest[32:]


def public_from_seed(seed: bytes) -> bytes:
    return _encode(_mul(_secret(seed)[0], _G))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _secret(seed)
    pub = _encode(_mul(a, _G))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _Q
    big_r = _encode(_mul(r, _G))
    k = int.from_bytes(hashlib.sha512(big_r + pub + message).digest(), "little") % _Q
    return big_r + ((r + k * a) % _Q).to_bytes(32, "little")


def manifest(version: str, digests: Mapping[str, str]) -> bytes:
    """서명 대상 글: 판본과 파일 이름·해시(이름순). 단말도 같은 방식으로 다시 만든다."""
    lines = [f"mint-kit-update-v1 {version}"] + [f"{n} {digests[n]}" for n in sorted(digests)]
    return "\n".join(lines).encode()


def seed(env: Mapping[str, str] | None = None) -> bytes | None:
    """환경의 서명 키 씨앗(32바이트). 없거나 잘못되면 None(갱신 기능이 꺼진다)."""
    text = ((os.environ if env is None else env).get(ENV) or "").strip()
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        return None
    return raw if len(raw) == 32 else None


def public_key_hex(env: Mapping[str, str] | None = None) -> str | None:
    key = seed(env)
    return public_from_seed(key).hex() if key else None


@lru_cache(maxsize=4)
def _bundle(key: bytes, version: str) -> dict:
    files = {name: kit_build.program_bytes(name) for name in UPDATE_FILES}
    digests = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    return {
        "version": version,
        "files": {n: base64.b64encode(zlib.compress(d, 9)).decode() for n, d in files.items()},
        "sig": sign(key, manifest(version, digests)).hex(),
    }


def update_bundle(env: Mapping[str, str] | None = None) -> dict | None:
    """서명한 키트 프로그램 묶음(판본이 같으면 같은 결과를 재사용). 서명 키가 없으면 None."""
    key = seed(env)
    return _bundle(key, kit_build.kit_version()) if key else None
