import asyncio, logging
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, List, Optional, Tuple
from dataclasses import dataclass
import secrets

logger = logging.getLogger(__name__)

@dataclass
class BlufiDH:
    _p: int
    _g: int
    _x: int
    _y: int
    _secret_key: Optional[bytes] = None

    @classmethod
    def create(cls, p: int, g: int, L_bits: int = 1024) -> "BlufiDH":
        if p <= 3 or g <= 1 or g >= p: raise ValueError("Invalid DH parameters (ranges)")
        max_bits = max(2, min(L_bits, p.bit_length() - 2))
        while True:
            x = secrets.randbits(max_bits) | 1  # non-zero-ish
            if 1 < x < (p - 1): break
        y = pow(g, x, p)
        return cls(p, g, x, y, None)

    def get_P(self) -> int: return self._p
    
    def get_G(self) -> int: return self._g

    def get_secret_key(self) -> Optional[bytes]: return self._secret_key

    def get_public_value_int(self) -> int: return self._y

    def get_public_value_hex(self) -> str: return format(self._y, "x")

    def generate_secret_key(self, peer_public_y: int) -> None:
        if not (1 < peer_public_y < self._p - 1): raise ValueError("Peer public value out of range")
        shared_int = pow(peer_public_y, self._x, self._p)
        size       = (self._p.bit_length() + 7) // 8
        self._secret_key = shared_int.to_bytes(size, "big").lstrip(b"\x00") or b"\x00"


@dataclass
class BlufiEvent:
    pkg: int
    sub: int
    seq: int
    encrypted: bool
    checksum: bool
    fragmented: bool
    payload: bytes

class BlufiEventHub:
    """
    Lightweight async event bus:
      - wait_for(pkg, sub, timeout): await next event's payload
      - on(pkg, sub, callback): subscribe (returns unsubscribe callable)
    Buffers one or more early events per key so callers don't race.
    """
    def __init__(self, loop: asyncio.AbstractEventLoop, max_buffer_per_key: int = 8):
        self._loop = loop
        self._waiters: Dict[Tuple[int, int], Deque[asyncio.Future[BlufiEvent]]] = defaultdict(deque)
        self._listeners: Dict[Tuple[int, int], List[Callable[[BlufiEvent], None]]] = defaultdict(list)
        self._buffers: Dict[Tuple[int, int], Deque[BlufiEvent]] = defaultdict(deque)
        self._max_buffer = max_buffer_per_key

    def emit(self, evt: BlufiEvent) -> None:
        key = (evt.pkg, evt.sub)

        # Satisfy one waiter if present
        if self._waiters[key]:
            fut = self._waiters[key].popleft()
            if not fut.done():
                fut.set_result(evt)
            return

        # Otherwise buffer (bounded)
        buf = self._buffers[key]
        if len(buf) >= self._max_buffer:
            buf.popleft()
        buf.append(evt)

        # Fan-out to listeners (best-effort)
        if self._listeners[key]:
            for cb in list(self._listeners[key]):
                try:
                    cb(evt)
                except Exception:  # don't break other listeners
                    logger.exception("listener error for key=%s", key)

    async def wait_for(self, pkg: int, sub: int, timeout: Optional[float] = None) -> BlufiEvent:
        key = (pkg, sub)
        # If we already have something buffered, return immediately
        buf = self._buffers[key]
        if buf:
            return buf.popleft()

        fut: asyncio.Future[BlufiEvent] = self._loop.create_future()
        self._waiters[key].append(fut)
        return await asyncio.wait_for(fut, timeout=timeout) if timeout else await fut

    def on(self, pkg: int, sub: int, callback: Callable[[BlufiEvent], None]) -> Callable[[], None]:
        key = (pkg, sub)
        self._listeners[key].append(callback)
        def unsubscribe() -> None:
            lst = self._listeners.get(key, [])
            if callback in lst:
                lst.remove(callback)
        return unsubscribe