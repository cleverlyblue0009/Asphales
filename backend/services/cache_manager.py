"""In-memory LRU cache with TTL for analysis results."""

import time
from collections import OrderedDict
from typing import Any, Optional

from utils.logger import setup_logger

logger = setup_logger("cache_manager")


class CacheManager:
    """Thread-safe in-memory LRU cache with per-entry TTL."""

    def __init__(self, max_size: int = 1000, ttl: int = 60):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Retrieve a cached value if it exists and has not expired."""
        if key not in self._cache:
            self._misses += 1
            return None

        timestamp, value = self._cache[key]
        if time.time() - timestamp > self.ttl:
            del self._cache[key]
            self._misses += 1
            logger.debug("Cache expired for key %s", key[:16])
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)
        self._hits += 1
        logger.debug("Cache hit for key %s", key[:16])
        return value

    def set(self, key: str, value: Any) -> None:
        """Store a value, evicting the oldest entry if at capacity."""
        if key in self._cache:
            self._cache.move_to_end(key)
        elif len(self._cache) >= self.max_size:
            evicted_key, _ = self._cache.popitem(last=False)
            logger.debug("Evicted cache entry %s", evicted_key[:16])

        self._cache[key] = (time.time(), value)

    def stats(self) -> dict:
        """Return cache statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0.0
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "ttl": self.ttl,
            "hits": self._hits,
            "misses": self._misses,
            "total_requests": total,
            "hit_rate_percent": round(hit_rate, 1),
        }

    def clear(self) -> None:
        """Remove all entries from the cache."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0
