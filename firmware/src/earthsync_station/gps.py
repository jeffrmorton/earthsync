"""GPS PPS timing via gpsd."""
# pyright: reportMissingImports=false

from abc import ABC, abstractmethod
from datetime import UTC, datetime


class GPSInterface(ABC):
    """Abstract GPS interface for testability."""

    @abstractmethod
    def get_time(self) -> datetime: ...

    @abstractmethod
    def is_synchronized(self) -> bool: ...

    @abstractmethod
    def close(self) -> None: ...


class GPSD(GPSInterface):
    """GPS timing via gpsd daemon."""

    def __init__(self, host: str = "localhost", port: int = 2947):
        self._host = host
        self._port = port
        self._session = None

    def get_time(self) -> datetime:
        try:
            import gps  # noqa: PLC0415

            if self._session is None:
                self._session = gps.gps(
                    host=self._host,
                    port=self._port,
                    mode=gps.WATCH_ENABLE,
                )
            self._session.next()
            if hasattr(self._session.fix, "time") and self._session.fix.time:
                return datetime.fromisoformat(str(self._session.fix.time))
        except ImportError as err:
            raise RuntimeError("gps module not available — install gpsd-py3") from err
        return datetime.now(UTC)

    def is_synchronized(self) -> bool:
        try:
            self.get_time()
        except Exception:
            return False
        else:
            return True

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None


class MockGPS(GPSInterface):
    """Mock GPS for testing."""

    def __init__(self, synchronized: bool = True):
        self._synchronized = synchronized

    def get_time(self) -> datetime:
        return datetime.now(UTC)

    def is_synchronized(self) -> bool:
        return self._synchronized

    def close(self) -> None:
        pass
