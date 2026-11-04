"""Optional local GeoIP using a MaxMind-format (.mmdb) file *you* supply.

HunterIntel does not ship, download or call a geolocation service: licences differ per
database and public APIs would receive your indicators. The lookup is fully local.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import maxminddb

from hunterintel.domain.evidence import Assurance, ObservationDraft, ProviderResult, RunStatus, Tier
from hunterintel.domain.indicators import IndicatorType, ParsedIndicator
from hunterintel.providers.base import Provider, ProviderContext

ACCURACY_NOTE = (
    "IP geolocation is statistical. Country is usually right; city is often wrong; "
    "mobile, VPN, proxy, CDN and anycast addresses can be thousands of km off."
)


def _name(node: Any) -> str | None:
    return (node or {}).get("names", {}).get("en") if isinstance(node, dict) else None


class GeoIPProvider(Provider):
    name = "geoip_local"
    display_name = "Local GeoIP database"
    description = "Offline lookup in a MaxMind-format database that you provide."
    tier = Tier.LOCAL
    supported_types = frozenset({IndicatorType.IP})
    key_env = "HUNTERINTEL_GEOIP_DB_PATH"
    reliability = 0.0

    def __init__(self, settings: Any) -> None:
        super().__init__(settings)
        self._reader: maxminddb.Reader | None = None

    def is_configured(self) -> bool:
        path = self.settings.geoip_db_path
        return bool(path) and Path(path).is_file()

    def not_configured_reason(self) -> str:
        return "No GeoIP database configured. Set HUNTERINTEL_GEOIP_DB_PATH to a .mmdb file you are licensed to use."

    def _open(self) -> maxminddb.Reader:
        if self._reader is None:
            self._reader = maxminddb.open_database(self.settings.geoip_db_path)
        return self._reader

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        try:
            record = await asyncio.to_thread(lambda: self._open().get(parsed.value))
        except (maxminddb.InvalidDatabaseError, OSError, ValueError) as exc:
            return ProviderResult.unavailable(
                RunStatus.ERROR, f"GeoIP database error: {type(exc).__name__}"
            )
        if not record:
            return ProviderResult.no_data("The database has no entry for this address.")
        meta = self._open().metadata()
        loc = record.get("location", {}) if isinstance(record, dict) else {}
        subdivisions = [n for n in (_name(s) for s in record.get("subdivisions", [])) if n]
        data = {
            "country": _name(record.get("country")),
            "country_iso": (record.get("country") or {}).get("iso_code"),
            "continent": _name(record.get("continent")),
            "region": subdivisions,
            "city": _name(record.get("city")),
            "latitude": loc.get("latitude"),
            "longitude": loc.get("longitude"),
            "accuracy_radius_km": loc.get("accuracy_radius"),
            "database": meta.database_type,
            "database_build_epoch": meta.build_epoch,
            "accuracy_note": ACCURACY_NOTE,
        }
        place = ", ".join(x for x in [data["city"], data["country"]] if x) or "unknown"
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="geo.location",
                    title="GeoIP estimate",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data=data,
                    summary=f"{place} (approximate)",
                )
            ]
        )
