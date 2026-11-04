"""Provider registry construction — the one place that knows every adapter."""

from __future__ import annotations

from hunterintel.config import Settings
from hunterintel.providers.abusech import MalwareBazaarProvider, URLhausProvider
from hunterintel.providers.abuseipdb import AbuseIPDBProvider
from hunterintel.providers.base import ProviderRegistry
from hunterintel.providers.crtsh import CrtShProvider
from hunterintel.providers.cymru import CymruProvider
from hunterintel.providers.dns_records import DnsProvider
from hunterintel.providers.geoip import GeoIPProvider
from hunterintel.providers.local import LocalProvider
from hunterintel.providers.otx import OTXProvider
from hunterintel.providers.probe import ProbeProvider
from hunterintel.providers.rdap import RdapProvider
from hunterintel.providers.virustotal import VirusTotalProvider


def build_registry(settings: Settings) -> ProviderRegistry:
    """Order here is display order and also the order observations are listed in the UI."""
    return ProviderRegistry(
        [
            LocalProvider(settings),
            DnsProvider(settings),
            RdapProvider(settings),
            CymruProvider(settings),
            CrtShProvider(settings),
            GeoIPProvider(settings),
            ProbeProvider(settings),
            VirusTotalProvider(settings),
            AbuseIPDBProvider(settings),
            OTXProvider(settings),
            URLhausProvider(settings),
            MalwareBazaarProvider(settings),
        ]
    )
