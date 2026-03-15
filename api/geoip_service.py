import os
import geoip2.database
from ipwhois import IPWhois

GEOIP_DB = os.getenv(
    "GEOIP_DB",
    "geoip/GeoLite2-City.mmdb"
)

reader = None

try:
    if os.path.exists(GEOIP_DB):
        reader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    reader = None


def geo_lookup_ip(ip):

    try:

        if reader:
            geo = reader.city(ip)
        else:
            raise Exception()

        city = geo.city.name or "Unknown"
        country = geo.country.iso_code or "??"
        lat = geo.location.latitude or 0
        lon = geo.location.longitude or 0

        origin_label = f"{city}, {country}"

    except:

        origin_label = "Unknown"
        lat = 0
        lon = 0
        country = "??"

    try:

        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)

        asn = res.get("asn", "N/A")

        isp = res.get(
            "network",
            {}
        ).get("name", "Unknown")

    except:

        asn = "N/A"
        isp = "Unknown"

    return origin_label, lat, lon, country, isp, asn