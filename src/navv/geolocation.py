"""
Geolocation lookup functionality for NAVV.

This module provides IP geolocation capabilities using the MaxMind GeoLite2
Country database to identify the country of external IP addresses.

Uses maxminddb package (lightweight alternative to geoip2).
"""

import ipaddress
import logging
import os
from pathlib import Path
from typing import Dict, Optional
import urllib.request
import urllib.error
import gzip
from datetime import datetime
from navv.message_handler import warning_msg, success_msg, error_msg


try:
    import maxminddb
    MAXMINDDB_AVAILABLE = True
except ImportError:
    MAXMINDDB_AVAILABLE = False

# logger = logging.getLogger(__name__)


class Geolocator:
    """
    Handles geolocation lookups for IP addresses using MaxMind GeoLite2.
    
    This class provides methods to lookup the country for IP addresses,
    with automatic detection of private/internal IPs and caching for
    improved performance.
    """

    def __init__(self, db_path: Optional[str] = None, enable_cache: bool = True):
        """
        Initialize the geolocator.

        Args:
            db_path: Path to the GeoLite2 Country database file (MMDB format).
                    If None, searches common locations.
            enable_cache: Enable caching of lookup results for performance.
        """
        self.reader = None
        self.city_reader = None
        self.asn_reader = None
        self.enabled = False
        self.enable_cache = enable_cache
        self._cache: Dict[str, Optional[str]] = {}
        self._ext_cache: Dict[str, Dict[str, str]] = {}

        if not MAXMINDDB_AVAILABLE:
            warning_msg("maxminddb library not available. Install with: pip install maxminddb")
            return
            
        def is_db_stale(path: Path, max_age_days=45) -> bool:
            if not path.exists():
                return True
            try:
                reader = maxminddb.open_database(str(path))
                epoch = reader.metadata().build_epoch
                reader.close()
                age = datetime.now().timestamp() - epoch
                return age > (max_age_days * 86400)
            except Exception:
                return True

        def get_previous_month(dt):
            first = dt.replace(day=1)
            if first.month == 1:
                 return first.replace(year=first.year - 1, month=12)
            return first.replace(month=first.month - 1)

        def download_dbip_lite(db_type: str, dest_path: Path):
            import ssl
            now = datetime.now()
            url_base = f"https://download.db-ip.com/free/dbip-{db_type}-lite-{{}}.mmdb.gz"
            months_to_try = [now, get_previous_month(now)]
            
            def attempt_download(url, ctx=None):
                req = urllib.request.Request(url, headers={'User-Agent': 'NAVV/3.4.2'})
                with urllib.request.urlopen(req, timeout=60, context=ctx) as response:
                    if response.status == 200:
                        uncompressed_data = gzip.decompress(response.read())
                        dest_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(dest_path, "wb") as f:
                            f.write(uncompressed_data)
                        return True
                return False

            for dt in months_to_try:
                ym = dt.strftime("%Y-%m")
                url = url_base.format(ym)
                try:
                    warning_msg(f"Downloading DB-IP {db_type.upper()} Lite database from {url}...")
                    try:
                        if attempt_download(url):
                            success_msg(f"Successfully downloaded DB-IP {db_type.upper()} Lite to {dest_path}")
                            return True
                    except urllib.error.URLError as e:
                        if hasattr(e, 'reason') and isinstance(e.reason, ssl.SSLError):
                            warning_msg("SSL Verification failed. Retrying without SSL verification...")
                            ctx = ssl.create_default_context()
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            if attempt_download(url, ctx):
                                success_msg(f"Successfully downloaded DB-IP {db_type.upper()} Lite to {dest_path} (Unverified SSL)")
                                return True
                        else:
                            raise e
                except urllib.error.HTTPError as e:
                    if e.code == 404: continue
                    error_msg(f"HTTP Error {e.code} downloading {url}")
                    break
                except Exception as e:
                     error_msg(f"Error downloading {url}: {e}")
                     break
            error_msg(f"Failed to auto-download DB-IP {db_type} database.")
            return False

        # If a specific offline path is provided via CLI (-g), rely completely on that directory
        if db_path:
            db_p = Path(db_path)
            if db_p.is_dir():
                c_path = db_p / "GeoLite2-Country.mmdb"
                city_path = db_p / "GeoLite2-City.mmdb"
                asn_path = db_p / "GeoLite2-ASN.mmdb"
            else:
                c_path = db_p
                city_path = Path(str(db_p).replace("Country", "City"))
                asn_path = Path(str(db_p).replace("Country", "ASN"))
                
            if c_path.exists():
                try:
                    self.reader = maxminddb.open_database(str(c_path))
                    self.enabled = True
                    success_msg(f"GeoLite2-Country loaded: {c_path}")
                except Exception: pass
            if city_path.exists():
                try:
                    self.city_reader = maxminddb.open_database(str(city_path))
                    if not self.enabled: self.reader = self.city_reader
                    self.enabled = True
                    success_msg(f"GeoLite2-City loaded: {city_path}")
                except Exception: pass
            if asn_path.exists():
                try:
                    self.asn_reader = maxminddb.open_database(str(asn_path))
                    success_msg(f"GeoLite2-ASN loaded: {asn_path}")
                except Exception: pass
                
            if self.enabled:
                success_msg("Offline MaxMind/DB-IP databases loaded.")
            else:
                warning_msg("Geolocation will be disabled.")
            return
            
        # If no offline path, leverage the automatic DB-IP infrastructure
        navv_dir = Path.home() / ".navv"
        city_path = navv_dir / "dbip-city-lite.mmdb"
        asn_path = navv_dir / "dbip-asn-lite.mmdb"

        if is_db_stale(city_path):
             download_dbip_lite("city", city_path)
        if is_db_stale(asn_path):
             download_dbip_lite("asn", asn_path)
             
        try:
             self.city_reader = maxminddb.open_database(str(city_path))
             self.reader = self.city_reader # City also provides country dict
             self.enabled = True
        except Exception:
             pass
             
        try:
             self.asn_reader = maxminddb.open_database(str(asn_path))
        except Exception:
             pass

        if self.enabled:
             success_msg("IP Geolocation by DB-IP (https://db-ip.com)")
        else:
            warning_msg("Networking failure. Geolocation will be disabled.")

        
        # logger.info(
        #     "Searched locations:\n" +
        #     "\n".join(f"  - {path}" for path in search_paths[:6])
        # )
        # logger.info(
        #     "To enable geolocation:\n"
        #     "  1. Sign up at https://www.maxmind.com/en/geolite2/signup\n"
        #     "  2. Download GeoLite2 Country database (MMDB format)\n"
        #     f"  3. Place it at one of:\n"
        #     f"     - {module_dir}/GeoLite2-Country.mmdb (same as geolocation.py)\n"
        #     f"     - ~/.navv/GeoLite2-Country.mmdb\n"
        #     f"     - {Path.cwd()}/GeoLite2-Country.mmdb (current directory)"
        # )

    def lookup(self, ip_address: str) -> Optional[str]:
        """
        Lookup the country for an IP address.

        Args:
            ip_address: IP address string to lookup

        Returns:
            Country name or None if:
            - Lookup fails
            - IP is private/internal
            - Geolocation is disabled
            - IP not found in database
            
        Examples:
            >>> geo = Geolocator()
            >>> geo.lookup("8.8.8.8")
            'United States'
            >>> geo.lookup("192.168.1.1")
            None
        """
        if not self.enabled or not self.reader:
            return None

        # Check cache first
        if self.enable_cache and ip_address in self._cache:
            return self._cache[ip_address]

        try:
            # Parse IP address to validate format
            ip_obj = ipaddress.ip_address(ip_address)

            # Skip private/internal addresses
            if self._is_internal_ip_obj(ip_obj):
                result = None
            else:
                # Perform lookup
                response = self.reader.get(ip_address)
                
                if response:
                    # Extract country information from response
                    country_data = response.get('country', {})
                    
                    # Prefer English name, fall back to ISO code
                    names = country_data.get('names', {})
                    country_name = names.get('en')  # English name
                    
                    if not country_name:
                        country_name = country_data.get('iso_code')
                    
                    result = country_name
                else:
                    result = None

        except (ValueError, KeyError):
            # Invalid IP format or not in database
            result = None
        except Exception as e:
            # logger.debug(f"Geolocation lookup failed for {ip_address}: {e}")
            result = None

        # Cache the result
        if self.enable_cache:
            self._cache[ip_address] = result

        return result

    def lookup_external(self, ip_address: str) -> Dict[str, str]:
        """Provides comprehensive location/isp data."""
        res = {"country": "", "region": "", "city": "", "isp": ""}
        if not self.enabled:
            return res
            
        if self.enable_cache and ip_address in self._ext_cache:
            return self._ext_cache[ip_address]

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if self._is_internal_ip_obj(ip_obj):
                return res

            # Fill country using default country or city reader
            if self.reader:
                c_resp = self.reader.get(ip_address)
                if c_resp:
                    res["country"] = c_resp.get('country', {}).get('names', {}).get('en', '')
            
            # Fill region/city using city reader
            if self.city_reader:
                city_resp = self.city_reader.get(ip_address)
                if city_resp:
                    if not res["country"]:
                        res["country"] = city_resp.get('country', {}).get('names', {}).get('en', '')
                    res["city"] = city_resp.get('city', {}).get('names', {}).get('en', '')
                    subdivs = city_resp.get('subdivisions', [])
                    if subdivs:
                        res["region"] = subdivs[0].get('names', {}).get('en', '')
                        
            # Fill isp using asn reader
            if self.asn_reader:
                asn_resp = self.asn_reader.get(ip_address)
                if asn_resp:
                    res["isp"] = asn_resp.get('autonomous_system_organization', '')
                    
        except Exception:
            pass
            
        if self.enable_cache:
            self._ext_cache[ip_address] = res
            
        return res

    def is_internal_ip(self, ip_address: str) -> bool:
        """
        Check if an IP address is internal/private.

        Args:
            ip_address: IP address string to check

        Returns:
            True if IP is private/internal, False otherwise
            
        Examples:
            >>> geo = Geolocator()
            >>> geo.is_internal_ip("192.168.1.1")
            True
            >>> geo.is_internal_ip("8.8.8.8")
            False
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            return self._is_internal_ip_obj(ip_obj)
        except ValueError:
            # Invalid IP address format
            return False

    def _is_internal_ip_obj(self, ip_obj) -> bool:
        """
        Check if an IP address object is internal/private.

        Args:
            ip_obj: IP address object

        Returns:
            True if IP is private/internal, False otherwise
        """
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_reserved or
            ip_obj.is_multicast
        )

    def lookup_with_iso(self, ip_address: str) -> Optional[tuple]:
        """
        Lookup both country name and ISO code for an IP address.

        Args:
            ip_address: IP address string to lookup

        Returns:
            Tuple of (country_name, iso_code) or None if lookup fails
            
        Examples:
            >>> geo = Geolocator()
            >>> geo.lookup_with_iso("8.8.8.8")
            ('United States', 'US')
        """
        if not self.enabled or not self.reader:
            return None

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            if self._is_internal_ip_obj(ip_obj):
                return None
                
            response = self.reader.get(ip_address)
            
            if response:
                country_data = response.get('country', {})
                names = country_data.get('names', {})
                country_name = names.get('en', '')
                iso_code = country_data.get('iso_code', '')
                
                if country_name or iso_code:
                    return (country_name, iso_code)
            
            return None

        except (ValueError, KeyError):
            return None
        except Exception as e:
            # logger.debug(f"Geolocation lookup failed for {ip_address}: {e}")
            return None

    def clear_cache(self):
        """Clear the lookup cache."""
        self._cache.clear()

    def get_cache_stats(self) -> Dict[str, int]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        return {
            'cached_entries': len(self._cache),
            'enabled': self.enable_cache
        }

    def close(self):
        """Close the database reader and clear cache."""
        if self.reader and self.reader != self.city_reader:
            self.reader.close()
        if self.city_reader:
            self.city_reader.close()
        if self.asn_reader:
            self.asn_reader.close()
        self.reader = None
        self.city_reader = None
        self.asn_reader = None
        self.enabled = False
        self._cache.clear()
        self._ext_cache.clear()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def __del__(self):
        """Destructor to ensure database is closed."""
        self.close()


def create_geolocator(db_path: Optional[str] = None) -> Geolocator:
    """
    Factory function to create a Geolocator instance.

    Args:
        db_path: Optional path to GeoLite2 database

    Returns:
        Initialized Geolocator instance
    """
    return Geolocator(db_path=db_path)
