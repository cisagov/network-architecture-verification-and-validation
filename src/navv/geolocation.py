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
        self.enabled = False
        self.enable_cache = enable_cache
        self._cache: Dict[str, Optional[str]] = {}

        if not MAXMINDDB_AVAILABLE:
            warning_msg("maxminddb library not available. Install with: pip install maxminddb")
            warning_msg("Geolocation functionality will be disabled.")
            return

        # Get the directory where this module is located
        module_dir = Path(__file__).parent.resolve()
        
        # Search for database in common locations
        search_paths = []
        if db_path:
            search_paths.append(Path(db_path))
        
        # Add common locations including module directory
        search_paths.extend([
            # Same directory as this module (for pip installed in .local)
            module_dir / "GeoLite2-Country.mmdb",
            # User home .navv directory
            Path.home() / ".navv" / "GeoLite2-Country.mmdb",
            # Current working directory
            Path.cwd() / "GeoLite2-Country.mmdb",
            # System-wide locations
            Path("/usr/local/share/GeoLite2-Country.mmdb"),
            Path("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
            Path("/var/lib/GeoIP/GeoLite2-Country.mmdb"),
        ])

        # Find first existing database
        for path in search_paths:
            if path.exists() and path.is_file():
                try:
                    self.reader = maxminddb.open_database(str(path))
                    self.enabled = True
                    if db_path:
                        success_msg(f"GeoIP database loaded successfully from: {str(path)}")
                    else:
                        success_msg("GeoIP database loaded successfully")                        
                    # MaxMind attribution as required by their license
                    success_msg("This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com.")
                    return
                except Exception as e:
                    error_msg(f"Failed to load GeoIP database from {path}: {e}")

        warning_msg("GeoIP database not found in any common location.")
        warning_msg("Geolocation will be disabled.")
        
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
        if self.reader:
            self.reader.close()
            self.reader = None
        self.enabled = False
        self._cache.clear()

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
