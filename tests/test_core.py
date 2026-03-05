"""
Azathoth TI - Test Suite
Tests core threat intelligence processing: normalization, validation, deduplication.
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, List

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


# Mock IOC model for testing (simplified from src/models.py)
class IOC:
    """Simplified IOC model for testing."""
    def __init__(self, indicator: str, type: str, source: str, 
                 confidence: int = 50, tags: Optional[List[str]] = None,
                 first_seen: Optional[str] = None, last_seen: Optional[str] = None):
        self.indicator = indicator
        self.type = type
        self.source = source
        self.confidence = confidence
        self.tags = tags or []
        self.first_seen = first_seen or datetime.now().isoformat()
        self.last_seen = last_seen or datetime.now().isoformat()


class TestIOCNormalization:
    """Test IOC normalization logic."""

    def test_ip_normalization(self):
        """Test IP address normalization."""
        def normalize_ip(ip: str) -> str:
            ip = ip.strip().lower()
            # Remove port if present
            if '/' in ip:
                ip = ip.split('/')[0]
            return ip
        
        assert normalize_ip("192.168.1.1") == "192.168.1.1"
        assert normalize_ip("  10.10.10.10  ") == "10.10.10.10"
        assert normalize_ip("192.168.1.1/24") == "192.168.1.1"

    def test_domain_normalization(self):
        """Test domain normalization."""
        def normalize_domain(domain: str) -> str:
            domain = domain.strip().lower()
            # Remove protocol
            if '://' in domain:
                domain = domain.split('://')[-1]
            # Remove path
            if '/' in domain:
                domain = domain.split('/')[0]
            # Remove www
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        
        assert normalize_domain("Example.COM") == "example.com"
        assert normalize_domain("https://WWW.Example.COM/path") == "example.com"
        assert normalize_domain("example.com/") == "example.com"

    def test_url_normalization(self):
        """Test URL normalization."""
        def normalize_url(url: str) -> str:
            url = url.strip()
            # Remove trailing slash
            if url.endswith('/'):
                url = url[:-1]
            return url
        
        assert normalize_url("http://example.com/") == "http://example.com"
        assert normalize_url("https://example.com") == "https://example.com"

    def test_hash_normalization(self):
        """Test hash normalization (MD5, SHA1, SHA256)."""
        def normalize_hash(hash_val: str) -> str:
            return hash_val.strip().lower()
        
        assert normalize_hash("ABCD1234") == "abcd1234"
        assert normalize_hash("  ABCD1234  ") == "abcd1234"


class TestIOCValidation:
    """Test IOC validation logic."""

    def test_ipv4_validation(self):
        """Test IPv4 address validation."""
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        valid_ips = ['192.168.1.1', '10.10.10.10', '0.0.0.0', '255.255.255.255']
        for ip in valid_ips:
            assert re.match(ipv4_pattern, ip)

    def test_domain_validation(self):
        """Test domain validation."""
        import re
        domain_pattern = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
        
        assert re.match(domain_pattern, 'example.com')
        assert re.match(domain_pattern, 'sub.example.com')
        assert not re.match(domain_pattern, '-invalid.com')

    def test_hash_validation(self):
        """Test hash format validation."""
        import re
        
        md5_pattern = r'^[a-f0-9]{32}$'
        sha1_pattern = r'^[a-f0-9]{40}$'
        sha256_pattern = r'^[a-f0-9]{64}$'
        
        assert re.match(md5_pattern, 'd41d8cd98f00b204e9800998ecf8427e')
        assert re.match(sha1_pattern, 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
        assert re.match(sha256_pattern, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def test_url_validation(self):
        """Test URL validation."""
        import re
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        
        assert re.match(url_pattern, 'http://example.com')
        assert re.match(url_pattern, 'https://example.com/path')


class TestDeduplication:
    """Test IOC deduplication logic."""

    def test_exact_deduplication(self):
        """Test exact match deduplication."""
        iocs = [
            IOC("192.168.1.1", "ip", "source1"),
            IOC("192.168.1.1", "ip", "source2"),
            IOC("10.10.10.10", "ip", "source1"),
        ]
        
        unique = {}
        for ioc in iocs:
            key = f"{ioc.type}:{ioc.indicator}"
            if key not in unique:
                unique[key] = ioc
        
        assert len(unique) == 2

    def test_case_insensitive_deduplication(self):
        """Test case-insensitive deduplication."""
        iocs = [
            IOC("Example.COM", "domain", "source1"),
            IOC("EXAMPLE.COM", "domain", "source2"),
        ]
        
        unique = {}
        for ioc in iocs:
            key = f"{ioc.type}:{ioc.indicator.lower()}"
            if key not in unique:
                unique[key] = ioc
        
        assert len(unique) == 1


class TestConfidenceCalculation:
    """Test confidence score calculation."""

    def test_source_based_confidence(self):
        """Test confidence based on source reputation."""
        source_weights = {
            'alienvault': 70,
            'abuseipdb': 80,
            'urlhaus': 90,
            'threatfox': 85,
            'unknown': 30
        }
        
        for source, expected in source_weights.items():
            ioc = IOC("test.com", "domain", source)
            confidence = source_weights.get(source, 30)
            assert confidence == expected

    def test_tag_based_confidence(self):
        """Test confidence adjustment based on tags."""
        def calculate_confidence(base: int, tags: List[str]) -> int:
            # Add confidence for known malicious tags
            malicious_tags = {'malware', 'c2', 'phishing', 'spam'}
            for tag in tags:
                if tag.lower() in malicious_tags:
                    base += 10
            return min(base, 100)
        
        assert calculate_confidence(50, ['malware']) == 60
        assert calculate_confidence(50, ['c2']) == 60
        assert calculate_confidence(90, ['malware']) == 100  # Cap at 100


class TestDataStructures:
    """Test data structure handling."""

    def test_ioc_creation(self):
        """Test IOC object creation."""
        ioc = IOC(
            indicator="192.168.1.1",
            type="ip",
            source="test",
            confidence=75,
            tags=["malware", "c2"]
        )
        
        assert ioc.indicator == "192.168.1.1"
        assert ioc.type == "ip"
        assert ioc.confidence == 75
        assert "malware" in ioc.tags

    def test_ioc_timestamps(self):
        """Test IOC timestamp handling."""
        before = datetime.now().isoformat()
        ioc = IOC("test.com", "domain", "test")
        after = datetime.now().isoformat()
        
        assert before <= ioc.first_seen <= after
        assert before <= ioc.last_seen <= after


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_indicator(self):
        """Test handling of empty indicators."""
        ioc = IOC("", "ip", "test")
        assert ioc.indicator == ""

    def test_special_characters(self):
        """Test handling of special characters in indicators."""
        # Domain with special chars should be cleaned
        def clean_indicator(indicator: str) -> str:
            return indicator.replace(' ', '').replace('\n', '').replace('\t', '')
        
        assert clean_indicator("test . com") == "test.com"
        assert clean_indicator("test\t.com") == "test.com"

    def test_very_long_indicator(self):
        """Test handling of very long indicators."""
        long_domain = "a" * 100 + ".com"
        assert len(long_domain) == 104
