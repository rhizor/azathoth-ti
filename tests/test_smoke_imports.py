"""
Smoke tests - verify core modules can be imported.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

def test_import_models():
    """Import real models module."""
    import models
    assert models is not None

def test_import_ioc_type():
    """Import IOCType enum."""
    from models import IOCType
    assert IOCType.IP is not None

def test_import_ioc_status():
    """Import IOCStatus enum."""
    from models import IOCStatus
    assert IOCStatus.ACTIVE is not None

def test_import_ioc_class():
    """Import IOC class."""
    from models import IOC
    assert IOC is not None

def test_import_collectors():
    """Import collectors module."""
    import collectors
    assert collectors is not None

def test_import_processors():
    """Import processors module."""
    import processors
    assert processors is not None

def test_import_storage():
    """Import storage module."""
    import storage
    assert storage is not None
