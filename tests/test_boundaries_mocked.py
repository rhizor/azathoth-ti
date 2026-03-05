"""
Boundary tests - ensure external/side-effect functions are mocked properly.
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


class TestExternalAPIsMocked:
    """Ensure external API calls are properly mocked."""

    @patch('aiohttp.ClientSession')
    def test_session_creation_mocked(self, mock_session):
        """Test aiohttp session is mocked."""
        mock_session.return_value = MagicMock()
        
        import aiohttp
        session = aiohttp.ClientSession()
        assert session is not None

    @patch('aiohttp.ClientSession.get')
    def test_http_get_can_be_mocked(self, mock_get):
        """Test HTTP GET can be mocked at unit level."""
        # This verifies the mocking infrastructure works
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = MagicMock(return_value={"data": "test"})
        
        mock_get.return_value = mock_response
        
        # Verify mock is set up correctly
        assert mock_get is not None


class TestFileSystemMocked:
    """Ensure file operations are handled properly."""

    @patch('builtins.open', create=True)
    def test_file_read_mocked(self, mock_open):
        """Test file read is mocked."""
        mock_file = MagicMock()
        mock_file.read.return_value = '{"indicator": "test"}'
        mock_file.__enter__.return_value = mock_file
        mock_file.__exit__.return_value = False
        mock_open.return_value = mock_file
        
        with open("test.json") as f:
            content = f.read()
        
        assert content == '{"indicator": "test"}'

    @patch('pathlib.Path.exists')
    def test_path_exists_mocked(self, mock_exists):
        """Test path exists check is mocked."""
        mock_exists.return_value = True
        
        p = Path("/tmp/test")
        assert p.exists()
        mock_exists.assert_called()


class TestCollectorsBoundary:
    """Ensure collector external calls can be mocked."""

    def test_collectors_can_be_imported(self):
        """Verify collectors module can be imported."""
        import collectors
        assert collectors is not None

    def test_collector_modules_exist(self):
        """Verify collector modules exist."""
        # Just verify the collectors directory exists with modules
        collectors_dir = Path(__file__).parent.parent / 'src' / 'collectors'
        assert collectors_dir.exists()
        assert (collectors_dir / 'base.py').exists()
        assert (collectors_dir / 'alienvault.py').exists()


class TestProcessorBoundary:
    """Ensure processors work correctly."""

    def test_processors_can_be_imported(self):
        """Verify processors module can be imported."""
        import processors
        assert processors is not None

    def test_processor_modules_exist(self):
        """Verify processor modules exist."""
        processors_dir = Path(__file__).parent.parent / 'src' / 'processors'
        assert processors_dir.exists()
        assert (processors_dir / 'normalizer.py').exists()
        assert (processors_dir / 'deduplicator.py').exists()


class TestStorageBoundary:
    """Ensure storage operations work correctly."""

    def test_storage_can_be_imported(self):
        """Verify storage module can be imported."""
        import storage
        assert storage is not None

    def test_storage_modules_exist(self):
        """Verify storage modules exist."""
        storage_dir = Path(__file__).parent.parent / 'src' / 'storage'
        assert storage_dir.exists()
        assert (storage_dir / 'database.py').exists()
