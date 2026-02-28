"""
Azathoth TI - CLI Interface
Interfaz de línea de comandos.
"""

import asyncio
import argparse
import sys
from typing import Optional
from pathlib import Path

from .collectors.alienvault import AlienVaultCollector
from .collectors.abuseipdb import AbuseIPDBCollector
from .collectors.urlhaus import URLhausCollector, ThreatFoxCollector
from .processors.normalizer import normalizer
from .processors.deduplicator import Deduplicator
from .storage.database import Database
from .models import IOCType


class CLI:
    """Interfaz CLI para Azathoth TI."""
    
    def __init__(self, db_path: str = "data/azathoth.db"):
        """Inicializar CLI."""
        self.db = Database(db_path)
        self.deduplicator = Deduplicator()
    
    async def collect_all(self, feeds: Optional[list] = None, enrich: bool = False):
        """Recopilar de todos los feeds."""
        collectors = self._get_collectors(feeds)
        
        all_iocs = []
        
        for name, collector in collectors.items():
            print(f"📡 Recopilando de {name}...")
            try:
                iocs = await collector.collect()
                print(f"   → Obtenidos {len(iocs)} IOCs")
                all_iocs.extend(iocs)
            except Exception as e:
                print(f"   → Error: {e}")
        
        # Normalizar
        print("🔄 Normalizando IOCs...")
        normalized = normalizer.normalize_batch(
            [ioc.value for ioc in all_iocs],
            source="multiple"
        )
        
        # Desduplicar
        print("🔃 Desduplicando...")
        unique_iocs = self.deduplicator.deduplicate(all_iocs)
        print(f"   → {len(unique_iocs)} IOCs únicos")
        
        # Guardar
        print("💾 Guardando en base de datos...")
        count = self.db.insert_iocs(unique_iocs)
        print(f"   → {count} IOCs guardados")
        
        return count
    
    def _get_collectors(self, feeds: Optional[list] = None):
        """Obtener instancias de collectors."""
        collectors = {}
        
        # Configurar API keys desde variables de entorno
        import os
        alienvault_key = os.getenv("ALIENVAULT_API_KEY")
        abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        
        if not feeds or "alienvault" in feeds:
            if alienvault_key:
                collectors["alienvault"] = AlienVaultCollector(alienvault_key)
        
        if not feeds or "abuseipdb" in feeds:
            if abuseipdb_key:
                collectors["abuseipdb"] = AbuseIPDBCollector(abuseipdb_key)
        
        if not feeds or "urlhaus" in feeds:
            collectors["urlhaus"] = URLhausCollector()
        
        if not feeds or "threatfox" in feeds:
            collectors["threatfox"] = ThreatFoxCollector()
        
        return collectors
    
    def search(self, ioc_type: Optional[str] = None, value: Optional[str] = None):
        """Buscar IOCs."""
        ioc_type_enum = IOCType(ioc_type) if ioc_type else None
        
        iocs = self.db.search_iocs(
            ioc_type=ioc_type_enum,
            value=value,
            limit=50
        )
        
        if not iocs:
            print("No se encontraron IOCs.")
            return
        
        for ioc in iocs:
            print(f"\n[{ioc.type.value.upper()}] {ioc.value}")
            print(f"  Fuente: {ioc.source}")
            print(f"  Score: {ioc.score}")
            print(f"  Estado: {ioc.status.value}")
            if ioc.tags:
                print(f"  Tags: {', '.join(ioc.tags)}")
            if ioc.description:
                print(f"  Desc: {ioc.description}")
    
    def stats(self):
        """Mostrar estadísticas."""
        stats = self.db.get_stats()
        
        print("\n📊 Estadísticas de Azathoth TI")
        print("=" * 40)
        print(f"Total IOCs: {stats.total_iocs}")
        print(f"IOCs Activos: {stats.active_iocs}")
        
        print("\nPor tipo:")
        for ioc_type, count in stats.by_type.items():
            print(f"  {ioc_type}: {count}")
        
        print("\nPor fuente:")
        for source, count in stats.by_source.items():
            print(f"  {source}: {count}")
    
    def export(self, format: str = "json", output: str = "export", ioc_type: Optional[str] = None):
        """Exportar IOCs."""
        ioc_type_enum = IOCType(ioc_type) if ioc_type else None
        
        if format == "json":
            filepath = f"{output}.json"
            self.db.export_json(filepath, ioc_type_enum)
        elif format == "csv":
            filepath = f"{output}.csv"
            self.db.export_csv(filepath, ioc_type_enum)
        
        print(f"✅ Exportado a {filepath}")


def main():
    """Entry point."""
    parser = argparse.ArgumentParser(description="Azathoth TI CLI")
    
    subparsers = parser.add_subparsers(dest="command", help="Comandos")
    
    # Collect
    collect_parser = subparsers.add_parser("collect", help="Recopilar IOCs")
    collect_parser.add_argument("--all", action="store_true", help="Recopilar de todos los feeds")
    collect_parser.add_argument("--feeds", nargs="+", help="Feeds específicos")
    collect_parser.add_argument("--enrich", action="store_true", help="Enriquecer IOCs")
    
    # Search
    search_parser = subparsers.add_parser("search", help="Buscar IOCs")
    search_parser.add_argument("--type", help="Tipo de IOC")
    search_parser.add_argument("--value", help="Valor a buscar")
    
    # Stats
    subparsers.add_parser("stats", help="Ver estadísticas")
    
    # Export
    export_parser = subparsers.add_parser("export", help="Exportar IOCs")
    export_parser.add_argument("--format", choices=["json", "csv"], default="json")
    export_parser.add_argument("--output", default="export")
    export_parser.add_argument("--type", help="Tipo de IOC")
    
    args = parser.parse_args()
    
    cli = CLI()
    
    if args.command == "collect":
        feeds = args.feeds if args.feeds else None
        asyncio.run(cli.collect_all(feeds, args.enrich))
    
    elif args.command == "search":
        cli.search(args.type, args.value)
    
    elif args.command == "stats":
        cli.stats()
    
    elif args.command == "export":
        cli.export(args.format, args.output, args.type)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
