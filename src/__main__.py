"""
Azathoth TI - Main Entry Point
Plataforma de Threat Intelligence.
"""

import asyncio
import argparse
from pathlib import Path

from .collectors.alienvault import AlienVaultCollector
from .collectors.abuseipdb import AbuseIPDBCollector
from .collectors.urlhaus import URLhausCollector, ThreatFoxCollector
from .processors.normalizer import normalizer
from .processors.deduplicator import Deduplicator
from .storage.database import Database
from .models import IOCType
from .api.main import run_server


async def collect_from_feeds(
    db: Database,
    feeds: list = None,
    enrich: bool = False
):
    """Recopilar IOCs desde feeds."""
    import os
    
    collectors = {}
    
    # AlienVault
    if not feeds or "alienvault" in feeds:
        key = os.getenv("ALIENVAULT_API_KEY")
        if key:
            collectors["alienvault"] = AlienVaultCollector(key)
    
    # AbuseIPDB
    if not feeds or "abuseipdb" in feeds:
        key = os.getenv("ABUSEIPDB_API_KEY")
        if key:
            collectors["abuseipdb"] = AbuseIPDBCollector(key)
    
    # URLhaus (no requiere API key)
    if not feeds or "urlhaus" in feeds:
        collectors["urlhaus"] = URLhausCollector()
    
    # ThreatFox (no requiere API key)
    if not feeds or "threatfox" in feeds:
        collectors["threatfox"] = ThreatFoxCollector()
    
    all_iocs = []
    deduplicator = Deduplicator()
    
    for name, collector in collectors.items():
        print(f"📡 Recopilando de {name}...")
        try:
            async with collector:
                iocs = await collector.collect()
                print(f"   → {len(iocs)} IOCs obtenidos")
                all_iocs.extend(iocs)
        except Exception as e:
            print(f"   → Error: {e}")
    
    if not all_iocs:
        print("No se obtuvo ningún IOC.")
        return 0
    
    # Normalizar
    print(f"🔄 Normalizando {len(all_iocs)} IOCs...")
    normalized_iocs = []
    for ioc in all_iocs:
        norm = normalizer.normalize(ioc.value, ioc.source)
        if norm:
            norm.tags = ioc.tags
            norm.metadata = ioc.metadata
            normalized_iocs.append(norm)
    
    # Desduplicar
    print("🔃 Desduplicando...")
    unique_iocs = deduplicator.deduplicate(normalized_iocs)
    print(f"   → {len(unique_iocs)} IOCs únicos")
    
    # Guardar
    print("💾 Guardando en base de datos...")
    count = db.insert_iocs(unique_iocs)
    print(f"   → {count} IOCs guardados")
    
    return count


def main():
    """Entry point principal."""
    parser = argparse.ArgumentParser(
        description="Azathoth TI - Threat Intelligence Platform"
    )
    
    parser.add_argument(
        "--db", 
        default="data/azathoth.db",
        help="Path a la base de datos"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Comandos")
    
    # Servidor API
    server_parser = subparsers.add_parser("server", help="Iniciar servidor API")
    server_parser.add_argument("--host", default="0.0.0.0")
    server_parser.add_argument("--port", type=int, default=8000)
    server_parser.add_argument("--debug", action="store_true")
    
    # Recopilar
    collect_parser = subparsers.add_parser("collect", help="Recopilar IOCs")
    collect_parser.add_argument("--feeds", nargs="+", help="Feeds específicos")
    collect_parser.add_argument("--enrich", action="store_true", help="Enriquecer IOCs")
    
    # Buscar
    search_parser = subparsers.add_parser("search", help="Buscar IOCs")
    search_parser.add_argument("--type", help="Tipo de IOC")
    search_parser.add_argument("--value", help="Valor a buscar")
    
    # Stats
    subparsers.add_parser("stats", help="Ver estadísticas")
    
    # Exportar
    export_parser = subparsers.add_parser("export", help="Exportar IOCs")
    export_parser.add_argument("--format", choices=["json", "csv"], default="json")
    export_parser.add_argument("--output", default="export")
    export_parser.add_argument("--type", help="Tipo de IOC")
    
    args = parser.parse_args()
    
    db = Database(args.db)
    
    if args.command == "server":
        print(f"🚀 Iniciando servidor en http://{args.host}:{args.port}")
        run_server(args.host, args.port, args.debug)
    
    elif args.command == "collect":
        feeds = args.feeds if args.feeds else None
        count = asyncio.run(collect_from_feeds(db, feeds, args.enrich))
        print(f"\n✅ Recopilación completada: {count} IOCs")
    
    elif args.command == "search":
        ioc_type = IOCType(args.type) if args.type else None
        iocs = db.search_iocs(ioc_type=ioc_type, value=args.value, limit=50)
        
        if not iocs:
            print("No se encontraron IOCs.")
        else:
            for ioc in iocs:
                print(f"\n[{ioc.type.value.upper()}] {ioc.value}")
                print(f"  Fuente: {ioc.source}")
                print(f"  Score: {ioc.score}")
                print(f"  Estado: {ioc.status.value}")
                if ioc.tags:
                    print(f"  Tags: {', '.join(ioc.tags)}")
    
    elif args.command == "stats":
        stats = db.get_stats()
        
        print("\n📊 Estadísticas de Azathoth TI")
        print("=" * 40)
        print(f"Total IOCs: {stats.total_iocs}")
        print(f"IOCs Activos: {stats.active_iocs}")
        
        if stats.by_type:
            print("\nPor tipo:")
            for ioc_type, count in stats.by_type.items():
                print(f"  {ioc_type}: {count}")
        
        if stats.by_source:
            print("\nPor fuente:")
            for source, count in stats.by_source.items():
                print(f"  {source}: {count}")
    
    elif args.command == "export":
        ioc_type = IOCType(args.type) if args.type else None
        
        if args.format == "json":
            filepath = f"{args.output}.json"
            db.export_json(filepath, ioc_type)
        else:
            filepath = f"{args.output}.csv"
            db.export_csv(filepath, ioc_type)
        
        print(f"✅ Exportado a {filepath}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
