"""
Azathoth TI - SIEM Integration
Envía IOCs a sistemas SIEM.
"""

import json
import requests
from typing import List, Optional, Dict, Any
from datetime import datetime
from ..models import IOC


class SIEMExporter:
    """Exportador para sistemas SIEM."""
    
    def __init__(self):
        """Inicializar exporter."""
        self.session = requests.Session()
    
    def send_to_elasticsearch(
        self,
        iocs: List[IOC],
        host: str,
        index: str = "threat-intel",
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None
    ) -> bool:
        """Enviar IOCs a Elasticsearch."""
        url = f"{host}/{index}/_bulk"
        
        # Preparar headers
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
        
        # Preparar payload
        actions = []
        for ioc in iocs:
            action = {"index": {"_index": index}}
            doc = ioc.to_dict()
            doc["@timestamp"] = datetime.now().isoformat()
            actions.append(json.dumps(action))
            actions.append(json.dumps(doc))
        
        payload = "\n".join(actions) + "\n"
        
        try:
            response = requests.post(
                url,
                data=payload,
                headers=headers,
                auth=(username, password) if username and password else None,
                timeout=30
            )
            return response.status_code in (200, 201)
        except Exception:
            return False
    
    def send_to_splunk(
        self,
        iocs: List[IOC],
        host: str,
        token: str,
        index: str = "main",
        source: str = "azathoth-ti"
    ) -> bool:
        """Enviar IOCs a Splunk via HEC."""
        url = f"{host}/services/collector"
        
        headers = {"Authorization": f"Splunk {token}"}
        
        for ioc in iocs:
            event = {
                "time": datetime.now().timestamp(),
                "host": "azathoth-ti",
                "source": source,
                "sourcetype": "azathoth:ioc",
                "index": index,
                "event": ioc.to_dict()
            }
            
            try:
                response = requests.post(
                    url,
                    data=json.dumps(event),
                    headers=headers,
                    timeout=10
                )
            except Exception:
                pass
        
        return True
    
    def send_to_syslog(
        self,
        iocs: List[IOC],
        host: str,
        port: int = 514,
        protocol: str = "udp",
        facility: int = 16  # local0
    ) -> bool:
        """Enviar IOCs via Syslog."""
        import socket
        
        for ioc in iocs:
            # Formato CEF-like
            message = f"CEF:0|Azathoth|TI|1.0|100|{ioc.type.value}|{ioc.score}|src={ioc.value} cs1={ioc.source}"
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM)
                sock.connect((host, port))
                sock.send(message.encode())
                sock.close()
            except Exception:
                pass
        
        return True
    
    def send_to_webhook(
        self,
        iocs: List[IOC],
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None
    ) -> bool:
        """Enviar IOCs a webhook."""
        payload = {
            "source": "azathoth-ti",
            "timestamp": datetime.now().isoformat(),
            "count": len(iocs),
            "iocs": [ioc.to_dict() for ioc in iocs]
        }
        
        headers = headers or {"Content-Type": "application/json"}
        
        try:
            response = requests.request(
                method,
                url,
                json=payload,
                headers=headers,
                timeout=30
            )
            return response.status_code in (200, 201, 202)
        except Exception:
            return False


# Singleton
siem = SIEMExporter()
