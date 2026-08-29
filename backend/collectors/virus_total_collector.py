import os
import re
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)
load_dotenv()


class VirusTotalCollector:
    """Enhanced VirusTotal domain intelligence collector"""
    
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"x-apikey": self.api_key})
        
    def collect_domain_intelligence(self, domain: str) -> Dict[str, Any]:
        """
        Collect comprehensive VirusTotal intelligence for a domain
        
        Returns structured data with:
        - Security vendor analysis (detailed breakdown)
        - Domain reputation scoring
        - Historical trends
        - Related domains and subdomains
        - URL analysis
        - Community feedback
        """
        if not self.api_key:
            raise ValueError("VIRUSTOTAL_API_KEY not configured")
            
        print(f"[*] Collecting comprehensive VirusTotal intelligence for: {domain}")
        
        result = {
            "domain": domain,
            "reputation": None,
            "security_vendors": {},
            "analysis_summary": {},
            "whois": {},
            "dns_records": [],
            "related_domains": [],
            "subdomains": [],
            "urls": [],
            "historical_data": [],
            "community_votes": {},
            "risk_score": 0,
            "categories": {},
            "registrar": None,
            "creation_date": None,
            "last_modification_date": None,
            "raw_data": {}
        }
        
        try:
            # 1. Get main domain report
            domain_data = self._get_domain_report(domain)
            if domain_data:
                result.update(self._parse_domain_report(domain_data))
            
            # 2. Get subdomains
            subdomains = self._get_subdomains(domain)
            if subdomains:
                result["subdomains"] = subdomains
            
            # 3. Get related domains
            related = self._get_related_domains(domain)
            if related:
                result["related_domains"] = related
            
            # 4. Get URL analysis
            urls = self._get_url_analysis(domain)
            if urls:
                result["urls"] = urls
            
            # 5. Get historical data (if available)
            historical = self._get_historical_data(domain)
            if historical:
                result["historical_data"] = historical
            
            # 6. Calculate risk score
            result["risk_score"] = self._calculate_risk_score(result)
            
            print(f"[+] VirusTotal intelligence collected. Risk Score: {result['risk_score']}/100")
            
        except requests.RequestException as e:
            logger.error(f"VirusTotal request failed: {e}")
            raise RuntimeError(f"VirusTotal request failed: {e}")
            
        return result
    
    def _get_domain_report(self, domain: str) -> Dict:
        """Fetch main domain report"""
        url = f"{self.base_url}/domains/{domain}"
        response = self.session.get(url, timeout=30)
        
        if response.status_code == 404:
            print("[!] Domain not found in VirusTotal.")
            return {}
        
        if response.status_code == 401:
            raise ValueError("VirusTotal API key is invalid or unauthorized.")
        
        if response.status_code == 429:
            raise ValueError("VirusTotal API rate limit exceeded.")
        
        response.raise_for_status()
        return response.json()
    
    def _parse_domain_report(self, data: Dict) -> Dict:
        """Parse comprehensive domain report"""
        attributes = data.get("data", {}).get("attributes", {})
        
        # Parse vendor analysis
        vendor_analysis = {}
        last_analysis = attributes.get("last_analysis_results", {})
        
        for vendor, result in last_analysis.items():
            vendor_analysis[vendor] = {
                "detected": result.get("category") == "malicious",
                "category": result.get("category", "unknown"),
                "result": result.get("result", "clean"),
                "method": result.get("method", ""),
                "engine_version": result.get("engine_version", "")
            }
        
        # Parse stats
        stats = attributes.get("last_analysis_stats", {})
        
        # Parse WHOIS
        whois_data = {}
        if "whois" in attributes:
            whois_data = self._parse_whois(attributes.get("whois", ""))
        
        # Parse DNS records
        dns_records = []
        for record in attributes.get("last_dns_records", []):
            dns_records.append({
                "type": record.get("type"),
                "value": record.get("value"),
                "ttl": record.get("ttl"),
                "record_name": record.get("record_name")
            })
        
        return {
            "reputation": attributes.get("reputation"),
            "security_vendors": vendor_analysis,
            "analysis_summary": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0)
            },
            "whois": whois_data,
            "dns_records": dns_records,
            "categories": attributes.get("categories", {}),
            "community_votes": attributes.get("total_votes", {}),
            "creation_date": attributes.get("creation_date"),
            "last_modification_date": attributes.get("last_modification_date"),
            "registrar": attributes.get("registrar"),
            "popularity_ranks": attributes.get("popularity_ranks", {})
        }
    
    def _parse_whois(self, whois_text: str) -> Dict:
        """Parse WHOIS data into structured format"""
        whois_data = {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "registrant": None,
            "admin_email": None,
            "tech_email": None
        }
        
        if not whois_text:
            return whois_data
        
        # Extract registrar
        registrar_match = re.search(r'Registrar:\s*(.+?)(?:\n|$)', whois_text, re.IGNORECASE)
        if registrar_match:
            whois_data["registrar"] = registrar_match.group(1).strip()
        
        # Extract dates
        creation_match = re.search(r'Creation Date:\s*(.+?)(?:\n|$)', whois_text, re.IGNORECASE)
        if creation_match:
            whois_data["creation_date"] = creation_match.group(1).strip()
        
        expiration_match = re.search(r'Registry Expiry Date:\s*(.+?)(?:\n|$)', whois_text, re.IGNORECASE)
        if expiration_match:
            whois_data["expiration_date"] = expiration_match.group(1).strip()
        
        updated_match = re.search(r'Updated Date:\s*(.+?)(?:\n|$)', whois_text, re.IGNORECASE)
        if updated_match:
            whois_data["updated_date"] = updated_match.group(1).strip()
        
        # Extract name servers
        ns_matches = re.findall(r'Name Server:\s*(.+?)(?:\n|$)', whois_text, re.IGNORECASE)
        whois_data["name_servers"] = [ns.strip() for ns in ns_matches]
        
        return whois_data
    
    def _get_subdomains(self, domain: str) -> List[Dict]:
        """Fetch subdomains from VirusTotal"""
        subdomains = []
        try:
            url = f"{self.base_url}/domains/{domain}/subdomains"
            params = {"limit": 100}
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    subdomains.append({
                        "domain": item.get("id"),
                        "reputation": attrs.get("reputation"),
                        "last_analysis_stats": attrs.get("last_analysis_stats", {})
                    })
        except Exception as e:
            logger.warning(f"Could not fetch subdomains: {e}")
        
        return subdomains
    
    def _get_related_domains(self, domain: str) -> List[Dict]:
        """Find domains related to the target"""
        related = []
        try:
            # Check for similar domains
            url = f"{self.base_url}/domains/{domain}/relationships"
            params = {"limit": 50}
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    related.append({
                        "domain": item.get("id"),
                        "relationship": item.get("type"),
                        "reputation": attrs.get("reputation", 0)
                    })
        except Exception as e:
            logger.warning(f"Could not fetch related domains: {e}")
        
        return related
    
    def _get_url_analysis(self, domain: str) -> List[Dict]:
        """Fetch URL analysis for the domain"""
        urls = []
        try:
            # Search for URLs containing the domain
            url = f"{self.base_url}/urls"
            params = {"filter": f"url:{domain}"}
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    urls.append({
                        "url": item.get("id"),
                        "last_analysis_stats": attrs.get("last_analysis_stats", {})
                    })
        except Exception as e:
            logger.warning(f"Could not fetch URL analysis: {e}")
        
        return urls
    
    def _get_historical_data(self, domain: str) -> List[Dict]:
        """Get historical analysis data"""
        historical = []
        try:
            # Get historical reports
            url = f"{self.base_url}/domains/{domain}/historical"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get("data", [])[:10]:  # Last 10 historical entries
                    attrs = item.get("attributes", {})
                    historical.append({
                        "date": attrs.get("date"),
                        "malicious_count": attrs.get("malicious", 0),
                        "total_scanners": attrs.get("total", 0)
                    })
        except Exception as e:
            logger.warning(f"Could not fetch historical data: {e}")
        
        return historical
    
    def _calculate_risk_score(self, data: Dict) -> int:
        """
        Calculate a risk score (0-100) based on multiple factors
        
        Factors considered:
        - Malicious vendor count (weighted heavily)
        - Suspicious vendor count
        - Domain reputation (negative is bad)
        - Community votes
        """
        score = 0
        max_score = 100
        
        # Factor 1: Malicious vendor detections (max 60 points)
        malicious = data.get("analysis_summary", {}).get("malicious", 0)
        if malicious > 0:
            score += min(malicious * 10, 60)
        
        # Factor 2: Suspicious vendor detections (max 20 points)
        suspicious = data.get("analysis_summary", {}).get("suspicious", 0)
        if suspicious > 0:
            score += min(suspicious * 5, 20)
        
        # Factor 3: Reputation (negative reputation = risk)
        reputation = data.get("reputation")
        if reputation is not None:
            if reputation < 0:
                score += min(abs(reputation) // 10, 10)
        
        # Factor 4: Community votes (if negative votes > positive)
        votes = data.get("community_votes", {})
        negative_votes = votes.get("malicious", 0)
        positive_votes = votes.get("harmless", 0)
        if negative_votes > positive_votes:
            score += min((negative_votes - positive_votes) * 2, 10)
        
        # Cap at 100
        return min(score, max_score)
    
    def get_detailed_analysis(self, domain: str) -> Dict:
        """
        Get a frontend-friendly detailed analysis
        
        Returns structured data optimized for UI display
        """
        intelligence = self.collect_domain_intelligence(domain)
        
        # Organize for frontend display
        return {
            "domain": domain,
            "risk_score": intelligence["risk_score"],
            "reputation": intelligence["reputation"],
            
            "security_summary": {
                "malicious": intelligence["analysis_summary"]["malicious"],
                "suspicious": intelligence["analysis_summary"]["suspicious"],
                "harmless": intelligence["analysis_summary"]["harmless"],
                "undetected": intelligence["analysis_summary"]["undetected"],
                "timeout": intelligence["analysis_summary"]["timeout"],
                "total_vendors": len(intelligence["security_vendors"])
            },
            
            "vendor_breakdown": [
                {
                    "vendor": vendor,
                    "status": details["category"],
                    "result": details["result"],
                    "detected": details["detected"]
                }
                for vendor, details in intelligence["security_vendors"].items()
                if details["category"] in ["malicious", "suspicious", "undetected"]
            ],
            
            "whois_info": intelligence["whois"],
            "dns_records": intelligence["dns_records"][:20],
            
            "relationships": {
                "subdomains_count": len(intelligence["subdomains"]),
                "subdomains": intelligence["subdomains"][:10],
                "related_domains_count": len(intelligence["related_domains"]),
                "related_domains": intelligence["related_domains"][:10]
            },
            
            "historical_trend": [
                {
                    "date": item["date"],
                    "malicious_count": item["malicious_count"]
                }
                for item in intelligence["historical_data"][:5]
            ],
            
            "categories": intelligence["categories"],
            
            "community_votes": {
                "harmless": intelligence.get("community_votes", {}).get("harmless", 0),
                "malicious": intelligence.get("community_votes", {}).get("malicious", 0)
            },
            
            "registrar": intelligence["registrar"],
            "creation_date": intelligence["creation_date"],
            "updated_date": intelligence["last_modification_date"],
            
            "risk_factors": self._generate_risk_factors(intelligence)
        }
    
    def _generate_risk_factors(self, intelligence: Dict) -> List[Dict]:
        """Generate human-readable risk factors"""
        factors = []
        
        # Check malicious detections
        malicious = intelligence["analysis_summary"]["malicious"]
        if malicious > 0:
            malicious_vendors = []
            for vendor, details in intelligence["security_vendors"].items():
                if details["category"] == "malicious":
                    malicious_vendors.append(f"{vendor}: {details['result']}")
            
            factors.append({
                "type": "malicious_detection",
                "severity": "high" if malicious > 3 else "medium",
                "description": f"{malicious} security vendors flagged this domain as malicious",
                "details": malicious_vendors[:3]
            })
        
        # Check suspicious detections
        suspicious = intelligence["analysis_summary"]["suspicious"]
        if suspicious > 3:
            suspicious_vendors = []
            for vendor, details in intelligence["security_vendors"].items():
                if details["category"] == "suspicious":
                    suspicious_vendors.append(f"{vendor}: {details['result']}")
            
            factors.append({
                "type": "suspicious_detection",
                "severity": "medium",
                "description": f"{suspicious} vendors found suspicious activity",
                "details": suspicious_vendors[:3]
            })
        
        # Check reputation
        reputation = intelligence["reputation"]
        if reputation is not None and reputation < 0:
            factors.append({
                "type": "low_reputation",
                "severity": "medium",
                "description": f"Domain has a negative reputation score ({reputation})",
                "details": ["Domain reputation is below average"]
            })
        
        # Check community votes
        votes = intelligence.get("community_votes", {})
        negative = votes.get("malicious", 0)
        if negative > 5:
            factors.append({
                "type": "community_concern",
                "severity": "low",
                "description": f"{negative} community members flagged this domain",
                "details": ["Domain has community-reported concerns"]
            })
        
        return factors


# ============================================================
# BACKWARD COMPATIBILITY FUNCTION
# ============================================================

def collect_virustotal_domain(domain: str) -> Dict:
    """
    Legacy function for backward compatibility.
    Returns the enhanced VirusTotal data.
    """
    collector = VirusTotalCollector()
    return collector.get_detailed_analysis(domain)