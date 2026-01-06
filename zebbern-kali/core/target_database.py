#!/usr/bin/env python3
"""Target Database - persistent storage for targets, findings, and scan history."""

import os
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from core.config import logger

# Database directory
DB_DIR = "/opt/zebbern-kali/database"
os.makedirs(DB_DIR, exist_ok=True)


class TargetDatabase:
    """Manage targets, findings, and scan history."""
    
    def __init__(self):
        self.targets: Dict[str, Dict] = {}
        self.findings: Dict[str, Dict] = {}
        self.scan_history: List[Dict] = []
        self.credentials: Dict[str, Dict] = {}
        self._load_database()
    
    def _load_database(self):
        """Load database from disk."""
        files = {
            "targets": "targets.json",
            "findings": "findings.json",
            "scan_history": "scan_history.json",
            "credentials": "credentials.json"
        }
        
        for attr, filename in files.items():
            filepath = f"{DB_DIR}/{filename}"
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        setattr(self, attr, json.load(f))
                except Exception as e:
                    logger.warning(f"Could not load {filename}: {e}")
    
    def _save_database(self):
        """Save database to disk."""
        files = {
            "targets": "targets.json",
            "findings": "findings.json",
            "scan_history": "scan_history.json",
            "credentials": "credentials.json"
        }
        
        for attr, filename in files.items():
            filepath = f"{DB_DIR}/{filename}"
            try:
                with open(filepath, 'w') as f:
                    json.dump(getattr(self, attr), f, indent=2, default=str)
            except Exception as e:
                logger.error(f"Could not save {filename}: {e}")
    
    # ==================== Target Management ====================
    
    def add_target(self, address: str, target_type: str = "host",
                   name: str = "", description: str = "",
                   tags: List[str] = None, metadata: Dict = None) -> Dict[str, Any]:
        """
        Add a new target to the database.
        
        Args:
            address: IP address, hostname, or URL
            target_type: Type (host, network, webapp, service)
            name: Friendly name
            description: Target description
            tags: Optional tags for filtering
            metadata: Additional metadata
            
        Returns:
            Created target info
        """
        target_id = str(uuid.uuid4())[:8]
        
        target = {
            "id": target_id,
            "address": address,
            "type": target_type,
            "name": name or address,
            "description": description,
            "tags": tags or [],
            "metadata": metadata or {},
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "status": "new",
            "scan_count": 0,
            "finding_count": 0,
            "notes": []
        }
        
        self.targets[target_id] = target
        self._save_database()
        
        return {"success": True, "target_id": target_id, "target": target}
    
    def get_target(self, target_id: str) -> Dict[str, Any]:
        """Get a target by ID."""
        if target_id not in self.targets:
            return {"success": False, "error": f"Target {target_id} not found"}
        
        target = self.targets[target_id]
        
        # Get related findings
        related_findings = [
            f for f in self.findings.values()
            if f.get("target_id") == target_id
        ]
        
        # Get related scans
        related_scans = [
            s for s in self.scan_history
            if s.get("target_id") == target_id
        ]
        
        return {
            "success": True,
            "target": target,
            "findings": related_findings,
            "scans": related_scans[-10:],  # Last 10 scans
            "finding_count": len(related_findings),
            "scan_count": len(related_scans)
        }
    
    def update_target(self, target_id: str, updates: Dict) -> Dict[str, Any]:
        """Update a target's information."""
        if target_id not in self.targets:
            return {"success": False, "error": f"Target {target_id} not found"}
        
        allowed_fields = ["name", "description", "tags", "metadata", "status", "notes"]
        
        for field, value in updates.items():
            if field in allowed_fields:
                if field == "tags" and isinstance(value, list):
                    self.targets[target_id]["tags"] = value
                elif field == "metadata" and isinstance(value, dict):
                    self.targets[target_id]["metadata"].update(value)
                elif field == "notes" and isinstance(value, str):
                    self.targets[target_id]["notes"].append({
                        "text": value,
                        "timestamp": datetime.now().isoformat()
                    })
                else:
                    self.targets[target_id][field] = value
        
        self.targets[target_id]["updated_at"] = datetime.now().isoformat()
        self._save_database()
        
        return {"success": True, "target": self.targets[target_id]}
    
    def delete_target(self, target_id: str, cascade: bool = False) -> Dict[str, Any]:
        """
        Delete a target.
        
        Args:
            target_id: Target ID to delete
            cascade: Also delete related findings and scans
        """
        if target_id not in self.targets:
            return {"success": False, "error": f"Target {target_id} not found"}
        
        deleted_findings = 0
        deleted_scans = 0
        
        if cascade:
            # Delete related findings
            findings_to_delete = [
                fid for fid, f in self.findings.items()
                if f.get("target_id") == target_id
            ]
            for fid in findings_to_delete:
                del self.findings[fid]
                deleted_findings += 1
            
            # Delete related scans
            self.scan_history = [
                s for s in self.scan_history
                if s.get("target_id") != target_id
            ]
        
        del self.targets[target_id]
        self._save_database()
        
        return {
            "success": True,
            "message": f"Target {target_id} deleted",
            "deleted_findings": deleted_findings if cascade else 0,
            "cascade": cascade
        }
    
    def list_targets(self, target_type: str = "", tags: List[str] = None,
                    status: str = "", search: str = "") -> Dict[str, Any]:
        """
        List targets with optional filtering.
        
        Args:
            target_type: Filter by type
            tags: Filter by tags (any match)
            status: Filter by status
            search: Search in name/address/description
        """
        results = []
        
        for tid, target in self.targets.items():
            # Apply filters
            if target_type and target.get("type") != target_type:
                continue
            if status and target.get("status") != status:
                continue
            if tags:
                target_tags = target.get("tags", [])
                if not any(t in target_tags for t in tags):
                    continue
            if search:
                search_lower = search.lower()
                searchable = f"{target.get('name', '')} {target.get('address', '')} {target.get('description', '')}".lower()
                if search_lower not in searchable:
                    continue
            
            results.append(target)
        
        return {
            "success": True,
            "targets": results,
            "count": len(results)
        }
    
    # ==================== Finding Management ====================
    
    def add_finding(self, target_id: str, title: str, severity: str,
                   description: str, finding_type: str = "vulnerability",
                   evidence: str = "", remediation: str = "",
                   cvss: float = 0.0, cve: str = "",
                   tags: List[str] = None) -> Dict[str, Any]:
        """
        Add a security finding.
        
        Args:
            target_id: Related target ID
            title: Finding title
            severity: critical, high, medium, low, info
            description: Detailed description
            finding_type: vulnerability, misconfiguration, info, etc.
            evidence: Proof/evidence of finding
            remediation: How to fix
            cvss: CVSS score
            cve: CVE identifier
            tags: Optional tags
        """
        if target_id and target_id not in self.targets:
            return {"success": False, "error": f"Target {target_id} not found"}
        
        finding_id = str(uuid.uuid4())[:8]
        
        finding = {
            "id": finding_id,
            "target_id": target_id,
            "title": title,
            "severity": severity.lower(),
            "description": description,
            "type": finding_type,
            "evidence": evidence,
            "remediation": remediation,
            "cvss": cvss,
            "cve": cve,
            "tags": tags or [],
            "status": "open",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        self.findings[finding_id] = finding
        
        # Update target finding count
        if target_id and target_id in self.targets:
            self.targets[target_id]["finding_count"] = \
                self.targets[target_id].get("finding_count", 0) + 1
            self.targets[target_id]["updated_at"] = datetime.now().isoformat()
        
        self._save_database()
        
        return {"success": True, "finding_id": finding_id, "finding": finding}
    
    def get_finding(self, finding_id: str) -> Dict[str, Any]:
        """Get a finding by ID."""
        if finding_id not in self.findings:
            return {"success": False, "error": f"Finding {finding_id} not found"}
        
        finding = self.findings[finding_id]
        
        # Get related target info
        target = None
        if finding.get("target_id"):
            target = self.targets.get(finding["target_id"])
        
        return {"success": True, "finding": finding, "target": target}
    
    def update_finding(self, finding_id: str, updates: Dict) -> Dict[str, Any]:
        """Update a finding."""
        if finding_id not in self.findings:
            return {"success": False, "error": f"Finding {finding_id} not found"}
        
        allowed_fields = ["title", "severity", "description", "evidence",
                         "remediation", "status", "tags", "cvss", "cve"]
        
        for field, value in updates.items():
            if field in allowed_fields:
                self.findings[finding_id][field] = value
        
        self.findings[finding_id]["updated_at"] = datetime.now().isoformat()
        self._save_database()
        
        return {"success": True, "finding": self.findings[finding_id]}
    
    def list_findings(self, target_id: str = "", severity: str = "",
                     status: str = "", finding_type: str = "",
                     tags: List[str] = None) -> Dict[str, Any]:
        """List findings with optional filtering."""
        results = []
        
        for fid, finding in self.findings.items():
            if target_id and finding.get("target_id") != target_id:
                continue
            if severity and finding.get("severity") != severity.lower():
                continue
            if status and finding.get("status") != status:
                continue
            if finding_type and finding.get("type") != finding_type:
                continue
            if tags:
                finding_tags = finding.get("tags", [])
                if not any(t in finding_tags for t in tags):
                    continue
            
            results.append(finding)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        results.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 5))
        
        return {
            "success": True,
            "findings": results,
            "count": len(results),
            "by_severity": {
                sev: len([f for f in results if f.get("severity") == sev])
                for sev in ["critical", "high", "medium", "low", "info"]
            }
        }
    
    # ==================== Scan History ====================
    
    def log_scan(self, target_id: str, scan_type: str, tool: str,
                 command: str = "", results_summary: str = "",
                 findings_count: int = 0, raw_output: str = "") -> Dict[str, Any]:
        """
        Log a scan in history.
        
        Args:
            target_id: Target that was scanned
            scan_type: Type of scan (port, vuln, web, etc.)
            tool: Tool used
            command: Command executed
            results_summary: Brief summary
            findings_count: Number of findings
            raw_output: Raw tool output (truncated)
        """
        scan_id = str(uuid.uuid4())[:8]
        
        scan = {
            "id": scan_id,
            "target_id": target_id,
            "scan_type": scan_type,
            "tool": tool,
            "command": command,
            "results_summary": results_summary,
            "findings_count": findings_count,
            "raw_output": raw_output[:10000] if raw_output else "",  # Limit size
            "timestamp": datetime.now().isoformat(),
            "duration": None
        }
        
        self.scan_history.append(scan)
        
        # Update target scan count
        if target_id and target_id in self.targets:
            self.targets[target_id]["scan_count"] = \
                self.targets[target_id].get("scan_count", 0) + 1
            self.targets[target_id]["updated_at"] = datetime.now().isoformat()
        
        # Keep only last 1000 scans
        if len(self.scan_history) > 1000:
            self.scan_history = self.scan_history[-1000:]
        
        self._save_database()
        
        return {"success": True, "scan_id": scan_id, "scan": scan}
    
    def get_scan_history(self, target_id: str = "", scan_type: str = "",
                        tool: str = "", limit: int = 50) -> Dict[str, Any]:
        """Get scan history with optional filtering."""
        results = self.scan_history.copy()
        
        if target_id:
            results = [s for s in results if s.get("target_id") == target_id]
        if scan_type:
            results = [s for s in results if s.get("scan_type") == scan_type]
        if tool:
            results = [s for s in results if tool.lower() in s.get("tool", "").lower()]
        
        # Return most recent first
        results = list(reversed(results))[:limit]
        
        return {
            "success": True,
            "scans": results,
            "count": len(results)
        }
    
    # ==================== Credential Management ====================
    
    def add_credential(self, username: str, password: str = "",
                       hash_value: str = "", target_id: str = "",
                       service: str = "", source: str = "",
                       notes: str = "") -> Dict[str, Any]:
        """
        Store a discovered credential.
        
        Args:
            username: Username
            password: Plaintext password (if known)
            hash_value: Password hash
            target_id: Related target
            service: Service (ssh, ftp, web, etc.)
            source: Where it was found
            notes: Additional notes
        """
        cred_id = str(uuid.uuid4())[:8]
        
        credential = {
            "id": cred_id,
            "username": username,
            "password": password,
            "hash": hash_value,
            "target_id": target_id,
            "service": service,
            "source": source,
            "notes": notes,
            "created_at": datetime.now().isoformat(),
            "verified": False
        }
        
        self.credentials[cred_id] = credential
        self._save_database()
        
        return {"success": True, "credential_id": cred_id}
    
    def list_credentials(self, target_id: str = "", service: str = "",
                        verified_only: bool = False) -> Dict[str, Any]:
        """List stored credentials."""
        results = []
        
        for cid, cred in self.credentials.items():
            if target_id and cred.get("target_id") != target_id:
                continue
            if service and cred.get("service") != service:
                continue
            if verified_only and not cred.get("verified"):
                continue
            
            # Mask passwords in list view
            masked = cred.copy()
            if masked.get("password"):
                masked["password"] = "***HIDDEN***"
            results.append(masked)
        
        return {
            "success": True,
            "credentials": results,
            "count": len(results)
        }
    
    def get_credential(self, cred_id: str) -> Dict[str, Any]:
        """Get a credential with full details."""
        if cred_id not in self.credentials:
            return {"success": False, "error": f"Credential {cred_id} not found"}
        return {"success": True, "credential": self.credentials[cred_id]}
    
    # ==================== Statistics ====================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        finding_severities = {}
        for f in self.findings.values():
            sev = f.get("severity", "unknown")
            finding_severities[sev] = finding_severities.get(sev, 0) + 1
        
        target_types = {}
        for t in self.targets.values():
            tt = t.get("type", "unknown")
            target_types[tt] = target_types.get(tt, 0) + 1
        
        return {
            "success": True,
            "statistics": {
                "total_targets": len(self.targets),
                "total_findings": len(self.findings),
                "total_scans": len(self.scan_history),
                "total_credentials": len(self.credentials),
                "findings_by_severity": finding_severities,
                "targets_by_type": target_types,
                "open_findings": len([f for f in self.findings.values() if f.get("status") == "open"])
            }
        }
    
    def export_database(self) -> Dict[str, Any]:
        """Export entire database as JSON."""
        return {
            "success": True,
            "export": {
                "targets": self.targets,
                "findings": self.findings,
                "scan_history": self.scan_history[-100:],  # Last 100 scans
                "credentials": self.credentials,
                "exported_at": datetime.now().isoformat()
            }
        }


# Global instance
target_db = TargetDatabase()
