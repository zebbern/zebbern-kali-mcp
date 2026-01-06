#!/usr/bin/env python3
"""Screenshot & Evidence Collector - captures web screenshots and stores evidence."""

import os
import subprocess
import time
import uuid
import base64
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from core.config import logger

# Evidence storage directory
EVIDENCE_DIR = "/opt/zebbern-kali/evidence"
SCREENSHOTS_DIR = f"{EVIDENCE_DIR}/screenshots"
NOTES_DIR = f"{EVIDENCE_DIR}/notes"

# Ensure directories exist
for d in [EVIDENCE_DIR, SCREENSHOTS_DIR, NOTES_DIR]:
    os.makedirs(d, exist_ok=True)


class EvidenceCollector:
    """Collect and manage penetration testing evidence."""
    
    def __init__(self):
        self.evidence_index: Dict[str, Dict] = {}
        self._load_index()
    
    def _load_index(self):
        """Load evidence index from disk."""
        index_file = f"{EVIDENCE_DIR}/index.json"
        if os.path.exists(index_file):
            try:
                with open(index_file, 'r') as f:
                    self.evidence_index = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load evidence index: {e}")
                self.evidence_index = {}
    
    def _save_index(self):
        """Save evidence index to disk."""
        index_file = f"{EVIDENCE_DIR}/index.json"
        try:
            with open(index_file, 'w') as f:
                json.dump(self.evidence_index, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Could not save evidence index: {e}")
    
    def take_screenshot(self, url: str, full_page: bool = True, 
                       wait_time: int = 3, width: int = 1920, 
                       height: int = 1080, tags: List[str] = None) -> Dict[str, Any]:
        """
        Take a screenshot of a web page using headless Chrome/Chromium.
        
        Args:
            url: URL to screenshot
            full_page: Capture full page or viewport only
            wait_time: Seconds to wait for page load
            width: Viewport width
            height: Viewport height
            tags: Optional tags for organizing
            
        Returns:
            Screenshot info with file path and base64 content
        """
        try:
            evidence_id = str(uuid.uuid4())[:8]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Sanitize URL for filename
            safe_url = url.replace("://", "_").replace("/", "_").replace("?", "_")[:50]
            filename = f"screenshot_{timestamp}_{safe_url}_{evidence_id}.png"
            filepath = f"{SCREENSHOTS_DIR}/{filename}"
            
            # Try different screenshot tools
            screenshot_taken = False
            tool_used = None
            
            # Method 1: Try chromium/google-chrome headless
            for browser in ["chromium", "google-chrome", "chromium-browser"]:
                if screenshot_taken:
                    break
                try:
                    cmd = [
                        browser, "--headless", "--disable-gpu",
                        "--no-sandbox", "--disable-dev-shm-usage",
                        f"--window-size={width},{height}",
                        f"--screenshot={filepath}",
                        "--hide-scrollbars"
                    ]
                    if full_page:
                        cmd.append("--full-page-screenshot")
                    cmd.append(url)
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=wait_time + 30
                    )
                    
                    if os.path.exists(filepath):
                        screenshot_taken = True
                        tool_used = browser
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
            
            # Method 2: Try cutycapt
            if not screenshot_taken:
                try:
                    cmd = [
                        "cutycapt",
                        f"--url={url}",
                        f"--out={filepath}",
                        f"--min-width={width}",
                        f"--min-height={height}",
                        f"--delay={wait_time * 1000}"
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    if os.path.exists(filepath):
                        screenshot_taken = True
                        tool_used = "cutycapt"
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
            
            # Method 3: Try wkhtmltoimage
            if not screenshot_taken:
                try:
                    cmd = [
                        "wkhtmltoimage",
                        "--width", str(width),
                        "--javascript-delay", str(wait_time * 1000),
                        url, filepath
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    if os.path.exists(filepath):
                        screenshot_taken = True
                        tool_used = "wkhtmltoimage"
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
            
            if not screenshot_taken:
                return {
                    "success": False,
                    "error": "No screenshot tool available. Install chromium, cutycapt, or wkhtmltoimage."
                }
            
            # Read and encode screenshot
            with open(filepath, 'rb') as f:
                content = f.read()
                file_hash = hashlib.sha256(content).hexdigest()
                file_size = len(content)
                # Only include base64 for smaller images
                b64_content = base64.b64encode(content).decode() if file_size < 2 * 1024 * 1024 else None
            
            # Store in index
            evidence = {
                "id": evidence_id,
                "type": "screenshot",
                "url": url,
                "filepath": filepath,
                "filename": filename,
                "timestamp": datetime.now().isoformat(),
                "tool": tool_used,
                "size": file_size,
                "hash": file_hash,
                "tags": tags or [],
                "metadata": {
                    "width": width,
                    "height": height,
                    "full_page": full_page
                }
            }
            self.evidence_index[evidence_id] = evidence
            self._save_index()
            
            return {
                "success": True,
                "evidence_id": evidence_id,
                "filepath": filepath,
                "filename": filename,
                "url": url,
                "size": file_size,
                "hash": file_hash,
                "tool": tool_used,
                "base64": b64_content
            }
            
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return {"success": False, "error": str(e)}
    
    def add_note(self, title: str, content: str, target: str = "",
                 tags: List[str] = None, category: str = "general") -> Dict[str, Any]:
        """
        Add a text note as evidence.
        
        Args:
            title: Note title
            content: Note content
            target: Related target (IP/URL)
            tags: Optional tags
            category: Note category (finding, vuln, recon, etc.)
            
        Returns:
            Note info
        """
        try:
            evidence_id = str(uuid.uuid4())[:8]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"note_{timestamp}_{evidence_id}.md"
            filepath = f"{NOTES_DIR}/{filename}"
            
            # Format note as markdown
            note_content = f"""# {title}

**Date:** {datetime.now().isoformat()}
**Target:** {target or 'N/A'}
**Category:** {category}
**Tags:** {', '.join(tags) if tags else 'None'}

---

{content}
"""
            
            with open(filepath, 'w') as f:
                f.write(note_content)
            
            evidence = {
                "id": evidence_id,
                "type": "note",
                "title": title,
                "target": target,
                "filepath": filepath,
                "filename": filename,
                "timestamp": datetime.now().isoformat(),
                "category": category,
                "tags": tags or [],
                "preview": content[:200] + "..." if len(content) > 200 else content
            }
            self.evidence_index[evidence_id] = evidence
            self._save_index()
            
            return {
                "success": True,
                "evidence_id": evidence_id,
                "filepath": filepath,
                "title": title
            }
            
        except Exception as e:
            logger.error(f"Add note failed: {e}")
            return {"success": False, "error": str(e)}
    
    def add_file(self, content_b64: str, filename: str, 
                 description: str = "", target: str = "",
                 tags: List[str] = None) -> Dict[str, Any]:
        """
        Add a file as evidence (base64 encoded).
        
        Args:
            content_b64: Base64 encoded file content
            filename: Original filename
            description: File description
            target: Related target
            tags: Optional tags
            
        Returns:
            File evidence info
        """
        try:
            evidence_id = str(uuid.uuid4())[:8]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Preserve extension
            ext = os.path.splitext(filename)[1] if '.' in filename else ''
            new_filename = f"file_{timestamp}_{evidence_id}{ext}"
            filepath = f"{EVIDENCE_DIR}/{new_filename}"
            
            # Decode and save
            content = base64.b64decode(content_b64)
            with open(filepath, 'wb') as f:
                f.write(content)
            
            file_hash = hashlib.sha256(content).hexdigest()
            
            evidence = {
                "id": evidence_id,
                "type": "file",
                "original_filename": filename,
                "filepath": filepath,
                "filename": new_filename,
                "timestamp": datetime.now().isoformat(),
                "size": len(content),
                "hash": file_hash,
                "description": description,
                "target": target,
                "tags": tags or []
            }
            self.evidence_index[evidence_id] = evidence
            self._save_index()
            
            return {
                "success": True,
                "evidence_id": evidence_id,
                "filepath": filepath,
                "size": len(content),
                "hash": file_hash
            }
            
        except Exception as e:
            logger.error(f"Add file failed: {e}")
            return {"success": False, "error": str(e)}
    
    def list_evidence(self, evidence_type: str = "", 
                     target: str = "", tags: List[str] = None) -> Dict[str, Any]:
        """
        List all evidence with optional filtering.
        
        Args:
            evidence_type: Filter by type (screenshot, note, file)
            target: Filter by target
            tags: Filter by tags (any match)
            
        Returns:
            List of evidence items
        """
        results = []
        
        for eid, evidence in self.evidence_index.items():
            # Apply filters
            if evidence_type and evidence.get("type") != evidence_type:
                continue
            if target and target.lower() not in evidence.get("target", "").lower():
                if target.lower() not in evidence.get("url", "").lower():
                    continue
            if tags:
                evidence_tags = evidence.get("tags", [])
                if not any(t in evidence_tags for t in tags):
                    continue
            
            # Check if file still exists
            filepath = evidence.get("filepath", "")
            exists = os.path.exists(filepath) if filepath else False
            
            results.append({
                **evidence,
                "exists": exists
            })
        
        return {
            "success": True,
            "evidence": results,
            "count": len(results)
        }
    
    def get_evidence(self, evidence_id: str) -> Dict[str, Any]:
        """Get a specific evidence item with content."""
        if evidence_id not in self.evidence_index:
            return {"success": False, "error": f"Evidence {evidence_id} not found"}
        
        evidence = self.evidence_index[evidence_id]
        filepath = evidence.get("filepath", "")
        
        if not os.path.exists(filepath):
            return {"success": False, "error": "Evidence file no longer exists"}
        
        result = {"success": True, **evidence}
        
        # Include content based on type
        try:
            if evidence["type"] == "note":
                with open(filepath, 'r') as f:
                    result["content"] = f.read()
            elif evidence["type"] in ["screenshot", "file"]:
                with open(filepath, 'rb') as f:
                    content = f.read()
                    if len(content) < 5 * 1024 * 1024:  # 5MB limit
                        result["base64"] = base64.b64encode(content).decode()
        except Exception as e:
            result["read_error"] = str(e)
        
        return result
    
    def delete_evidence(self, evidence_id: str) -> Dict[str, Any]:
        """Delete an evidence item."""
        if evidence_id not in self.evidence_index:
            return {"success": False, "error": f"Evidence {evidence_id} not found"}
        
        evidence = self.evidence_index.pop(evidence_id)
        filepath = evidence.get("filepath", "")
        
        try:
            if filepath and os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            logger.warning(f"Could not delete file: {e}")
        
        self._save_index()
        return {"success": True, "message": f"Evidence {evidence_id} deleted"}
    
    def add_command_output(self, command: str, output: str, 
                          target: str = "", tags: List[str] = None) -> Dict[str, Any]:
        """
        Save command output as evidence.
        
        Args:
            command: The command that was executed
            output: Command output
            target: Related target
            tags: Optional tags
            
        Returns:
            Evidence info
        """
        title = f"Command: {command[:50]}..." if len(command) > 50 else f"Command: {command}"
        content = f"""## Command
```
{command}
```

## Output
```
{output}
```
"""
        return self.add_note(
            title=title,
            content=content,
            target=target,
            tags=tags or ["command-output"],
            category="command"
        )


# Global instance
evidence_collector = EvidenceCollector()
