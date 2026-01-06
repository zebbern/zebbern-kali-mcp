#!/usr/bin/env python3
"""
Session Manager - Save and restore entire engagement state
Handles persistence of targets, findings, credentials, scan history, and evidence index
"""

import os
import json
import shutil
import tarfile
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class SessionManager:
    """Manages engagement session persistence - save, restore, list sessions"""
    
    def __init__(self, sessions_dir: str = "/opt/zebbern-kali/sessions",
                 database_dir: str = "/opt/zebbern-kali/database",
                 evidence_dir: str = "/opt/zebbern-kali/evidence"):
        self.sessions_dir = sessions_dir
        self.database_dir = database_dir
        self.evidence_dir = evidence_dir
        self.sessions_index_file = os.path.join(sessions_dir, "sessions_index.json")
        self._ensure_dirs()
        self._load_index()
    
    def _ensure_dirs(self):
        """Ensure session directories exist."""
        os.makedirs(self.sessions_dir, exist_ok=True)
        os.makedirs(os.path.join(self.sessions_dir, "archives"), exist_ok=True)
    
    def _load_index(self):
        """Load sessions index from disk."""
        if os.path.exists(self.sessions_index_file):
            try:
                with open(self.sessions_index_file, 'r') as f:
                    self.sessions_index = json.load(f)
            except Exception as e:
                logger.error(f"Error loading sessions index: {e}")
                self.sessions_index = {"sessions": []}
        else:
            self.sessions_index = {"sessions": []}
    
    def _save_index(self):
        """Save sessions index to disk."""
        try:
            with open(self.sessions_index_file, 'w') as f:
                json.dump(self.sessions_index, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving sessions index: {e}")
    
    def save_session(self, name: str, description: str = "", 
                     include_evidence: bool = True,
                     include_raw_outputs: bool = False) -> Dict[str, Any]:
        """
        Save current engagement state to a session archive.
        
        Args:
            name: Session name (will be sanitized for filesystem)
            description: Optional description of the session
            include_evidence: Include evidence files (screenshots, etc.)
            include_raw_outputs: Include raw scan outputs (can be large)
            
        Returns:
            Session metadata including archive path
        """
        try:
            # Sanitize name for filesystem
            safe_name = "".join(c for c in name if c.isalnum() or c in "-_").strip()
            if not safe_name:
                safe_name = "session"
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            session_id = f"{safe_name}_{timestamp}"
            
            # Create temporary directory for session data
            temp_dir = os.path.join(self.sessions_dir, f"temp_{session_id}")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Copy database files
            db_dest = os.path.join(temp_dir, "database")
            os.makedirs(db_dest, exist_ok=True)
            
            db_files = ["targets.json", "findings.json", "credentials.json", "scans.json"]
            copied_db = []
            for db_file in db_files:
                src = os.path.join(self.database_dir, db_file)
                if os.path.exists(src):
                    shutil.copy2(src, os.path.join(db_dest, db_file))
                    copied_db.append(db_file)
            
            # Copy evidence index and optionally files
            evidence_dest = os.path.join(temp_dir, "evidence")
            os.makedirs(evidence_dest, exist_ok=True)
            
            evidence_index = os.path.join(self.evidence_dir, "evidence_index.json")
            evidence_count = 0
            if os.path.exists(evidence_index):
                shutil.copy2(evidence_index, os.path.join(evidence_dest, "evidence_index.json"))
                
                if include_evidence:
                    # Copy evidence files
                    for subdir in ["screenshots", "notes", "commands", "files"]:
                        src_subdir = os.path.join(self.evidence_dir, subdir)
                        if os.path.exists(src_subdir):
                            dst_subdir = os.path.join(evidence_dest, subdir)
                            shutil.copytree(src_subdir, dst_subdir)
                            evidence_count += len(os.listdir(dst_subdir))
            
            # Create session metadata
            metadata = {
                "session_id": session_id,
                "name": name,
                "description": description,
                "created_at": datetime.now().isoformat(),
                "include_evidence": include_evidence,
                "include_raw_outputs": include_raw_outputs,
                "database_files": copied_db,
                "evidence_count": evidence_count,
                "version": "1.0"
            }
            
            # Save metadata
            with open(os.path.join(temp_dir, "session_meta.json"), 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Create tar.gz archive
            archive_path = os.path.join(self.sessions_dir, "archives", f"{session_id}.tar.gz")
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(temp_dir, arcname=session_id)
            
            # Cleanup temp directory
            shutil.rmtree(temp_dir)
            
            # Get archive size
            archive_size = os.path.getsize(archive_path)
            metadata["archive_path"] = archive_path
            metadata["archive_size"] = archive_size
            metadata["archive_size_human"] = self._format_size(archive_size)
            
            # Update index
            self.sessions_index["sessions"].append(metadata)
            self._save_index()
            
            logger.info(f"Session saved: {session_id} ({metadata['archive_size_human']})")
            
            return {
                "success": True,
                "session_id": session_id,
                "archive_path": archive_path,
                "archive_size": metadata["archive_size_human"],
                "database_files": copied_db,
                "evidence_count": evidence_count
            }
            
        except Exception as e:
            logger.error(f"Error saving session: {e}")
            return {"success": False, "error": str(e)}
    
    def restore_session(self, session_id: str, 
                        overwrite: bool = False,
                        restore_evidence: bool = True) -> Dict[str, Any]:
        """
        Restore engagement state from a saved session.
        
        Args:
            session_id: Session ID to restore
            overwrite: Overwrite existing data (if False, merge)
            restore_evidence: Restore evidence files
            
        Returns:
            Restoration status and counts
        """
        try:
            # Find session in index
            session_meta = None
            for s in self.sessions_index["sessions"]:
                if s["session_id"] == session_id:
                    session_meta = s
                    break
            
            if not session_meta:
                return {"success": False, "error": f"Session not found: {session_id}"}
            
            archive_path = session_meta.get("archive_path")
            if not archive_path or not os.path.exists(archive_path):
                return {"success": False, "error": "Session archive not found"}
            
            # Extract to temp directory
            temp_extract = os.path.join(self.sessions_dir, f"restore_temp_{session_id}")
            os.makedirs(temp_extract, exist_ok=True)
            
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(temp_extract)
            
            session_dir = os.path.join(temp_extract, session_id)
            
            restored = {
                "database_files": [],
                "evidence_count": 0
            }
            
            # Restore database files
            db_src = os.path.join(session_dir, "database")
            if os.path.exists(db_src):
                os.makedirs(self.database_dir, exist_ok=True)
                
                for db_file in os.listdir(db_src):
                    src = os.path.join(db_src, db_file)
                    dst = os.path.join(self.database_dir, db_file)
                    
                    if overwrite or not os.path.exists(dst):
                        shutil.copy2(src, dst)
                        restored["database_files"].append(db_file)
                    else:
                        # Merge data
                        merged = self._merge_json_files(dst, src)
                        if merged:
                            restored["database_files"].append(f"{db_file} (merged)")
            
            # Restore evidence
            if restore_evidence:
                evidence_src = os.path.join(session_dir, "evidence")
                if os.path.exists(evidence_src):
                    os.makedirs(self.evidence_dir, exist_ok=True)
                    
                    for item in os.listdir(evidence_src):
                        src = os.path.join(evidence_src, item)
                        dst = os.path.join(self.evidence_dir, item)
                        
                        if os.path.isdir(src):
                            if not os.path.exists(dst):
                                shutil.copytree(src, dst)
                            else:
                                # Copy individual files
                                for f in os.listdir(src):
                                    src_f = os.path.join(src, f)
                                    dst_f = os.path.join(dst, f)
                                    if not os.path.exists(dst_f):
                                        shutil.copy2(src_f, dst_f)
                                        restored["evidence_count"] += 1
                        else:
                            if not os.path.exists(dst):
                                shutil.copy2(src, dst)
            
            # Cleanup
            shutil.rmtree(temp_extract)
            
            logger.info(f"Session restored: {session_id}")
            
            return {
                "success": True,
                "session_id": session_id,
                "restored": restored,
                "message": f"Restored {len(restored['database_files'])} database files and {restored['evidence_count']} evidence items"
            }
            
        except Exception as e:
            logger.error(f"Error restoring session: {e}")
            return {"success": False, "error": str(e)}
    
    def _merge_json_files(self, existing: str, new: str) -> bool:
        """Merge two JSON files (for lists, append new items)."""
        try:
            with open(existing, 'r') as f:
                existing_data = json.load(f)
            with open(new, 'r') as f:
                new_data = json.load(f)
            
            if isinstance(existing_data, list) and isinstance(new_data, list):
                # Get existing IDs
                existing_ids = set()
                for item in existing_data:
                    if isinstance(item, dict) and "id" in item:
                        existing_ids.add(item["id"])
                
                # Add new items
                for item in new_data:
                    if isinstance(item, dict) and "id" in item:
                        if item["id"] not in existing_ids:
                            existing_data.append(item)
                
                with open(existing, 'w') as f:
                    json.dump(existing_data, f, indent=2)
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error merging files: {e}")
            return False
    
    def list_sessions(self, limit: int = 20) -> Dict[str, Any]:
        """
        List all saved sessions.
        
        Args:
            limit: Maximum number of sessions to return
            
        Returns:
            List of session metadata
        """
        try:
            sessions = self.sessions_index.get("sessions", [])
            # Sort by created_at descending
            sessions = sorted(sessions, key=lambda x: x.get("created_at", ""), reverse=True)
            
            return {
                "success": True,
                "count": len(sessions),
                "sessions": sessions[:limit]
            }
        except Exception as e:
            logger.error(f"Error listing sessions: {e}")
            return {"success": False, "error": str(e)}
    
    def get_session(self, session_id: str) -> Dict[str, Any]:
        """
        Get details of a specific session.
        
        Args:
            session_id: Session ID to retrieve
            
        Returns:
            Session metadata
        """
        try:
            for s in self.sessions_index["sessions"]:
                if s["session_id"] == session_id:
                    return {"success": True, "session": s}
            
            return {"success": False, "error": f"Session not found: {session_id}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def delete_session(self, session_id: str) -> Dict[str, Any]:
        """
        Delete a saved session.
        
        Args:
            session_id: Session ID to delete
            
        Returns:
            Deletion status
        """
        try:
            session_meta = None
            session_idx = -1
            
            for i, s in enumerate(self.sessions_index["sessions"]):
                if s["session_id"] == session_id:
                    session_meta = s
                    session_idx = i
                    break
            
            if not session_meta:
                return {"success": False, "error": f"Session not found: {session_id}"}
            
            # Delete archive
            archive_path = session_meta.get("archive_path")
            if archive_path and os.path.exists(archive_path):
                os.remove(archive_path)
            
            # Remove from index
            self.sessions_index["sessions"].pop(session_idx)
            self._save_index()
            
            logger.info(f"Session deleted: {session_id}")
            
            return {
                "success": True,
                "message": f"Session {session_id} deleted"
            }
            
        except Exception as e:
            logger.error(f"Error deleting session: {e}")
            return {"success": False, "error": str(e)}
    
    def export_session(self, session_id: str, export_path: str = "/tmp") -> Dict[str, Any]:
        """
        Export a session archive to a specified path.
        
        Args:
            session_id: Session ID to export
            export_path: Directory to export to
            
        Returns:
            Export path
        """
        try:
            session_meta = None
            for s in self.sessions_index["sessions"]:
                if s["session_id"] == session_id:
                    session_meta = s
                    break
            
            if not session_meta:
                return {"success": False, "error": f"Session not found: {session_id}"}
            
            archive_path = session_meta.get("archive_path")
            if not archive_path or not os.path.exists(archive_path):
                return {"success": False, "error": "Session archive not found"}
            
            os.makedirs(export_path, exist_ok=True)
            export_file = os.path.join(export_path, os.path.basename(archive_path))
            shutil.copy2(archive_path, export_file)
            
            return {
                "success": True,
                "export_path": export_file,
                "size": self._format_size(os.path.getsize(export_file))
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def import_session(self, archive_path: str) -> Dict[str, Any]:
        """
        Import a session from an external archive.
        
        Args:
            archive_path: Path to the .tar.gz archive
            
        Returns:
            Import status
        """
        try:
            if not os.path.exists(archive_path):
                return {"success": False, "error": "Archive not found"}
            
            # Extract to temp to read metadata
            temp_dir = os.path.join(self.sessions_dir, "import_temp")
            os.makedirs(temp_dir, exist_ok=True)
            
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(temp_dir)
            
            # Find session directory
            session_id = None
            for item in os.listdir(temp_dir):
                meta_file = os.path.join(temp_dir, item, "session_meta.json")
                if os.path.exists(meta_file):
                    session_id = item
                    with open(meta_file, 'r') as f:
                        metadata = json.load(f)
                    break
            
            if not session_id:
                shutil.rmtree(temp_dir)
                return {"success": False, "error": "Invalid session archive"}
            
            # Copy archive to sessions directory
            new_archive = os.path.join(self.sessions_dir, "archives", f"{session_id}.tar.gz")
            shutil.copy2(archive_path, new_archive)
            
            # Update metadata with new path
            metadata["archive_path"] = new_archive
            metadata["archive_size"] = os.path.getsize(new_archive)
            metadata["archive_size_human"] = self._format_size(metadata["archive_size"])
            metadata["imported_at"] = datetime.now().isoformat()
            
            # Add to index if not exists
            existing_ids = [s["session_id"] for s in self.sessions_index["sessions"]]
            if session_id not in existing_ids:
                self.sessions_index["sessions"].append(metadata)
                self._save_index()
            
            # Cleanup
            shutil.rmtree(temp_dir)
            
            return {
                "success": True,
                "session_id": session_id,
                "message": f"Session imported: {metadata.get('name', session_id)}"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def clear_current(self, confirm: bool = False) -> Dict[str, Any]:
        """
        Clear current engagement data (use with caution!).
        
        Args:
            confirm: Must be True to actually clear
            
        Returns:
            Clear status
        """
        if not confirm:
            return {
                "success": False, 
                "error": "Set confirm=True to clear all current data. This cannot be undone!"
            }
        
        try:
            cleared = []
            
            # Clear database files
            if os.path.exists(self.database_dir):
                for f in os.listdir(self.database_dir):
                    if f.endswith(".json"):
                        os.remove(os.path.join(self.database_dir, f))
                        cleared.append(f"database/{f}")
            
            # Clear evidence
            if os.path.exists(self.evidence_dir):
                for item in os.listdir(self.evidence_dir):
                    path = os.path.join(self.evidence_dir, item)
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                        cleared.append(f"evidence/{item}/")
                    else:
                        os.remove(path)
                        cleared.append(f"evidence/{item}")
            
            return {
                "success": True,
                "message": "Current engagement data cleared",
                "cleared": cleared
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _format_size(self, size: int) -> str:
        """Format byte size to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


# Global instance
session_manager = SessionManager()
