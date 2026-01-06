#!/usr/bin/env python3
"""Kali Server File Operations - Direct filesystem operations on Kali server."""

import os
import base64
from typing import Dict, Any
from core.config import logger
from .transfer_manager import transfer_manager


def upload_content(content: str, remote_path: str) -> Dict[str, Any]:
    """
    Upload content directly to the Kali server filesystem with checksum verification.
    
    Args:
        content: Base64 encoded content to upload
        remote_path: Destination path on the Kali server
        
    Returns:
        Dict with success status and message
    """
    try:
        return transfer_manager.upload_to_kali_with_verification(
            content=content,
            remote_path=remote_path
        )
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return {"error": str(e), "success": False}


def download_content(remote_file: str) -> Dict[str, Any]:
    """
    Download content from the Kali server filesystem with checksum verification.
    
    Args:
        remote_file: Path to the file on the Kali server
        
    Returns:
        Dict with file content and metadata or error
    """
    try:
        return transfer_manager.download_from_kali_with_verification(
            file_path=remote_file
        )
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return {"error": str(e), "success": False}
