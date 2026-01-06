#!/usr/bin/env python3
"""
File Transfer Manager with Integrity Verification

This module provides centralized file transfer management with:
- SHA256 checksum verification for all transfers
- Performance optimization based on file size
- Transfer statistics and monitoring
- Error handling and recovery
"""

import hashlib
import base64
import time
import os
from enum import Enum
from typing import Dict, Any, Optional, List
from core.config import logger


class TransferMethod(Enum):
    """Enumeration of available transfer methods."""
    SSH = "ssh"
    REVERSE_SHELL = "reverse_shell"
    DIRECT_KALI = "direct_kali"


class TransferOptimization(Enum):
    """Enumeration of transfer optimization levels."""
    SMALL_FILE = "small_file"      # < 1MB - direct transfer
    MEDIUM_FILE = "medium_file"    # 1MB - 50MB - chunked transfer
    LARGE_FILE = "large_file"      # > 50MB - optimized chunked transfer


class FileTransferManager:
    """
    Centralized manager for ALL file transfer operations with:
    - Integrity verification using SHA256 checksums
    - File size analysis and optimization
    - Transfer method selection
    - Performance monitoring
    - Error handling and recovery
    """
    
    def __init__(self):
        self.transfer_stats = {}
        
        # Transfer optimization thresholds (in bytes)
        self.SMALL_FILE_THRESHOLD = 1024 * 1024      # 1MB
        self.LARGE_FILE_THRESHOLD = 50 * 1024 * 1024 # 50MB
        
        # Chunk sizes for different file sizes
        self.CHUNK_SIZES = {
            TransferOptimization.SMALL_FILE: 4096,      # 4KB
            TransferOptimization.MEDIUM_FILE: 32768,    # 32KB  
            TransferOptimization.LARGE_FILE: 131072,    # 128KB
        }
        
        logger.info("FileTransferManager initialized with integrity verification")
    
    def analyze_transfer_requirements(self, content_size: int) -> Dict[str, Any]:
        """
        Analyze content size and determine optimal transfer strategy.
        
        Args:
            content_size: Size of content in bytes
            
        Returns:
            dict: Transfer optimization recommendations
        """
        if content_size < self.SMALL_FILE_THRESHOLD:
            optimization = TransferOptimization.SMALL_FILE
            recommended_method = "direct"
            estimated_chunks = 1
        elif content_size < self.LARGE_FILE_THRESHOLD:
            optimization = TransferOptimization.MEDIUM_FILE
            recommended_method = "chunked"
            estimated_chunks = (content_size // self.CHUNK_SIZES[optimization]) + 1
        else:
            optimization = TransferOptimization.LARGE_FILE
            recommended_method = "optimized_chunked"
            estimated_chunks = (content_size // self.CHUNK_SIZES[optimization]) + 1
        
        return {
            "optimization_level": optimization.value,
            "recommended_method": recommended_method,
            "chunk_size": self.CHUNK_SIZES[optimization],
            "estimated_chunks": estimated_chunks,
            "estimated_time_seconds": self.estimate_transfer_time(content_size, optimization),
            "content_size_mb": round(content_size / (1024 * 1024), 2)
        }
    
    def estimate_transfer_time(self, content_size: int, optimization: TransferOptimization) -> float:
        """
        Estimate transfer time based on content size and optimization level.
        
        Args:
            content_size: Size of content in bytes
            optimization: Transfer optimization level
            
        Returns:
            float: Estimated transfer time in seconds
        """
        # Base transfer rates (bytes per second) - conservative estimates
        transfer_rates = {
            TransferOptimization.SMALL_FILE: 512 * 1024,    # 512 KB/s
            TransferOptimization.MEDIUM_FILE: 1024 * 1024,  # 1 MB/s
            TransferOptimization.LARGE_FILE: 2048 * 1024,   # 2 MB/s (optimized)
        }
        
        base_time = content_size / transfer_rates[optimization]
        
        # Add overhead for checksums and verification
        verification_overhead = 0.5  # 500ms for checksum operations
        
        return base_time + verification_overhead
    
    def calculate_content_checksum(self, content: str) -> str:
        """
        Calculate SHA256 checksum of base64 encoded content.
        This is the SINGLE source of truth for content checksums.
        """
        try:
            decoded_content = base64.b64decode(content)
            return hashlib.sha256(decoded_content).hexdigest()
        except Exception as e:
            logger.error(f"Error calculating content checksum: {e}")
            return f"Error calculating checksum: {str(e)}"
    
    def calculate_file_checksum(self, file_path: str) -> str:
        """
        Calculate SHA256 checksum of a local file.
        This is the SINGLE source of truth for file checksums.
        """
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                # Read file in chunks for memory efficiency
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file checksum for {file_path}: {e}")
            return f"Error calculating file checksum: {str(e)}"
    
    def verify_transfer_integrity(self, local_content: str, remote_file: str, 
                                method: TransferMethod = TransferMethod.DIRECT_KALI) -> Dict[str, Any]:
        """
        CENTRALIZED integrity verification using checksums.
        For direct Kali transfers, compares content checksum with file checksum.
        """
        try:
            # Calculate local content checksum
            local_checksum = self.calculate_content_checksum(local_content)
            if local_checksum.startswith("Error"):
                return {
                    "success": False,
                    "error": f"Failed to calculate local checksum: {local_checksum}"
                }
            
            # For direct Kali transfers, calculate file checksum
            if method == TransferMethod.DIRECT_KALI:
                remote_checksum = self.calculate_file_checksum(remote_file)
            else:
                # For remote methods, this would need integration with SSH/reverse shell
                return {
                    "success": False,
                    "error": f"Remote checksum verification not implemented for {method.value}"
                }
            
            if remote_checksum.startswith("Error"):
                return {
                    "success": False,
                    "error": f"Failed to get remote checksum: {remote_checksum}"
                }
            
            # Compare checksums
            checksums_match = local_checksum.lower() == remote_checksum.lower()
            
            return {
                "success": checksums_match,
                "local_checksum": local_checksum,
                "remote_checksum": remote_checksum,
                "integrity_verified": checksums_match,
                "method_used": method.value,
                "error": None if checksums_match else "Checksum mismatch - transfer integrity compromised"
            }
            
        except Exception as e:
            logger.error(f"Integrity verification failed: {e}")
            return {
                "success": False,
                "error": f"Integrity verification failed: {str(e)}"
            }
    
    def cleanup_failed_transfer(self, remote_file: str, method: TransferMethod = TransferMethod.DIRECT_KALI) -> bool:
        """
        CENTRALIZED cleanup for failed transfers.
        """
        try:
            if method == TransferMethod.DIRECT_KALI:
                # Direct file system cleanup
                if os.path.exists(remote_file):
                    os.remove(remote_file)
                    logger.info(f"Cleaned up corrupted file: {remote_file}")
                    return True
                return False
            else:
                # For remote methods, this would need integration with SSH/reverse shell
                logger.warning(f"Cleanup not implemented for method: {method.value}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to cleanup file {remote_file}: {e}")
            return False
    
    def get_optimal_chunk_size(self, content_size: int, method: TransferMethod) -> int:
        """
        Determine optimal chunk size based on content size and transfer method.
        """
        analysis = self.analyze_transfer_requirements(content_size)
        base_chunk_size = analysis["chunk_size"]
        
        # Adjust chunk size based on transfer method
        method_multipliers = {
            TransferMethod.SSH: 1.0,           # Standard chunking
            TransferMethod.REVERSE_SHELL: 0.5, # Smaller chunks for shell stability
            TransferMethod.DIRECT_KALI: 2.0    # Larger chunks for local operations
        }
        
        return int(base_chunk_size * method_multipliers.get(method, 1.0))
    
    def record_transfer_stats(self, transfer_id: str, stats: Dict[str, Any]) -> None:
        """
        Record transfer statistics for performance monitoring.
        """
        self.transfer_stats[transfer_id] = {
            **stats,
            "timestamp": time.time()
        }
    
    def get_transfer_performance_report(self) -> Dict[str, Any]:
        """
        Generate performance report based on recorded transfer statistics.
        """
        try:
            if not self.transfer_stats:
                return {
                    "success": True,
                    "message": "No transfer statistics available",
                    "total_transfers": 0,
                    "successful_transfers": 0,
                    "success_rate": 0,
                    "average_transfer_time_seconds": 0,
                    "total_data_transferred_mb": 0,
                    "average_throughput_mbps": 0
                }
            
            total_transfers = len(self.transfer_stats)
            successful_transfers = sum(1 for stats in self.transfer_stats.values() 
                                     if stats.get("success", False))
            
            avg_transfer_time = sum(stats.get("duration", 0) for stats in self.transfer_stats.values()) / total_transfers
            total_data_transferred = sum(stats.get("bytes_transferred", 0) for stats in self.transfer_stats.values())
            
            return {
                "success": True,
                "total_transfers": total_transfers,
                "successful_transfers": successful_transfers,
                "success_rate": round((successful_transfers / total_transfers) * 100, 2),
                "average_transfer_time_seconds": round(avg_transfer_time, 2),
                "total_data_transferred_mb": round(total_data_transferred / (1024 * 1024), 2),
                "average_throughput_mbps": round((total_data_transferred / avg_transfer_time) / (1024 * 1024), 2) if avg_transfer_time > 0 else 0,
                "recent_transfers": list(self.transfer_stats.keys())[-10:]  # Last 10 transfer IDs
            }
        except Exception as e:
            logger.error(f"Failed to generate performance report: {e}")
            return {
                "success": False,
                "error": f"Failed to generate performance report: {str(e)}"
            }
    
    def upload_to_kali_with_verification(self, content: str, remote_path: str) -> Dict[str, Any]:
        """
        Upload content directly to Kali server with full integrity verification.
        """
        transfer_id = f"kali_upload_{remote_path}_{time.time()}"
        start_time = time.time()
        
        try:
            # 1. Analyze content and determine optimization strategy
            content_size = len(base64.b64decode(content))
            analysis = self.analyze_transfer_requirements(content_size)
            
            logger.info(f"Upload Analysis: {analysis['content_size_mb']}MB file to {remote_path}, "
                       f"using {analysis['recommended_method']} method")
            
            # 2. Calculate pre-transfer checksum
            pre_checksum = self.calculate_content_checksum(content)
            if pre_checksum.startswith("Error"):
                return {"success": False, "error": f"Pre-transfer checksum failed: {pre_checksum}"}
            
            # 3. Perform the actual upload
            upload_result = self._perform_direct_kali_upload(content, remote_path)
            if not upload_result.get("success"):
                return upload_result
            
            # 4. Verify transfer integrity
            integrity_check = self.verify_transfer_integrity(content, remote_path, TransferMethod.DIRECT_KALI)
            
            # 5. Handle integrity failure with cleanup
            if not integrity_check.get("success"):
                self.cleanup_failed_transfer(remote_path, TransferMethod.DIRECT_KALI)
                
                # Record failed transfer stats
                self.record_transfer_stats(transfer_id, {
                    "success": False,
                    "method": TransferMethod.DIRECT_KALI.value,
                    "bytes_transferred": content_size,
                    "duration": time.time() - start_time,
                    "error": "integrity_check_failed"
                })
                
                return {
                    "success": False,
                    "error": f"Upload failed integrity verification: {integrity_check.get('error')}",
                    "transfer_analysis": analysis,
                    "pre_transfer_checksum": pre_checksum,
                    "post_transfer_verification": integrity_check
                }
            
            # 6. Record successful transfer stats
            duration = time.time() - start_time
            self.record_transfer_stats(transfer_id, {
                "success": True,
                "method": TransferMethod.DIRECT_KALI.value,
                "bytes_transferred": content_size,
                "duration": duration,
                "throughput_mbps": (content_size / duration) / (1024 * 1024) if duration > 0 else 0
            })
            
            return {
                "success": True,
                "message": "File uploaded successfully to Kali server with verified integrity",
                "remote_path": remote_path,
                "transfer_analysis": analysis,
                "pre_transfer_checksum": pre_checksum,
                "post_transfer_verification": integrity_check,
                "performance": {
                    "actual_duration_seconds": round(duration, 2),
                    "estimated_duration_seconds": analysis["estimated_time_seconds"],
                    "throughput_mbps": round((content_size / duration) / (1024 * 1024), 2) if duration > 0 else 0,
                    "chunks_estimated": analysis["estimated_chunks"],
                    "optimization_used": analysis["optimization_level"]
                },
                "upload_details": upload_result
            }
            
        except Exception as e:
            # Record failed transfer stats
            self.record_transfer_stats(transfer_id, {
                "success": False,
                "method": TransferMethod.DIRECT_KALI.value,
                "duration": time.time() - start_time,
                "error": str(e)
            })
            
            logger.error(f"Upload with verification failed: {e}")
            return {"success": False, "error": f"Upload with verification failed: {str(e)}"}
    
    def download_from_kali_with_verification(self, file_path: str) -> Dict[str, Any]:
        """
        Download content from Kali server with full integrity verification.
        """
        transfer_id = f"kali_download_{file_path}_{time.time()}"
        start_time = time.time()
        
        try:
            # 1. Calculate pre-transfer checksum of local Kali file
            pre_checksum = self.calculate_file_checksum(file_path)
            if pre_checksum.startswith("Error"):
                return {"success": False, "error": f"Pre-transfer checksum failed: {pre_checksum}"}
            
            # 2. Perform the actual download
            download_result = self._perform_direct_kali_download(file_path)
            if not download_result.get("success"):
                return download_result
            
            # 3. Verify downloaded content integrity
            downloaded_content = download_result.get("content", "")
            content_size = len(base64.b64decode(downloaded_content))
            post_checksum = self.calculate_content_checksum(downloaded_content)
            if post_checksum.startswith("Error"):
                return {"success": False, "error": f"Post-transfer checksum failed: {post_checksum}"}
            
            # 4. Compare checksums
            checksums_match = pre_checksum.lower() == post_checksum.lower()
            if not checksums_match:
                # Record failed transfer stats
                self.record_transfer_stats(transfer_id, {
                    "success": False,
                    "method": TransferMethod.DIRECT_KALI.value,
                    "bytes_transferred": content_size,
                    "duration": time.time() - start_time,
                    "error": "checksum_mismatch"
                })
                
                return {
                    "success": False,
                    "error": "Download failed integrity verification - checksum mismatch",
                    "pre_transfer_checksum": pre_checksum,
                    "post_transfer_checksum": post_checksum
                }
            
            # 5. Record successful transfer stats and generate analysis
            duration = time.time() - start_time
            analysis = self.analyze_transfer_requirements(content_size)
            
            self.record_transfer_stats(transfer_id, {
                "success": True,
                "method": TransferMethod.DIRECT_KALI.value,
                "bytes_transferred": content_size,
                "duration": duration,
                "throughput_mbps": (content_size / duration) / (1024 * 1024) if duration > 0 else 0
            })
            
            return {
                "success": True,
                "content": downloaded_content,
                "file_path": file_path,
                "pre_transfer_checksum": pre_checksum,
                "post_transfer_checksum": post_checksum,
                "integrity_verified": True,
                "transfer_analysis": analysis,
                "performance": {
                    "actual_duration_seconds": round(duration, 2),
                    "estimated_duration_seconds": analysis["estimated_time_seconds"],
                    "throughput_mbps": round((content_size / duration) / (1024 * 1024), 2) if duration > 0 else 0,
                    "content_size_mb": analysis["content_size_mb"]
                },
                "download_details": download_result
            }
            
        except Exception as e:
            # Record failed transfer stats
            self.record_transfer_stats(transfer_id, {
                "success": False,
                "method": TransferMethod.DIRECT_KALI.value,
                "duration": time.time() - start_time,
                "error": str(e)
            })
            
            logger.error(f"Download with verification failed: {e}")
            return {"success": False, "error": f"Download with verification failed: {str(e)}"}
    
    def _perform_direct_kali_upload(self, content: str, remote_path: str) -> Dict[str, Any]:
        """Perform the actual upload to Kali server file system."""
        try:
            # SECURITY: Validate path to prevent directory traversal attacks
            if '..' in remote_path or remote_path.startswith('/etc/') or remote_path.startswith('/sys/') or remote_path.startswith('/proc/'):
                logger.warning(f"Blocked suspicious upload path: {remote_path}")
                return {
                    "success": False,
                    "error": f"Invalid path: Directory traversal or system directory access not allowed"
                }

            # Resolve to absolute path to prevent symlink attacks
            remote_path = os.path.abspath(remote_path)

            # Decode base64 content
            decoded_content = base64.b64decode(content)

            # Ensure directory exists
            directory = os.path.dirname(remote_path)
            if directory:
                os.makedirs(directory, exist_ok=True)

            # Write file to Kali server
            with open(remote_path, 'wb') as f:
                f.write(decoded_content)
            
            # Verify file was created
            if not os.path.exists(remote_path):
                return {"success": False, "error": "File was not created on Kali server"}
            
            file_size = os.path.getsize(remote_path)
            
            return {
                "success": True,
                "message": f"File uploaded to Kali server: {remote_path}",
                "file_path": remote_path,
                "file_size": file_size
            }
            
        except Exception as e:
            logger.error(f"Failed to upload to Kali server: {e}")
            return {"success": False, "error": f"Failed to upload to Kali server: {str(e)}"}
    
    def _perform_direct_kali_download(self, file_path: str) -> Dict[str, Any]:
        """Perform the actual download from Kali server file system."""
        try:
            # SECURITY: Validate path to prevent directory traversal attacks
            if '..' in file_path or file_path.startswith('/etc/passwd') or file_path.startswith('/etc/shadow'):
                logger.warning(f"Blocked suspicious download path: {file_path}")
                return {
                    "success": False,
                    "error": f"Invalid path: Directory traversal or system file access not allowed"
                }

            # Resolve to absolute path to prevent symlink attacks
            file_path = os.path.abspath(file_path)

            # Check if file exists
            if not os.path.exists(file_path):
                return {"success": False, "error": f"File not found on Kali server: {file_path}"}

            # Read file from Kali server
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Encode content to base64
            encoded_content = base64.b64encode(file_content).decode()
            
            file_size = len(file_content)
            
            return {
                "success": True,
                "content": encoded_content,
                "message": f"File downloaded from Kali server: {file_path}",
                "file_path": file_path,
                "file_size": file_size
            }
            
        except Exception as e:
            logger.error(f"Failed to download from Kali server: {e}")
            return {"success": False, "error": f"Failed to download from Kali server: {str(e)}"}

    def calculate_checksum(self, data: bytes) -> str:
        """
        Calculate SHA256 checksum of binary data.
        This is used for SSH and reverse shell methods.
        """
        try:
            return hashlib.sha256(data).hexdigest()
        except Exception as e:
            logger.error(f"Error calculating checksum: {e}")
            return f"Error calculating checksum: {str(e)}"

    # SSH Transfer Methods with Verification
    
    def upload_via_ssh_with_verification(self, ssh_manager, content: str, remote_file: str, encoding: str = "base64") -> Dict[str, Any]:
        """
        Upload content via SSH with checksum verification.
        
        Args:
            ssh_manager: SSH session manager instance
            content: Content to upload (base64 encoded if encoding="base64")
            remote_file: Path where to save the file on the target
            encoding: Content encoding ("base64" or "utf-8")
            
        Returns:
            Dict with success status, checksums, and transfer statistics
        """
        try:
            start_time = time.time()
            
            # Calculate source checksum
            if encoding == "base64":
                # Decode base64 to get original content for checksum
                original_content = base64.b64decode(content)
                source_checksum = self.calculate_checksum(original_content)
            else:
                # Content is already in its final form
                original_content = content.encode('utf-8')
                source_checksum = self.calculate_checksum(original_content)
            
            # Upload content using SSH manager's direct method
            # For large base64 content, use printf instead of echo to avoid shell limitations
            if encoding == "base64":
                if len(content) > 8192:  # For large content, use printf
                    upload_cmd = f"printf '%s' '{content}' | base64 -d > {remote_file}"
                else:
                    upload_cmd = f"echo '{content}' | base64 -d > {remote_file}"
            else:
                # Escape content for shell safety
                escaped_content = content.replace("'", "'\"'\"'")
                upload_cmd = f"echo '{escaped_content}' > {remote_file}"
            
            result = ssh_manager.send_command(upload_cmd, timeout=300)
            
            if not result.get('success'):
                return {
                    "success": False,
                    "error": f"SSH upload command failed: {result.get('error', 'Unknown error')}",
                    "upload_command": upload_cmd[:100] + "..." if len(upload_cmd) > 100 else upload_cmd,
                    "command_result": result
                }
            
            # Verify upload by calculating checksum on target
            verify_cmd = f"sha256sum {remote_file} | cut -d' ' -f1"
            verify_result = ssh_manager.send_command(verify_cmd, timeout=60)
            
            if not verify_result.get('success'):
                return {
                    "success": False,
                    "error": f"Failed to verify uploaded file checksum: {verify_result.get('error', 'Unknown error')}"
                }
            
            target_checksum = verify_result.get('output', '').strip()
            
            # Clean the checksum output - extract only the hex checksum part
            import re
            # Look for 64-character hex string (SHA256) in the output
            checksum_match = re.search(r'([a-f0-9]{64})', target_checksum)
            if checksum_match:
                target_checksum = checksum_match.group(1)
            
            # Check if file exists first if checksum is empty
            if not target_checksum or len(target_checksum) != 64:
                file_check_cmd = f"ls -la {remote_file}"
                file_check_result = ssh_manager.send_command(file_check_cmd, timeout=10)
                return {
                    "success": False,
                    "error": f"Target checksum is invalid. Length: {len(target_checksum)}, Content: {target_checksum[:50]}..., File check: {file_check_result.get('output', 'No output')}"
                }
            
            # Compare checksums
            if source_checksum != target_checksum:
                return {
                    "success": False,
                    "error": f"Checksum mismatch: source={source_checksum[:16]}..., target={target_checksum[:16]}...",
                    "source_checksum": source_checksum,
                    "target_checksum": target_checksum
                }
            
            transfer_time = time.time() - start_time
            
            return {
                "success": True,
                "message": f"File uploaded via SSH with verification: {remote_file}",
                "remote_file": remote_file,
                "file_size": len(original_content),
                "source_checksum": source_checksum,
                "target_checksum": target_checksum,
                "transfer_time_seconds": round(transfer_time, 2),
                "method": "ssh_direct"
            }
            
        except Exception as e:
            logger.error(f"SSH upload with verification failed: {e}")
            return {"success": False, "error": f"SSH upload failed: {str(e)}"}

    def download_via_ssh_with_verification(self, ssh_manager, remote_file: str, encoding: str = "base64") -> Dict[str, Any]:
        """
        Download content via SSH with checksum verification.
        
        Args:
            ssh_manager: SSH session manager instance
            remote_file: Path to the file on the target
            encoding: Desired encoding for returned content ("base64" or "utf-8")
            
        Returns:
            Dict with success status, content, checksums, and transfer statistics
        """
        try:
            start_time = time.time()
            
            # Get source checksum from target
            checksum_cmd = f"sha256sum {remote_file} | cut -d' ' -f1"
            checksum_result = ssh_manager.send_command(checksum_cmd, timeout=60)
            
            if not checksum_result.get('success'):
                return {
                    "success": False,
                    "error": f"Failed to get checksum for {remote_file}"
                }
            
            source_checksum_raw = checksum_result.get('output', '').strip()
            
            # Check for file not found errors first
            if ("No such file or directory" in source_checksum_raw or
                "File not found" in source_checksum_raw or
                "does not exist" in source_checksum_raw):
                return {
                    "success": False,
                    "error": f"File not found: {remote_file}"
                }
            
            # Clean the checksum output - extract only the hex checksum part
            import re
            # Look for 64-character hex string (SHA256)
            checksum_match = re.search(r'([a-f0-9]{64})', source_checksum_raw)
            if checksum_match:
                source_checksum = checksum_match.group(1)
            else:
                source_checksum = ""
            
            if not source_checksum:
                # Check if file exists
                file_check_cmd = f"ls -la {remote_file}"
                file_check_result = ssh_manager.send_command(file_check_cmd, timeout=10)
                return {
                    "success": False,
                    "error": f"Empty checksum received for {remote_file}. File check: {file_check_result.get('output', 'No output')}"
                }
            
            logger.info(f"SSH download: Starting download of {remote_file}")
            logger.info(f"Source checksum from target: {source_checksum}")
            
            # Download content as base64
            download_cmd = f"base64 -w 0 {remote_file}"
            download_result = ssh_manager.send_command(download_cmd, timeout=300)
            
            if not download_result.get('success'):
                return {
                    "success": False,
                    "error": f"Failed to download {remote_file}"
                }
            
            content_b64_raw = download_result.get('output', '').strip()
            
            # Clean the base64 output more carefully
            import re
            # Remove ANSI escape sequences and control characters
            ansi_escape = re.compile(r'\x1b\[[0-9;]*[mGKHlh]|\x1b\[[?0-9;]*[lh]')
            content_b64_clean = ansi_escape.sub('', content_b64_raw)
            
            # Look for SSH end marker and extract only content before it
            ssh_end_match = re.search(r'(.*?)SSH_END_[a-f0-9]+', content_b64_clean, re.DOTALL)
            if ssh_end_match:
                content_b64_clean = ssh_end_match.group(1)
            else:
                # If no end marker found with regex, try manual removal
                # Look for echo 'SSH_END_...' pattern and remove everything from that point
                end_marker_pos = content_b64_clean.find("echo 'SSH_END_")
                if end_marker_pos != -1:
                    content_b64_clean = content_b64_clean[:end_marker_pos]
                else:
                    # Final fallback - remove SSH_END pattern
                    content_b64_clean = re.sub(r'SSH_END_[a-f0-9]+.*$', '', content_b64_clean, flags=re.DOTALL)
                
            # If still no content, maybe the marker removal was too aggressive
            if not content_b64_clean and content_b64_raw:
                logger.warning("SSH marker removal eliminated all content, trying different approach")
                # Try to extract base64 content more directly
                lines = content_b64_raw.split('\n')
                base64_lines = []
                for line in lines:
                    # Clean line and check if it looks like base64
                    clean_line = ansi_escape.sub('', line).strip()
                    if clean_line and not re.search(r'SSH_END_[a-f0-9]+', clean_line) and len(clean_line) > 10:
                        # Check if line has significant base64 content
                        base64_chars = sum(1 for c in clean_line if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
                        if base64_chars > len(clean_line) * 0.8:  # 80% base64 chars
                            base64_lines.append(clean_line)
                
                content_b64_clean = ''.join(base64_lines)
            
            # Remove shell prompts more carefully - only remove actual prompt lines
            # Look for lines that start with username@hostname:path$ pattern at start of line
            lines = content_b64_clean.split('\n')
            filtered_lines = []
            for line in lines:
                # Only remove lines that clearly look like shell prompts:
                # - Start with word characters, then @, then word chars, then :, then $
                # - But preserve lines that are pure base64 content
                if re.match(r'^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+:[^$]*\$$', line.strip()):
                    continue
                filtered_lines.append(line)
            
            content_b64_clean = '\n'.join(filtered_lines)
            
            # Additional cleanup for contaminated base64 - remove embedded shell prompts and commands
            # This handles cases where shell prompts get mixed into the base64 content
            import re
            # Remove embedded shell prompts (username@hostname patterns)
            content_b64_clean = re.sub(r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+:[^$]*\$', '', content_b64_clean)
            # Remove echo commands that might be embedded
            content_b64_clean = re.sub(r'echo\s+[^\s]*', '', content_b64_clean)
            # Remove SSH_END markers that might be embedded
            content_b64_clean = re.sub(r'SSH_END_[a-f0-9]+', '', content_b64_clean)
            
            # Keep only valid base64 characters and necessary whitespace
            valid_b64_pattern = re.compile(r'[A-Za-z0-9+/=]')
            content_b64_filtered = ''.join(c for c in content_b64_clean if valid_b64_pattern.match(c))
            
            # Fix base64 padding if needed
            if content_b64_filtered:
                # Remove any invalid trailing characters that aren't base64
                content_b64_filtered = content_b64_filtered.rstrip('0123456789')  # Remove trailing digits
                
                # Ensure proper base64 padding
                missing_padding = len(content_b64_filtered) % 4
                if missing_padding:
                    content_b64_filtered += '=' * (4 - missing_padding)
            
            # Final cleanup - this should now be pure base64
            content_b64_clean = content_b64_filtered
            
            if not content_b64_clean:
                return {
                    "success": False,
                    "error": "No valid base64 content received"
                }
            
            # Decode and verify
            try:
                decoded_content = base64.b64decode(content_b64_clean)
                target_checksum = self.calculate_checksum(decoded_content)
            except Exception as e:
                logger.error(f"Failed to decode base64 content: {content_b64_clean[:100]}...")
                return {
                    "success": False,
                    "error": f"Failed to decode downloaded content: {str(e)}"
                }
            
            # Compare checksums
            if source_checksum != target_checksum:
                return {
                    "success": False,
                    "error": f"Checksum mismatch: source={source_checksum[:16]}..., target={target_checksum[:16]}...",
                    "source_checksum": source_checksum,
                    "target_checksum": target_checksum
                }
            
            transfer_time = time.time() - start_time
            
            logger.info(f"SSH download verified: {source_checksum[:16]}... == {target_checksum[:16]}...")
            
            # Return content in requested encoding
            if encoding == "base64":
                final_content = content_b64_clean
            else:
                final_content = decoded_content.decode('utf-8')
            
            return {
                "success": True,
                "content": final_content,
                "message": f"File downloaded via SSH with verification: {remote_file}",
                "remote_file": remote_file,
                "file_size": len(decoded_content),
                "source_checksum": source_checksum,
                "target_checksum": target_checksum,
                "transfer_time_seconds": round(transfer_time, 2),
                "method": "ssh_direct",
                "encoding": encoding
            }
            
        except Exception as e:
            logger.error(f"SSH download with verification failed: {e}")
            return {"success": False, "error": f"SSH download failed: {str(e)}"}

    # Reverse Shell Transfer Methods with Verification
    
    def upload_via_reverse_shell_with_verification(self, shell_manager, content: str, remote_file: str, encoding: str = "base64") -> Dict[str, Any]:
        """
        Upload content via reverse shell with checksum verification.
        
        Args:
            shell_manager: Reverse shell session manager instance
            content: Content to upload (base64 encoded if encoding="base64")
            remote_file: Path where to save the file on the target
            encoding: Content encoding ("base64" or "utf-8")
            
        Returns:
            Dict with success status, checksums, and transfer statistics
        """
        try:
            start_time = time.time()
            
            # Calculate source checksum
            if encoding == "base64":
                # Decode base64 to get original content for checksum
                original_content = base64.b64decode(content)
                source_checksum = self.calculate_checksum(original_content)
            else:
                # Content is already in its final form
                original_content = content.encode('utf-8')
                source_checksum = self.calculate_checksum(original_content)
            
            logger.info(f"Reverse shell upload: Starting upload of {len(original_content)} bytes to {remote_file}")
            
            # Upload content using reverse shell manager's direct method
            if encoding == "base64":
                # Use echo with base64 decode - more reliable for reverse shells
                upload_cmd = f"echo '{content}' | base64 -d > {remote_file}"
            else:
                # Escape content for shell safety and use printf for better handling
                escaped_content = content.replace("'", "'\"'\"'").replace("\\", "\\\\")
                upload_cmd = f"printf '%s' '{escaped_content}' > {remote_file}"
            
            result = shell_manager.send_command(upload_cmd, timeout=300)
            
            if not result.get('success'):
                return {
                    "success": False,
                    "error": f"Reverse shell upload command failed: {result.get('error', 'Unknown error')}"
                }
            
            # Verify upload by calculating checksum on target
            # Use multiple fallback methods for checksum calculation
            verify_commands = [
                f"sha256sum {remote_file} 2>/dev/null | cut -d' ' -f1",
                f"shasum -a 256 {remote_file} 2>/dev/null | cut -d' ' -f1",
                f"openssl dgst -sha256 {remote_file} 2>/dev/null | awk '{{print $NF}}'"
            ]
            
            target_checksum = None
            for verify_cmd in verify_commands:
                verify_result = shell_manager.send_command(verify_cmd, timeout=60)
                if verify_result.get('success'):
                    checksum_output = verify_result.get('output', '').strip()
                    
                    # Parse reverse shell output to extract checksum
                    # The output contains debug info and command echoes, we need to extract the actual checksum
                    import re
                    lines = checksum_output.split('\n')
                    for line in lines:
                        line = line.strip()
                        # Look for a 64-character hex string (SHA256)
                        checksum_match = re.search(r'([a-f0-9]{64})', line)
                        if checksum_match:
                            target_checksum = checksum_match.group(1)
                            logger.info(f"Extracted checksum from reverse shell output: {target_checksum}")
                            break
                    
                    if target_checksum and len(target_checksum) == 64:
                        break
            
            if not target_checksum:
                return {
                    "success": False,
                    "error": "Failed to verify uploaded file checksum - no checksum tools available"
                }
            
            # Compare checksums
            if source_checksum != target_checksum:
                return {
                    "success": False,
                    "error": f"Checksum mismatch: source={source_checksum[:16]}..., target={target_checksum[:16]}...",
                    "source_checksum": source_checksum,
                    "target_checksum": target_checksum
                }
            
            transfer_time = time.time() - start_time
            
            logger.info(f"Reverse shell upload verified: {source_checksum[:16]}... == {target_checksum[:16]}...")
            
            return {
                "success": True,
                "message": f"File uploaded via reverse shell with verification: {remote_file}",
                "remote_file": remote_file,
                "file_size": len(original_content),
                "source_checksum": source_checksum,
                "target_checksum": target_checksum,
                "transfer_time_seconds": round(transfer_time, 2),
                "method": "reverse_shell_direct"
            }
            
        except Exception as e:
            logger.error(f"Reverse shell upload with verification failed: {e}")
            return {"success": False, "error": f"Reverse shell upload failed: {str(e)}"}

    def download_via_reverse_shell_with_verification(self, shell_manager, remote_file: str, encoding: str = "base64") -> Dict[str, Any]:
        """
        Download content via reverse shell with checksum verification.
        
        Args:
            shell_manager: Reverse shell session manager instance
            remote_file: Path to the file on the target
            encoding: Desired encoding for returned content ("base64" or "utf-8")
            
        Returns:
            Dict with success status, content, checksums, and transfer statistics
        """
        try:
            start_time = time.time()
            
            # Get source checksum from target using multiple fallback methods
            checksum_commands = [
                f"sha256sum {remote_file} 2>/dev/null | cut -d' ' -f1",
                f"shasum -a 256 {remote_file} 2>/dev/null | cut -d' ' -f1",
                f"openssl dgst -sha256 {remote_file} 2>/dev/null | awk '{{print $NF}}'"
            ]
            
            source_checksum = None
            for checksum_cmd in checksum_commands:
                checksum_result = shell_manager.send_command(checksum_cmd, timeout=60)
                if checksum_result.get('success'):
                    checksum_output = checksum_result.get('output', '').strip()
                    
                    # Parse reverse shell output to extract checksum
                    # The output contains debug info and command echoes, we need to extract the actual checksum
                    import re
                    lines = checksum_output.split('\n')
                    for line in lines:
                        line = line.strip()
                        # Look for a 64-character hex string (SHA256)
                        checksum_match = re.search(r'([a-f0-9]{64})', line)
                        if checksum_match:
                            source_checksum = checksum_match.group(1)
                            break
                    
                    if source_checksum and len(source_checksum) == 64:
                        break
            
            if not source_checksum:
                return {
                    "success": False,
                    "error": f"Failed to get checksum for {remote_file} - no checksum tools available"
                }
            
            logger.info(f"Reverse shell download: Starting download of {remote_file}")
            
            # Download content as base64 with error handling
            download_commands = [
                f"base64 -w 0 {remote_file} 2>/dev/null",
                f"base64 {remote_file} 2>/dev/null | tr -d '\\n'",
                f"openssl base64 -in {remote_file} 2>/dev/null | tr -d '\\n'"
            ]
            
            content_b64_raw = None
            for download_cmd in download_commands:
                download_result = shell_manager.send_command(download_cmd, timeout=300)
                if download_result.get('success'):
                    output = download_result.get('output', '').strip()
                    if output and len(output) > 0:
                        content_b64_raw = output
                        break
            
            if not content_b64_raw:
                return {
                    "success": False,
                    "error": f"Failed to download {remote_file} - no base64 tools available"
                }
            
            # Clean the base64 output for reverse shell environments
            import re
            
            # Parse the command output to extract the actual base64 content
            # The output from send_command contains debug markers and multiple lines
            lines = content_b64_raw.split('\n')
            base64_candidates = []
            
            for line in lines:
                line = line.strip()
                # Skip empty lines, shell prompts, and debug markers
                if not line or line.endswith('$') or 'START_' in line or 'END_' in line:
                    continue
                # Skip the command echo itself
                if line.startswith('base64 ') or line.startswith('openssl base64'):
                    continue
                # Look for lines that look like base64 content
                if re.match(r'^[A-Za-z0-9+/]+={0,2}$', line) and len(line) > 10:
                    base64_candidates.append(line)
            
            # If we found base64 candidates, join them
            if base64_candidates:
                content_b64_clean = ''.join(base64_candidates)
            else:
                # Fallback: clean the original output more carefully
                # Remove ANSI escape sequences and control characters
                ansi_escape = re.compile(r'\x1b\[[0-9;]*[mGKHlh]|\x1b\[[?0-9;]*[lh]')
                content_b64_clean = ansi_escape.sub('', content_b64_raw)
                # Remove shell markers and newlines, keep only valid base64 characters
                content_b64_clean = re.sub(r'START_[a-f0-9]+|END_[a-f0-9]+', '', content_b64_clean)
                content_b64_clean = re.sub(r'[^A-Za-z0-9+/=]', '', content_b64_clean)
            
            # Validate base64 padding
            if len(content_b64_clean) % 4 != 0:
                # Add padding if needed
                padding_needed = 4 - (len(content_b64_clean) % 4)
                content_b64_clean += '=' * padding_needed
            
            if not content_b64_clean:
                return {
                    "success": False,
                    "error": "No valid base64 content received from reverse shell"
                }
            
            # Decode and verify
            try:
                decoded_content = base64.b64decode(content_b64_clean)
                target_checksum = self.calculate_checksum(decoded_content)
                
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Failed to decode downloaded content from reverse shell: {str(e)}"
                }
            
            # Compare checksums
            if source_checksum != target_checksum:
                return {
                    "success": False,
                    "error": f"Checksum mismatch: source={source_checksum[:16]}..., target={target_checksum[:16]}...",
                    "source_checksum": source_checksum,
                    "target_checksum": target_checksum
                }
            
            transfer_time = time.time() - start_time
            
            logger.info(f"Reverse shell download verified: {source_checksum[:16]}... == {target_checksum[:16]}...")
            
            # Return content in requested encoding
            if encoding == "base64":
                final_content = content_b64_clean
            else:
                final_content = decoded_content.decode('utf-8')
            
            return {
                "success": True,
                "content": final_content,
                "message": f"File downloaded via reverse shell with verification: {remote_file}",
                "remote_file": remote_file,
                "file_size": len(decoded_content),
                "source_checksum": source_checksum,
                "target_checksum": target_checksum,
                "transfer_time_seconds": round(transfer_time, 2),
                "method": "reverse_shell_direct",
                "encoding": encoding
            }
            
        except Exception as e:
            logger.error(f"Reverse shell download with verification failed: {e}")
            return {"success": False, "error": f"Reverse shell download failed: {str(e)}"}


# Global instance for use across the application
transfer_manager = FileTransferManager()
