"""Batch processing for multiple domains."""

import logging
from pathlib import Path
from typing import List, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from ssl_tester.models import CheckResult

logger = logging.getLogger(__name__)


@dataclass
class BatchTarget:
    """Target for batch processing."""

    hostname: str
    port: int = 443
    service: Optional[str] = None


def read_targets_from_file(file_path: Path) -> List[BatchTarget]:
    """
    Read targets from a file (one per line, format: hostname[:port]).
    
    Args:
        file_path: Path to file containing targets
        
    Returns:
        List of BatchTarget
    """
    targets = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                # Parse hostname:port or just hostname
                if ":" in line:
                    parts = line.split(":", 1)
                    hostname = parts[0].strip()
                    try:
                        port = int(parts[1].strip())
                    except ValueError:
                        logger.warning(f"Invalid port in line {line_num}: {line}")
                        continue
                else:
                    hostname = line
                    port = 443
                
                if hostname:
                    targets.append(BatchTarget(hostname=hostname, port=port))
    except Exception as e:
        logger.error(f"Error reading targets from file {file_path}: {e}")
        raise
    
    return targets


def process_batch(
    targets: List[BatchTarget],
    check_function: Callable[[str, int, Optional[str]], CheckResult],
    max_workers: int = 5,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> List[CheckResult]:
    """
    Process multiple targets in parallel.
    
    Args:
        targets: List of BatchTarget to process
        check_function: Function to call for each target (hostname, port, service) -> CheckResult
        max_workers: Maximum number of parallel workers
        progress_callback: Optional callback function(current, total)
        
    Returns:
        List of CheckResult
    """
    results = []
    total = len(targets)
    
    logger.info(f"Processing {total} target(s) with {max_workers} worker(s)...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_target = {
            executor.submit(check_function, target.hostname, target.port, target.service): target
            for target in targets
        }
        
        # Process completed tasks
        completed = 0
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                results.append(result)
                completed += 1
                
                if progress_callback:
                    progress_callback(completed, total)
                
                logger.debug(f"Completed {completed}/{total}: {target.hostname}:{target.port}")
            except Exception as e:
                logger.error(f"Error processing {target.hostname}:{target.port}: {e}")
                completed += 1
                
                if progress_callback:
                    progress_callback(completed, total)
    
    logger.info(f"Batch processing completed: {len(results)}/{total} successful")
    return results

