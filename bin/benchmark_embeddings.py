#!/usr/bin/env python3
"""Benchmark Embedding Performance: CPU vs GPU

Tests sentence-transformers embedding speed on CPU vs GPU (CUDA)
to help determine optimal configuration for CaseScope RAG.

Usage:
    python bin/benchmark_embeddings.py
    
Requirements:
    - sentence-transformers
    - torch with CUDA support
"""

import time
import sys
import os

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check_cuda():
    """Check if CUDA is available"""
    try:
        import torch
        cuda_available = torch.cuda.is_available()
        if cuda_available:
            device_name = torch.cuda.get_device_name(0)
            vram = torch.cuda.get_device_properties(0).total_memory / (1024**3)
            return True, device_name, vram
        return False, None, 0
    except Exception as e:
        return False, str(e), 0


def generate_sample_events(count: int) -> list:
    """Generate realistic forensic event text samples"""
    import random
    
    templates = [
        "EventID:4624 Logon Type:10 User:{user} Host:{host} Source:{ip}",
        "EventID:4625 Failed Logon User:{user} Host:{host} Failure:Bad Password",
        "EventID:4688 Process Created: {process} CommandLine: {cmd} User:{user}",
        "EventID:7045 Service Installed: {service} Path:{path} Host:{host}",
        "EventID:4698 Scheduled Task Created: {task} User:{user} Host:{host}",
        "EventID:4104 PowerShell ScriptBlock: {script} User:{user}",
        "EventID:1 Sysmon Process Create: {process} Parent:{parent} User:{user}",
        "EventID:3 Sysmon Network Connection: {process} Dest:{ip}:{port}",
        "EventID:11 Sysmon FileCreate: {path} Process:{process}",
        "EventID:13 Sysmon Registry: {key} Value:{value} Process:{process}",
    ]
    
    users = ["admin", "john.doe", "svc_backup", "SYSTEM", "Administrator", "guest"]
    hosts = ["WORKSTATION1", "DC01", "FILESERVER", "WEB01", "LAPTOP-ABC", "EXCHANGE01"]
    ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25", "192.168.1.1", "10.10.10.10"]
    processes = ["powershell.exe", "cmd.exe", "rundll32.exe", "svchost.exe", "explorer.exe"]
    
    events = []
    for _ in range(count):
        template = random.choice(templates)
        event = template.format(
            user=random.choice(users),
            host=random.choice(hosts),
            ip=random.choice(ips),
            port=random.randint(1, 65535),
            process=random.choice(processes),
            parent=random.choice(processes),
            cmd=f"C:\\Windows\\System32\\{random.choice(processes)} /c {random.choice(['dir', 'net user', 'whoami', 'ipconfig'])}",
            service=f"Service{random.randint(1,100)}",
            path=f"C:\\Windows\\Temp\\file{random.randint(1,1000)}.exe",
            task=f"Task{random.randint(1,50)}",
            script=f"Invoke-{random.choice(['WebRequest', 'Expression', 'Command', 'Mimikatz'])}",
            key=f"HKLM\\Software\\{random.choice(['Microsoft', 'Policies', 'Classes'])}",
            value=f"Value{random.randint(1,100)}"
        )
        events.append(event)
    
    return events


def benchmark_device(device: str, model_name: str, events: list, batch_sizes: list) -> dict:
    """Benchmark embedding on a specific device"""
    from sentence_transformers import SentenceTransformer
    import torch
    
    print(f"\n{'='*60}")
    print(f"Testing on: {device.upper()}")
    print(f"{'='*60}")
    
    # Load model on device
    print(f"Loading model '{model_name}' on {device}...")
    load_start = time.time()
    
    try:
        model = SentenceTransformer(model_name, device=device)
        load_time = time.time() - load_start
        print(f"Model loaded in {load_time:.2f}s")
    except Exception as e:
        print(f"ERROR: Failed to load model on {device}: {e}")
        return None
    
    # Warmup
    print("Warming up...")
    _ = model.encode(events[:10], show_progress_bar=False)
    
    # Clear GPU cache if using CUDA
    if device == 'cuda':
        torch.cuda.synchronize()
        torch.cuda.empty_cache()
    
    results = {
        'device': device,
        'model': model_name,
        'load_time': load_time,
        'benchmarks': []
    }
    
    for batch_size in batch_sizes:
        print(f"\nBatch size: {batch_size}")
        
        # Single event
        start = time.time()
        for event in events[:100]:
            _ = model.encode(event, show_progress_bar=False)
        single_time = time.time() - start
        single_per_event = (single_time / 100) * 1000  # ms
        
        # Batched
        start = time.time()
        _ = model.encode(events, batch_size=batch_size, show_progress_bar=False)
        if device == 'cuda':
            torch.cuda.synchronize()
        batch_time = time.time() - start
        batch_per_event = (batch_time / len(events)) * 1000  # ms
        
        print(f"  Single-event (100 events): {single_time:.2f}s ({single_per_event:.2f}ms/event)")
        print(f"  Batched ({len(events)} events):    {batch_time:.2f}s ({batch_per_event:.2f}ms/event)")
        
        results['benchmarks'].append({
            'batch_size': batch_size,
            'single_time_100': single_time,
            'single_ms_per_event': single_per_event,
            'batch_time': batch_time,
            'batch_ms_per_event': batch_per_event,
            'events_per_second': len(events) / batch_time
        })
    
    # Memory usage
    if device == 'cuda':
        allocated = torch.cuda.memory_allocated() / (1024**2)
        reserved = torch.cuda.memory_reserved() / (1024**2)
        print(f"\nGPU Memory: {allocated:.1f}MB allocated, {reserved:.1f}MB reserved")
        results['gpu_memory_mb'] = allocated
    
    # Cleanup
    del model
    if device == 'cuda':
        torch.cuda.empty_cache()
    
    return results


def print_comparison(cpu_results: dict, gpu_results: dict, event_count: int):
    """Print comparison table"""
    print(f"\n{'='*70}")
    print("COMPARISON SUMMARY")
    print(f"{'='*70}")
    
    if not gpu_results:
        print("GPU results not available - CUDA may not be properly configured")
        return
    
    print(f"\n{'Metric':<30} {'CPU':<15} {'GPU':<15} {'Speedup':<10}")
    print("-" * 70)
    
    # Model load time
    cpu_load = cpu_results['load_time']
    gpu_load = gpu_results['load_time']
    print(f"{'Model Load Time':<30} {cpu_load:.2f}s{'':<8} {gpu_load:.2f}s{'':<8} {cpu_load/gpu_load:.1f}x")
    
    # Best batch results
    cpu_best = min(cpu_results['benchmarks'], key=lambda x: x['batch_ms_per_event'])
    gpu_best = min(gpu_results['benchmarks'], key=lambda x: x['batch_ms_per_event'])
    
    print(f"{'Best Batch Size':<30} {cpu_best['batch_size']:<15} {gpu_best['batch_size']:<15}")
    print(f"{'Time per Event (batched)':<30} {cpu_best['batch_ms_per_event']:.3f}ms{'':<6} {gpu_best['batch_ms_per_event']:.3f}ms{'':<6} {cpu_best['batch_ms_per_event']/gpu_best['batch_ms_per_event']:.1f}x")
    print(f"{'Events per Second':<30} {cpu_best['events_per_second']:.0f}{'':<10} {gpu_best['events_per_second']:.0f}{'':<10} {gpu_best['events_per_second']/cpu_best['events_per_second']:.1f}x")
    
    # Projections
    print(f"\n{'='*70}")
    print("PROJECTIONS FOR YOUR DATA")
    print(f"{'='*70}")
    
    projections = [
        ("1,000 events", 1000),
        ("10,000 events", 10000),
        ("100,000 events", 100000),
        ("1,000,000 events", 1000000),
        ("30,000,000 events (your scale)", 30000000),
    ]
    
    print(f"\n{'Event Count':<30} {'CPU Time':<20} {'GPU Time':<20} {'Savings':<15}")
    print("-" * 85)
    
    for label, count in projections:
        cpu_time = count * (cpu_best['batch_ms_per_event'] / 1000)  # seconds
        gpu_time = count * (gpu_best['batch_ms_per_event'] / 1000)  # seconds
        savings = cpu_time - gpu_time
        
        cpu_str = format_time(cpu_time)
        gpu_str = format_time(gpu_time)
        savings_str = format_time(savings)
        
        print(f"{label:<30} {cpu_str:<20} {gpu_str:<20} {savings_str:<15}")
    
    # GPU memory note
    if 'gpu_memory_mb' in gpu_results:
        print(f"\nGPU Memory Used: {gpu_results['gpu_memory_mb']:.1f} MB (leaves ~15.7 GB for Ollama)")


def format_time(seconds: float) -> str:
    """Format seconds into human readable time"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}min"
    elif seconds < 86400:
        return f"{seconds/3600:.1f}hr"
    else:
        return f"{seconds/86400:.1f}days"


def main():
    print("="*70)
    print("CaseScope Embedding Benchmark: CPU vs GPU")
    print("="*70)
    
    # Check CUDA
    cuda_available, gpu_name, vram = check_cuda()
    print(f"\nCUDA Available: {cuda_available}")
    if cuda_available:
        print(f"GPU: {gpu_name}")
        print(f"VRAM: {vram:.1f} GB")
    else:
        print(f"CUDA Error: {gpu_name}")
    
    # Configuration
    model_name = "all-MiniLM-L6-v2"
    event_count = 1000
    batch_sizes = [32, 64, 128, 256]
    
    print(f"\nModel: {model_name}")
    print(f"Test Events: {event_count}")
    print(f"Batch Sizes: {batch_sizes}")
    
    # Generate test data
    print("\nGenerating sample forensic events...")
    events = generate_sample_events(event_count)
    print(f"Generated {len(events)} events")
    print(f"Sample: {events[0][:80]}...")
    
    # Benchmark CPU
    cpu_results = benchmark_device('cpu', model_name, events, batch_sizes)
    
    # Benchmark GPU
    gpu_results = None
    if cuda_available:
        gpu_results = benchmark_device('cuda', model_name, events, batch_sizes)
    else:
        print("\nSkipping GPU benchmark - CUDA not available")
    
    # Print comparison
    print_comparison(cpu_results, gpu_results, event_count)
    
    # Recommendation
    print(f"\n{'='*70}")
    print("RECOMMENDATION")
    print(f"{'='*70}")
    
    if gpu_results:
        cpu_best = min(cpu_results['benchmarks'], key=lambda x: x['batch_ms_per_event'])
        gpu_best = min(gpu_results['benchmarks'], key=lambda x: x['batch_ms_per_event'])
        speedup = cpu_best['batch_ms_per_event'] / gpu_best['batch_ms_per_event']
        
        if speedup > 3:
            print(f"\n✅ GPU provides {speedup:.1f}x speedup - STRONGLY RECOMMENDED")
            print("\nTo enable GPU embeddings, update rag_embeddings.py:")
            print("  _embedding_model = SentenceTransformer(model_name, device='cuda')")
        elif speedup > 1.5:
            print(f"\n✅ GPU provides {speedup:.1f}x speedup - Recommended")
        else:
            print(f"\n⚠️  GPU provides only {speedup:.1f}x speedup - CPU is fine")
    else:
        print("\n⚠️  Could not benchmark GPU - check CUDA installation")
    
    print()


if __name__ == '__main__':
    main()
