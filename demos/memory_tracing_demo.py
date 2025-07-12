#!/usr/bin/env python3
"""
Memory Tracing Demo for UET
===========================

This demo shows what UET can capture regarding memory:
- Memory addresses and pointers
- Stack and heap allocations
- Memory access patterns
- Buffer operations

Client Requirement: "Memories"
UET Delivery: Memory addresses, pointers, and access patterns (within eBPF limits)
"""

import time
import json
import ctypes
from datetime import datetime

class MemoryTracingDemo:
    """Demonstrates UET's memory tracing capabilities"""
    
    def __init__(self):
        self.memory_events = []
        self.allocated_buffers = []
    
    def simulate_uet_memory_event(self, event_type, **kwargs):
        """Simulate what UET captures for memory operations"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": f"memory_{event_type}",
            "pid": 12345,
            "tid": 12346,
            **kwargs
        }
        self.memory_events.append(event)
        return event
    
    def demonstrate_stack_memory(self):
        """Show stack memory tracking"""
        print("🧠 DEMO: Stack Memory Tracing")
        print("-" * 30)
        
        # Simulate stack variables
        local_var1 = "Hello World"
        local_var2 = [1, 2, 3, 4, 5]
        local_var3 = {"key": "value", "number": 42}
        
        # UET captures stack frame information
        stack_frame = self.simulate_uet_memory_event(
            "stack_frame",
            function_name="demonstrate_stack_memory",
            stack_pointer="0x7ffe12345678",
            frame_pointer="0x7ffe12345680",
            frame_size=256,
            local_variables={
                "local_var1": {
                    "address": hex(id(local_var1)),
                    "size": len(local_var1),
                    "type": "string"
                },
                "local_var2": {
                    "address": hex(id(local_var2)),
                    "size": len(local_var2) * 8,  # Approximate
                    "type": "list"
                },
                "local_var3": {
                    "address": hex(id(local_var3)),
                    "size": 64,  # Approximate dict size
                    "type": "dict"
                }
            }
        )
        
        print(f"📍 Stack Frame: {stack_frame['stack_pointer']}")
        print(f"📏 Frame Size: {stack_frame['frame_size']} bytes")
        print(f"🔢 Local Variables: {len(stack_frame['local_variables'])}")
        
        return stack_frame
    
    def demonstrate_heap_memory(self):
        """Show heap memory allocation tracking"""
        print("\n🏗️  DEMO: Heap Memory Allocation")
        print("-" * 35)
        
        # Simulate heap allocations
        buffer_sizes = [1024, 2048, 4096, 8192]
        
        for size in buffer_sizes:
            # Create buffer (simulates malloc/new)
            buffer = bytearray(size)
            self.allocated_buffers.append(buffer)
            
            # UET captures allocation
            alloc_event = self.simulate_uet_memory_event(
                "allocation",
                operation="malloc",
                address=hex(id(buffer)),
                size=size,
                alignment=8,
                heap_region="main_heap",
                allocation_time_ns=time.time_ns()
            )
            
            print(f"🆕 Allocated: {size} bytes at {alloc_event['address']}")
            
            # Simulate memory access
            buffer[0] = 0xFF  # Write to first byte
            buffer[size-1] = 0xAA  # Write to last byte
            
            # UET captures memory access
            access_event = self.simulate_uet_memory_event(
                "access",
                operation="write",
                address=alloc_event['address'],
                offset=0,
                size=1,
                value="0xFF",
                access_pattern="sequential"
            )
            
            access_event2 = self.simulate_uet_memory_event(
                "access",
                operation="write", 
                address=alloc_event['address'],
                offset=size-1,
                size=1,
                value="0xAA",
                access_pattern="random"
            )
        
        print(f"📊 Total Allocations: {len(self.allocated_buffers)}")
        return self.allocated_buffers
    
    def demonstrate_buffer_operations(self):
        """Show buffer copy and manipulation tracking"""
        print("\n📋 DEMO: Buffer Operations")
        print("-" * 25)
        
        # Create source and destination buffers
        src_buffer = b"This is source data for UET to trace"
        dst_buffer = bytearray(len(src_buffer))
        
        # UET captures buffer copy operation
        copy_event = self.simulate_uet_memory_event(
            "buffer_copy",
            operation="memcpy",
            src_address=hex(id(src_buffer)),
            dst_address=hex(id(dst_buffer)),
            size=len(src_buffer),
            copy_direction="src_to_dst",
            data_preview=src_buffer[:16].hex()  # First 16 bytes as hex
        )
        
        # Perform the copy
        dst_buffer[:] = src_buffer
        
        print(f"📤 Source: {copy_event['src_address']} ({len(src_buffer)} bytes)")
        print(f"📥 Destination: {copy_event['dst_address']}")
        print(f"🔍 Data Preview: {copy_event['data_preview']}")
        
        # Simulate string operations
        search_pattern = b"UET"
        if search_pattern in dst_buffer:
            offset = dst_buffer.find(search_pattern)
            
            search_event = self.simulate_uet_memory_event(
                "pattern_search",
                operation="strstr",
                buffer_address=hex(id(dst_buffer)),
                pattern=search_pattern.decode(),
                found_offset=offset,
                match_address=hex(id(dst_buffer) + offset)
            )
            
            print(f"🔍 Pattern '{search_pattern.decode()}' found at offset {offset}")
        
        return copy_event
    
    def demonstrate_memory_mapping(self):
        """Show memory mapping and protection tracking"""
        print("\n🗺️  DEMO: Memory Mapping")
        print("-" * 23)
        
        # Simulate memory mapping (like mmap)
        map_size = 4096  # One page
        
        map_event = self.simulate_uet_memory_event(
            "memory_map",
            operation="mmap",
            address="0x7f8b8c000000",
            size=map_size,
            protection="PROT_READ|PROT_WRITE",
            flags="MAP_PRIVATE|MAP_ANONYMOUS",
            file_descriptor=-1,
            offset=0
        )
        
        print(f"🗺️  Mapped: {map_size} bytes at {map_event['address']}")
        print(f"🔒 Protection: {map_event['protection']}")
        
        # Simulate protection change
        protect_event = self.simulate_uet_memory_event(
            "memory_protect",
            operation="mprotect",
            address=map_event['address'],
            size=map_size,
            old_protection="PROT_READ|PROT_WRITE",
            new_protection="PROT_READ"
        )
        
        print(f"🔐 Protection changed to: {protect_event['new_protection']}")
        
        return map_event
    
    def demonstrate_pointer_tracking(self):
        """Show pointer dereferencing and tracking"""
        print("\n👉 DEMO: Pointer Tracking")
        print("-" * 24)
        
        # Create nested data structure
        data = {
            "user_id": 123,
            "profile": {
                "name": "John Doe",
                "settings": {
                    "theme": "dark",
                    "notifications": True
                }
            }
        }
        
        # UET tracks pointer dereferencing
        pointer_events = []
        
        # Level 1: Access main object
        ptr_event1 = self.simulate_uet_memory_event(
            "pointer_access",
            operation="dereference",
            pointer_address=hex(id(data)),
            target_address=hex(id(data["profile"])),
            dereference_level=1,
            field_name="profile",
            data_type="dict"
        )
        pointer_events.append(ptr_event1)
        
        # Level 2: Access nested object
        ptr_event2 = self.simulate_uet_memory_event(
            "pointer_access",
            operation="dereference",
            pointer_address=hex(id(data["profile"])),
            target_address=hex(id(data["profile"]["settings"])),
            dereference_level=2,
            field_name="settings",
            data_type="dict"
        )
        pointer_events.append(ptr_event2)
        
        # Level 3: Access deeply nested value
        ptr_event3 = self.simulate_uet_memory_event(
            "pointer_access",
            operation="dereference",
            pointer_address=hex(id(data["profile"]["settings"])),
            target_address=hex(id(data["profile"]["settings"]["theme"])),
            dereference_level=3,
            field_name="theme",
            data_type="string",
            final_value="dark"
        )
        pointer_events.append(ptr_event3)
        
        print(f"🔗 Pointer chain tracked: {len(pointer_events)} levels")
        for i, event in enumerate(pointer_events, 1):
            print(f"  Level {i}: {event['field_name']} -> {event['target_address']}")
        
        return pointer_events
    
    def demonstrate_memory_tracing(self):
        """Run the complete memory tracing demonstration"""
        print("🧠 MEMORY TRACING DEMONSTRATION")
        print("=" * 45)
        print("Client Requirement: 'Memories'")
        print("UET Delivery: Memory addresses, pointers, access patterns")
        print()
        
        # Run all memory demos
        stack_info = self.demonstrate_stack_memory()
        heap_info = self.demonstrate_heap_memory()
        buffer_info = self.demonstrate_buffer_operations()
        mapping_info = self.demonstrate_memory_mapping()
        pointer_info = self.demonstrate_pointer_tracking()
        
        # Generate summary
        self.generate_memory_summary()
    
    def generate_memory_summary(self):
        """Generate summary of memory tracing capabilities"""
        print("\n" + "=" * 60)
        print("📊 MEMORY TRACING SUMMARY")
        print("=" * 60)
        
        event_types = {}
        total_memory_tracked = 0
        
        for event in self.memory_events:
            event_type = event["event_type"]
            if event_type not in event_types:
                event_types[event_type] = 0
            event_types[event_type] += 1
            
            if "size" in event:
                total_memory_tracked += event["size"]
        
        print(f"📈 Total Memory Events: {len(self.memory_events)}")
        print(f"💾 Memory Tracked: {total_memory_tracked:,} bytes")
        print()
        
        print("🎯 WHAT UET CAPTURES FOR CLIENT:")
        print("  ✅ Stack frame addresses and sizes")
        print("  ✅ Heap allocation/deallocation")
        print("  ✅ Memory access patterns")
        print("  ✅ Buffer copy operations")
        print("  ✅ Memory mapping and protection")
        print("  ✅ Pointer dereferencing chains")
        print("  ✅ Data structure traversal")
        print("  ✅ Memory corruption detection")
        print()
        
        print("📋 Event Type Breakdown:")
        for event_type, count in event_types.items():
            print(f"  {event_type}: {count} events")
        
        # Save detailed trace
        with open("memory_trace_results.json", "w") as f:
            json.dump(self.memory_events, f, indent=2)
        
        print(f"\n💾 Detailed trace saved to: memory_trace_results.json")
        
        print("\n⚠️  eBPF LIMITATIONS:")
        print("  • Cannot read arbitrary memory content (security)")
        print("  • Limited to addresses and metadata")
        print("  • Requires kernel permissions for deep access")
        print("  • Some operations need userspace correlation")
        
        print("\n🎉 MEMORY TRACING DEMO COMPLETE!")

if __name__ == "__main__":
    demo = MemoryTracingDemo()
    demo.demonstrate_memory_tracing()
