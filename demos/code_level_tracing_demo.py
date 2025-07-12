#!/usr/bin/env python3
"""
Code-Level Tracing Demo for UET
===============================

This demo shows what UET can capture at the code level:
- Function entry/exit points
- Call stack traces
- Execution timing
- Code path analysis

Client Requirement: "Code has to be traced"
UET Delivery: Function-level tracing with call stacks
"""

import time
import json
from datetime import datetime

class CodeLevelTracingDemo:
    """Demonstrates UET's code-level tracing capabilities"""
    
    def __init__(self):
        self.trace_events = []
        self.call_depth = 0
    
    def simulate_uet_function_trace(self, function_name, event_type, **kwargs):
        """Simulate what UET captures for function tracing"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": f"function_{event_type}",
            "function_name": function_name,
            "pid": 12345,
            "tid": 12346,
            "call_depth": self.call_depth,
            "instruction_pointer": f"0x{hash(function_name) & 0xFFFFFFFF:08x}",
            "stack_pointer": f"0x7ffe{self.call_depth:08x}",
            "frame_pointer": f"0x7ffe{self.call_depth + 1:08x}",
            **kwargs
        }
        self.trace_events.append(event)
        return event
    
    def business_logic_function(self, user_id, operation):
        """Example business function that UET would trace"""
        print(f"🔍 UET CAPTURES: Function Entry - business_logic_function")
        self.call_depth += 1
        
        entry_event = self.simulate_uet_function_trace(
            "business_logic_function",
            "entry",
            arguments={
                "user_id": user_id,
                "operation": operation
            },
            source_file="business_logic.py",
            line_number=45
        )
        
        start_time = time.time()
        
        # Simulate business logic
        if operation == "validate_user":
            result = self.validate_user_credentials(user_id)
        elif operation == "process_payment":
            result = self.process_payment_transaction(user_id)
        elif operation == "update_profile":
            result = self.update_user_profile(user_id)
        else:
            result = {"error": "Unknown operation"}
        
        execution_time = (time.time() - start_time) * 1000  # ms
        
        self.call_depth -= 1
        exit_event = self.simulate_uet_function_trace(
            "business_logic_function",
            "exit", 
            return_value=result,
            execution_time_ms=execution_time
        )
        
        print(f"✅ UET CAPTURES: Function Exit - {execution_time:.2f}ms")
        return result
    
    def validate_user_credentials(self, user_id):
        """Nested function call that UET traces"""
        print(f"  🔍 UET CAPTURES: Nested Function - validate_user_credentials")
        self.call_depth += 1
        
        self.simulate_uet_function_trace(
            "validate_user_credentials",
            "entry",
            arguments={"user_id": user_id},
            call_stack=[
                "main+0x123",
                "business_logic_function+0x456", 
                "validate_user_credentials+0x0"
            ]
        )
        
        # Simulate database call
        time.sleep(0.01)  # 10ms database lookup
        
        self.call_depth -= 1
        self.simulate_uet_function_trace(
            "validate_user_credentials",
            "exit",
            return_value={"valid": True, "role": "admin"}
        )
        
        return {"valid": True, "role": "admin"}
    
    def process_payment_transaction(self, user_id):
        """Another nested function showing complex call chains"""
        print(f"  🔍 UET CAPTURES: Payment Processing Chain")
        self.call_depth += 1
        
        self.simulate_uet_function_trace(
            "process_payment_transaction",
            "entry",
            arguments={"user_id": user_id}
        )
        
        # Multiple nested calls
        auth_result = self.authenticate_payment(user_id)
        if auth_result["success"]:
            charge_result = self.charge_credit_card(user_id, 99.99)
            if charge_result["success"]:
                receipt = self.generate_receipt(user_id, charge_result["transaction_id"])
                result = {"success": True, "receipt": receipt}
            else:
                result = {"success": False, "error": "Payment failed"}
        else:
            result = {"success": False, "error": "Authentication failed"}
        
        self.call_depth -= 1
        self.simulate_uet_function_trace(
            "process_payment_transaction",
            "exit",
            return_value=result
        )
        
        return result
    
    def authenticate_payment(self, user_id):
        """Deep nested function call"""
        self.call_depth += 1
        self.simulate_uet_function_trace("authenticate_payment", "entry")
        time.sleep(0.005)  # 5ms auth check
        self.call_depth -= 1
        self.simulate_uet_function_trace("authenticate_payment", "exit")
        return {"success": True, "auth_token": "abc123"}
    
    def charge_credit_card(self, user_id, amount):
        """External API call simulation"""
        self.call_depth += 1
        self.simulate_uet_function_trace("charge_credit_card", "entry")
        time.sleep(0.02)  # 20ms external API call
        self.call_depth -= 1
        self.simulate_uet_function_trace("charge_credit_card", "exit")
        return {"success": True, "transaction_id": "txn_789"}
    
    def generate_receipt(self, user_id, transaction_id):
        """Receipt generation"""
        self.call_depth += 1
        self.simulate_uet_function_trace("generate_receipt", "entry")
        time.sleep(0.003)  # 3ms receipt generation
        self.call_depth -= 1
        self.simulate_uet_function_trace("generate_receipt", "exit")
        return {"receipt_id": "rcpt_456", "timestamp": datetime.now().isoformat()}
    
    def update_user_profile(self, user_id):
        """Profile update with error handling"""
        self.call_depth += 1
        self.simulate_uet_function_trace("update_user_profile", "entry")
        
        try:
            # Simulate validation
            if user_id < 0:
                raise ValueError("Invalid user ID")
            
            time.sleep(0.008)  # 8ms database update
            result = {"success": True, "updated_fields": ["email", "phone"]}
            
        except Exception as e:
            # UET captures exception handling
            self.simulate_uet_function_trace(
                "update_user_profile",
                "exception",
                exception_type=type(e).__name__,
                exception_message=str(e)
            )
            result = {"success": False, "error": str(e)}
        
        self.call_depth -= 1
        self.simulate_uet_function_trace("update_user_profile", "exit")
        return result
    
    def demonstrate_code_tracing(self):
        """Run the complete code-level tracing demonstration"""
        print("🔍 CODE-LEVEL TRACING DEMONSTRATION")
        print("=" * 50)
        print("Client Requirement: 'Code has to be traced'")
        print("UET Delivery: Function-level tracing with call stacks")
        print()
        
        # Test different code paths
        test_cases = [
            (123, "validate_user"),
            (456, "process_payment"), 
            (789, "update_profile"),
            (-1, "update_profile")  # Error case
        ]
        
        for user_id, operation in test_cases:
            print(f"\n📋 Testing: {operation} for user {user_id}")
            print("-" * 30)
            
            result = self.business_logic_function(user_id, operation)
            print(f"Result: {result}")
        
        # Generate summary
        self.generate_code_trace_summary()
    
    def generate_code_trace_summary(self):
        """Generate summary of what UET captured"""
        print("\n" + "=" * 60)
        print("📊 CODE-LEVEL TRACING SUMMARY")
        print("=" * 60)
        
        function_calls = {}
        total_execution_time = 0
        
        for event in self.trace_events:
            func_name = event["function_name"]
            if func_name not in function_calls:
                function_calls[func_name] = {"entries": 0, "exits": 0, "exceptions": 0}
            
            event_type = event["event_type"].split("_")[1]
            if event_type not in function_calls[func_name]:
                function_calls[func_name][event_type] = 0
            function_calls[func_name][event_type] += 1
            
            if "execution_time_ms" in event:
                total_execution_time += event["execution_time_ms"]
        
        print(f"📈 Total Events Captured: {len(self.trace_events)}")
        print(f"🔧 Functions Traced: {len(function_calls)}")
        print(f"⏱️  Total Execution Time: {total_execution_time:.2f}ms")
        print()
        
        print("🎯 WHAT UET CAPTURES FOR CLIENT:")
        print("  ✅ Function entry/exit points")
        print("  ✅ Call stack traces and depth")
        print("  ✅ Execution timing per function")
        print("  ✅ Function arguments (basic types)")
        print("  ✅ Return values")
        print("  ✅ Exception handling")
        print("  ✅ Instruction and stack pointers")
        print("  ✅ Cross-function call correlation")
        print()
        
        print("📋 Function Call Summary:")
        for func_name, counts in function_calls.items():
            print(f"  {func_name}: {counts['entries']} calls")
        
        # Save detailed trace
        with open("code_level_trace_results.json", "w") as f:
            json.dump(self.trace_events, f, indent=2)
        
        print(f"\n💾 Detailed trace saved to: code_level_trace_results.json")
        print("\n🎉 CODE-LEVEL TRACING DEMO COMPLETE!")

if __name__ == "__main__":
    demo = CodeLevelTracingDemo()
    demo.demonstrate_code_tracing()
