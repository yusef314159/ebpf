# Feedback from client, 12 July 2025 6:00PM
A 4. What needs refinement or extra work?

Area 							Status				Suggestions

1. DWARF unwinding				(x) Stub only		Offload to user space; drop in-kernel parser
2. Instruction/Stack pointer	(x) Zeroed			Extract from ctx or arch-specific methods
3. Frame pointer unwinding		(+) (simplified)	Could improve using inline asm per arch
4. Mixed stacks					(!) Partial			Real mixed stacks require frame merging
5. Correlation ID				(!) Stub			Implement real request context tracking
6. Symbol names 				(!) Cached			Actual symbolization needs user-space tools like perf-map-agent , libbfd,or libdw

