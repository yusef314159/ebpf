package symbols

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// BTFManager handles BTF (BPF Type Format) information for symbol resolution
type BTFManager struct {
	spec       *btf.Spec
	kernelSpec *btf.Spec
	cache      map[string]*SymbolInfo
	mutex      sync.RWMutex
}

// SymbolInfo represents information about a symbol
type SymbolInfo struct {
	Name       string            `json:"name"`
	Address    uint64            `json:"address"`
	Size       uint64            `json:"size"`
	Type       string            `json:"type"`
	Module     string            `json:"module"`
	Offset     uint64            `json:"offset"`
	Parameters []ParameterInfo   `json:"parameters,omitempty"`
	ReturnType string            `json:"return_type,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// ParameterInfo represents function parameter information
type ParameterInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Size     uint32 `json:"size"`
	Offset   uint32 `json:"offset"`
	Register string `json:"register,omitempty"`
}

// BTFConfig holds configuration for BTF symbol resolution
type BTFConfig struct {
	KernelBTFPath    string   `json:"kernel_btf_path" yaml:"kernel_btf_path"`
	ModuleBTFPaths   []string `json:"module_btf_paths" yaml:"module_btf_paths"`
	EnableCache      bool     `json:"enable_cache" yaml:"enable_cache"`
	CacheSize        int      `json:"cache_size" yaml:"cache_size"`
	EnableKallsyms   bool     `json:"enable_kallsyms" yaml:"enable_kallsyms"`
	KallsymsPath     string   `json:"kallsyms_path" yaml:"kallsyms_path"`
	EnableModules    bool     `json:"enable_modules" yaml:"enable_modules"`
	ModulesPath      string   `json:"modules_path" yaml:"modules_path"`
	EnableUserspace  bool     `json:"enable_userspace" yaml:"enable_userspace"`
	BinaryPaths      []string `json:"binary_paths" yaml:"binary_paths"`
}

// DefaultBTFConfig returns default BTF configuration
func DefaultBTFConfig() *BTFConfig {
	return &BTFConfig{
		KernelBTFPath:    "/sys/kernel/btf/vmlinux",
		ModuleBTFPaths:   []string{"/sys/kernel/btf"},
		EnableCache:      true,
		CacheSize:        10000,
		EnableKallsyms:   true,
		KallsymsPath:     "/proc/kallsyms",
		EnableModules:    true,
		ModulesPath:      "/proc/modules",
		EnableUserspace:  true,
		BinaryPaths:      []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"},
	}
}

// NewBTFManager creates a new BTF manager
func NewBTFManager(config *BTFConfig) (*BTFManager, error) {
	manager := &BTFManager{
		cache: make(map[string]*SymbolInfo),
	}

	// Load kernel BTF
	if err := manager.loadKernelBTF(config.KernelBTFPath); err != nil {
		return nil, fmt.Errorf("failed to load kernel BTF: %w", err)
	}

	// Initialize cache
	if config.EnableCache {
		manager.cache = make(map[string]*SymbolInfo, config.CacheSize)
	}

	return manager, nil
}

// loadKernelBTF loads kernel BTF information
func (bm *BTFManager) loadKernelBTF(btfPath string) error {
	// Try to load from /sys/kernel/btf/vmlinux first
	if _, err := os.Stat(btfPath); err == nil {
		spec, err := btf.LoadKernelSpec()
		if err != nil {
			return fmt.Errorf("failed to load kernel BTF spec: %w", err)
		}
		bm.kernelSpec = spec
		return nil
	}

	// Fallback to extracting from vmlinux
	return bm.extractBTFFromVmlinux()
}

// extractBTFFromVmlinux extracts BTF from vmlinux binary
func (bm *BTFManager) extractBTFFromVmlinux() error {
	vmlinuxPaths := []string{
		"/boot/vmlinux-" + getKernelVersion(),
		"/usr/lib/debug/boot/vmlinux-" + getKernelVersion(),
		"/usr/lib/debug/lib/modules/" + getKernelVersion() + "/vmlinux",
		"/lib/modules/" + getKernelVersion() + "/build/vmlinux",
	}

	for _, path := range vmlinuxPaths {
		if _, err := os.Stat(path); err == nil {
			spec, err := btf.LoadSpec(path)
			if err != nil {
				continue
			}
			bm.kernelSpec = spec
			return nil
		}
	}

	return fmt.Errorf("could not find vmlinux with BTF information")
}

// ResolveKernelSymbol resolves a kernel symbol using BTF
func (bm *BTFManager) ResolveKernelSymbol(name string) (*SymbolInfo, error) {
	bm.mutex.RLock()
	if cached, exists := bm.cache[name]; exists {
		bm.mutex.RUnlock()
		return cached, nil
	}
	bm.mutex.RUnlock()

	if bm.kernelSpec == nil {
		return nil, fmt.Errorf("kernel BTF not loaded")
	}

	// Look for the symbol in BTF
	var symbolInfo *SymbolInfo
	
	// Iterate through BTF types to find the symbol
	iter := bm.kernelSpec.Iterate()
	for iter.Next() {
		typ := iter.Type
		if typ == nil {
			continue
		}

		// Check if this is a function type
		if fn, ok := typ.(*btf.Func); ok {
			if fn.Name == name {
				symbolInfo = &SymbolInfo{
					Name:     name,
					Type:     "function",
					Module:   "kernel",
					Metadata: make(map[string]string),
				}

				// Get function prototype
				if fnProto, ok := fn.Type.(*btf.FuncProto); ok {
					if fnProto.Return != nil {
						symbolInfo.ReturnType = fmt.Sprintf("%T", fnProto.Return)
					}

					// Extract parameters
					for i, param := range fnProto.Params {
						paramInfo := ParameterInfo{
							Name: param.Name,
							Type: fmt.Sprintf("%T", param.Type),
							Size: 0, // Size not directly available
						}
						symbolInfo.Parameters = append(symbolInfo.Parameters, paramInfo)
						symbolInfo.Metadata[fmt.Sprintf("param_%d", i)] = param.Name
					}
				}
				break
			}
		}

		// Check if this is a variable
		if variable, ok := typ.(*btf.Var); ok {
			if variable.Name == name {
				symbolInfo = &SymbolInfo{
					Name:     name,
					Type:     "variable",
					Module:   "kernel",
					Size:     0, // Size not directly available
					Metadata: make(map[string]string),
				}
				symbolInfo.Metadata["linkage"] = fmt.Sprintf("%v", variable.Linkage)
				break
			}
		}
	}

	if symbolInfo == nil {
		return nil, fmt.Errorf("symbol %s not found in BTF", name)
	}

	// Cache the result
	bm.mutex.Lock()
	bm.cache[name] = symbolInfo
	bm.mutex.Unlock()

	return symbolInfo, nil
}

// ResolveUserspaceSymbol resolves a userspace symbol using DWARF
func (bm *BTFManager) ResolveUserspaceSymbol(binaryPath, symbolName string) (*SymbolInfo, error) {
	cacheKey := fmt.Sprintf("%s:%s", binaryPath, symbolName)
	
	bm.mutex.RLock()
	if cached, exists := bm.cache[cacheKey]; exists {
		bm.mutex.RUnlock()
		return cached, nil
	}
	bm.mutex.RUnlock()

	// Open the binary file
	file, err := elf.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open binary %s: %w", binaryPath, err)
	}
	defer file.Close()

	// Look for the symbol in the symbol table
	symbols, err := file.Symbols()
	if err != nil {
		// Try dynamic symbols if regular symbols fail
		symbols, err = file.DynamicSymbols()
		if err != nil {
			return nil, fmt.Errorf("failed to read symbols from %s: %w", binaryPath, err)
		}
	}

	var symbolInfo *SymbolInfo
	for _, sym := range symbols {
		if sym.Name == symbolName {
			symbolInfo = &SymbolInfo{
				Name:     symbolName,
				Address:  sym.Value,
				Size:     sym.Size,
				Type:     getSymbolType(sym.Info),
				Module:   filepath.Base(binaryPath),
				Metadata: make(map[string]string),
			}
			symbolInfo.Metadata["section"] = getSymbolSection(sym.Section)
			break
		}
	}

	if symbolInfo == nil {
		return nil, fmt.Errorf("symbol %s not found in %s", symbolName, binaryPath)
	}

	// Try to get additional DWARF information
	if dwarfData, err := file.DWARF(); err == nil {
		bm.enrichWithDWARF(symbolInfo, dwarfData)
	}

	// Cache the result
	bm.mutex.Lock()
	bm.cache[cacheKey] = symbolInfo
	bm.mutex.Unlock()

	return symbolInfo, nil
}

// enrichWithDWARF enriches symbol information with DWARF debug data
func (bm *BTFManager) enrichWithDWARF(symbolInfo *SymbolInfo, dwarfData interface{}) {
	// This is a simplified DWARF parsing - in a full implementation,
	// you would parse the DWARF debug information to extract:
	// - Function parameters and their types
	// - Local variables
	// - Source file and line number information
	// - Call frame information
	
	// For now, we'll add basic metadata
	symbolInfo.Metadata["debug_info"] = "available"
	symbolInfo.Metadata["dwarf_version"] = "available"
}

// GetKernelFunctions returns a list of all kernel functions
func (bm *BTFManager) GetKernelFunctions() ([]string, error) {
	if bm.kernelSpec == nil {
		return nil, fmt.Errorf("kernel BTF not loaded")
	}

	var functions []string
	iter := bm.kernelSpec.Iterate()
	for iter.Next() {
		if fn, ok := iter.Type.(*btf.Func); ok {
			functions = append(functions, fn.Name)
		}
	}

	return functions, nil
}

// GetKernelStructs returns a list of all kernel structures
func (bm *BTFManager) GetKernelStructs() ([]string, error) {
	if bm.kernelSpec == nil {
		return nil, fmt.Errorf("kernel BTF not loaded")
	}

	var structs []string
	iter := bm.kernelSpec.Iterate()
	for iter.Next() {
		if st, ok := iter.Type.(*btf.Struct); ok {
			structs = append(structs, st.Name)
		}
	}

	return structs, nil
}

// GetStructLayout returns the layout of a kernel structure
func (bm *BTFManager) GetStructLayout(structName string) (*StructLayout, error) {
	if bm.kernelSpec == nil {
		return nil, fmt.Errorf("kernel BTF not loaded")
	}

	iter := bm.kernelSpec.Iterate()
	for iter.Next() {
		if st, ok := iter.Type.(*btf.Struct); ok && st.Name == structName {
			layout := &StructLayout{
				Name:   structName,
				Size:   uint64(st.Size),
				Fields: make([]FieldInfo, 0, len(st.Members)),
			}

			for _, member := range st.Members {
				field := FieldInfo{
					Name:   member.Name,
					Type:   fmt.Sprintf("%T", member.Type),
					Offset: uint64(member.Offset.Bytes()),
					Size:   0, // Size not directly available
				}
				layout.Fields = append(layout.Fields, field)
			}

			return layout, nil
		}
	}

	return nil, fmt.Errorf("struct %s not found", structName)
}

// StructLayout represents the layout of a structure
type StructLayout struct {
	Name   string      `json:"name"`
	Size   uint64      `json:"size"`
	Fields []FieldInfo `json:"fields"`
}

// FieldInfo represents information about a structure field
type FieldInfo struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset uint64 `json:"offset"`
	Size   uint64 `json:"size"`
}

// Helper functions

func getKernelVersion() string {
	// This would typically read from /proc/version or uname
	// For now, return a placeholder
	return "6.1.0"
}

func getSymbolType(info byte) string {
	switch elf.ST_TYPE(info) {
	case elf.STT_FUNC:
		return "function"
	case elf.STT_OBJECT:
		return "object"
	case elf.STT_NOTYPE:
		return "notype"
	default:
		return "unknown"
	}
}

func getSymbolSection(section elf.SectionIndex) string {
	switch section {
	case elf.SHN_UNDEF:
		return "undefined"
	case elf.SHN_ABS:
		return "absolute"
	case elf.SHN_COMMON:
		return "common"
	default:
		return fmt.Sprintf("section_%d", section)
	}
}

// Close cleans up BTF resources
func (bm *BTFManager) Close() error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()
	
	bm.cache = nil
	bm.spec = nil
	bm.kernelSpec = nil
	
	return nil
}

// GetCacheStats returns cache statistics
func (bm *BTFManager) GetCacheStats() map[string]interface{} {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()
	
	return map[string]interface{}{
		"cache_size":     len(bm.cache),
		"kernel_btf":     bm.kernelSpec != nil,
		"userspace_btf":  bm.spec != nil,
	}
}
