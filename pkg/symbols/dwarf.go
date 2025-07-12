package symbols

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// DWARFManager handles DWARF debug information for symbol resolution
type DWARFManager struct {
	cache       map[string]*DWARFInfo
	binaryCache map[string]*elf.File
	mutex       sync.RWMutex
	config      *DWARFConfig
}

// DWARFInfo represents DWARF debug information for a symbol
type DWARFInfo struct {
	Symbol       *SymbolInfo       `json:"symbol"`
	SourceFile   string            `json:"source_file"`
	LineNumber   int               `json:"line_number"`
	Directory    string            `json:"directory"`
	CompileUnit  string            `json:"compile_unit"`
	InlineInfo   []InlineFrame     `json:"inline_info,omitempty"`
	Variables    []VariableInfo    `json:"variables,omitempty"`
	CallFrame    *CallFrameInfo    `json:"call_frame,omitempty"`
	Metadata     map[string]string `json:"metadata"`
}

// InlineFrame represents an inlined function frame
type InlineFrame struct {
	Function   string `json:"function"`
	SourceFile string `json:"source_file"`
	LineNumber int    `json:"line_number"`
	CallSite   uint64 `json:"call_site"`
}

// VariableInfo represents variable debug information
type VariableInfo struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Location     string `json:"location"`
	Scope        string `json:"scope"`
	FrameOffset  int64  `json:"frame_offset,omitempty"`
	RegisterName string `json:"register_name,omitempty"`
}

// CallFrameInfo represents call frame information
type CallFrameInfo struct {
	FrameBase       string            `json:"frame_base"`
	CanonicalFrame  uint64            `json:"canonical_frame"`
	ReturnAddress   uint64            `json:"return_address"`
	StackPointer    uint64            `json:"stack_pointer"`
	RegisterRules   map[string]string `json:"register_rules"`
}

// DWARFConfig holds configuration for DWARF processing
type DWARFConfig struct {
	EnableInlineInfo    bool     `json:"enable_inline_info" yaml:"enable_inline_info"`
	EnableVariableInfo  bool     `json:"enable_variable_info" yaml:"enable_variable_info"`
	EnableCallFrame     bool     `json:"enable_call_frame" yaml:"enable_call_frame"`
	MaxInlineDepth      int      `json:"max_inline_depth" yaml:"max_inline_depth"`
	CacheSize           int      `json:"cache_size" yaml:"cache_size"`
	DebugInfoPaths      []string `json:"debug_info_paths" yaml:"debug_info_paths"`
	EnableSourceLookup  bool     `json:"enable_source_lookup" yaml:"enable_source_lookup"`
	SourcePaths         []string `json:"source_paths" yaml:"source_paths"`
}

// DefaultDWARFConfig returns default DWARF configuration
func DefaultDWARFConfig() *DWARFConfig {
	return &DWARFConfig{
		EnableInlineInfo:   true,
		EnableVariableInfo: true,
		EnableCallFrame:    true,
		MaxInlineDepth:     10,
		CacheSize:          5000,
		DebugInfoPaths: []string{
			"/usr/lib/debug",
			"/usr/lib/debug/.build-id",
			"/var/cache/debuginfo",
		},
		EnableSourceLookup: true,
		SourcePaths: []string{
			"/usr/src",
			"/usr/src/debug",
			"/usr/src/kernels",
		},
	}
}

// NewDWARFManager creates a new DWARF manager
func NewDWARFManager(config *DWARFConfig) *DWARFManager {
	return &DWARFManager{
		cache:       make(map[string]*DWARFInfo),
		binaryCache: make(map[string]*elf.File),
		config:      config,
	}
}

// ResolveSymbolWithDWARF resolves a symbol with full DWARF information
func (dm *DWARFManager) ResolveSymbolWithDWARF(binaryPath, symbolName string, address uint64) (*DWARFInfo, error) {
	cacheKey := fmt.Sprintf("%s:%s:0x%x", binaryPath, symbolName, address)
	
	dm.mutex.RLock()
	if cached, exists := dm.cache[cacheKey]; exists {
		dm.mutex.RUnlock()
		return cached, nil
	}
	dm.mutex.RUnlock()

	// Open the binary file
	elfFile, err := dm.getELFFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open binary %s: %w", binaryPath, err)
	}

	// Get DWARF data
	dwarfData, err := elfFile.DWARF()
	if err != nil {
		return nil, fmt.Errorf("failed to get DWARF data from %s: %w", binaryPath, err)
	}

	// Create DWARF info
	dwarfInfo := &DWARFInfo{
		Metadata: make(map[string]string),
	}

	// Find the compilation unit containing this address
	reader := dwarfData.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			break
		}
		if entry == nil {
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			if err := dm.processCompileUnit(dwarfInfo, reader, entry, address, symbolName); err == nil {
				break
			}
		}
	}

	// Look up source file and line information
	if dm.config.EnableSourceLookup {
		dm.resolveSourceInfo(dwarfInfo, dwarfData, address)
	}

	// Get inline information
	if dm.config.EnableInlineInfo {
		dm.resolveInlineInfo(dwarfInfo, dwarfData, address)
	}

	// Get call frame information
	if dm.config.EnableCallFrame {
		dm.resolveCallFrameInfo(dwarfInfo, dwarfData, address)
	}

	// Cache the result
	dm.mutex.Lock()
	dm.cache[cacheKey] = dwarfInfo
	dm.mutex.Unlock()

	return dwarfInfo, nil
}

// getELFFile gets an ELF file from cache or opens it
func (dm *DWARFManager) getELFFile(binaryPath string) (*elf.File, error) {
	dm.mutex.RLock()
	if cached, exists := dm.binaryCache[binaryPath]; exists {
		dm.mutex.RUnlock()
		return cached, nil
	}
	dm.mutex.RUnlock()

	elfFile, err := elf.Open(binaryPath)
	if err != nil {
		return nil, err
	}

	dm.mutex.Lock()
	dm.binaryCache[binaryPath] = elfFile
	dm.mutex.Unlock()

	return elfFile, nil
}

// processCompileUnit processes a DWARF compilation unit
func (dm *DWARFManager) processCompileUnit(dwarfInfo *DWARFInfo, reader *dwarf.Reader, entry *dwarf.Entry, address uint64, symbolName string) error {
	// Get compilation unit information
	if name, ok := entry.Val(dwarf.AttrName).(string); ok {
		dwarfInfo.CompileUnit = name
	}
	
	if dir, ok := entry.Val(dwarf.AttrCompDir).(string); ok {
		dwarfInfo.Directory = dir
	}

	// Process child entries
	for {
		entry, err := reader.Next()
		if err != nil {
			break
		}
		if entry == nil {
			break
		}

		switch entry.Tag {
		case dwarf.TagSubprogram:
			if dm.processSubprogram(dwarfInfo, reader, entry, address, symbolName) {
				return nil
			}
		case dwarf.TagVariable:
			if dm.config.EnableVariableInfo {
				dm.processVariable(dwarfInfo, entry)
			}
		}

		if entry.Children {
			reader.SkipChildren()
		}
	}

	return fmt.Errorf("symbol not found in compilation unit")
}

// processSubprogram processes a DWARF subprogram (function)
func (dm *DWARFManager) processSubprogram(dwarfInfo *DWARFInfo, reader *dwarf.Reader, entry *dwarf.Entry, address uint64, symbolName string) bool {
	// Check if this is the function we're looking for
	name, hasName := entry.Val(dwarf.AttrName).(string)
	if !hasName {
		return false
	}

	// Check if name matches (handle mangled names)
	if name != symbolName && !strings.Contains(name, symbolName) {
		return false
	}

	// Check if address is within function range
	lowPC, hasLowPC := entry.Val(dwarf.AttrLowpc).(uint64)
	highPC, hasHighPC := entry.Val(dwarf.AttrHighpc).(uint64)
	
	if hasLowPC && hasHighPC {
		if address < lowPC || address >= lowPC+highPC {
			return false
		}
	}

	// Create symbol info
	dwarfInfo.Symbol = &SymbolInfo{
		Name:     name,
		Address:  lowPC,
		Size:     highPC,
		Type:     "function",
		Module:   filepath.Base(dwarfInfo.CompileUnit),
		Metadata: make(map[string]string),
	}

	// Process function parameters and local variables
	if dm.config.EnableVariableInfo {
		dm.processFunctionVariables(dwarfInfo, reader, entry)
	}

	return true
}

// processVariable processes a DWARF variable entry
func (dm *DWARFManager) processVariable(dwarfInfo *DWARFInfo, entry *dwarf.Entry) {
	name, hasName := entry.Val(dwarf.AttrName).(string)
	if !hasName {
		return
	}

	variable := VariableInfo{
		Name:  name,
		Scope: "global",
	}

	// Get type information
	if typeRef, ok := entry.Val(dwarf.AttrType).(dwarf.Offset); ok {
		variable.Type = fmt.Sprintf("type_offset_0x%x", typeRef)
	}

	// Get location information
	if location, ok := entry.Val(dwarf.AttrLocation).([]byte); ok {
		variable.Location = fmt.Sprintf("location_expr_%x", location)
	}

	dwarfInfo.Variables = append(dwarfInfo.Variables, variable)
}

// processFunctionVariables processes variables within a function
func (dm *DWARFManager) processFunctionVariables(dwarfInfo *DWARFInfo, reader *dwarf.Reader, entry *dwarf.Entry) {
	if !entry.Children {
		return
	}

	for {
		childEntry, err := reader.Next()
		if err != nil || childEntry == nil {
			break
		}

		if childEntry.Tag == 0 { // End of children
			break
		}

		switch childEntry.Tag {
		case dwarf.TagFormalParameter:
			dm.processFormalParameter(dwarfInfo, childEntry)
		case dwarf.TagVariable:
			dm.processLocalVariable(dwarfInfo, childEntry)
		}

		if childEntry.Children {
			reader.SkipChildren()
		}
	}
}

// processFormalParameter processes a function parameter
func (dm *DWARFManager) processFormalParameter(dwarfInfo *DWARFInfo, entry *dwarf.Entry) {
	name, hasName := entry.Val(dwarf.AttrName).(string)
	if !hasName {
		name = "unnamed_param"
	}

	param := ParameterInfo{
		Name: name,
	}

	// Get type information
	if typeRef, ok := entry.Val(dwarf.AttrType).(dwarf.Offset); ok {
		param.Type = fmt.Sprintf("type_offset_0x%x", typeRef)
	}

	// Get location information (register or stack offset)
	if location, ok := entry.Val(dwarf.AttrLocation).([]byte); ok {
		if len(location) > 0 {
			// Simple location parsing - in practice, this would be more complex
			if location[0] == 0x91 { // DW_OP_fbreg
				if len(location) > 1 {
					param.Offset = uint32(int8(location[1])) // Signed offset
				}
			}
		}
	}

	if dwarfInfo.Symbol != nil {
		dwarfInfo.Symbol.Parameters = append(dwarfInfo.Symbol.Parameters, param)
	}
}

// processLocalVariable processes a local variable
func (dm *DWARFManager) processLocalVariable(dwarfInfo *DWARFInfo, entry *dwarf.Entry) {
	name, hasName := entry.Val(dwarf.AttrName).(string)
	if !hasName {
		return
	}

	variable := VariableInfo{
		Name:  name,
		Scope: "local",
	}

	// Get type information
	if typeRef, ok := entry.Val(dwarf.AttrType).(dwarf.Offset); ok {
		variable.Type = fmt.Sprintf("type_offset_0x%x", typeRef)
	}

	// Get location information
	if location, ok := entry.Val(dwarf.AttrLocation).([]byte); ok {
		variable.Location = fmt.Sprintf("location_expr_%x", location)
		
		// Parse simple frame-relative locations
		if len(location) > 1 && location[0] == 0x91 { // DW_OP_fbreg
			variable.FrameOffset = int64(int8(location[1]))
		}
	}

	dwarfInfo.Variables = append(dwarfInfo.Variables, variable)
}

// resolveSourceInfo resolves source file and line information
func (dm *DWARFManager) resolveSourceInfo(dwarfInfo *DWARFInfo, dwarfData *dwarf.Data, address uint64) {
	lineReader, err := dwarfData.LineReader(nil)
	if err != nil {
		return
	}

	var lineEntry dwarf.LineEntry
	for {
		err := lineReader.Next(&lineEntry)
		if err != nil {
			break
		}

		if lineEntry.Address <= address {
			dwarfInfo.SourceFile = lineEntry.File.Name
			dwarfInfo.LineNumber = lineEntry.Line
			break
		}
	}
}

// resolveInlineInfo resolves inline function information
func (dm *DWARFManager) resolveInlineInfo(dwarfInfo *DWARFInfo, dwarfData *dwarf.Data, address uint64) {
	// This is a simplified implementation
	// In practice, you would parse DW_TAG_inlined_subroutine entries
	// and build a complete inline call stack
	
	dwarfInfo.Metadata["inline_support"] = "basic"
}

// resolveCallFrameInfo resolves call frame information
func (dm *DWARFManager) resolveCallFrameInfo(dwarfInfo *DWARFInfo, dwarfData *dwarf.Data, address uint64) {
	// This would parse .debug_frame or .eh_frame sections
	// to provide call frame information for stack unwinding
	
	dwarfInfo.CallFrame = &CallFrameInfo{
		FrameBase:      "rbp",
		RegisterRules:  make(map[string]string),
	}
	
	dwarfInfo.CallFrame.RegisterRules["rbp"] = "cfa-16"
	dwarfInfo.CallFrame.RegisterRules["rip"] = "cfa-8"
}

// GetSourceLine gets the source line for a given address
func (dm *DWARFManager) GetSourceLine(binaryPath string, address uint64) (string, int, error) {
	elfFile, err := dm.getELFFile(binaryPath)
	if err != nil {
		return "", 0, err
	}

	dwarfData, err := elfFile.DWARF()
	if err != nil {
		return "", 0, err
	}

	lineReader, err := dwarfData.LineReader(nil)
	if err != nil {
		return "", 0, err
	}

	var lineEntry dwarf.LineEntry
	for {
		err := lineReader.Next(&lineEntry)
		if err != nil {
			break
		}

		if lineEntry.Address <= address {
			return lineEntry.File.Name, lineEntry.Line, nil
		}
	}

	return "", 0, fmt.Errorf("no source line found for address 0x%x", address)
}

// Close cleans up DWARF resources
func (dm *DWARFManager) Close() error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	// Close all cached ELF files
	for _, elfFile := range dm.binaryCache {
		elfFile.Close()
	}

	dm.cache = nil
	dm.binaryCache = nil

	return nil
}

// GetCacheStats returns cache statistics
func (dm *DWARFManager) GetCacheStats() map[string]interface{} {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	return map[string]interface{}{
		"dwarf_cache_size":  len(dm.cache),
		"binary_cache_size": len(dm.binaryCache),
		"inline_enabled":    dm.config.EnableInlineInfo,
		"variables_enabled": dm.config.EnableVariableInfo,
		"callframe_enabled": dm.config.EnableCallFrame,
	}
}
