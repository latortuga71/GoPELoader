package peloader

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/latortuga71/GoPeLoader/pkg/winapi"
	"golang.org/x/sys/windows"
)

// Section characteristics flags.
const (
	IMAGE_SCN_CNT_CODE               = 0x00000020
	IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
	IMAGE_SCN_LNK_OTHER              = 0x00000100
	IMAGE_SCN_LNK_INFO               = 0x00000200
	IMAGE_SCN_LNK_REMOVE             = 0x00000800
	IMAGE_SCN_LNK_COMDAT             = 0x00001000
	IMAGE_SCN_GPREL                  = 0x00008000
	IMAGE_SCN_MEM_PURGEABLE          = 0x00020000
	IMAGE_SCN_MEM_16BIT              = 0x00020000
	IMAGE_SCN_MEM_LOCKED             = 0x00040000
	IMAGE_SCN_MEM_PRELOAD            = 0x00080000
	IMAGE_SCN_ALIGN_1BYTES           = 0x00100000
	IMAGE_SCN_ALIGN_2BYTES           = 0x00200000
	IMAGE_SCN_ALIGN_4BYTES           = 0x00300000
	IMAGE_SCN_ALIGN_8BYTES           = 0x00400000
	IMAGE_SCN_ALIGN_16BYTES          = 0x00500000
	IMAGE_SCN_ALIGN_32BYTES          = 0x00600000
	IMAGE_SCN_ALIGN_64BYTES          = 0x00700000
	IMAGE_SCN_ALIGN_128BYTES         = 0x00800000
	IMAGE_SCN_ALIGN_256BYTES         = 0x00900000
	IMAGE_SCN_ALIGN_512BYTES         = 0x00A00000
	IMAGE_SCN_ALIGN_1024BYTES        = 0x00B00000
	IMAGE_SCN_ALIGN_2048BYTES        = 0x00C00000
	IMAGE_SCN_ALIGN_4096BYTES        = 0x00D00000
	IMAGE_SCN_ALIGN_8192BYTES        = 0x00E00000
	IMAGE_SCN_LNK_NRELOC_OVFL        = 0x01000000
	IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
	IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
	IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000
	IMAGE_SCN_MEM_SHARED             = 0x10000000
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000
	IMAGE_SCN_MEM_READ               = 0x40000000
	IMAGE_SCN_MEM_WRITE              = 0x80000000
)
const (
	IMAGE_DOS_SIGNATURE = 0x5A4D
	IMAGE_NT_SIGNATURE  = 0x00004550 // PE00
)

var (
	PAGE_SIZE = os.Getpagesize()
)

type MemorySection struct {
	Name           string
	PeSection      pe.Section
	MemoryAddress  uintptr
	AlignedAddress uintptr
	Size           uint32
}

type ProtFlags [2][2][2]uint32

var ProtectionFlags = ProtFlags{
	{
		// not executable
		{winapi.PAGE_NOACCESS, winapi.PAGE_WRITECOPY},
		{winapi.PAGE_READONLY, winapi.PAGE_READWRITE},
	},
	{
		// executable
		{winapi.PAGE_EXECUTE, winapi.PAGE_EXECUTE_WRITECOPY},
		{winapi.PAGE_EXECUTE_READ, winapi.PAGE_EXECUTE_READWRITE},
	},
}

const (
	IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
	IMAGE_ORDINAL_FLAG32 = 0x80000000
)

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

const (
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
)

const (
	IMAGE_REL_BASED_ABSOLUTE = 0
	IMAGE_REL_BASED_HIGHLOW  = 3
	IMAGE_REL_BASED_DIR64    = 10
)

type BASE_RELOCATION_ENTRY struct {
	Offset uint8 //: 12;
	Type   uint8 //: 4;
}

type IMAGE_IMPORT_BY_NAME struct {
	Hint [2]byte
	Name [10]byte
}

// ImageDOSHeader represents the DOS stub of a PE.
type ImageDOSHeader struct {
	// Magic number.
	Magic uint16

	// Bytes on last page of file.
	BytesOnLastPageOfFile uint16

	// Pages in file.
	PagesInFile uint16

	// Relocations.
	Relocations uint16

	// Size of header in paragraphs.
	SizeOfHeader uint16

	// Minimum extra paragraphs needed.
	MinExtraParagraphsNeeded uint16

	// Maximum extra paragraphs needed.
	MaxExtraParagraphsNeeded uint16

	// Initial (relative) SS value.
	InitialSS uint16

	// Initial SP value.
	InitialSP uint16

	// Checksum.
	Checksum uint16

	// Initial IP value.
	InitialIP uint16

	// Initial (relative) CS value.
	InitialCS uint16

	// File address of relocation table.
	AddressOfRelocationTable uint16

	// Overlay number.
	OverlayNumber uint16

	// Reserved words.
	ReservedWords1 [4]uint16

	// OEM identifier.
	OEMIdentifier uint16

	// OEM information.
	OEMInformation uint16

	// Reserved words.
	ReservedWords2 [10]uint16

	// File address of new exe header (Elfanew).
	AddressOfNewEXEHeader uint32
}

func ImageOrdinal64(ordinal uint64) uint64 {
	return ordinal & 0xffff
}

func ImageOrdinal32(ordinal uint32) uint32 {
	return ordinal & 0xffff
}

func ImageSnapByOridinal32(ordinal uint32) bool {
	return ((ordinal & IMAGE_ORDINAL_FLAG32) != 0)
}

func ImageSnapByOridinal64(ordinal uint64) bool {
	return ((ordinal & IMAGE_ORDINAL_FLAG64) != 0)
}

func OffsetPointer(start uintptr, offset uintptr) uintptr {
	return start + offset
}

///https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c
func ReadAsciiFromMemory(startPtr uintptr, memoryStart uintptr) []byte {
	var asciiArray []byte
	for x := 0; ; x++ {
		byteValue := *(*byte)(unsafe.Pointer(uintptr(startPtr+uintptr(x)) + memoryStart))
		if byteValue == 0 {
			break
		}
		asciiArray = append(asciiArray, byteValue)
	}
	return asciiArray
}

func ReadAsciiFromMemoryNoBase(startPtr uintptr) []byte {
	var asciiArray []byte
	for x := 0; ; x++ {
		byteValue := *(*byte)(unsafe.Pointer(uintptr(startPtr + uintptr(x))))
		if byteValue == 0 {
			break
		}
		asciiArray = append(asciiArray, byteValue)
	}
	return asciiArray
}

func AlignAddressDown(address, alignment uintptr) uintptr {
	return address & ^(alignment - 1)
}

func AlignValueUp(value, alignment uint32) uint32 {
	not := ^(alignment - 1)
	return (value + alignment - 1) & not
}

func CheckSize(size uint32, expectedSz uint32) bool {
	if size < expectedSz {
		return false
	}
	return true
}

func GetRealSectionSize(peHeader *pe.OptionalHeader64, section *pe.Section) uint32 {
	if section.Size != 0 {
		return section.Size
	}
	if section.Characteristics&IMAGE_SCN_CNT_INITIALIZED_DATA > 0 {
		return peHeader.SizeOfInitializedData
	}
	if section.Characteristics&IMAGE_SCN_CNT_UNINITIALIZED_DATA > 0 {
		return peHeader.SizeOfUninitializedData
	}
	return 0
}

func CreateImportAddressTable(peHeader *pe.OptionalHeader64, memoryStart uintptr) error {
	dataDirectory := peHeader.DataDirectory
	if len(dataDirectory) == 0 {
		return errors.New("[+] Data Directory Empty")
	}
	directory := dataDirectory[1]
	importDirectorySize := unsafe.Sizeof(pe.ImportDirectory{})
	importDescriptionPtr := unsafe.Pointer(memoryStart + uintptr(directory.VirtualAddress))
	for winapi.IsBadReadPtr(uintptr(importDescriptionPtr), importDirectorySize) && (*pe.ImportDirectory)(importDescriptionPtr).Name != 0 {
		importDescriptor := (*pe.ImportDirectory)(importDescriptionPtr)
		namePtr := importDescriptor.Name
		nameAscii := ReadAsciiFromMemory(uintptr(namePtr), memoryStart)
		libraryHandle, err := windows.LoadLibrary(string(nameAscii))
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to load required libary %v", err))
		}
		var thunkRef unsafe.Pointer
		var funcRef unsafe.Pointer
		if importDescriptor.OriginalFirstThunk == 0 {
			thunkRef = unsafe.Pointer(uintptr(importDescriptor.OriginalFirstThunk) + memoryStart)
			funcRef = unsafe.Pointer(uintptr(importDescriptor.FirstThunk) + memoryStart)
		} else {
			thunkRef = unsafe.Pointer(uintptr(importDescriptor.FirstThunk) + memoryStart)
			funcRef = unsafe.Pointer(uintptr(importDescriptor.FirstThunk) + memoryStart)
		}
		for {
			if *(*uintptr)(thunkRef) == 0 {
				break
			}
			if ImageSnapByOridinal64(*(*uint64)(thunkRef)) {
				funcPtr, err := windows.GetProcAddressByOrdinal(libraryHandle, uintptr(ImageOrdinal64(*(*uint64)(thunkRef))))
				if err != nil {
					return errors.New(fmt.Sprintf("Failed to get proc address by ordinal %v", err))
				}
				*(*uintptr)(funcRef) = funcPtr
			} else {
				thunkData := memoryStart + *(*uintptr)(thunkRef)
				funcName := string(ReadAsciiFromMemoryNoBase(thunkData + 2))
				funcPtr, err := windows.GetProcAddress(libraryHandle, funcName)
				if err != nil {
					return errors.New(fmt.Sprintf("Failed to get proc addess by name %v", err))
				}
				*(*uintptr)(funcRef) = uintptr(unsafe.Pointer(funcPtr))
			}
			if *(*uint64)(funcRef) == 0 {
				return errors.New("Failed to get function pointer")
			}
			sizeOfPtr := unsafe.Sizeof(uintptr(thunkRef))
			thunkRef = unsafe.Pointer(uintptr(thunkRef) + sizeOfPtr)
			funcRef = unsafe.Pointer(uintptr(funcRef) + sizeOfPtr)
		}
		importDescriptionPtr = unsafe.Pointer((uintptr(importDescriptionPtr) + unsafe.Sizeof(pe.ImportDirectory{})/2))
	}
	return nil
}

func FinalizeSections(dll *pe.File, peHeaderOptionalHeader64 *pe.OptionalHeader64, baseAddress uintptr, memorySections []MemorySection) error {
	for _, s := range memorySections {
		s.AlignedAddress = AlignAddressDown(s.MemoryAddress, uintptr(PAGE_SIZE))
		s.Size = GetRealSectionSize(peHeaderOptionalHeader64, &s.PeSection)
	}
	for _, s := range memorySections {
		if s.Size == 0 {
			continue
		}
		if s.PeSection.Characteristics&IMAGE_SCN_MEM_DISCARDABLE != 0 {
			err := windows.VirtualFree(s.MemoryAddress, uintptr(s.Size), windows.MEM_DECOMMIT)
			if err != nil {
				return errors.New(fmt.Sprintf("Failed to free discarded section %v", err))
			}
			continue
		}
		//var protFlags uint32
		executable := (s.PeSection.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
		readable := (s.PeSection.Characteristics & IMAGE_SCN_MEM_READ) != 0
		writable := (s.PeSection.Characteristics & IMAGE_SCN_MEM_WRITE) != 0
		var e, r, w uint32
		if executable {
			e = 1
		}
		if readable {
			r = 1
		}
		if writable {
			w = 1
		}
		e, r, w = 1, 1, 1
		protFlags := ProtectionFlags[e][r][w]
		var oldFlags uint32
		if s.PeSection.Characteristics&IMAGE_SCN_MEM_NOT_CACHED != 0 {
			protFlags |= winapi.PAGE_NOCACHE
		}
		err := windows.VirtualProtect(s.MemoryAddress, uintptr(s.Size), protFlags, &oldFlags)
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to change memory protections for section %s %v", s.Name, err))
		}
	}
	return nil
}

func CopySectionsToMemory(dll *pe.File, peHeaderOptionalHeader64 *pe.OptionalHeader64, baseAddress uintptr) ([]MemorySection, error) {
	memSections := make([]MemorySection, 0)
	for _, section := range dll.Sections {
		memSection := MemorySection{}
		memSection.Name = section.Name
		data, err := section.Data()
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Failed to get section data %v", err))
		}
		if len(data) == 0 {
			sectionSz := peHeaderOptionalHeader64.SectionAlignment
			if sectionSz > 0 {
				dest, _ := winapi.VirtualAlloc(baseAddress+uintptr(section.VirtualAddress), sectionSz, winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
				if dest == 0 {
					return nil, errors.New(fmt.Sprintf("Failed to allocate memory for section, %v", err))
				}
				memSection.MemoryAddress = dest
				memSection.PeSection = *section
				memSection.Size = sectionSz
				memSections = append(memSections, memSection)
			}
			continue
		}
		dest, _ := winapi.VirtualAlloc(baseAddress+uintptr(section.VirtualAddress), section.Size, winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
		if dest == 0 {
			return nil, errors.New(fmt.Sprintf("Failed to allocate memory for section, %v", err))
		}
		dest = baseAddress + uintptr(section.VirtualAddress)
		var wrote uint32
		result, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), dest, uintptr(unsafe.Pointer(&data[0])), section.Size, &wrote)
		if !result {
			return nil, errors.New(fmt.Sprintf("Failed to write section to memory%v", err))
		}
		memSection.MemoryAddress = dest
		memSection.Size = section.Size
		memSection.PeSection = *section
		memSections = append(memSections, memSection)
	}
	return memSections, nil
}

func BaseRelocate(addressDiff uint64, baseAddress uintptr, peHeader pe.OptionalHeader64) error {
	dataDirectory := peHeader.DataDirectory
	if len(dataDirectory) == 0 {
		return errors.New("Data Directory Empty")
	}
	directory := dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	baseRelocDirectoryPtr := unsafe.Pointer(baseAddress + uintptr(directory.VirtualAddress))
	relocate := (*IMAGE_BASE_RELOCATION)(baseRelocDirectoryPtr)
	if directory.Size == 0 {
		return errors.New("Something went wrong, if directory size is zero we shouldnt need to relocate.")
	}
	for relocate.VirtualAddress > 0 {
		destinationAddress := baseAddress + uintptr(relocate.VirtualAddress)
		relocationInfoPtr := unsafe.Pointer(OffsetPointer(uintptr(unsafe.Pointer(relocate)), unsafe.Sizeof(IMAGE_BASE_RELOCATION{})))
		relocationInfo := (*uint16)(relocationInfoPtr)
		var i uint32
		for i = 0; i < ((relocate.SizeOfBlock - 8) / 2); i++ {
			relocType := *relocationInfo >> 12
			offset := *relocationInfo & 0xfff
			switch relocType {
			case IMAGE_REL_BASED_ABSOLUTE:
				break
			case IMAGE_REL_BASED_HIGHLOW:
				patchAddressHl := (*uint32)(unsafe.Pointer(destinationAddress + uintptr(offset)))
				*patchAddressHl += uint32(addressDiff)
				break
			case IMAGE_REL_BASED_DIR64:
				patchAddress64 := (*uint64)(unsafe.Pointer(destinationAddress + uintptr(offset)))
				*patchAddress64 += uint64(addressDiff)
				break
			default:
				break
			}
			relocationInfo = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(relocationInfo)) + 2))
		}
		if relocate.VirtualAddress < 1 {
			break
		}
		relocate = (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(uintptr(unsafe.Pointer(relocate)) + uintptr(relocate.SizeOfBlock))) //32

	}
	return nil
}

type PeType int

const (
	Dll PeType = iota
	Exe
)

type RawPe struct {
	peType           PeType
	rawData          []byte
	peStruct         *pe.File
	peHeaders        *pe.OptionalHeader64
	alignedImageSize uint32
	removeHeader     bool
	// other stuff here in the future like exports
	// delete header flags etcs
}

func NewRawPE(peT PeType, removeDOSHeaders bool, data []byte) *RawPe {
	return &RawPe{
		peType:   peT,
		rawData:  data,
		peStruct: nil,
	}
}

func (r *RawPe) LoadPEFromMemory() error {
	buffer := bytes.NewBuffer(r.rawData)
	peFile, err := pe.NewFile(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		log.Fatalf("Failed to load pe file %v", err)
	}
	r.peStruct = peFile
	if !DosHeaderCheck(r.rawData) {
		return errors.New("Dos header check failed.")
	}
	// only support 64 bit.
	r.peHeaders = r.peStruct.OptionalHeader.(*pe.OptionalHeader64)
	if (r.peHeaders.SectionAlignment & 1) != 0 {
		return (errors.New("Unknown Alignment error."))
	}
	//alignedImgSize := AlignValueUp(r.peHeaders.SizeOfImage, uint32(PAGE_SIZE))
	r.alignedImageSize = AlignValueUp(r.peHeaders.SizeOfImage, uint32(PAGE_SIZE))
	if r.alignedImageSize != AlignValueUp(r.peStruct.Sections[r.peStruct.NumberOfSections-1].VirtualAddress+r.peStruct.Sections[r.peStruct.NumberOfSections-1].Size, uint32(PAGE_SIZE)) {
		return errors.New("Failed to align image.")
	}
	// allocating memory chunk for image.
	var baseAddressOfMemoryAlloc uintptr
	prefBaseAddr := uintptr(r.peHeaders.ImageBase)
	baseAddressOfMemoryAlloc, err = winapi.VirtualAlloc(uintptr(r.peHeaders.ImageBase), r.alignedImageSize, winapi.MEM_RESERVE|winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
	if baseAddressOfMemoryAlloc == 0 {
		log.Println("Failed to allocate at preffered base address...Attempting to allocate anywhere else.")
		baseAddressOfMemoryAlloc, err = winapi.VirtualAlloc(uintptr(0), r.alignedImageSize, winapi.MEM_RESERVE|winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to allocate memory at random location %v", err))
		}
	}
	// base memory chunk allocated.
	peHead, err := winapi.VirtualAlloc(baseAddressOfMemoryAlloc, r.peHeaders.SizeOfHeaders, winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
	if peHead == 0 {
		return errors.New(fmt.Sprintf("Failed to commit memory for pe headers %v", err))
	}
	// committed memory for pe headers.
	var wrote uint32
	if ok, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), peHead, uintptr(unsafe.Pointer(&r.rawData[0])), r.peHeaders.SizeOfHeaders, &wrote); !ok {
		return errors.New(fmt.Sprintf("Failed to write pe headers to memory %v", err))
	}
	// wrote pe headers to memory
	r.peHeaders.ImageBase = uint64(baseAddressOfMemoryAlloc)
	// updating pe header to reflect base address (just incase it changed)
	// now you commit sections in the memory block and copy the sections to the proper locations
	memSections, err := CopySectionsToMemory(r.peStruct, r.peHeaders, baseAddressOfMemoryAlloc)
	if err != nil {
		return err
	}
	//base relocations if preferred base address is doesnt match where we allocated memory
	baseAddressDiff := uint64(baseAddressOfMemoryAlloc - prefBaseAddr)
	if baseAddressDiff != 0 {
		if err := BaseRelocate(baseAddressDiff, baseAddressOfMemoryAlloc, *r.peHeaders); err != nil {
			return errors.New(fmt.Sprintf("Failed to base relocate %v", err))
		}
	}
	err = CreateImportAddressTable(r.peHeaders, baseAddressOfMemoryAlloc)
	if err != nil {
		return err
	}
	err = FinalizeSections(r.peStruct, r.peHeaders, baseAddressOfMemoryAlloc, memSections)
	if err != nil {
		return err
	}
	//ExecuteTLSCallbacks TODO
	entryPointPtr := unsafe.Pointer(uintptr(r.peHeaders.AddressOfEntryPoint) + baseAddressOfMemoryAlloc)
	runtime.LockOSThread()
	switch r.peType {
	case Dll:
		// calling dll entry point
		syscall.Syscall(uintptr(entryPointPtr), 3, baseAddressOfMemoryAlloc, 1, 0)
		break
	case Exe:
		// calling exe entry point no args
		// we are not patching exitThread so when exes exit they will crash process
		// exe needs to call exitThread before exiting and needs to be run in seperate thread
		hThread, err := winapi.CreateThread(0, 0, uintptr(entryPointPtr), 0, 0, nil)
		if err != nil {
			log.Fatal(err)
		}
		windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
		break
	default:
		return errors.New("Provided Invalid PE Type")
	}
	runtime.UnlockOSThread()
	return nil
}

func (r *RawPe) FreePeFromMemory() error {
	err := windows.VirtualFree(uintptr(r.peHeaders.ImageBase), uintptr(r.alignedImageSize), winapi.MEM_DECOMMIT)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to free PE memory allocation %v", err))
	}
	return err
}

func DosHeaderCheck(rawPeFileData []byte) bool {
	dosHeaderStruct := (*ImageDOSHeader)(unsafe.Pointer(&rawPeFileData[0]))
	if dosHeaderStruct.Magic != IMAGE_DOS_SIGNATURE {
		return false
	}
	return true
}
