import re
import json
import struct
import string
from collections import namedtuple
import idautils
from ida_kernwin import ask_file
from idc import get_segm_by_sel, selector_by_name, get_segm_end, get_wide_dword, \
                set_cmt, get_func_attr, generate_disasm_line, print_insn_mnem, \
                get_operand_type, get_operand_value, o_reg, o_imm, FUNCATTR_FLAGS, FUNC_LIB, FUNC_THUNK

HashesDict = namedtuple('HashesDict', ('libraries', 'symbols'),  defaults=({},{}))

STRINGS_SECTION = '.text'
VALID_CHARACTERS = [ord(c) for c in string.printable]
DWORD_SIZE = 4
REGISTER_REGEX = "e[abcds][xi]"
MOV_LDR_REGEX       = re.compile(f"mov     {REGISTER_REGEX}, \[{REGISTER_REGEX}\+0Ch\]")
MOV_DLL_NAME_REGEX  = re.compile(f"mov     {REGISTER_REGEX}, \[{REGISTER_REGEX}\+30h\]")
PUSH_DLL_NAME_REGEX = re.compile(f"push    dword ptr \[{REGISTER_REGEX}\+30h\]")
MOV_DATA_DIRS_REGEX = re.compile(f"mov     {REGISTER_REGEX}, \[{REGISTER_REGEX}\+.*78h\]")

def is_invalid_string(buffer):
    for byte in buffer:
        if byte not in VALID_CHARACTERS:
            return True
    return False

def sanitize_string(str):
    str = str.decode()
    for c in "\t\r\n":
        str = str.replace(c, "_")
    return str

# the encrypted strings are stored inside the STRINGS_SECTION
def get_section_with_strings():
    section_start = get_segm_by_sel(selector_by_name(STRINGS_SECTION))
    section_end = get_segm_end(section_start)
    return section_start, section_end

def search_for_strings(section_start, section_end):
    strings_found = set()

    # decrypt arbitrary data and check if it results in a valid string
    for ea in range(section_start, section_end - 8, DWORD_SIZE):

        # read two DWORDs from buffer
        key = get_wide_dword(ea)
        encrypted_size = get_wide_dword(ea + DWORD_SIZE)
        size = encrypted_size ^ key

        # sanity check. If the size is too large skip to the next 4 bytes
        if size > 400 or (ea + 8 + size) > section_end:
            continue

        # align size to the size of DWORD
        aligned_size = (size + 3) & 0xFFFFFFFC

        # decrypt each DWORD after the encrypted_size and add it to the buffer
        decrypted_bytes = b''
        for offset in range(8, aligned_size + 8, DWORD_SIZE):
            decrypted_dword = get_wide_dword(ea + offset) ^ key
            decrypted_bytes += struct.pack('<I', decrypted_dword)
        
        # remove padded bytes
        decrypted_bytes = decrypted_bytes[:size]

        # skip buffers that were decrypted into invalid strings
        if is_invalid_string(decrypted_bytes) or len(decrypted_bytes) < 3:
            continue
        decrypted_string = sanitize_string(decrypted_bytes)
        strings_found.add(decrypted_string)

        # add comment to the IDB
        set_cmt(ea, decrypted_string, 1)
        print(hex(ea), decrypted_string)
    strings_found = list(strings_found)
    strings_found.sort()
    return strings_found

def decrypt_strings():
    section_start, section_end = get_section_with_strings()
    return search_for_strings(section_start, section_end)

def hash_string(string, key):
    hash_value = 0
    for c in string:
        hash_value = ord(c) + (hash_value << 6) + (hash_value << 16) - hash_value
    return (hash_value & 0xFFFFFFFF) ^ key

def find_dll_xor_key(func):
    # the dll xor key is in a function that parses the PEB
    ldr_access_found = False
    dll_name_access_found = False

    for ea in idautils.FuncItems(func):
        instr = generate_disasm_line(ea, 0)

        # we are looking for instructions that access the LDR and the BaseDllName
        # mov     edi, [eax+0Ch] - LDR
        # mov     edx, [esi+30h] - BaseDllName
        # push    dword ptr [esi+30h] - BaseDllName
        if MOV_LDR_REGEX.match(instr):
            ldr_access_found = True
        elif MOV_DLL_NAME_REGEX.match(instr):
            dll_name_access_found = True
        elif PUSH_DLL_NAME_REGEX.match(instr):
            dll_name_access_found = True

        # if the function reads LDR, then the dll xor key is in it
        elif ldr_access_found and \
            dll_name_access_found and \
            print_insn_mnem(ea) == "xor" and \
            get_operand_type(ea, 0) == o_reg and \
            get_operand_type(ea, 1) == o_imm:
                key = get_operand_value(ea,1)
                return key
        
        # reset the flag if the function ended
        elif instr.startswith("ret"):
            ldr_access_found = False
            dll_name_access_found = False

def find_symbol_xor_key(func):
    # the symbol xor key is in a function that parses the PE
    data_dirs_access_found = False

    for ea in idautils.FuncItems(func):
        instr = generate_disasm_line(ea, 0)
        
        # check if the function reads the data directories
        # mov eax, dword ptr [edx + 0x78]
        if MOV_DATA_DIRS_REGEX.match(instr):
            data_dirs_access_found = True
        
        # if the function reads the data directories, then the symbol xor key is in it
        elif data_dirs_access_found and \
        print_insn_mnem(ea) == "xor" and \
            get_operand_type(ea, 0) == o_reg and \
            get_operand_type(ea, 1) == o_imm:
                key = get_operand_value(ea,1)
                return key
        
        # reset the flag if the function ended
        elif instr.startswith("ret"):
            data_dirs_access_found = False

def find_xor_keys():
    dll_key = None
    symbol_key = None

    # search in each function for xor keys
    for func in idautils.Functions():

        # only stop when both keys are found
        if None not in (symbol_key, dll_key):
            break

        # skip library & thunk functions
        flags = get_func_attr(func, FUNCATTR_FLAGS)
        if flags & (FUNC_LIB | FUNC_THUNK):
            continue
        if dll_key == None:
            dll_key = find_dll_xor_key(func)
        if symbol_key == None:
            symbol_key = find_symbol_xor_key(func)
    return dll_key, symbol_key

def create_custom_dict(dll_key, symbol_key, symbols_dict):
    hashes_dict = HashesDict()
    for dll_name, symbols in symbols_dict.items():
        hashes_dict.libraries[hash_string(dll_name, dll_key)] = dll_name
        for symbol in symbols:
            hashes_dict.symbols[hash_string(symbol, symbol_key)] = symbol
    return hashes_dict

def find_imports(hashes_dict):
    libraries = set()
    symbols = set()

    # iterate the functions
    for func in idautils.Functions():

        # skip library & thunk functions
        flags = get_func_attr(func, FUNCATTR_FLAGS)
        if flags & (FUNC_LIB | FUNC_THUNK):
            continue

        # iterate the instructions in each function
        for ea in idautils.FuncItems(func):
            comment = None
            value = None
            
            instr = print_insn_mnem(ea)
            # in some cases the hashes are passed to the resolving functions through the stack
            if instr == "push" and get_operand_type(ea, 0) == o_imm:
                value = get_operand_value(ea, 0)
                
            # in other cases they are passed through the registers
            if instr == "mov" and get_operand_type(ea, 0) == o_reg and get_operand_type(ea, 1) == o_imm:
                value = get_operand_value(ea, 1)
                
            if value in hashes_dict.libraries:
                dll_name = hashes_dict.libraries[value]
                libraries.add(dll_name)
                comment = dll_name
            
            if value in hashes_dict.symbols:
                symbol = hashes_dict.symbols[value]
                symbols.add(symbol)
                comment = symbol

                # add comments to references to this function
                for xref in idautils.CodeRefsTo(func, 0):
                    set_cmt(xref, comment, 0)

            # add a comment to the line with the hash
            if comment:
                set_cmt(ea, comment, 0)

    # return the data as sorted lists
    libraries = list(libraries)
    symbols = list(symbols)
    libraries.sort()
    symbols.sort()
    return libraries,symbols

def main():
    dict_path = ask_file(0, "*.json", "choose symbols dictionary")
    symbols_dict = json.load(open(dict_path, 'r'))
    decrypted_info = {}

    # decrypt strings from the STRINGS_SECTION
    strings = decrypt_strings()
    if strings:
        decrypted_info['strings'] = strings
    else:
        print("no strings were found")
    
    # search for xor keys in disassembly
    dll_key, symbol_key = find_xor_keys()
    if dll_key is None:
        print(f"dll xor key not found")
        return
    if symbol_key is None:
        print(f"symbol xor key not found")
        return

    # create a custom dictionary using the unique keys from the sample
    hashes_dict = create_custom_dict(dll_key, symbol_key, symbols_dict)
    libraries, symbols = find_imports(hashes_dict)
    decrypted_info['libraries'] = libraries
    decrypted_info['symbols'] = symbols

    # save decrypted info to disk
    decrypted_info_path = ask_file(1, "*.json", "choose where to save decrypted info")
    json.dump(decrypted_info, open(decrypted_info_path, 'w'), indent=4, sort_keys=True)

if __name__ == '__main__':
    main()