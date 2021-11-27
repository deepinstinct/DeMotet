import re
import json
import struct
import string
import argparse
from pathlib import Path
from collections import namedtuple
import pefile
from capstone import Cs,CS_ARCH_X86, CS_MODE_32

HashesDict = namedtuple('HashesDict', ('libraries', 'symbols'),  defaults=({},{}))

STRINGS_SECTION = b'.text\x00\x00\x00'
VALID_CHARACTERS = [ord(c) for c in string.printable]
DWORD_SIZE = 4
REGISTER_REGEX = "e[abcds][xi]"
MOV_LDR_REGEX       = re.compile(f"mov {REGISTER_REGEX}, dword ptr \[{REGISTER_REGEX} \+ 0xc\]")
MOV_DLL_NAME_REGEX  = re.compile(f"mov {REGISTER_REGEX}, dword ptr \[{REGISTER_REGEX} \+ 0x30\]")
PUSH_DLL_NAME_REGEX = re.compile(f"push dword ptr \[{REGISTER_REGEX} \+ 0x30\]")
MOV_DATA_DIRS_REGEX = re.compile(f"mov {REGISTER_REGEX}, dword ptr \[{REGISTER_REGEX} \+.* 0x78\]")
XOR_REG_WITH_VAL_REGEX = re.compile(f"xor {REGISTER_REGEX}, 0x.*")
PUSH_VAL = re.compile(f"push 0x.*")
MOV_VAL_TO_REG_REGEX = re.compile(f"mov {REGISTER_REGEX}, 0x.*")

def is_invalid_string(buffer: bytes):
    for byte in buffer:
        if byte not in VALID_CHARACTERS:
            return True
    return False

def sanitize_string(str: bytes):
    str = str.decode()
    for c in "\t\r\n":
        str = str.replace(c, "_")
    return str

# the encrypted strings are stored inside the STRINGS_SECTION
def get_section_with_strings(pe: pefile.PE):
    section = next(filter(lambda section: section.Name == STRINGS_SECTION, pe.sections))
    section_start = section.PointerToRawData
    section_end = section_start + section.SizeOfRawData
    return section_start, section_end

def search_for_strings(pe, section_start, section_end):
    strings_found = set()

    # decrypt arbitrary data and check if it results in a valid string
    for ea in range(section_start, section_end - 8, DWORD_SIZE):

        # read two DWORDs from buffer
        key = pe.get_dword_from_offset(ea)
        encrypted_size = pe.get_dword_from_offset(ea + DWORD_SIZE)
        size = encrypted_size ^ key

        # sanity check. If the size is too large skip to the next 4 bytes
        if size > 400 or (ea + 8 + size) > section_end:
            continue

        # align size to the size of DWORD
        aligned_size = (size + 3) & 0xFFFFFFFC

        # decrypt each DWORD after the encrypted_size and add it to the buffer
        decrypted_bytes = b''
        for offset in range(8, aligned_size + 8, DWORD_SIZE):
            decrypted_dword = pe.get_dword_from_offset(ea + offset) ^ key
            decrypted_bytes += struct.pack('<I', decrypted_dword)
        
        # remove padded bytes
        decrypted_bytes = decrypted_bytes[:size]

        # skip buffers that were decrypted into invalid strings
        if is_invalid_string(decrypted_bytes) or len(decrypted_bytes) < 3:
            continue
        decrypted_string = sanitize_string(decrypted_bytes)
        strings_found.add(decrypted_string)

    strings_found = list(strings_found)
    strings_found.sort()
    return strings_found

def decrypt_strings(pe: pefile.PE):
    section_start, section_end = get_section_with_strings(pe)
    return search_for_strings(pe, section_start, section_end)

def get_executable_sections(pe: pefile.PE):
    return filter(lambda section: section.IMAGE_SCN_MEM_EXECUTE, pe.sections)

def get_disassembly(pe: pefile.PE):
    # define architecutre of the machine 
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    # get the section that contains assembly
    sections = get_executable_sections(pe)
    commands = list()

    for section in sections:
        data = section.get_data()
        virtual_address = section.VirtualAddress
        section_end = section.SizeOfRawData
        offset = 0

        # disassemble bytes until the end of the section
        while offset < section_end:
            for i in md.disasm(data[offset:], virtual_address):
                commands.append(f"{i.mnemonic} {i.op_str}")
                offset += i.size
            # sequence of bytes that cannot be disassembled will stop the for loop
            # skip it and try again until the end of the section
            offset += 1
    return commands

def hash_string(string, key):
    hash_value = 0
    for c in string:
        hash_value = ord(c) + (hash_value << 6) + (hash_value << 16) - hash_value
    return (hash_value & 0xFFFFFFFF) ^ key

def find_dll_xor_key(dism_cmds):
    # the dll xor key is in a function that parses the PEB
    ldr_access_found = False
    dll_name_access_found = False

    for cmd in dism_cmds:
        # we are looking for instructions that access the LDR and the BaseDllName
        # mov     edi, [eax+0Ch] - LDR
        # mov     edx, [esi+30h] - BaseDllName
        # push    dword ptr [esi+30h] - BaseDllName
        if MOV_LDR_REGEX.match(cmd):
            ldr_access_found = True
        elif MOV_DLL_NAME_REGEX.match(cmd):
            dll_name_access_found = True
        elif PUSH_DLL_NAME_REGEX.match(cmd):
            dll_name_access_found = True

        # if the function reads LDR, then the dll xor key is in it
        elif ldr_access_found and \
            dll_name_access_found and \
            XOR_REG_WITH_VAL_REGEX.match(cmd):
                xor_value = cmd.split(' ')[2]
                key = int(xor_value, 16)
                return key
        
        # reset the flag if the function ended
        elif cmd.startswith("ret"):
            ldr_access_found = False
            dll_name_access_found = False

def find_symbol_xor_key(dism_cmds):
    # the symbol xor key is in a function that parses the PE
    data_dirs_access_found = False

    for cmd in dism_cmds:
        
        # check if the function reads the data directories
        # mov eax, dword ptr [edx + 0x78]
        if MOV_DATA_DIRS_REGEX.match(cmd):
            data_dirs_access_found = True
        
        # if the function reads the data directories, then the symbol xor key is in it
        elif data_dirs_access_found and \
            XOR_REG_WITH_VAL_REGEX.match(cmd):
                xor_value = cmd.split(' ')[2]
                key = int(xor_value, 16)
                return key
        
        # reset the flag if the function ended
        elif cmd.startswith("ret"):
            data_dirs_access_found = False

def create_custom_dict(dll_key, symbol_key, symbols_dict):
    hashes_dict = HashesDict()
    for dll_name, symbols in symbols_dict.items():
        hashes_dict.libraries[hash_string(dll_name, dll_key)] = dll_name
        for symbol in symbols:
            hashes_dict.symbols[hash_string(symbol, symbol_key)] = symbol
    return hashes_dict

def find_imports(dism_cmds, hashes_dict):
    libraries = set()
    symbols = set()
    for cmd in dism_cmds:
        value = None

        # in some cases the hashes are passed to the resolving functions through the stack
        if PUSH_VAL.match(cmd):
            value = int(cmd.split(' ')[1],16)

        # in other cases they are passed through the registers
        elif MOV_VAL_TO_REG_REGEX.match(cmd):
            value = int(cmd.split(' ')[2],16)

        if value in hashes_dict.libraries:
            dll_name = hashes_dict.libraries[value]
            libraries.add(dll_name)
            
        if value in hashes_dict.symbols:
            symbol = hashes_dict.symbols[value]
            symbols.add(symbol)

    # return the data as sorted lists
    libraries = list(libraries)
    symbols = list(symbols)
    libraries.sort()
    symbols.sort()
    return libraries,symbols

def handle_file(file_path: Path, symbols_dict: dict):
    file_name = file_path.name
    pe = pefile.PE(file_path)
    decrypted_info = {}

    # decrypt strings from the STRINGS_SECTION
    strings = decrypt_strings(pe)
    if strings:
        decrypted_info['strings'] = strings
    else:
        print(f"no strings were found for {file_name}")

    # search for xor keys in disassembly
    disassembly_commands = get_disassembly(pe)
    dll_key = find_dll_xor_key(disassembly_commands)
    if dll_key is None:
        print(f"dll xor key not found for {file_name}")
        return
    symbol_key = find_symbol_xor_key(disassembly_commands)
    if symbol_key is None:
        print(f"symbol xor key not found for {file_name}")
        return

    # create a custom dictionary using the unique keys from the sample
    hashes_dict = create_custom_dict(dll_key, symbol_key, symbols_dict)
    libraries, symbols = find_imports(disassembly_commands, hashes_dict)
    decrypted_info['libraries'] = libraries
    decrypted_info['symbols'] = symbols

    return decrypted_info

def handle_directory(folder: Path, symbols_dict: dict):
    decrypted_info = {}
    for file_path in folder.iterdir():
        decrypted_info[file_path.name] = handle_file(file_path, symbols_dict)
    return decrypted_info

def handle_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path', required=True, type=Path,
                        help="Path to a file/folder to decrypt")
    parser.add_argument('-j', '--json', type=Path,
                        help="Path to the decrypted info to")
    parser.add_argument('-s', '--symbols-dict', type=Path,
                        help="Path to the symbols.json file", default="symbols.json")
    return parser.parse_args()

def main():
    # get arguments
    args = handle_args()
    path = args.path
    symbols_dict = json.load(args.symbols_dict.open('r'))
    output_path = args.json

    # decrypt file/folder
    handle_func = handle_directory if path.is_dir() else handle_file
    decrypted_info = handle_func(path, symbols_dict)
    
    # write results
    if output_path:
        output_handle = output_path.open('w')
        json.dump(decrypted_info, output_handle, indent=4, sort_keys=True)
        output_handle.close()
    else:
        print(json.dumps(decrypted_info, indent=4, sort_keys=True))

if __name__ == '__main__':
    main()