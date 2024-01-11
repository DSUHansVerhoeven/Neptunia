
#https://wiki.osdev.org/ELF_Tutorial#Relocation_Sections
#32 bit but good explanations of sections and structures/uses
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import *
from elftools.elf.relocation import RelocationSection
from capstone import *
from keystone import *
import struct
from ropper import RopperService
import operator
import re

md = Cs(CS_ARCH_X86, CS_MODE_64)
ks = Ks(KS_ARCH_X86, KS_MODE_64)
one_call = False
one_relative = False
relocation_fix = False
call_fix = False
allow_jmp_fix = False

class Elf_Header:
    def __init__(self,header):
        eident = header.e_ident

        self.format = [x for x in eident['EI_MAG']]
        self.file_class = ENUM_EI_CLASS[eident['EI_CLASS']] 
        self.encoding = ENUM_EI_DATA[eident['EI_DATA']]
        self.file_version = ENUM_E_VERSION[eident['EI_VERSION']]
        self.osabi = ENUM_EI_OSABI[eident['EI_OSABI']]
        self.abi_version = eident['EI_ABIVERSION']

        self.type = ENUM_E_TYPE[header.e_type]
        self.machine = ENUM_E_MACHINE[header.e_machine]
        #same as the one above
        #self.file_version = 
        self.entry = header.e_entry
        self.pht_offset = header.e_phoff
        self.sht_offset = header.e_shoff
        self.flags = header.e_flags
        self.header_size = header.e_ehsize
        self.pht_size = header.e_phentsize
        self.pht_entries = header.e_phnum
        self.sht_size = header.e_shentsize
        self.sht_entries = header.e_shnum
        self.sht_string = header.e_shstrndx

        self.processor_flags = header.e_flags

    def build(self):
        #HARD CODED TO BE LITTLE ENDIAN FOR NOW
        self.format = bytes(self.format)
        return bytes(self.format) + struct.pack("<5b7xhhi3qi6h", self.file_class, self.encoding, self.file_version, self.osabi, self.abi_version, self.type,self.machine,self.file_version,self.entry,self.pht_offset,self.sht_offset,self.flags,self.header_size,self.pht_size,self.pht_entries,self.sht_size,self.sht_entries,self.sht_string) 

    #updates section, these should be used to update the classes data, this data will be used in the data function above to print out the valid header
    def update_entry(self, value):
        self.entry += value
    
    def update_sht_offset(self, value):
        self.sht_offset = value

#class used to hold each sections data, can then be rebuilt or indexed through itself
class Section:
    def __init__(self, section):
        header = section.header
        self.name = header.sh_name
        self.type = ENUM_SH_TYPE_BASE[header.sh_type]
        self.address = header.sh_addr
        self.offset = header.sh_offset
        self.size = header.sh_size
        self.entsize = header.sh_entsize
        self.flags = header.sh_flags
        self.link = header.sh_link
        self.info = header.sh_info
        self.align = header.sh_addralign
        self.data = section.data()
        self.dynamic_segment = 0

        self.print_name = section.name
        self.old_address = self.address
        self.old_offset = self.offset
        self.old_size = self.size

    def build(self):
        '''
        typedef struct {
            Elf64_Word    sh_name;
            Elf64_Word    sh_type;
            Elf64_Xword    sh_flags; #xword is qword in 64
            Elf64_Addr    sh_addr;
            Elf64_Off    sh_offset;
            Elf64_Xword    sh_size;
            Elf64_Word    sh_link;
            Elf64_Word    sh_info;
            Elf64_Xword    sh_addralign;
            Elf64_Xword    sh_entsize;
        } Elf64_Shdr;

        '''
        return struct.pack("<ii4qiiqq", self.name,self.type,self.flags,self.address,self.offset,self.size,self.link,self.info,self.align,self.entsize)

    def check_within(self, address):

        if address >= self.old_address and address <= self.old_address+self.old_size:
            return 1
        return 0

#class used to hold a segments information, can then be further indexed or rebuilt from here, also holds a direct connection to the section if it is dynamic 
class Segment:
    def __init__(self, segment):
        header = segment.header
        self.type = ENUM_P_TYPE_BASE[header['p_type']]
        self.print_name = header['p_type']
        self.flags = header['p_flags']
        self.offset = header['p_offset']
        self.virtual_address = header['p_vaddr'] 
        self.physical_address = header['p_paddr']
        self.file_size = header['p_filesz']
        self.memory_size = header['p_memsz']
        self.align = header['p_align']
        self.data = segment.data()
        self.dynamic_section = 0
        if header['p_type'] == 'PT_DYNAMIC':
            self.dynamic_section = 1

        self.old_address = self.virtual_address
        self.old_offset = self.offset
        self.old_file_size = self.file_size
    
    def build(self):
        return struct.pack("<ii6Q", self.type,self.flags,self.offset,self.virtual_address,self.physical_address,self.file_size,self.memory_size,self.align)

    def check_within(self, variable):
        if type(variable) == Section:
            address = variable.old_offset
            size = variable.size
        else:
            address = variable
            size = 8
        #file size for now, and this should be accurate at the moment as this is only checking for executable at the moment
        if address >= self.old_offset and address+size <= self.old_offset+self.old_file_size:
            return 1
        return 0

#class that holds all the data for the symbols table
class Symtab:
    def __init__(self, section):
        self.data = section.data
        self.symbols = []
        self.section = section
        self.values = []
        self.pos = {}

        counter = 0
        while counter < len(self.data):
            name,info,other,shndx,value,size = struct.unpack("<ibbhqq", self.data[counter:counter+24])
            create = {}
            create["name"] = name
            create["info"] = info
            create["other"] = other
            create["shndx"] = shndx
            create["value"] = value
            self.values.append(value)
            create["size"] = size
            self.symbols.append(create)

            counter += 24

    def build(self):
        '''
        typedef struct {
            Elf64_Word      st_name; #4 bytes
            unsigned char   st_info;
            unsigned char   st_other;
            Elf64_Half      st_shndx; #2 bytes
            Elf64_Addr      st_value;
            Elf64_Xword     st_size;
        } Elf64_Sym;
        '''
        final = b''
        for symbols in self.symbols:
            final += struct.pack("<ibbhqq", symbols['name'],symbols['info'],symbols['other'],symbols['shndx'],symbols['value'],symbols['size'])
        return final

#dynamic table, at the moment I don't think this should ever change and I will leave as is
class Dynamic:
    def __init__(self, segment):
        self.data = segment.data
        self.entries = []
        self.values = []
        self.segment = segment
        self.pos = {}

        counter = 0
        while counter < len(self.data):
            create = {}
            create['tag'], create['value'] = struct.unpack("<QQ", self.data[counter:counter+16])
            self.entries.append(create)
            self.values.append(create['value'])
            counter += 16
        

        
    def build(self):
        final = b''

        for x in self.entries:
            final += struct.pack("<QQ", x['tag'],x['value'])

        self.segment.data = final

#relocation table, holds information regarding symbols that could change based on PIE address
class Relocation:
    def __init__(self,section):
        self.data = section.data
        self.entries = []
        counter = 0
        self.address = section.address
        self.section = section
        self.pos = {}
        while counter < len(self.data):
            offset,info,addend = struct.unpack("<3Q", self.data[counter:counter+24])
            create = {}
            create['offset'] = offset
            create['info'] = info
            create['addend'] = addend
            self.entries.append(create)
            if info == 8:
                if addend not in self.pos:
                    self.pos[addend] = []
                self.pos[addend].append(self.entries[-1])
            counter+=24



    def build(self):
        final = b''
        for entry in self.entries:
            final += struct.pack("<3Q", entry['offset'],entry['info'],entry['addend'])
        return final

class GotPlt:
    def __init__(self,section):
        self.section = section
        counter = 0
        self.data = section.data
        self.address = section.address
        self.entries = []
        self.pos = {}
        
        while counter < len(self.data):
            self.entries.append(struct.unpack("<Q", self.data[counter:counter+8])[0])
            counter += 8


    def build(self):
        final = b''
        for x in self.entries:
            final += struct.pack("<Q", x)
        return final

#should more or less be the exact same as relocation, but they are technically different tables
class RelaPlt(Relocation):
    def __init__(self, section):
        super(RelaPlt, self).__init__(section)
        self.pos = {}
        for x in self.entries[:]:
            if x['addend'] in self.pos:
                self.pos[x['addend']].append(x)
            else:
                self.pos[x['addend']] = [x]

#class to relate to every instruction, holds information about each instruction
class Instruction:
    def __init__(self, instruction, inserted):
        if type(instruction) == CsInsn:
            self.mnemonic = instruction.mnemonic
            self.op_str = instruction.op_str
            self.address = instruction.address
            self.bytes = instruction.bytes
        else:
            self.mnemonic = instruction["mnemonic"]
            self.op_str = instruction["op_str"]
            self.address = instruction['address']
            self.bytes = instruction['bytes']
        self.size = lambda : len(self.bytes)
        self.old_address = self.address
        self.inserted = inserted
        self.section = 0
        self.data = 0
    
    def __str__(self):
        try:
            return str([self.mnemonic, self.op_str, hex(self.address), self.bytes.hex(), hex(self.jmp_addr), hex(self.rip_offset)])
        except:
            return str([self.mnemonic, self.op_str, hex(self.address), self.bytes.hex()])

class Jump_Table:
    #relocation symbol is passed in and next address
    def __init__(self, symbol,printf, next_address, instruction,reference):
        self.data = 0
        #this could change in build so we can't store the address yet
        self.symbol = symbol
        self.size = next_address - symbol[0]
        self.instruction = instruction
        #create table
        self.jumps = []
        self.reference = reference
        self.printf = printf

    def modify(self, instructions):
        check = 0
        for x in self.jumps:
            if x == 0 and check == 0:
                print(0)
                continue
            elif x == 0:
                break
            addr = self.reference + x
            jump = self.jumps.index(x)
            #the point of this is to make sure that we are still going after the correct address
            try:
                new = instructions[addr].address - self.symbol[0]
            except:
                print ("failed jump")
                print(self.instruction, hex(self.reference), hex(x), hex(addr))
                exit(-2)
            if x < 0:
                check = 1
            #print(hex(self.jumps[jump]),hex(new))
            self.jumps[jump] = new

    def generate(self, data):
        self.data = data
        counter = 0
        print (len(data))
        while counter < len(data):
            self.jumps.append(struct.unpack('<i', data[counter: counter + 4])[0])
            counter += 4
        #print(self.size,data.hex(), self.jumps)
            
    def build(self):
        final = b''
        for x in self.jumps:
            final += struct.pack('<i', x)

        return final

#class Elf:
class Gamindustri:
    needed_insts = []
    inst_list = []
    referenced = {}
    start = 0
    reg_list = [ ['rax','eax','ax','al'],
             ['rbx','ebx','bx','bl'],
             ['rcx','ecx','cx','cl'],
             ['rdx','edx','dx','dl'],
             ['rsi','esi','si','sil'],
             ['rdi','edi','di','dil'],
             ['rbp','ebp','bp','bpl'],
             ['rsp','esp','sp','spl'],
             ['r8','r8d','r8w','r8b'],
             ['r9','r9d','r9w','r9b'],
             ['r10','r10d','r10w','r10b'],
             ['r11','r11d','r11w','r11b'],
             ['r12','r12d','r12w','r12b'],
             ['r13','r13d','r13w','r13b'],
             ['r14','r14d','r14w','r14b'],
             ['r15','r15d','r15w','r15b'] ]

    def __init__(self, filename):
        #self.file = ELFFile(open(file, 'rb'))
        #self.start = self.file.header['e_entry']
        #self.segments = []
        #self.symbols = []
        #find the relocation symbols needed
        self.first = -1
        self.last = -1

        self.file = open(filename,'rb')
        self.elffile = ELFFile(self.file)
        self.header = Elf_Header(self.elffile.header)
        self.segments = []
        self.sections = []
        self.instructions = []
        self.text = 0
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.relatives = []
        self.text_relatives = []
        self.relocation = []
        self.gotplt = []
        self.relaplt = []
        self.symtab = []
        self.dynsym = []
        self.ret_list = []
        self.inst_dict = {}
        self.jmp_list = []
        self.jmp_table_list = []
        self.call_list = []
        self.registers = [x[0] for x in self.reg_list]
        self.inserted = 20
        #iterate through the segments
        for segment in self.elffile.iter_segments():
            created = Segment(segment)
            self.segments.append(created)
            if created.flags==5 and not self.text:
                self.text = created
            if created.type == 2:
                self.dynamic = Dynamic(created)

        for section in self.elffile.iter_sections():
            created = Section(section)
            self.sections.append(created)

            #create the symbol table if there is one
            if created.print_name == ".symtab":
                self.symtab = Symtab(created)
            #commonly used in shared objects
            if created.print_name == ".dynsym":
                self.dynsym = Symtab(created)
            #connect the dynamic section and segment for easier access in the future
            elif created.print_name == '.dynamic':
                for segment in self.segments:
                    if segment.dynamic_section:
                        segment.dynamic_section = created
                        created.dynamic_segment = segment
            elif created.print_name == '.rela.dyn':
                self.relocation = Relocation(created)
            elif created.print_name == '.got.plt':
                self.gotplt = GotPlt(created)
            elif created.print_name == '.rela.plt':
                self.relaplt = RelaPlt(created)
            #executable section, section with instructions in it
            if created.flags & 4 == 4:
                self.get_instruction_list(created)

    #appends information about an instruction, so far jumps and [rip + offset]
    def get_additional_inst_info(self, instruction):
        #rip indirect jump

        #add logic for + and - not just +
        if '[rip +' in instruction.op_str or '[rip -' in instruction.op_str:
            #grab the offset value from the instruction
            if '+' in instruction.op_str:
                position = int(instruction.op_str.split('+ ')[1].split(']')[0],16)
            else:
                position = -int(instruction.op_str.split('- ')[1].split(']')[0],16)

            #find byte offset
            offset = -1
            for x in range(len(instruction.bytes)):
                if position < 0:
                    address = int.from_bytes(instruction.bytes[x:x+4], "little")
                    address = address - (1<<32)
                else:
                    address = int.from_bytes(instruction.bytes[x:x+4], "little")

                if address == position:
                    offset = x
                    instruction.offset = offset
                    break

            if offset == -1:
                print("offset not found, something went wrong")
                exit(-1)
            address = position + instruction.address + len(instruction.bytes) 
            if address > self.text.offset+self.text.file_size or address < self.text.offset:
                #so at this point there is a possibility that this is a jump table as well
                self.relatives.append([address,instruction,False])
            elif address >= self.text.offset and address <= self.text.offset + self.text.file_size:
                self.text_relatives.append([address,instruction])
        #Standard jump instruction
        elif 'j' in instruction.mnemonic and '0x' in instruction.op_str and '[' not in instruction.op_str and 'jrcxz' != instruction.mnemonic:
            if instruction.size() > 2:
                #Some jumps were not working, this is a protection
                try:
                    rip_offset = struct.unpack("<i", instruction.bytes[-4:])[0]
                except:
                    print(instruction)
                    exit(-3)
            else:
                rip_offset = struct.unpack("<b", instruction.bytes[1:])[0]

            next_instruction = instruction.size() + instruction.address
            addr = rip_offset + next_instruction

            instruction.jmp_addr = addr
            instruction.rip_offset = rip_offset

        #ret instruction, append to ret list
        if instruction.bytes == b'\xc3':
            self.ret_list.append(instruction)
        #careful usage required
        self.inst_dict[instruction.address] = instruction

    def creator(self,created,section):
        created.section = section
        self.instructions.append(created)
        if created.address == self.header.entry:
            self.entry = created
        if 'j' in created.mnemonic and '[' not in created.op_str and '0x' in created.op_str and created.mnemonic != 'jrcxz':
            self.jmp_list.append(created)
        if 'call' in created.mnemonic and '0x' in created.op_str and '[' not in created.op_str :
            self.call_list.append(created)
        self.get_additional_inst_info(created)

        return created.size()

    #return list of each instruction of a given section
    def get_instruction_list(self, section):
        size = 0
        while size < len(section.data):
            for instruction in self.md.disasm(section.data[size:], section.address+size):
                size += self.creator(Instruction(instruction,0),section)
            #rdpkru is not supported by capstone for some reason, https://github.com/aquynh/capstone/issues/1076
            if section.data[size:size+3] == b'\x0f\x01\xee':
                size += self.creator(Instruction({"mnemonic":"rdpkru","op_str":"", "address": section.address+size, "bytes":section.data[size:size+3]},0), section)
            #wrpkru is not supported by capstone for some reason, https://github.com/aquynh/capstone/issues/1076
            elif section.data[size:size+3] == b'\x0f\x01\xef':
                size += self.creator(Instruction({"mnemonic":"wrpkru","op_str":"", "address": section.address+size, "bytes":section.data[size:size+3]},0), section)
            elif size < len(section.data):
                #problem is that if there is text data in the executable segment, capstone doesn't know how to handle it, this causes problems for us. 
                #temporary fix, not really sure how to handle this
                #or we found an instruction we don't know of
                created = Instruction({"mnemonic":"STRING","op_str":"", "address": section.address+size, "bytes":section.data[size:]},0)
                created.data = 1
                size += self.creator(created, section)

    def build(self):
        #set text segment/sections
        text = b'\x00' * (self.instructions[-1].address - self.text.virtual_address + self.instructions[-1].size())
        if not self.DEBUG:
            for instruction in self.instructions:
                addr = instruction.address-self.text.virtual_address
                text = text[:addr] + instruction.bytes + text[addr+instruction.size():]
                if instruction.inserted == 0:
                    #fix relocations
                    #if self.relocation and instruction.old_address in self.relocation.pos:
                    #    self.relocation.pos[instruction.old_address]['addend'] = instruction.address
                    if self.gotplt and instruction.old_address in self.gotplt.entries:
                        self.gotplt.pos[instruction.old_address] = instruction
                    if self.symtab and instruction.old_address in self.symtab.values:
                        self.symtab.pos[instruction.old_address] = instruction
                    if self.dynamic and instruction.old_address in self.dynamic.values:
                        self.dynamic.pos[instruction.old_address] = instruction
                    if self.dynsym and instruction.old_address in self.dynsym.values:
                        self.dynsym.pos[instruction.old_address] = instruction
                    if self.relaplt and instruction.old_address in self.relaplt.pos:
                        for relaplt in self.relaplt.pos[instruction.old_address]:
                            relaplt['addend'] = instruction.address
                    #fix relocations found within text segment
                    if self.relocation and not instruction.inserted:
                        tmp_list = [x for x in range(instruction.old_address, instruction.old_address + instruction.size())]
                        for x in tmp_list:
                            if x in self.relocation.pos:
                                for y in self.relocation.pos[x]:
                                    y['addend'] = y['addend'] + (instruction.address-instruction.old_address)
                                    y['changed'] = 1

        self.relatives = sorted(self.relatives, key=lambda x: x[0])

        #fix segments
        diff = 0
        if(self.text.file_size//0x1000 != len(text)//0x1000):
            #should give us the next boundry difference that we will work with
            diff = (len(text)//0x1000 - self.text.file_size//0x1000) * 0x1000

        if diff:
            #print(hex(diff))
            #need to increase the segment locations for all segments now
            for segments in self.segments:
                if segments.offset > self.text.offset:
                    segments.offset += diff
                    segments.virtual_address += diff
                    segments.physical_address += diff

            #need to increase the section locations for all sections now
            for sections in self.sections:
                if sections.offset > self.text.offset + self.text.file_size:
                    sections.offset += diff
                    sections.address += diff
            #need to increate relocation locations for any relocations that are not instructions
            if self.relocation:
                for relocation in self.relocation.entries:
                    #this should be guarenteed
                    relocation['offset'] += diff
                    #this depends on the instruciton that is being modified
                    if relocation['info'] == 8 and not self.text.check_within(relocation['addend']) and 'changed' not in relocation:
                        relocation['addend'] += diff
            if self.relaplt:
                #fix plt got entries
                for relaplt in self.relaplt.entries:
                    relaplt['offset'] += diff


            #fix dynamic table
            if self.dynamic:
                for dynamic in self.dynamic.entries:
                    
                    if dynamic['value'] > self.text.offset + self.text.file_size:
                        dynamic['value'] += diff
                    
            #increase got.plt entries that may be off now
            if self.gotplt:
                got = []
                for gotplt in self.gotplt.entries:
                    if gotplt > self.text.offset+self.text.file_size:
                        gotplt += diff
                        got.append(gotplt)
                    else:
                        got.append(gotplt)
                self.gotplt.entries = got
            
            #increase any symbols
            if self.symtab:
                for symbol in self.symtab.symbols:
                    if symbol['value'] > self.text.offset+self.text.file_size:
                        symbol['value'] += diff
            #increase any dynamic symbols
            if self.dynsym:
                for symbol in self.dynsym.symbols:
                    if symbol['value'] > self.text.offset+self.text.file_size:
                        symbol['value'] += diff


        #fix start address
        self.header.entry = self.entry.address
        
        #further fix sections
        for section in self.sections:
            if self.text.check_within(section) and section.size and section.flags&4:
                last_instruction = 0
                first_instruction = 0
                for instruction in self.instructions:
                    if instruction.section == section:
                        if not first_instruction:
                            first_instruction = instruction
                        last_instruction = instruction
                    #shorten the loop if possible
                    elif last_instruction and instruction.section != section and not instruction.inserted:
                        break
                try:
                    last_instruction = last_instruction.address + last_instruction.size()
                except:
                    print("section fix failed")
                    exit(-4)
                section.size = last_instruction - first_instruction.address
                #I believe that this is correct
                section.offset = first_instruction.address
                section.address = first_instruction.address
    
        #fix relocatable instructions such as call [rip + 0x2000]
        for relative in self.relatives:
            for section in self.sections:
                #check if the relocation originally came from this address
                if section.check_within(relative[0]):
                    instruction = relative[1]
                    #if a value has moved with its section
                    relative.append(section.offset-section.old_offset)

                    #swap the extra append that holds the extra offset if needed
                    relative[2], relative[3] = relative[3], relative[2]

                    relative[0] += relative[2]
                    new = relative[0] - instruction.address - len(instruction.bytes)

                    #relative previously contained a bad byte and was shifted
                    if relative[3] != False:
                        new = new - relative[3]
                    try:
                        instruction.bytes = instruction.bytes[:instruction.offset] + struct.pack("<i", new) + instruction.bytes[instruction.offset+4:]
                    except Exception as e:
                        print("new failed")
                        print(e,new)
                        exit(-5)
                    addr = instruction.address-self.text.virtual_address
                    text = text[:addr] + instruction.bytes + text[addr+instruction.size():]
                    break
                    #need to do 2 checks
                    #1. if the page has changed we need to update the address
                    #2. if any instructions have changed and the page hasn't change

                    #2 will probably need to happen either way

        #see if it is possible to fix up jump tables, experimental
        #new method idea,
        #locate jump
        #find addition
        #then two things
        #find offset
        #find initial set
        #find where inital set is set
        #see if this is the same
        done = []
        for symbol in self.relatives:
            if symbol[0] in done or 'lea' not in symbol[1].mnemonic:
                continue
            index = self.instructions.index(symbol[1])

            check = 0
            #make sure reference is in a read section, should be jump table then
            for section in self.sections:
                if section.check_within(symbol[0]):
                    if section.flags == 2 and section.type == 1:
                        check = 1
                    break
            if check != 1:
                continue
            done.append(symbol[0])
            found = 0
            #check if there is a jump register in range
            for x in range(index+1, index+20):
                #this should be a good enough check for a jump table, it doesn't guarentee though
                if 'jmp' in self.instructions[x].mnemonic and self.instructions[x].op_str in self.registers:
                    found = x
                    break
            if found == 0:
                continue

            found2 = 0
            reg1 = 0
            reg2 = 0
            #found holds the index of the jump, now find the addition of the jump register
            for x in range(found, found-20, -1):
                if 'add' in self.instructions[x].mnemonic:
                    reg1,reg2 = self.instructions[x].op_str.split(', ')
                    if reg1 == self.instructions[found].op_str and reg2 in self.registers:
                        found2 = x
                        break

            #something something not a jumptable jump, didn't test though
            if found2 == 0:
                continue

            found3 = 0
            lea_reg = 0
            lea_reg2 = 0
            #find the lea of the second register
            for x in range(found2, found-20, -1):
                if 'lea' in self.instructions[x].mnemonic:
                    lea_reg,lea_reg2 = self.instructions[x].op_str.split(', [')
                    lea_reg2 = lea_reg2[:3]
                    #is the hard check to 'rip' the correct method here
                    if lea_reg == reg2 and lea_reg2 == 'rip':
                        found3 = x
                        break
            #not found?
            if found3 == 0:
                continue
            #at this point we should have two test cases, I think,
            #1. found3 should be the same as our first found
            #2. found3 is different implying a printf internal jump?
            #these are the only two because, our check to create a possible jumptable
            #is checked against read sections only, so this is not possible within
            #to be the same and be a printf internal jump
            #good jump table
            if self.instructions[found3] == symbol[1]:
                #self.jmp_table_list.append(Jump_Table(symbol, self.relatives[self.relatives.index(symbol)+1][0], self.instructions[index]))
                index = found3
                printf = 0
                #something about if this has changed
                reference = symbol[0]-symbol[2]

                
            #wrong lea before the jump
            else:
                continue

            i = self.relatives.index(symbol) + 1
            while 1:
                if self.relatives[i][0] != symbol[0]:
                    break
                i += 1
            self.jmp_table_list.append(Jump_Table(symbol, printf, self.relatives[i][0], self.instructions[index], reference))

        #fix any plt address that may have change in gotplt
        if self.gotplt:
            got = []
            for gotplt in self.gotplt.entries:
                if gotplt in self.gotplt.pos:
                    got.append(self.gotplt.pos[gotplt].address)
                else:
                    got.append(gotplt)
            self.gotplt.entries = got
            self.gotplt.section.data = self.gotplt.build()

        #fix any symbols in the binary
        if self.symtab:
            for symbol in self.symtab.symbols:
                if symbol['value'] in self.symtab.pos:
                    symbol['value'] = self.symtab.pos[symbol['value']].address

            self.symtab.section.data = self.symtab.build()

        #fix any dynamic symbols in the binary
        if self.dynsym:
            for symbol in self.dynsym.symbols:
                if symbol['value'] in self.dynsym.pos:
                    symbol['value'] = self.dynsym.pos[symbol['value']].address

            self.dynsym.section.data = self.dynsym.build()

        #fix dynamic table
        if self.dynamic:
            for dynamic in self.dynamic.entries:
                if dynamic['value'] in self.dynamic.pos:
                    dynamic['value'] = self.dynamic.pos[dynamic['value']].address
            self.dynamic.build()

        self.text.file_size = len(text)
        self.text.memory_size = len(text)
        self.text.data = text


        pht = b''
        for segment in self.segments:
            pht += segment.build()

        sht = b''
        for section in self.sections:
            sht += section.build()

        final = b''
        #append the load segments first
        for segment in self.segments:
            if segment.type == 1:
                size =  segment.file_size % segment.align
                if size == 0:
                    size = segment.align
                if len(final) < segment.offset:
                    final += b'\x00' * (segment.offset-len(final))
                final += segment.data

        #insert relocated table back into elf
        if self.relocation:
            self.relocation.section.data = self.relocation.build()
            self.relocation.data = self.relocation.build()

        #insert relaplt table back into elf
        if self.relaplt:
            relaplt = self.relaplt.build()
            self.relaplt.section.data = relaplt
            #final = final[:self.relaplt.address] + relaplt + final[self.relaplt.address + len(relaplt):]
        
        last = 0

        #this needs to be done seperetely as these segments usually fall within the segments above, alignment wise
        for segment in self.segments:
            #if(len(final) < segment.offset):
            #    final += b'\x00' * (segment.offset-len(final))
            if segment.type == 2:
                final = final[:segment.offset] + segment.data + final[segment.offset + segment.file_size:]
                last = segment.offset + segment.file_size

        for section in self.sections:
            if(len(final) < section.offset):
                final += b'\x00' * (section.offset-len(final))
            if section.type != 8:
                if (section.offset >= last or section.address == 0) and section.offset != 0 and section.flags != 3:
                    final = final[:section.offset] + section.data + final[section.offset + section.size:]
                    last = section.offset + section.size
                elif (section.offset >= last or section.address == 0) and section.offset != 0 and section.flags == 3:
                    final = final[:section.offset] + section.data + final[section.offset + section.size:]
                elif section.offset != 0 and section.offset < self.text.offset: 
                    final = final[:section.offset] + section.data + final[section.offset + section.size:]
                elif self.text.check_within(section) and not section.flags & 4:
                    final = final[:section.offset] + section.data + final[section.offset + section.size:]


        self.header.sht_offset = len(final)
        final += sht

        final = self.header.build() + pht + final[64 + len(pht):]
        
        #lastly fix jump tables?
        for pos in self.jmp_table_list:
            #grab the data
            pos.generate(final[pos.symbol[0]:pos.symbol[0]+pos.size])
            pos.table = pos.symbol[0]

            #print(pos.instruction)
            pos.modify(self.inst_dict) 

            data = pos.build()
            final = final[:pos.table] + data + final[pos.table+len(data):]

        return final

    #build insertion instruction
    def build_instruction(self, b, addr):
        for x in elf.md.disasm(b, addr):
            inst = Instruction(x,1)
        #inst = ['ret', '', 33, b'\xc3']
        return inst

    #Modifies the instruction list if a jmp becomes a 5 byte jmp
    def jmp_conversion_shift(self, insert_address, jmp):
        size = 0
        inst_list_index = 0
        jmp_list_index = 0

        #check if bytes need to shift from 2 to 5
        if jmp.size() == 2 and (jmp.rip_offset > 127 or jmp.rip_offset < -128):
            #find the location of jmp instruction in the lists
            inst_list_index = self.instructions.index(jmp) + 1

            jmp_list_index = self.jmp_list.index(jmp)

            #build new jmp
            new_jmp, size = self.create_jmp_conversion(jmp)

            #nop out previous instruction
            nops = b"\x90" * jmp.size()
            jmp.bytes = nops

            #change mnem so it is no longer hit by jump
            jmp.mnemonic = "nop"

            #remove old jmp from list and replace with new jmp
            self.jmp_list[jmp_list_index] = new_jmp
            self.inserted += 1

            #add the jmp to the instruction list
            self.instructions.insert(inst_list_index, new_jmp)

            #shift all addresses by the new size and add to the total
            jmp_address = new_jmp.address

            #shift insert address if needed
            if insert_address >= jmp_address:
                insert_address += size
            
            for inst in self.instructions[inst_list_index + 1:]:
                #increase the address if below the new jmp instruction
                inst.address += size

            for inst in self.jmp_list:
                if 'j' in inst.mnemonic and '[' not in inst.op_str and '0x' in inst.op_str and inst.mnemonic != 'jrcxz':
                    #backward jmps
                    #if inst.jmp_addr < inst.next_inst:
                    if inst.jmp_addr < inst.address + inst.size():
                        #jmp over the new jmp instruction
                        if inst.jmp_addr < jmp_address and inst.address > jmp_address:
                            #inst.next_inst += size
                            inst.rip_offset -= size

                        #both are under the new jmp instruction
                        elif inst.address > jmp_address:
                        #else:
                            inst.jmp_addr += size
                            #inst.next_inst += size

                    #forward jmps
                    else:
                        #jmp over the new jmp instruction
                        if inst.address < jmp_address and inst.jmp_addr >= jmp_address:
                            inst.jmp_addr += size
                            inst.rip_offset += size

                        #both are under the new jmp instruction
                        elif inst.address > jmp_address:
                            inst.jmp_addr += size
                            #inst.next_inst += size

            
            #fix relocation table and call list
            for inst in self.call_list:
                #needs to be able to be negative
                rip_offset = inst.address + 5
                value = struct.unpack("<i", inst.bytes[-4:])[0]
                call_target = rip_offset + value


                #think about <= or >=
                if rip_offset < insert_address and call_target >= insert_address:
                    #value += total_size
                    value += size
                elif call_target < insert_address and rip_offset > insert_address:
                    #value -= total_size
                    value -= size

                inst.bytes = inst.bytes[:-4] + struct.pack("<i", value) 

            for inst in self.text_relatives:
                offset = inst[0]
                instruction = inst[1]
                value = offset - instruction.address - instruction.size()
                #Backwards lookup over insert
                if offset < insert_address and instruction.address >= insert_address:
                    #put instruction. back together
                    instruction.bytes = instruction.bytes[:instruction.offset] + struct.pack("<i", value) + instruction.bytes[instruction.offset+4:]

                #Forwards lookup over insert
                elif offset >= insert_address and instruction.address < insert_address:
                    value += size
                    inst[0] += size

                    #put instruction back together
                    instruction.bytes = instruction.bytes[:instruction.offset] + struct.pack("<i", value) + instruction.bytes[instruction.offset+4:]

                #Both offset and address are under the insert
                elif offset >= insert_address and instruction.address >= insert_address:
                    inst[0] += size

            return True, size, new_jmp
        else:
            return False, size, jmp

    #fix the jmps of a instruction list
    def insert_and_shift(self, insert):
        insert_address = insert.address
        insert_size = insert.size()
        counter = 0
        shift = False
        again = True
        temp_offset = 0
        size = 0
        total_size = insert_size
        inst = 0
    
        #shift the address of the instructions and add the new instruction to the list
        for inst in self.instructions:
            if inst.address == insert_address:
                inst.address += insert_size
                shift = True
            elif inst.address > insert_address and not shift:
                break
            else:
                if (shift):
                    inst.address += insert_size
                else:
                    counter += 1

        if not shift and inst.address != insert_address and inst.address + inst.size() != insert_address:
            exit(-6)
            return

        self.instructions.insert(counter, insert)
        #first jmp pass
        for jmp in self.jmp_list:

            jmp_loc = jmp.jmp_addr
            rip = jmp.address + jmp.size()
            offset = jmp.rip_offset

            #backward jmps
            if jmp_loc < rip:
                #jmp over insert
                if jmp.address >= insert_address and jmp.jmp_addr < insert_address:
                    jmp.rip_offset -= insert_size

                    #check to see if the instruction needs to be converted to 5 bytes
                    #then change the offsets of all the instructions
                    shift, size, jmp = self.jmp_conversion_shift(insert_address, jmp)
                    if shift == True:
                        total_size += size

                    #standard non 2 byte jump
                    elif jmp.size() >= 5:
                        temp_offset = jmp.rip_offset
                        jmp.bytes = jmp.bytes[:-4] + temp_offset.to_bytes(4, "little", signed=True)

                    #standard 2 byte jump
                    else:
                        temp_offset = jmp.rip_offset
                        try:
                            jmp.bytes = jmp.bytes[:-1] + temp_offset.to_bytes(1, "little", signed=True)
                        except:
                            print("bad jump bytes 1")
                            print(hex(temp_offset))
                            exit(-7)

                #both are under insert
                #elif jmp.address < insert_address and jmp.jmp_addr > insert_address:
                else:
                    jmp.jmp_addr += insert_size

                    #check to see if the instruction needs to be converted to 5 bytes
                    #then chnage the offsets of all the instructions
                    #don't think this should ever happend
                    shift, size, jmp = self.jmp_conversion_shift(insert_address, jmp)
                    if shift == True:
                        total_size += size
            #forward jmps
            else:
                #jmp over insert
                if jmp.address < insert_address and jmp.jmp_addr >= insert_address:
                    jmp.jmp_addr += insert_size
                    jmp.rip_offset += insert_size

                    #check to see if the instruction needs to be converted to 5 bytes
                    #then chnage the offsets of all the instructions
                    shift, size, jmp = self.jmp_conversion_shift(insert_address, jmp)
                    if shift == True:
                        total_size += size

                    #standard 5 byte jump
                    elif jmp.size() >= 5:
                        jmp.bytes = jmp.bytes[:-4] + jmp.rip_offset.to_bytes(4, "little", signed = True)

                    #standard 2 byte jump
                    else:
                        try:
                            jmp.bytes = jmp.bytes[:-1] + jmp.rip_offset.to_bytes(1, "little", signed=True)
                        except Exception as e:
                            print(e)
                            print("new jump failed")
                            print(hex(jmp.rip_offset))
                            exit(-8)

                #both are under insert
                #convert to else?
                #elif jmp.address > insert_address and jmp.jmp_addr < insert_address:
                else:
                    jmp.jmp_addr += insert_size
                    #jmp.next_inst += insert_size

                    #check to see if the instruction needs to be converted to 5 bytes
                    #then chnage the offsets of all the instructions
                    shift, size, jmp = self.jmp_conversion_shift(insert_address, jmp)
                    if shift == True:
                        total_size += size

        #Make every other pass
        counter = -1
        while again:
            counter += 1
            again = False
            for jmp in self.jmp_list:
                #check to see if the instruction needs to be converted to 5 bytes
                #then change the offets of all the instructions
                shift, size, jmp = self.jmp_conversion_shift(insert_address, jmp)

                if shift == True:
                    total_size += size
                    again = True

                #standard 5 byte jump
                elif jmp.size() >= 5:
                    #check for negative offset
                    if jmp.rip_offset < 0:
                        temp_offset = jmp.rip_offset
                        jmp.bytes = jmp.bytes[:-4] + temp_offset.to_bytes(4, "little", signed=True)
                    else:
                        jmp.bytes = jmp.bytes[:-4] + jmp.rip_offset.to_bytes(4, "little")

                #standard 2 byte jump
                else:
                    #check for negative offset
                    if jmp.rip_offset < 0:
                        temp_offset = jmp.rip_offset
                        try:
                            jmp.bytes = jmp.bytes[:-1] + temp_offset.to_bytes(1, "little", signed=True)
                        except:
                            print(hex(temp_offset))
                            print("jump bytes bad 3 ")
                            exit(-1)
                    else:
                        try:
                            jmp.bytes = jmp.bytes[:-1] + jmp.rip_offset.to_bytes(1, "little")
                        except:
                            print("jump bytes bad 2 ")
                            exit(-10)

        for inst in self.call_list:
            #needs to be able to be negative
            rip_offset = inst.address + 5
            value = struct.unpack("<i", inst.bytes[-4:])[0]
            call_target = rip_offset + value


            #think about <= or >=
            if rip_offset < insert_address and call_target >= insert_address:
                #value += total_size
                value += insert_size
            elif call_target < insert_address and rip_offset > insert_address:
                #value -= total_size
                value -= insert_size

            inst.bytes = inst.bytes[:-4] + struct.pack("<i", value) 

        for inst in self.text_relatives:
            offset = inst[0]
            instruction = inst[1]
            value = offset - instruction.address - instruction.size()
            #Backwards lookup over insert
            if offset < insert_address and instruction.address >= insert_address:
                #put instruction. back together
                instruction.bytes = instruction.bytes[:instruction.offset] + struct.pack("<i", value) + instruction.bytes[instruction.offset+4:]

            #Forwards lookup over insert
            elif offset >= insert_address and instruction.address < insert_address:
                value += insert_size
                inst[0] += insert_size

                #put instruction back together
                instruction.bytes = instruction.bytes[:instruction.offset] + struct.pack("<i", value) + instruction.bytes[instruction.offset+4:]

            #Both offset and address are under the insert
            elif offset >= insert_address and instruction.address >= insert_address:
                inst[0] += insert_size

        return total_size

    #Create the list of instructions needed to change the instruction
    def create_insertion (self, inst, address):
        opcode = b""
        ks_opcode = 0

        #can just insert one nop under the jmp instruction to shift it down
        nop = "nop"
        nop = nop.encode()
        ks_opcode = ks.asm(nop)

        for value in ks_opcode[0]:
            opcode += value.to_bytes(1,"little")

            for i in self.md.disasm(opcode, address):
                i = Instruction(i,1)
                i.address = address + inst.size()
                self.insert_and_shift(i)

        return

    #Convert a instruction that creates a rop gadget into a list of instructions that will
    #Remove it
    def fix_rop_instruction (self, inst, address, index): 
        opcode = b""
        temp_reg = ""
        fix = 0
        ks_opcode = 0
        instructions = ""
        save = False
        fix_relative = False
        negative = False

        #the b registers have a c3 in the opcode for the following
        #a registers are used
        #r8 registers are used
        #constant value is used

        #the r11 registers have a c3 in the opcode for the following
        #a registers are used
        #r8 registers are used
        #constant value is used

        #mid instruction return
        if 'c3' in inst.bytes.hex():
            ptr_str = ''

            # grab the ptr <size> from mov ptr <size> [...], ...
            if 'ptr' in inst.op_str:
                ptr_str = inst.op_str.split('[')[0]
                #check if it is mov ... , ptr <size> [...]
                if ',' in ptr_str:
                    ptr_str = ptr_str.split(',')[1]

            #check if the byte 0xc3 is being caused by a constant in the instruction
            if re.search("[^\-][\s]*0x[\w]*c3([\w]{2})*",inst.op_str) or re.search("\-[\s]*0x[\w]*3d[^\w]",inst.op_str) or re.search("\-[\s]*0x[\w]*3c([\w]{2})+",inst.op_str):

                #check to see if there are multiple operands in the instruction
                if ',' in inst.op_str:
                    #check if there are 3 operands. Currently don't support this
                    if len(inst.op_str.split(',')) == 3:
                        return
                    
                    #check for [<reg + (reg * num)> +/- 0xc3]
                    #only looking at mov and lea
                    if '[' in inst.op_str and (inst.mnemonic == "lea" or inst.mnemonic == "mov"):
                        #print (inst.op_str)
                        #break the instruction apart and store the values
                        single, sub_insts, regs, reg_size = self.get_instruction_information(inst.op_str)
                        
                        #first available register (except for the b registers)
                        temp_reg = self.reg_list[regs[0]][reg_size]
                        #grab the value that is causing the c3 byte
                        c3_value = int(inst.op_str.split('0x')[1].split(']')[0],16)
                        
                        #convert to negative value if needed
                        #print (sub_insts)
                        if sub_insts != []:
                            if sub_insts[1][-1] == "-":
                                c3_value = c3_value * -1

                        #-3d is still a one byte value
                        if c3_value == -61:
                            fix = 1

                        #every other value
                        else:
                            temp_value = c3_value

                            if temp_value < 0:
                                temp_value += 0x100000000
                            for x in range(0,4):
                                temp = (temp_value >> (x*8)) & 0xff
                                if temp == 0xc3:
                                    fix += pow(256,x)

                        #check for [rip + 0xc3] going to assume that it will be reg, [rip+value] and not [rip+value], reg
                        if "rip" in inst.op_str and ("lea" in inst.mnemonic or "mov" in inst.mnemonic):

                            #reloc argument was not passed in duing runtime
                            if relocation_fix == False:
                                return

                            for relative in self.relatives:
                                if relative[1] == inst:

                                    #Checks if the single value is not a register eg mov [rip + 0x10], 1
                                    if not any(single in reg_row for reg_row in self.reg_list):
                                        return False                    

                                    #save the current offset for later
                                    offset = inst.offset
                                    target_address = relative[0]

                                    #remove the current relative entry from the list because it is going to be NOPed out
                                    self.relatives.remove(relative)
                                    fix_relative = True

                                    #need to account for the fix amount and the amount rip is going to be shifted by
                                    new = c3_value - fix - inst.size()

                                    #Example: lea rax, [rip + 0x96bb]; lea rax, [rax + 1]
                                    #check for mov or lea
                                    if inst.mnemonic == "mov":
                                        instructions = f"lea {single}, [rip {sub_insts[1][0]} {hex(new)}]; mov {single}, [{single} + {hex(fix)}]"

                                    else:
                                        instructions = f"lea {single}, [rip {sub_insts[1][0]} {hex(new)}]; lea {single}, [{single} + {hex(fix)}]"
                                
                                    #attempt to build out the instrucion list
                                    instructions = instructions.encode()   
                                    try:
                                        ks_opcode = ks.asm(instructions)
                                    except:
                                        print ("bad")
                                        print(instructions)
                                        exit(-14)
                        
                        #non rip instruction
                        else:
                            pass

                    # standard reg, value or value, reg instruction. Not implemented
                    elif '[' not in inst.op_str and "rip" not in inst.op_str:

                        #grab the register from the op string
                        reg = inst.op_str.split(',')[0].strip()
                        #grab the c3 constant
                        c3_value = int(inst.op_str.split(',')[1].strip(),16)

                        return
            
            #The op code for the instruction is causing the c3
            else:
                #For now just going to solve for mov, add, and sub
                
                #check to see if there are multiple operands in the instruction
                if ',' in inst.op_str:
                    #check if there are 3 operands. Currently don't support this
                    if len(inst.op_str.split(',')) == 3:
                        return
                    
                    if inst.mnemonic != "mov" and inst.mnemonic != "add" and inst.mnemonic != "sub":
                        return
                    
                    #check for memory locations
                    #mov <reg>, <size> ptr [<b register> + <a register>*8] generates a c3
                    if '[' in inst.op_str:
                        pass

                    #The operation is now either <reg>, <reg> or <reg>, <const>
                    else:
                        #grab both of the operands
                        temp_str = inst.op_str.split(',')
                        first_op = temp_str[0].strip()
                        second_op = temp_str[1].strip()

                        #check for the b registers
                        if first_op in self.reg_list[1]:
                            
                            #The b registers have a c3 in the opcode for the following:
                                #a registers are used
                                #r8 registers are used
                                #constant value is used

                            # check for the a registers
                            if second_op in self.reg_list[0]:
                                #get the size of the a register
                                x = self.reg_list[0].index(second_op)
                                #create the same size c register
                                c_reg = self.reg_list[2][x]
                                #Example: xchg rcx, rax; mov rbx, rcx; xchg rcx, rax
                                instructions = f"XCHG {c_reg}, {second_op}; {inst.mnemonic} {first_op}, {c_reg}; XCHG {c_reg}, {second_op}"
                                
                                #attempt to build out the instrucion list
                                instructions = instructions.encode()    
                                try:
                                    ks_opcode = ks.asm(instructions)
                                except:
                                    print(instructions)
                                    exit(-14)
                            
                            # check for the r8 registers
                            elif second_op in self.reg_list[8]:
                                #get the size of the r8 register
                                x = self.reg_list[8].index(second_op)
                                #create the same size c register
                                c_reg = self.reg_list[2][x]
                                #Example: xchg rcx, r8; mov rbx, rcx; xchg rcx, r8
                                instructions = f"XCHG {c_reg}, {second_op}; {inst.mnemonic} {first_op}, {c_reg}; XCHG {c_reg}, {second_op}"
                                
                                #attempt to build out the instrucion list
                                instructions = instructions.encode()    
                                try:
                                    ks_opcode = ks.asm(instructions)
                                except:
                                    print(instructions)
                                    exit(-14)

                            # second operation is a constant value
                            #only going to be checking for mov and add
                            else:
                                #don't need to check if the constant contains a c3 value because of the first if statement checking for the c3 value first
                                
                                #not sure about other instructions other than mov and add as of now
                                if inst.mnemonic == "mov" or inst.mnemonic == "add":
                                    #get the size of the b register
                                    x = self.reg_list[1].index(first_op)    
                                    #create the same size c register
                                    c_reg = self.reg_list[2][x]
                                    #Example: xchg rcx, rbx; add rcx, 5; xchg rcx, rbx
                                    instructions = f"XCHG {c_reg}, {first_op}; {inst.mnemonic} {c_reg}, {second_op}; XCHG {c_reg}, {first_op}"
                                
                                    #attempt to build out the instrucion list
                                    instructions = instructions.encode()    
                                    try:
                                        ks_opcode = ks.asm(instructions)
                                    except:
                                        print(instructions)
                                        exit(-14)

                        #check for the r11 registers                     
                        elif first_op in self.reg_list[11]:

                            #The r11 registers have a c3 in the opcode for the following: 
                                #a registers are used
                                #r8 registers are used
                                #constant value is used

                            # check for the a registers
                            if second_op in self.reg_list[0]:
                                #get the size of the a register
                                x = self.reg_list[0].index(second_op)
                                #create the same size c register
                                c_reg = self.reg_list[2][x]
                                #Example: xchg rcx, rax; mov rbx, rcx; xchg rcx, rax
                                instructions = f"XCHG {c_reg}, {second_op}; {inst.mnemonic} {first_op}, {c_reg}; XCHG {c_reg}, {second_op}"
                                
                                #attempt to build out the instrucion list
                                instructions = instructions.encode()    
                                try:
                                    ks_opcode = ks.asm(instructions)
                                except:
                                    print(instructions)
                                    exit(-14)
                            
                            # check for the r8 registers
                            elif second_op in self.reg_list[8]:
                                #get the size of the r8 register
                                x = self.reg_list[8].index(second_op)
                                #create the same size c register
                                c_reg = self.reg_list[2][x]
                                #Example: xchg rcx, r8; mov rbx, rcx; xchg rcx, r8
                                instructions = f"XCHG {c_reg}, {second_op}; {inst.mnemonic} {first_op}, {c_reg}; XCHG {c_reg}, {second_op}"
                                
                                #attempt to build out the instrucion list
                                instructions = instructions.encode()    
                                try:
                                    ks_opcode = ks.asm(instructions)
                                except:
                                    print(instructions)
                                    exit(-14)

                            # second operation is a constant value
                            #only going to be checking for mov and add
                            else:
                                #don't need to check if the constant contains a c3 value because of the first if statement checking for the c3 value first
                                
                                #not sure about other instructions other than mov and add as of now
                                if inst.mnemonic == "mov" or inst.mnemonic == "add":
                                    #get the size of the b register
                                    x = self.reg_list[11].index(first_op)    
                                    #create the same size c register
                                    c_reg = self.reg_list[2][x]
                                    #Example: xchg rcx, rbx; add rcx, 5; xchg rcx, rbx
                                    instructions = f"XCHG {c_reg}, {first_op}; {inst.mnemonic} {c_reg}, {second_op}; XCHG {c_reg}, {first_op}"
                                
                                    #attempt to build out the instrucion list
                                    instructions = instructions.encode()    
                                    try:
                                        ks_opcode = ks.asm(instructions)
                                    except:
                                        print(instructions)
                                        exit(-14)
                
                #only one operand
                #only looking at calls and jmps for now
                else:
                    #check for calls
                    global one_call
                    if inst.mnemonic == "call":

                        #call argument was not passed in duing runtime
                        if call_fix == False:
                            return

                        #unlike jmp I can't just split the call into 2 calls (I think)
                        #for now I am only going to fix it if the first byte is the c3
                        #otherwise I have to insert a minimum of 256 nops to shift c3 to c4
                        #Compare the first byte of the call offset to c3
                        fix = 0
                        save = True
                        #loop through each of the offset bytes for the call
                        for x in range(1,5):
                            #check which bytes are a c3
                            if inst.bytes[x] == 0xc3:
                                #amount of nops that need to be inserted
                                fix += pow(256,x-1)

                        #Not going to go past the first byte for now
                        if fix > 1:
                            return 

                        #need to check if is a negative or positive jump
                        #check if the first byte is set
                        if inst.bytes[4] >> 7:
                            negative = True

                        #Only fixing 1 byte fixes for now
                        if fix != 0:

                            instructions = ""
                            #insert the amount of nops need to flip the c3 to a c4
                            for x in range(0,fix):
                                instructions += "NOP;"
    
                            #attempt to build out the instrucion list
                            instructions = instructions.encode()    
                            try:
                                if one_call != True:
                                    ks_opcode = ks.asm(instructions)
                            except:
                                print(instructions)
                                exit(-14)

                            one_call = True
                            
                    #check for jmp instructions
                    elif 'j' in inst.mnemonic and inst.mnemonic != 'jrcxz':
                        big_shift = False

                        #check if the jmp_fix argument was set
                        if allow_jmp_fix == False:
                            return

                        #positive jmp
                        if inst.rip_offset > 0:
                            #don't need to check instruction size because it will always have a 4 byte integer jmp
                            for byte in inst.bytes[-3:]:
                                if byte == 195:
                                    big_shift = True
                                    break

                            #if big_shift is false, the jump does not need to be split into 2 seperate jumps
                            if big_shift == False:

                                #can just insert one nop under the jmp instruction to shift it down
                                nop = "nop"
                                nop = nop.encode()
                                ks_opcode = ks.asm(nop)

                                for value in ks_opcode[0]:
                                    opcode += value.to_bytes(1,"little")

                                    for i in self.md.disasm(opcode, address):
                                        i = Instruction(i,1)
                                        i.address = address + inst.size()
                                        #print('2')
                                        self.insert_and_shift(i)

                                return

                            #split the jmp into 2 smaller jmps
                            else:

                                #loop through the offset bytes and mark the needed shift amount
                                bytes = inst.bytes[-4:]
                                fix = 0
                                for x in range(0,4):
                                    if bytes[x] == 0xc3:
                                        fix += 1 * pow(256,x)

                                #get the index of where we are jumping to
                                #start at the current instruction
                                index = self.instructions.index(inst)

                                #loop through each instruction until the address is found
                                while self.instructions[index].address != inst.jmp_addr:
                                    index += 1

                                #find the first instruction that is at or above the new jmp's value
                                #also need to make room for the 2 bytes the new jmp will create
                                #this is so we don't risk splitting an instruction
                                while True:
                                    if self.instructions[index].address <= inst.jmp_addr - fix - 2:
                                        break

                                    index -= 1

                                #fix the current jmp values
                                #fix now equals the difference between the old jmp target and the newly found safe address
                                fix = inst.jmp_addr - self.instructions[index].address
                                #the jmp target is now the safe address
                                inst.jmp_addr = self.instructions[index].address
                                #subtract the fix from the old offset
                                inst.rip_offset = inst.rip_offset - fix

                                #need to create 2 new jmp instructions
                                op_code = b""

                                #jmp that links the old jmp back to where it should jmp to
                                #minus to is accounting for the new jmp that will be inserted right after
                                offset = fix-2

                                jmp_fix = f"jmp {offset}".encode()
                                kap_op_code = ks.asm(jmp_fix)

                                #convert to an actual op_code
                                for value in kap_op_code[0]:
                                    op_code += value.to_bytes(1,"little")

                                #covert to our data structure
                                jmp_fix = self.build_instruction(op_code, self.instructions[index].address)

                                #add all the jmp instruction values
                                jmp_fix.jmp_addr = int(jmp_fix.op_str,16)
                                jmp_fix.next_inst = jmp_fix.address + jmp_fix.size()
                                jmp_fix.rip_offset = offset - jmp_fix.size()

                                #create the jmp that skips over the linking jmp
                                op_code = b""

                                #have to add 2 because of kapstone
                                offset = jmp_fix.size()+2

                                jmp_over = f"jmp {offset}".encode()
                                kap_op_code = ks.asm(jmp_over)

                                #convert to an actual op_code
                                for value in kap_op_code[0]:
                                    op_code += value.to_bytes(1,"little")

                                #covert to our data structure
                                jmp_over = self.build_instruction(op_code, self.instructions[index].address)

                                #add all the jmp instruction values
                                jmp_over.jmp_addr = jmp_over.address + 2 + jmp_fix.size()
                                jmp_over.next_inst = jmp_over.address + jmp_over.size()
                                jmp_over.rip_offset = offset - 2

                                #insert the 2 jmps into the list
                                jmps = jmp_fix,jmp_over
                                for jmp in jmps:
                                    self.insert_and_shift(jmp)
                                    #insert_and_shift shifts some vaules and we have to counter shift
                                    if jmp == jmp_fix:
                                        inst.jmp_addr -= 5
                                        inst.rip_offset -= 5
                                        #also doesn't seem to be adding the 5 bytes to the linking jmp
                                        jmp.jmp_addr += 5
                                        jmp.rip_offset += 5

                                return

                        #negative jmp
                        else:
                            #have to check if it is a 2 byte jmp or not
                            if inst.size() >= 5:
                                for byte in inst.bytes[-3:]:
                                    if byte == 195:
                                        big_shift = True
                                        break

                            #check to make the the kapstone shift is still working
                            #if big_shift is false, the jump does not need to be split into 2 seperate jumps
                            if big_shift == False:
                                #can just insert one nop above the jmp instruction to shift it down
                                nop = "nop"
                                nop = nop.encode()
                                ks_opcode = ks.asm(nop)

                                for value in ks_opcode[0]:
                                    opcode += value.to_bytes(1,"little")

                                    for i in self.md.disasm(opcode, address):
                                        i = Instruction(i,1)
                                        i.address = address
                                        self.insert_and_shift(i)

                                    return

                            #split the jmp into 2 smaller jmps
                            else:
                                bytes = inst.bytes[-4:]
                                fix = 0
                                for x in range(0,4):
                                    if bytes[x] == 0xc3:
                                        fix += 1 * pow(256,x)

                                #get the current index of the instruction
                                index = self.instructions.index(inst)

                                #find the first instruction that is at or below the new jmp's value
                                #this is so we don't risk splitting an instruction
                                while True:
                                    if self.instructions[index].address <= inst.jmp_addr + fix:
                                        break

                                    index -= 1

                                #fix the current jmp values
                                fix = self.instructions[index].address - inst.jmp_addr
                                inst.jmp_addr = self.instructions[index].address
                                inst.rip_offset = inst.rip_offset + fix

                                #need to create 2 new jmp instructions
                                op_code = b""

                                #jmp that links the old jmp back to where it should jmp to
                                #convert fix back to a negative number
                                offset = fix*-1

                                jmp_fix = f"jmp {offset}".encode()
                                kap_op_code = ks.asm(jmp_fix)

                                #convert to an actual op_code
                                for value in kap_op_code[0]:
                                    op_code += value.to_bytes(1,"little")

                                #covert to our data structure
                                jmp_fix = self.build_instruction(op_code, self.instructions[index].address)

                                #add all the jmp instruction values
                                jmp_fix.jmp_addr = int(jmp_fix.op_str,16)
                                jmp_fix.next_inst = jmp_fix.address + jmp_fix.size()
                                jmp_fix.rip_offset = offset - jmp_fix.size()

                                #create the jmp that skips over the linking jmp
                                op_code = b""

                                offset = jmp_fix.size()+2

                                jmp_over = f"jmp {offset}".encode()
                                kap_op_code = ks.asm(jmp_over)

                                #convert to an actual op_code
                                for value in kap_op_code[0]:
                                    op_code += value.to_bytes(1,"little")

                                #covert to our data structure
                                jmp_over = self.build_instruction(op_code, self.instructions[index].address)

                                #add all the jmp instruction values
                                jmp_over.jmp_addr = jmp_over.address + 2 + jmp_fix.size()
                                jmp_over.next_inst = jmp_over.address + jmp_over.size()
                                jmp_over.rip_offset = offset - 2

                                #insert the 2 jmps into the list
                                jmps = jmp_fix,jmp_over
                                for jmp in jmps:
                                    #print('3')
                                    self.insert_and_shift(jmp)
                                    #insert_and_shift shifts some vaules and we have to counter shift
                                    if jmp == jmp_fix:
                                        inst.jmp_addr -= 5
                                        inst.rip_offset -= 5

                                return

        #check for keystone encoded instructions and convert to little endian
        if ks_opcode and ks_opcode[0]:
            for value in ks_opcode[0]:
                opcode += value.to_bytes(1,"little")

            #some of the fixes simply insert under the instruction and want to keep the old instruction
            #Example call c3 will simply insert a nop under and let the insert and shift handle the modifcation
            if save == False:

                #"Destroy" old instruction
                inst.mnemonic = 'nop'
                nops = b"\x90" * inst.size()
                inst.bytes = nops

                #set the first address as the address after the now "destroyed" instruction
                address += inst.size()

            #Need to check if it was a negative or positive call
            else:
                if negative:
                    address = inst.address
                else:
                    address += inst.size()

            relative_inserted = False
            #loop through each instruction in the created list
            for i in self.md.disasm(opcode, address):
                i = Instruction(i,1)
                #insert the new instruction back into the self.relatives list
                if fix_relative and not relative_inserted:
                    relative_inserted = True
                    i.offset = offset
                    self.relatives.append([target_address,i,fix])
 
                i.address = address

                #insert each instruction
                self.insert_and_shift(i)
                address = i.address + i.size()

        return False
                
    def create_insert_list(self):
        split_rop_count = 0
        bad_insts = []
        #loop through every byte of every instruction

        #for x in self.sections:
        #    print (x.print_name, x.address)

        #Find and remove any gadgets that use a ret that is part of an instruction
        for gadget in gadgets:
            rel_ret = True
            if (gadget.disassemblyString().split(':')[1].strip() == "ret"):

                #ret was created from a bad byte
                if gadget.address not in self.inst_dict:
                    address = gadget.address

                    #print (address)
                    #print (x)
                    #exit()
                    while(address not in self.inst_dict):
                        address -= 1
                    #add to the list to be removed
                    #secondary check to stop repz retq from hitting, more info here https://repzret.org/p/repzret/
                    if self.inst_dict[address] not in bad_insts and self.inst_dict[address].bytes != b'\xf3\xc3':
                        split_rop_count += 1
                        bad_insts.append(self.inst_dict[address])
                        print (self.inst_dict[address])

        check = False                        
        for inst in bad_insts:
            #print (self.instructions[self.instructions.index(self.inst_dict[address])])
            #print ("check")
            #check for movabs. I believe this is the only standard instruction that accepts 8 byte values.
            #doesn't work so it needs to be skipped
            #if inst.mnemoinc == "movabs":
            #   pass
            #if inst.mnemonic != "mov" and inst.mnemonic != "add":
            #    pass
            #else:
            if (True):
                #print(inst, inst.mnemonic)
                index = self.instructions.index(inst)
                check = self.fix_rop_instruction(inst, inst.address,index)
                if check == True:
                    break

        return bad_insts, split_rop_count

    #Convertion of a 2 byte jmp into a 5 byte jmp
    #Create a jmp instruction
    def create_jmp_conversion(self, old_inst):
        op_code = b""
        #Need to increase/decrease the offset because keystone decreases it
        offset = old_inst.rip_offset
        if offset < -0:
            offset -= old_inst.size()
        else:
            offset += old_inst.size()

        #create op code for the new jmp instruction
        jmp_inst = f"{old_inst.mnemonic} {offset}".encode()
        kap_op_code = ks.asm(jmp_inst)

        #convert to an actual op_code
        for value in kap_op_code[0]:
            op_code += value.to_bytes(1,"little")

        size = len(op_code)
        #covert to our data structure
        inst = self.build_instruction(op_code, old_inst.address + old_inst.size())

        #check for forward or backwards jump
        #inst.next_inst = inst.address+size
        if offset < -128:
            inst.jmp_addr = old_inst.jmp_addr
            inst.rip_offset = old_inst.rip_offset-size

        else:
            inst.jmp_addr = old_inst.jmp_addr+size
            inst.rip_offset = old_inst.rip_offset

        return (inst,size)
        
    #generate register and operation information for the given instruction
    def get_instruction_information(self, op_str):
        values = []
        bracket_str = ""
        ops = []
        single = ""
        sub_insts = []
        regs = [True]*16
        reg_size = -1
        #the b register is a pain sometimes so just not going to use it
        regs[1] = False

        match = re.search(",[\w ]*\[", op_str)

        if match:
            single = op_str.split(',')[0].strip()

        else:
            single = op_str.split(',')[1].strip()

        #remove all white space and then grab the values
        bracket_str = op_str.split('[')[1].split(']')[0].strip().replace(" ","")
        tmp_str = bracket_str
        tmp_str = re.split(r"(\W)", tmp_str)
        for x in range(len(tmp_str)):
            if x % 2 == 0:
                values.append(tmp_str[x])
            else:
                ops.append(tmp_str[x])


        #determine what regs are in use
        for row in range(len(self.reg_list)):
            for col in range(0,4):
                if single == self.reg_list[row][col]:
                    regs[row] = False
                    reg_size = col
                    break
                else:
                    #this checks the non-register values too
                    #should probably fix this at some point
                    for value in values:
                        if value == self.reg_list[row][col]:
                            regs[row] = False
                            reg_size = col
                            break

        regs = [index for index, value in enumerate(regs) if value == True]

        #create a sublist of the orignial instruction
        try:
            check = int(values[-1],16)
            check = True
        except:
            check = False

        if check and (ops[-1] == '+' or ops[-1] == '-'):
            sub_insts.append(bracket_str.rsplit(ops[-1],1)[0])
            sub_insts.append(ops[-1] + values[-1])
        else:
            sub_insts = bracket_str

        return single, sub_insts, regs, reg_size

import sys
check = False
try:
    in_file  = sys.argv[1]
    out_file = sys.argv[2]

    if len(sys.argv) >= 4:

        if sys.argv[3] == "check":
            check = True

        else:
            fixes = sys.argv[3]
        
            if fixes == "all":
                relocation_fix = True
                call_fix = True
                allow_jmp_fix = True
            elif fixes == "reloc":
                relocation_fix = True
            elif fixes == "call":
                call_fix = True
            elif fixes == "jmp":
                allow_jmp_fix = True

except Exception as e:
    print(e)
    print("Usage: python Neptunia.py org_binary new_binary fix")
    exit(0)
elf = Gamindustri(sys.argv[1])
#elf.get_additional_inst_info()
elf.DEBUG = 0

#Gadgets
ls = in_file
rs = RopperService()

rs.addFile(ls)

rs.setArchitectureFor(name=ls, arch='x86_64')

rs.options.type = 'rop'
rs.options.all = True
rs.options.inst_count = 1
rs.loadGadgetsFor(name=ls)

gadgets = rs.getFileFor(name=ls).gadgets

gadgets = sorted(gadgets, key=operator.attrgetter("address"))

print (len(gadgets))
i, split_rop_count = elf.create_insert_list()

print (split_rop_count)
#for gadget in i:
#    print (gadget)
#for x in range(4000):
#    i = elf.build_instruction(b'\x90', elf.instructions[0].address)

#    elf.insert_and_shift(i)


print()

#for instruction in elf.instructions:
#    print(instruction)

if check == False:
    with open(out_file,'wb') as f:
        f.write(elf.build())
