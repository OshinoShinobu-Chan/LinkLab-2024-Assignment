#include "fle.hpp"
#include <cassert>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>

static const size_t ENTRY_POINT = 0x400000;
static const size_t PAGE_SIZE = 0x1000;

struct Relocation_ {
    size_t write_position;
    std::string obj;
    std::string section;
    Relocation reloc;
};

bool check_reloc_addr(const Relocation& reloc, size_t addr)
{
    size_t high;
    switch (reloc.type) {
    case RelocationType::R_X86_64_32:
        high = (addr >> 32) & 0xFFFFFFFF;
        return high == 0;
    case RelocationType::R_X86_64_32S:
        high = (addr >> 32) & 0xFFFFFFFF;
        return high == 0 || high == 0xFFFFFFFF;
    default:
        return true;
    }
}

void write_reloc(const Relocation_& reloc, std::vector<uint8_t>& data, size_t addr, size_t reloc_section_offset)
{
    if (reloc.reloc.type == RelocationType::R_X86_64_32 || reloc.reloc.type == RelocationType::R_X86_64_32S) {
        printf("write reloc: %lx, position: %lx\n", addr, reloc.write_position);
        fflush(stdout);
        data[reloc.write_position] = (uint8_t)(addr & 0xFF);
        data[reloc.write_position + 1] = (uint8_t)((addr >> 8) & 0xFF);
        data[reloc.write_position + 2] = (uint8_t)((addr >> 16) & 0xFF);
        data[reloc.write_position + 3] = (uint8_t)((addr >> 24) & 0xFF);
    } else if (reloc.reloc.type == RelocationType::R_X86_64_PC32) {
        size_t rel = addr + reloc.reloc.addend - reloc.reloc.offset - reloc_section_offset;
        printf("write reloc: %lx, symbol: %s, position: %lx, addr: %lx, addend: %lx, offset: %lx\n",
            rel, reloc.reloc.symbol.c_str(), reloc.write_position, addr, reloc.reloc.addend, reloc.reloc.offset + reloc_section_offset);
        fflush(stdout);
        data[reloc.write_position] = (uint8_t)(rel & 0xFF);
        data[reloc.write_position + 1] = (uint8_t)((rel >> 8) & 0xFF);
        data[reloc.write_position + 2] = (uint8_t)((rel >> 16) & 0xFF);
        data[reloc.write_position + 3] = (uint8_t)((rel >> 24) & 0xFF);
    } else {
        data[reloc.write_position] = (uint8_t)(addr & 0xFF);
        data[reloc.write_position + 1] = (uint8_t)((addr >> 8) & 0xFF);
        data[reloc.write_position + 2] = (uint8_t)((addr >> 16) & 0xFF);
        data[reloc.write_position + 3] = (uint8_t)((addr >> 24) & 0xFF);
        data[reloc.write_position + 4] = (uint8_t)((addr >> 32) & 0xFF);
        data[reloc.write_position + 5] = (uint8_t)((addr >> 40) & 0xFF);
        data[reloc.write_position + 6] = (uint8_t)((addr >> 48) & 0xFF);
        data[reloc.write_position + 7] = (uint8_t)((addr >> 56) & 0xFF);
    }
}

std::string get_prefix(const std::string& input)
{
    size_t firstDotPos = input.find('.');
    if (firstDotPos == std::string::npos) {
        // 如果没有找到第一个点，返回空字符串
        return "";
    }

    size_t secondDotPos = input.find('.', firstDotPos + 1);
    if (secondDotPos == std::string::npos) {
        // 如果没有找到第二个点，返回空字符串
        return input;
    }

    // 返回第二个点之前的内容
    return input.substr(0, secondDotPos);
}

FLEObject FLE_ld(const std::vector<FLEObject>& objects)
{
    // TODO: 实现链接器
    // 1. 收集和合并段
    //    - 遍历所有输入对象的段
    //    - 按段名分组并计算偏移量
    //    - 设置段的属性（读/写/执行）

    // 2. 处理符号
    //    - 收集所有全局符号和局部符号
    //    - 处理符号冲突（强符号/弱符号）

    // 3. 重定位
    //    - 遍历所有重定位项
    //    - 计算并填充重定位值
    //    - 注意不同重定位类型的处理

    // 4. 生成可执行文件
    //    - 设置程序入口点（_start）
    //    - 确保所有必要的段都已正确设置
    FLEObject exe;
    std::map<std::string, Symbol> global_symbols;
    std::map<std::string, std::map<std::string, Symbol>> local_symbols_g;
    std::vector<Relocation_> global_relocations = std::vector<Relocation_>();
    size_t size = 0;
    exe.type = ".exe";
    exe.name = "a.out";
    exe.entry = ENTRY_POINT;

    FLESection text;
    text.name = ".text";
    SectionHeader text_hdr;
    text_hdr.name = ".text";
    text_hdr.type = 1;
    text_hdr.flags = 1;
    text_hdr.size = 0;

    FLESection data;
    data.name = ".data";
    SectionHeader data_hdr;
    data_hdr.name = ".data";
    data_hdr.type = 1;
    data_hdr.flags = 1;
    data_hdr.size = 0;

    FLESection bss;
    bss.name = ".bss";
    SectionHeader bss_hdr;
    bss_hdr.name = ".bss";
    bss_hdr.type = 8;
    bss_hdr.flags = 9;
    bss_hdr.size = 0;

    FLESection rodata;
    rodata.name = ".rodata";
    SectionHeader rodata_hdr;
    rodata_hdr.name = ".rodata";
    rodata_hdr.type = 1;
    rodata_hdr.flags = 1;
    rodata_hdr.size = 0;

    // merge sections
    for (const auto& obj : objects) {
        printf("object: %s\n", obj.name.c_str());
        std::map<std::string, Symbol> local_symbols;
        std::map<std::string, size_t> section_offsets;
        for (const auto& s : obj.shdrs) {
            FLESection section = obj.sections.at(s.name);
            std::string name = s.name;
            FLESection* target_section;
            SectionHeader* target_hdr;
            if (get_prefix(name) == ".text") {
                target_section = &text;
                target_hdr = &text_hdr;
            } else if (get_prefix(name) == ".data") {
                target_section = &data;
                target_hdr = &data_hdr;
            } else if (get_prefix(name) == ".bss") {
                target_section = &bss;
                target_hdr = &bss_hdr;
            } else if (get_prefix(name) == ".rodata") {
                target_section = &rodata;
                target_hdr = &rodata_hdr;
            } else {
                throw std::runtime_error("Unknown section: " + name);
            }
            section_offsets.insert({ name, target_hdr->size });
            target_hdr->size += s.size;
            if (target_section->name != ".bss")
                target_section->data.insert(target_section->data.end(), section.data.begin(), section.data.end());

            printf("section: %s, offset: %lx, size: %lx\n", name.c_str(), target_hdr->size - s.size, s.size);
        }

        for (const auto& symbol : obj.symbols) {
            printf("symbol: %s, type: %d, section: %s, offset: %lx\n", symbol.name.c_str(), symbol.type, symbol.section.c_str(), symbol.offset);
            if (symbol.type == SymbolType::GLOBAL) {
                Symbol new_symbol;
                new_symbol.name = symbol.name;
                new_symbol.offset = section_offsets[symbol.section] + symbol.offset;
                new_symbol.type = symbol.type;
                new_symbol.section = get_prefix(symbol.section);
                new_symbol.size = symbol.size;

                if (global_symbols.find(symbol.name) != global_symbols.end()) {
                    if (global_symbols[symbol.name].type == SymbolType::WEAK || global_symbols[symbol.name].type == SymbolType::UNDEFINED) {
                        global_symbols[symbol.name] = new_symbol;
                    } else {
                        throw std::runtime_error("Multiple definition of strong symbol: " + symbol.name);
                    }
                } else {
                    global_symbols.insert({ symbol.name, new_symbol });
                }
            } else if (symbol.type == SymbolType::UNDEFINED) {
                if (global_symbols.find(symbol.name) == global_symbols.end()) {
                    Symbol new_symbol;
                    new_symbol.name = symbol.name;
                    new_symbol.type = symbol.type;
                    new_symbol.section = "";
                    new_symbol.size = symbol.size;
                    global_symbols.insert({ symbol.name, new_symbol });
                }
            } else if (symbol.type == SymbolType::LOCAL) {
                if (local_symbols.find(symbol.name) != local_symbols.end()) {
                    throw std::runtime_error("Multiple definition of local symbol: " + symbol.name);
                } else {
                    Symbol new_symbol;
                    new_symbol.name = symbol.name;
                    new_symbol.offset = section_offsets[symbol.section] + symbol.offset;
                    new_symbol.type = symbol.type;
                    new_symbol.section = get_prefix(symbol.section);
                    new_symbol.size = symbol.size;
                    local_symbols.insert({ symbol.name, new_symbol });
                }
            } else {
                Symbol new_symbol;
                new_symbol.name = symbol.name;
                new_symbol.type = symbol.type;
                new_symbol.section = get_prefix(symbol.section);
                new_symbol.size = symbol.size;
                new_symbol.offset = section_offsets[symbol.section] + symbol.offset;
                if (global_symbols.find(symbol.name) == global_symbols.end()) {
                    global_symbols.insert({ symbol.name, new_symbol });
                } else if (global_symbols[symbol.name].type == SymbolType::UNDEFINED) {
                    global_symbols[symbol.name] = new_symbol;
                }
            }
        }
        local_symbols_g.insert({ obj.name, local_symbols });

        printf("local relocation\n");
        // handle local symbols relocation
        for (const auto& [name, section] : obj.sections) {
            for (const auto& reloc : section.relocs) {
                Relocation new_reloc;
                new_reloc.offset = reloc.offset + section_offsets[name];
                new_reloc.symbol = reloc.symbol;
                new_reloc.type = reloc.type;
                new_reloc.addend = reloc.addend;
                Relocation_ new_reloc_;
                new_reloc_.write_position = section_offsets[name] + reloc.offset;
                new_reloc_.obj = obj.name;
                new_reloc_.section = get_prefix(name);
                printf("symbol: %s, section: %s, section_offset: %lx, offset: %lx\n", reloc.symbol.c_str(), new_reloc_.section.c_str(), section_offsets[name], reloc.offset);
                new_reloc_.reloc = new_reloc;
                global_relocations.push_back(new_reloc_);
            }
        }
    }

    std::map<std::string, size_t> section_addr;
    // calc section size and offset
    text_hdr.offset = size;
    text_hdr.addr = ENTRY_POINT + size;
    size += text_hdr.size;
    size = (size + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
    section_addr.insert({ ".text", text_hdr.addr });
    printf(".text: size: %lx, offset: %lx, addr: %lx\n", text_hdr.size, text_hdr.offset, text_hdr.addr);

    data_hdr.offset = size;
    data_hdr.addr = ENTRY_POINT + size;
    size += data_hdr.size;
    size = (size + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
    section_addr.insert({ ".data", data_hdr.addr });
    printf(".data: size: %lx, offset: %lx, addr: %lx\n", data_hdr.size, data_hdr.offset, data_hdr.addr);

    rodata_hdr.offset = size;
    rodata_hdr.addr = ENTRY_POINT + size;
    size += rodata_hdr.size;
    size = (size + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
    section_addr.insert({ ".rodata", rodata_hdr.addr });
    printf(".rodata: size: %lx, offset: %lx, addr: %lx\n", rodata_hdr.size, rodata_hdr.offset, rodata_hdr.addr);

    bss_hdr.offset = size;
    bss_hdr.addr = ENTRY_POINT + size;
    size += bss_hdr.size;
    section_addr.insert({ ".bss", bss_hdr.addr });
    printf(".bss: size: %lx, offset: %lx, addr: %lx\n", bss_hdr.size, bss_hdr.offset, bss_hdr.addr);

    // check undefined symbol
    for (const auto& [name, symbol] : global_symbols) {
        if (symbol.type == SymbolType::UNDEFINED) {
            throw std::runtime_error("Undefined symbol: " + symbol.name);
        }
    }

    // resolve relocations
    for (auto& reloc : global_relocations) {
        size_t addr;
        FLESection* target_section;
        if (global_symbols.find(reloc.reloc.symbol) == global_symbols.end()) {
            if (local_symbols_g[reloc.obj].find(reloc.reloc.symbol) == local_symbols_g[reloc.obj].end()) {
                throw std::runtime_error("Symbol not found: " + reloc.reloc.symbol);
            } else {
                addr = local_symbols_g[reloc.obj][reloc.reloc.symbol].offset;
                printf("local symbol: %s, section: %s, section addr: %lx\n",
                    reloc.reloc.symbol.c_str(), local_symbols_g[reloc.obj][reloc.reloc.symbol].section.c_str(),
                    section_addr[local_symbols_g[reloc.obj][reloc.reloc.symbol].section]);
                fflush(stdout);
                addr += section_addr[local_symbols_g[reloc.obj][reloc.reloc.symbol].section];
            }
        } else {
            addr = global_symbols[reloc.reloc.symbol].offset;
            printf("global symbol: %s, symbol section: %s, section addr: %lx, reloc section: %s, section addr: %lx\n",
                reloc.reloc.symbol.c_str(),
                global_symbols[reloc.reloc.symbol].section.c_str(),
                section_addr[global_symbols[reloc.reloc.symbol].section],
                reloc.section.c_str(),
                section_addr[reloc.section]);
            fflush(stdout);
            addr += section_addr[global_symbols[reloc.reloc.symbol].section];
        }

        if (!check_reloc_addr(reloc.reloc, addr)) {
            throw std::runtime_error("Relocation address invalid: " + reloc.reloc.symbol);
        }

        if (reloc.section == ".text") {
            target_section = &text;
        } else if (reloc.section == ".data") {
            target_section = &data;
        } else if (reloc.section == ".rodata") {
            target_section = &rodata;
        } else if (reloc.section == ".bss") {
            target_section = &bss;
        } else {
            throw std::runtime_error("Unknown section: " + reloc.section);
        }

        printf("reloc section: %s, data size: %lx\n", reloc.section.c_str(), target_section->data.size());
        write_reloc(reloc, target_section->data, addr, section_addr[reloc.section]);
    }

    // set entry point
    if (global_symbols.find("_start") == global_symbols.end()) {
        throw std::runtime_error("Entry point not found");
    } else {
        exe.entry = global_symbols["_start"].offset + text_hdr.addr;
    }

    // has symbols
    // load.has_symbols = global_symbols.size() > 0;

    ProgramHeader text_phdr = {
        .name = ".text", // 描述的是 .load 段
        .vaddr = text_hdr.addr, // 我们使用固定的加载地址 0x400000
        .size = text_hdr.size, // 合并后的总大小
        .flags = (uint32_t)PHF::R | (uint32_t)PHF::X // 可读、可写、可执行，简单地赋予所有权限
    };

    ProgramHeader data_phdr = {
        .name = ".data",
        .vaddr = data_hdr.addr,
        .size = data_hdr.size,
        .flags = (uint32_t)PHF::R | (uint32_t)PHF::W
    };

    ProgramHeader rodata_phdr = {
        .name = ".rodata",
        .vaddr = rodata_hdr.addr,
        .size = rodata_hdr.size,
        .flags = (uint32_t)PHF::R
    };

    ProgramHeader bss_phdr = {
        .name = ".bss",
        .vaddr = bss_hdr.addr,
        .size = bss_hdr.size,
        .flags = (uint32_t)PHF::R | (uint32_t)PHF::W
    };

    exe.phdrs.push_back(text_phdr);
    exe.phdrs.push_back(data_phdr);
    exe.phdrs.push_back(rodata_phdr);
    exe.phdrs.push_back(bss_phdr);

    exe.sections.insert({ ".text", text });
    exe.sections.insert({ ".data", data });
    exe.sections.insert({ ".rodata", rodata });
    exe.sections.insert({ ".bss", bss });

    exe.shdrs.push_back(text_hdr);
    exe.shdrs.push_back(data_hdr);
    exe.shdrs.push_back(rodata_hdr);
    exe.shdrs.push_back(bss_hdr);

    return exe;
}