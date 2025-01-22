#include "fle.hpp"
#include <cassert>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>

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
    FLESection load;
    std::map<std::string, Symbol> global_symbols;
    size_t offset = 0x400000;
    size_t size = 0;
    exe.type = ".exe";
    exe.name = "a.out";
    exe.entry = offset;

    load.name = ".load";
    load.has_symbols = false;

    // merge sections
    for (const auto& obj : objects) {
        std::map<std::string, size_t> section_offsets;
        for (const auto& [name_, section] : obj.sections) {
            load.data.insert(load.data.end(), section.data.begin(), section.data.end());
            load.relocs.insert(load.relocs.end(), section.relocs.begin(), section.relocs.end());
            section_offsets.insert({ name_, offset });
            printf("section: %s, offset: %lx\n", name_.c_str(), offset);

            offset += section.data.size();
            size += section.data.size();
        }
        for (const auto& symbol : obj.symbols) {
            if (symbol.type == SymbolType::GLOBAL) {
                Symbol new_symbol;
                new_symbol.name = symbol.name;
                new_symbol.offset = section_offsets[symbol.section] + symbol.offset;
                new_symbol.type = symbol.type;
                new_symbol.section = ".load";
                new_symbol.size = symbol.size;

                if (global_symbols.find(symbol.name) != global_symbols.end()) {
                    if (global_symbols[symbol.name].type == SymbolType::WEAK || global_symbols[symbol.name].type == SymbolType::UNDEFINED) {
                        global_symbols[symbol.name] = new_symbol;
                    } else {
                        throw std::runtime_error("Symbol conflict: " + symbol.name);
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
            }
        }
    }

    // check undefined symbol
    for (const auto& symbol : exe.symbols) {
        if (symbol.type == SymbolType::UNDEFINED) {
            throw std::runtime_error("Undefined symbol: " + symbol.name);
        }
    }

    // resolve relocations
    for (const auto& reloc : load.relocs) {
        if (global_symbols.find(reloc.symbol) == global_symbols.end()) {
            throw std::runtime_error("Undefined symbol: " + reloc.symbol);
        }
        size_t addr = global_symbols[reloc.symbol].offset;
        if (!check_reloc_addr(reloc, addr)) {
            throw std::runtime_error("Relocation address invalid: " + reloc.symbol);
        }
        load.data[reloc.offset] = (uint8_t)(addr & 0xFF);
        load.data[reloc.offset + 1] = (uint8_t)((addr >> 8) & 0xFF);
        load.data[reloc.offset + 2] = (uint8_t)((addr >> 16) & 0xFF);
        load.data[reloc.offset + 3] = (uint8_t)((addr >> 24) & 0xFF);
    }

    // erase relocations
    load.relocs.clear();

    // set entry point
    if (global_symbols.find("_start") == global_symbols.end()) {
        throw std::runtime_error("Entry point not found");
    } else {
        exe.entry = global_symbols["_start"].offset;
    }

    // has symbols
    load.has_symbols = global_symbols.size() > 0;

    ProgramHeader header = {
        .name = ".load", // 描述的是 .load 段
        .vaddr = 0x400000, // 我们使用固定的加载地址 0x400000
        .size = size, // 合并后的总大小
        .flags = (uint32_t)PHF::R | (uint32_t)PHF::W | (uint32_t)PHF::X // 可读、可写、可执行，简单地赋予所有权限
    };
    exe.phdrs.push_back(header);
    exe.sections.insert({ ".load", load });

    return exe;
}