#pragma once
#include <string>
#include <vector>
#include <zasm/zasm.hpp>

namespace ObfuscatorLib
{

using namespace zasm;

uint32_t regMask(const Reg& reg);
std::string formatFlagsMask(uint32_t mask);
std::string formatRegsMask(uint64_t mask);
std::vector<x86::Gp> maskToRegs(uint64_t mask);

} // namespace ObfuscatorLib
