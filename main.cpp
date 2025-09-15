#include <iostream>   // 標準入出力
#include <iomanip>    // 出力フォーマット操作
#include <sstream>    // 文字列ストリーム
#include <string>     // std::string

#include <array>      // 固定長配列
#include <vector>     // 可変長配列
#include <map>        // 連想配列

#include <tuple>      // 複数の型をまとめる
#include <functional> // std::function
#include <stdexcept>  // 標準例外

#include <algorithm>  // sort, find など

#include <bitset>     // ビット操作
#include <cstdint>    // 固定幅整数
#include <cstring>    // メモリ操作

#include <chrono>     // 時間管理
#include <thread>     // マルチスレッド

using instruction_word = uint32_t;

// ANSI カラーコード
namespace Colors {
    constexpr const char* RESET = "\033[0m";
    constexpr const char* RED = "\033[31m";
    constexpr const char* GREEN = "\033[32m";
    constexpr const char* YELLOW = "\033[33m";
    constexpr const char* BLUE = "\033[34m";
    constexpr const char* MAGENTA = "\033[35m";
    constexpr const char* CYAN = "\033[36m";
    constexpr const char* BOLD = "\033[1m";
    constexpr const char* DIM = "\033[2m";
}

// CPU 設定
namespace CPUConfig {
    constexpr double ALUDelay = 0.8;
    constexpr uint8_t RegCount = 16;
    constexpr bool UseZeroReg = true;
    constexpr double RegReadDelay = 0.4;
    constexpr double RegWriteDelay = 0.4;
}

// ALUのオペコードの定義
enum class ALU_Opcode : uint8_t {
    ADD  = 0b0000, ADC  = 0b0001, SBC  = 0b0010, SUB  = 0b0011,
    NOR  = 0b0100, AND  = 0b0101, XOR  = 0b0110, RSH  = 0b0111,
    LRO  = 0b1000, RRO  = 0b1001, BSET = 0b1010, BCLR = 0b1011,
    BNOT = 0b1100
};

// フラグビットの定義
namespace Flags {
    constexpr uint8_t P = 1 << 0; // Parity (Odd/Even of LSB)
    constexpr uint8_t Z = 1 << 1; // Zero
    constexpr uint8_t C = 1 << 2; // Carry
}

// アセンブリをマシンコードに変換するクラス
class Assembler {
public:
    // コンストラクタ
    Assembler() {
        initializeInstructionSet();
        initializeConditionAliases();
        initializeSpecialRegisters();
    }

    // アセンブル実行
    bool assemble(const std::string& source) {
        labels.clear();
        machineCode.clear();
        errors.clear();

        std::vector<std::string> lines;
        std::istringstream stream(source);
        std::string line;
        while (std::getline(stream, line)) {
            lines.push_back(line);
        }

        firstPass(lines);
        if (errors.empty()) {
            secondPass(lines);
        }

        return errors.empty();
    }

    const std::vector<instruction_word>& getMachineCode() const { return machineCode; }
    const std::vector<std::string>& getErrors() const { return errors; }

private:
    // 命令フォーマット
    enum class Format {
        REG_ABC, OFFSET_AC, REG_AB, REG_A_IMM, REG_A_SPEC_REG, ADDR_ONLY, REG_A, REG_C, COND_ADDR, NONE
    };

    struct InstructionInfo {
        uint8_t opcode;
        Format format;
    };

    std::map<std::string, InstructionInfo> instructionSet;
    std::map<std::string, uint8_t> condTable;
    std::map<std::string, std::string> condAliases;
    std::map<std::string, uint8_t> specialRegisters;
    std::map<std::string, uint16_t> labels;
    std::vector<instruction_word> machineCode;
    std::vector<std::string> errors;

    // 命令セットを初期化する
    void initializeInstructionSet() {
        instructionSet = {
            {"ADD",  {0x00, Format::REG_ABC}},
            {"ADC",  {0x01, Format::REG_ABC}},
            {"SBC",  {0x02, Format::REG_ABC}},
            {"SUB",  {0x03, Format::REG_ABC}},
            {"NOR",  {0x04, Format::REG_ABC}},
            {"AND",  {0x05, Format::REG_ABC}},
            {"XOR",  {0x06, Format::REG_ABC}},
            {"RSH",  {0x07, Format::REG_ABC}},
            {"LRO",  {0x08, Format::REG_ABC}},
            {"RRO",  {0x09, Format::REG_ABC}},
            {"BSET", {0x0A, Format::REG_ABC}},
            {"BCLR", {0x0B, Format::REG_ABC}},
            {"BNOT", {0x0C, Format::REG_ABC}},
            {"ADI",  {0x0D, Format::REG_A_IMM}},
            {"ANI",  {0x0E, Format::REG_A_IMM}},
            {"XRI",  {0x0F, Format::REG_A_IMM}},
            {"LDI",  {0x10, Format::REG_A_IMM}},
            {"SLD",  {0x11, Format::REG_A_SPEC_REG}},
            {"SPS",  {0x12, Format::REG_A}},
            {"PSH",  {0x13, Format::REG_A}},
            {"POP",  {0x14, Format::REG_C}},
            {"CMP",  {0x15, Format::REG_AB}},
            {"CMI",  {0x16, Format::REG_A_IMM}},
            {"JMP",  {0x17, Format::ADDR_ONLY}},
            {"BRH",  {0x18, Format::COND_ADDR}},
            {"CAL",  {0x19, Format::ADDR_ONLY}},
            {"RET",  {0x1A, Format::NONE}},
            {"MST",  {0x1B, Format::OFFSET_AC}},
            {"MLD",  {0x1C, Format::OFFSET_AC}},
            {"PST",  {0x1D, Format::OFFSET_AC}},
            {"PLD",  {0x1E, Format::OFFSET_AC}},
            {"HLT",  {0x1F, Format::NONE}}
        };
    }

    // 条件コードのエイリアスを初期化する
    void initializeConditionAliases() {
        condTable = {
            {"even", 0b0000}, {"odd", 0b0001}, {"<", 0b0010}, {">=", 0b0011},
            {"!=", 0b0100}, {"=", 0b0101}
        };
        condAliases = {
            {"eq", "="}, {"ne", "!="}, {"lo", "<"}, {"hs", ">="}
        };
    }

    // 特殊レジスタ名のエイリアスを初期化する
    void initializeSpecialRegisters() {
        specialRegisters = {
            {"fr", 0}, {"gp", 1}, {"cp", 2}, {"bc", 3}
        };
    }

    // 文字列の前後にある空白文字を削除する
    void trim(std::string& s) {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) {
            s.clear();
            return;
        }
        auto end = s.find_last_not_of(" \t\r\n");
        s = s.substr(start, end - start + 1);
    }

    // 文字列をデリミタで分割する
    std::vector<std::string> split(const std::string& s, char delimiter) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(s);
        while (std::getline(tokenStream, token, delimiter)) {
            trim(token);
            if (!token.empty()) tokens.push_back(token);
        }
        return tokens;
    }

    // 1パス目：ラベルを収集してアドレスを確定する
    void firstPass(const std::vector<std::string>& lines) {
        uint16_t address = 0;
        for (size_t i = 0; i < lines.size(); ++i) {
            std::string line = lines[i];
            auto commentPos = line.find(';');
            if (commentPos != std::string::npos) line = line.substr(0, commentPos);
            
            auto labelPos = line.find(':');
            std::string instructionPart = line;
            if (labelPos != std::string::npos) {
                std::string label = line.substr(0, labelPos);
                trim(label);
                if (labels.count(label)) {
                    errors.push_back("Line " + std::to_string(i + 1) + ": Duplicate label definition for '" + label + "'");
                } else {
                    labels[label] = address;
                }
                instructionPart = line.substr(labelPos + 1);
            }
            
            trim(instructionPart);
            if (!instructionPart.empty()) {
                address++;
            }
        }
    }

    // 2パス目：マシンコードを生成する
    void secondPass(const std::vector<std::string>& lines) {
        for (size_t i = 0; i < lines.size(); ++i) {
            std::string line = lines[i];
            auto commentPos = line.find(';');
            if (commentPos != std::string::npos) line = line.substr(0, commentPos);

            auto labelPos = line.find(':');
            if (labelPos != std::string::npos) line = line.substr(labelPos + 1);
            
            trim(line);
            if (line.empty()) continue;

            try {
                machineCode.push_back(parseLine(line));
            } catch (const std::exception& e) {
                errors.push_back("Line " + std::to_string(i + 1) + ": " + lines[i] + "\n  Error: " + e.what());
            }
        }
    }

    // 1行のアセンブリコードをパースしてマシンコードに変換する
    instruction_word parseLine(const std::string& line) {
        const instruction_word mask = 0x1FFFF; // 17ビットマスク
        std::istringstream iss(line);
        std::string mnemonic, operandStr;
        iss >> mnemonic;
        std::getline(iss, operandStr);
        trim(operandStr);
        
        std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(),
            [](unsigned char c){ return std::toupper(c); });

        auto it = instructionSet.find(mnemonic);
        if (it == instructionSet.end()) throw std::runtime_error("Unknown mnemonic '" + mnemonic + "'");

        const auto& info = it->second;
        auto operands = split(operandStr, ',');

        switch (info.format) {
            case Format::REG_ABC: {
                if (operands.size() != 3) throw std::runtime_error("Invalid operand count for '" + mnemonic + "'. Expected 3 (A, B, C), but got " + std::to_string(operands.size()) + ".");
                uint8_t a = parseRegister(operands[0]), b = parseRegister(operands[1]), c = parseRegister(operands[2]);
                return ((info.opcode << 12) | (a << 8) | (b << 4) | c) & mask;
            }
            case Format::OFFSET_AC: {
                if (operands.size() != 3) throw std::runtime_error("Invalid operand count for '" + mnemonic + "'. Expected 3 (A, offset, C), but got " + std::to_string(operands.size()) + ".");
                uint8_t a = parseRegister(operands[0]), offset = parseOffset(operands[1]), c = parseRegister(operands[2]);
                return ((info.opcode << 12) | (a << 8) | (offset << 4) | c) & mask;
            }
            case Format::REG_AB: {
                if (operands.size() != 2) throw std::runtime_error("Invalid operand count for '" + mnemonic + "'. Expected 2 (A, B), but got " + std::to_string(operands.size()) + ".");
                uint8_t a = parseRegister(operands[0]), b = parseRegister(operands[1]);
                return ((info.opcode << 12) | (a << 8) | (b << 4)) & mask;
            }
            case Format::REG_A_IMM: {
                if (operands.size() != 2) throw std::runtime_error("Invalid operand count for '" + mnemonic + "'. Expected 2 (Register, Immediate), but got " + std::to_string(operands.size()) + ".");
                uint8_t a = parseRegister(operands[0]), imm = parseImmediate(operands[1]);
                return ((info.opcode << 12) | (a << 8) | imm) & mask;
            }
            case Format::REG_A_SPEC_REG: {
                if (operands.size() != 2) throw std::runtime_error("Invalid operand count for '" + mnemonic + "'. Expected 2 (Register, SpecialRegister), but got " + std::to_string(operands.size()) + ".");
                uint8_t a = parseRegister(operands[0]);
                uint8_t spec_reg = parseSldImmediate(operands[1]);
                return ((info.opcode << 12) | (a << 8) | spec_reg) & mask;
            }
            case Format::ADDR_ONLY: {
                if (operands.size() != 1) throw std::runtime_error("Invalid operand count for '" + mnemonic + "'. Expected 1 (address), but got " + std::to_string(operands.size()) + ".");
                uint8_t addr = parseImmediate(operands[0]);
                return ((info.opcode << 12) | addr) & mask;
            }
            case Format::REG_A: {
                if (operands.size() != 1) throw std::runtime_error("Invalid operand count for '" + mnemonic + "'. Expected 1 (register), but got " + std::to_string(operands.size()) + ".");
                uint8_t a = parseRegister(operands[0]);
                return ((info.opcode << 12) | (a << 8)) & mask;
            }
            case Format::REG_C: {
                if (operands.size() != 1) throw std::runtime_error("Invalid operand count for '" + mnemonic + "'. Expected 1 (register), but got " + std::to_string(operands.size()) + ".");
                uint8_t c = parseRegister(operands[0]);
                return ((info.opcode << 12) | c) & mask;
            }
            case Format::COND_ADDR: {
                if (operands.size() != 2) throw std::runtime_error("Invalid operand count for '" + mnemonic + "'. Expected 2 (Condition, Address), but got " + std::to_string(operands.size()) + ".");
                uint8_t cond = parseCondition(operands[0]), addr = parseImmediate(operands[1]);
                return ((info.opcode << 12) | (cond << 8) | addr) & mask;
            }
            case Format::NONE: {
                if (!operandStr.empty()) throw std::runtime_error("'" + mnemonic + "' instruction does not take any operands.");
                return (info.opcode << 12) & mask;
            }
        }
        throw std::runtime_error("Internal error: Unhandled instruction format");
    }

    // 0b, 0x, 10進数プレフィックス付きの数値をパースするヘルパー関数
    unsigned long stringToUlong(const std::string& token) {
        std::string s = token;
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });

        if (s.rfind("0b", 0) == 0) { // 2進数プレフィックス
            std::string bin_part = s.substr(2);
            if (bin_part.empty() || bin_part.find_first_not_of("01") != std::string::npos) {
                throw std::invalid_argument("invalid binary literal");
            }
            return std::stoul(bin_part, nullptr, 2);
        }
        // 10進数、16進数(0x)、8進数(0)はstoulが自動で処理
        size_t pos;
        unsigned long val = std::stoul(s, &pos, 0);
        if (pos != s.length()) throw std::invalid_argument("trailing characters");
        return val;
    }

    // レジスタオペランドをパースする
    uint8_t parseRegister(const std::string& token) {
        std::string t = token;
        std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c){ return std::tolower(c); });
        if (t.rfind("r", 0) != 0) throw std::runtime_error("Invalid format for register operand '" + token + "'. Register must start with 'r' (e.g., 'r5').");
        try {
            unsigned long regNum = stringToUlong(t.substr(1));
            if (regNum <= 15) return regNum;
            else throw std::out_of_range("out of range");
        } catch (...) {
            throw std::runtime_error("Invalid register number for operand '" + token + "'. Must be between 0 and 15 (r0-r15).");
        }
    }

    // 即値またはラベルをパースする
    uint8_t parseImmediate(const std::string& token) {
        if (labels.count(token)) {
            uint16_t addr = labels.at(token);
            if (addr > 255) throw std::runtime_error("Address of label '" + token + "' (" + std::to_string(addr) + ") exceeds 8-bit limit (0-255).");
            return addr;
        }
        try {
            unsigned long val = stringToUlong(token);
            if (val <= 255) return val;
            else throw std::out_of_range("value exceeds 8-bit limit");
        } catch (const std::invalid_argument&) {
            throw std::runtime_error("Invalid immediate value or unknown label: '" + token + "'. Must be a number (e.g., 10, 0xFF, 0b1010) or a defined label.");
        } catch (const std::out_of_range&) {
            throw std::runtime_error("Immediate value '" + token + "' is out of the 8-bit range (0-255).");
        }
    }

    // オフセット値をパースする
    uint8_t parseOffset(const std::string& token) {
        try {
            unsigned long val = stringToUlong(token);
            if (val <= 15) return val;
            else throw std::out_of_range("value out of 4-bit range");
        } catch (const std::invalid_argument&) {
            throw std::runtime_error("Invalid format for offset value '" + token + "'. Must be a number (e.g., 5, 0xF, 0b1101).");
        } catch (const std::out_of_range&) {
            throw std::runtime_error("Offset value '" + token + "' is out of the 4-bit range (0-15).");
        }
    }

    // 条件コードをパースする
    uint8_t parseCondition(const std::string& token) {
        std::string t = token;
        std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c){ return std::tolower(c); });
        
        if (condAliases.count(t)) t = condAliases.at(t);
        if (condTable.count(t)) return condTable.at(t);
        
        throw std::runtime_error("Unknown condition code '" + token + "'.");
    }

    // SLD命令の即値（特殊レジスタ名または数値）をパースする
    uint8_t parseSldImmediate(const std::string& token) {
        std::string t = token;
        std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c){ return std::tolower(c); });
        auto it = specialRegisters.find(t);
        if (it != specialRegisters.end()) {
            return it->second;
        }
        
        try {
            unsigned long val = stringToUlong(token);
            if (val <= 3) return val;
            else throw std::out_of_range("value exceeds 2-bit limit");
        } catch (const std::invalid_argument&) {
            throw std::runtime_error("Invalid special register specifier '" + token + "'. Must be one of 'fr', 'gp', 'cp', 'bc', or a number from 0 to 3.");
        } catch (const std::out_of_range&) {
            throw std::runtime_error("Special register number '" + token + "' is out of the valid range (0-3).");
        }
    }
};

// ALU クラス
class ALU {
private:
    // フラグを更新するヘルパー関数
    void update_flags(uint8_t res, bool carry) {
        flags = 0;
        bit_count = static_cast<uint8_t>(__builtin_popcount(static_cast<unsigned int>(res)));
        if (carry)            flags |= Flags::C;
        if (res == 0)         flags |= Flags::Z;
        if ((res & 0b1) != 0) flags |= Flags::P; // LSBが1ならParityフラグを立てる (Odd)
    }
    
    struct ALU_settings {
        bool is_arith = true;
        bool carry_in = false;
        bool B_invert = false;
    };

public:
    uint8_t result;
    uint8_t flags; // フラグレジスタ
    uint8_t bit_count; // 立ってるビットの数
    bool carry_out;
    int normalization;
    double alu_delay;

    // コンストラクタでALUの遅延を設定
    ALU(double aluDelay) 
        : result(0), flags(0), bit_count(0), carry_out(false), normalization(0), alu_delay(aluDelay) {
        std::cout << Colors::GREEN << "ALU created: " << Colors::RESET
                  << "ALU Delay: " << this->alu_delay << "s" << std::endl;
    }
    
    // 演算実行
    uint8_t execute(ALU_Opcode opcode, uint8_t a, uint8_t b) {
        ALU_settings alu_st;
        result = 0;
        flags = 0;
        normalization = static_cast<int>(b % 8); // 0〜7に正規化
        
        std::this_thread::sleep_for(std::chrono::duration<double>(alu_delay));
        
        switch (opcode) {
            case ALU_Opcode::ADD: // ADD
                break;
            case ALU_Opcode::ADC: // ADC
                alu_st.B_invert = false;
                alu_st.carry_in = true;
                break;
            case ALU_Opcode::SBC: // SBC
                alu_st.B_invert = true;
                alu_st.carry_in = false;
                break;
            case ALU_Opcode::SUB: // SUB
                alu_st.B_invert = true;
                alu_st.carry_in = true;
                break;
            default:
                alu_st.is_arith = false; // それ以外は論理演算など
                break;
        }
        
        if (alu_st.is_arith) {
            uint8_t b2 = alu_st.B_invert ? static_cast<uint8_t>(~b) : b;
            uint16_t tmp = static_cast<uint16_t>(a) + static_cast<uint16_t>(b2) + static_cast<uint16_t>(alu_st.carry_in);
            result = static_cast<uint8_t>(tmp & 0xFF);
            carry_out = (tmp & 0x100) != 0;
            update_flags(result, carry_out);
        } else {
            switch (opcode) {
                // 論理演算
                case ALU_Opcode::NOR:
                    result = ~(a | b);
                    break;
                case ALU_Opcode::AND:
                    result = a & b;
                    break;
                case ALU_Opcode::XOR:
                    result = a ^ b;
                    break;
                // シフト・ローテート演算
                case ALU_Opcode::RSH:
                    result = static_cast<uint8_t>(a >> normalization);
                    break;
                case ALU_Opcode::LRO: 
                    result = static_cast<uint8_t>((a << normalization) | (a >> (8 - normalization)));
                    break;
                case ALU_Opcode::RRO: 
                    result = static_cast<uint8_t>((a >> normalization) | (a << (8 - normalization)));
                    break;
                // ビット演算
                case ALU_Opcode::BSET:
                    result = a | (1 << normalization);
                    break;
                case ALU_Opcode::BCLR:
                    result = a & ~(1 << normalization);
                    break;
                case ALU_Opcode::BNOT:
                    result = a ^ (1 << normalization);
                    break;
                default:
                    result = 0;
                    break;
            }
            // フラグを更新
            update_flags(result, false);
        }
        return result;
    }

    void print_flags() const {
        auto print_flag = [](const char* name, bool val) {
            std::cout << name << ":"
                      << (val ? Colors::GREEN : Colors::YELLOW) << val << Colors::RESET;
        };
        std::cout << "Flags -> ";
        print_flag("C", (flags & Flags::C) != 0);
        std::cout << " ";
        print_flag("Z", (flags & Flags::Z) != 0);
        std::cout << " ";
        print_flag("P", (flags & Flags::P) != 0);
        std::cout << " (raw: 0b" << std::bitset<8>(flags) << ")";
    }
};

// Register クラス (clearメソッド修正版)
class Register {
private:
    std::vector<uint8_t> regs;
    bool has_zero_reg = false;
  
    // アドレス範囲チェック
    void check_address(size_t addr) const {
        if (addr >= regs.size()) {
            std::cerr << "Error: Invalid address r" << +addr << ". Terminate." << std::endl;
            exit(1);
        }
    }
  
public:
    double read_delay;
    double write_delay;
  
    // コンストラクタ
    Register(size_t count, bool use_zero_register, double new_read_delay, double new_write_delay)
        : has_zero_reg(use_zero_register), read_delay(new_read_delay), write_delay(new_write_delay) {
        regs.assign(count, 0);
        std::cout << "Register created: " << count << " bytes" << std::endl
                  << "ZeroReg feature: " << (use_zero_register ? "Enabled" : "Disabled")
                  << std::endl
                  << "ReadDelay: " << this->read_delay << "s"
                  << ", Write delay: " << this->write_delay << "s" << std::endl;
    }
  
    // 全レジスタをクリア (ゼロレジスタは除く)
    void clear() {
        if (regs.empty()) return;
        
        if (has_zero_reg) {
            // 先頭は残して、残りを0クリア
            memset(regs.data() + 1, 0, regs.size() - 1);
        } else {
            // 全部0クリア
            memset(regs.data(), 0, regs.size());
        }
        
        std::cout << "Register cleared." << std::endl;
    }
  
    // 書き込み
    void write(size_t addr, uint8_t data) {
        check_address(addr);
        if (has_zero_reg && addr == 0) {
            std::cout << "Write ignored: Zero Register (r0)" << std::endl;
        } else {
            regs[addr] = data;
        }
        std::this_thread::sleep_for(std::chrono::duration<double>(write_delay));
    }
  
    // 読み出し（2つ同時）
    std::tuple<uint8_t, uint8_t> read(size_t addr_a, size_t addr_b) {
        check_address(addr_a);
        check_address(addr_b);
        std::this_thread::sleep_for(std::chrono::duration<double>(read_delay));
        return {regs[addr_a], regs[addr_b]};
    }
    
    // 読み出し（一つ）
    uint8_t read(size_t addr) {
        check_address(addr);
        std::this_thread::sleep_for(std::chrono::duration<double>(read_delay));
        return regs[addr];
    }

    // レジスタ一覧を表示
    void dump(size_t start = 0, size_t end = static_cast<size_t>(-1)) const {
        // endがデフォルト値の場合、最後まで表示するように設定
        if (end == static_cast<size_t>(-1) || end >= regs.size()) {
            end = regs.size();
        }
        // startがendを超えていたり、範囲外だったりする場合は何もしない
        if (start >= end || start >= regs.size()) {
            std::cout << "--- Register Dump (Invalid Range) ---" << std::endl;
            return;
        }

        std::cout << "--- Registe Dump (" << regs.size() << " bytes, showing " << start << "-" << end - 1 << ") ---" << std::endl;
        for (size_t i = start; i < end; ++i) {
            // この範囲表示では省略ロジックは不要
            std::cout << "Addr[" << std::setw(3) << i << "]: " << std::setw(3) << std::setfill(' ')  << +regs[i] 
                      << " (0x" << std::hex << std::setw(2)  << std::setfill('0') << +regs[i] << std::dec << ")" << std::endl;
        }
        std::cout << "---------------------------------" << std::endl;
    }
};

class Stack {
private:
    std::vector<uint8_t> stack_data; // スタックの実体 (ハードウェアレジスタ配列)

public:
    double read_delay;
    double write_delay;

    size_t sp;          // スタックポインタ
    const size_t depth; // スタックの深さ
    
    // コンストラクタ
    Stack(size_t new_depth, double new_read_delay, double new_write_delay)
        : sp(0), depth(new_depth), read_delay(new_read_delay), write_delay(new_write_delay) {
        if (depth == 0) {
            throw std::invalid_argument("Stack depth cannot be zero.");
        }
        stack_data.assign(depth, 0);
        std::cout << "Hardware Stack created: " << depth << " levels"
                  << std::endl
                  << "ReadDelay: " << read_delay << "s"
                  << ", Write delay: " << write_delay << "s" << std::endl;
    }

    // スタックをクリアする
    void clear() {
        sp = 0;
        stack_data.assign(depth, 0);
    }

    // スタックにデータをプッシュする
    void push(uint8_t val) {
        if (is_full()) {
            // スタックオーバーフロー: 操作を無視
            return;
        }
        stack_data[sp] = val;
        sp++;
    }

    // スタックからデータをポップする (値を削除するバージョン)
    uint8_t pop() {
        if (is_empty()) {
            // スタックアンダーフロー: 0を返し、ポインタは動かさない
            return 0;
        }
        sp--;
        uint8_t val = stack_data[sp]; // SPが指す場所から値を取得
        stack_data[sp] = 0;           // ポップした場所を0でクリア
        return val;                   // 取得した値を返す
    }

    // スタックポインタの現在値を取得する
    size_t get_pointer() const {
        return sp;
    }

    // スタックポインタを任意の値に設定する
    void set_pointer(size_t new_pointer) {
        // new_pointerがdepthを超えても設定可能とするが、
        // is_full()で正しく判定されるように上限はdepthとする
        if (new_pointer > depth) {
            sp = depth;
            return;
        }
        sp = new_pointer;
    }

    // スタックが満杯かチェックする
    bool is_full() const {
        return sp >= depth;
    }

    // スタックが空かチェックする
    bool is_empty() const {
        return sp == 0;
    }

    // デバッグ用にスタックの内容を表示する
    void dump(const std::string& name, size_t start = 0, size_t end = -1) const {
        // endがデフォルト値の場合、最後まで表示するように設定
        if (end == static_cast<size_t>(-1) || end >= depth) {
            end = depth;
        }
        // startがendを超えていたり、範囲外だったりする場合は何もしない
        if (start >= end || start >= depth) {
            std::cout << "--- " << name << " Dump (Invalid Range) ---" << std::endl;
            return;
        }

        std::cout << "--- ";
        if (!name.empty()) {
            std::cout << name << " ";
        }
        std::cout << "Dump (SP=" << sp << ", Depth=" << depth << ", showing " << start << "-" << end - 1 << ") ---" << std::endl;
        
        for (size_t i = start; i < end; ++i) {
            // 表示本体
            std::cout << "Addr[" << std::setw(3) << i << "]: " 
                      << std::setw(3) << std::setfill(' ') << +stack_data[i] 
                      << " (0x" << std::hex << std::setw(2) << std::setfill('0') << +stack_data[i] << std::dec << ")";

            // ポインタ表示ロジック
            if (i + 1 == sp && !is_empty()) {
                std::cout << " <- TOP";
            } else if (i == sp) {
                std::cout << " <- SP (next push)";
            }
            
            std::cout << std::endl;
        }
        std::cout << "---------------------------------" << std::endl;
    }
};

// Helper クラス
class Helper {
public:
    void print_assembly(const Assembler& assembler, bool is_binary) {
        const auto& errors = assembler.getErrors();

        // エラーありなら即終了
        if (!errors.empty()) {
            std::cerr << Colors::BOLD << Colors::RED << "Assembly failed." << Colors::RESET << (is_binary ? " Cannot output raw binary." : "") << std::endl;
            for (const auto& error : errors) std::cerr << "  " << error << std::endl;
            return;
        }

        // 成功メッセージ（両モード共通）
        std::cout << Colors::GREEN << Colors::BOLD << "Assembly successful." << Colors::RESET << std::endl;

        if (!is_binary) {
            std::cout << Colors::BOLD << "\nAssembled Code:" << Colors::RESET << std::endl;
            std::cout << "Addr | Machine Code (17-bit)|   Hex" << std::endl;
            std::cout << "-----+----------------------+---------" << std::endl;

            int addr = 0;
            for (const auto& code : assembler.getMachineCode()) {
                // バイナリ文字列生成
                std::string binary_str;
                for (int i = 16; i >= 0; --i) {
                    binary_str += ((code >> i) & 1) ? '1' : '0';
                }

                // addr は 10進3桁スペース埋め
                std::cout << Colors::CYAN << std::dec << std::setw(3) << std::setfill(' ') << addr++ << Colors::RESET << "  | ";

                // バイナリ分割 [5][4][4][4]
                std::cout << Colors::YELLOW << binary_str.substr(0, 5)  << Colors::RESET << " "
                          << Colors::GREEN << binary_str.substr(5, 4)  << Colors::RESET << " "
                          << Colors::BLUE << binary_str.substr(9, 4)  << Colors::RESET << " "
                          << Colors::MAGENTA << binary_str.substr(13, 4) << Colors::RESET;

                // Hex 出力（16進5桁ゼロ埋め）
                std::cout << " | " << Colors::YELLOW << "0x" 
                          << std::hex << std::setw(5) << std::setfill('0') << code << Colors::RESET
                          << std::dec << std::setfill(' ') // リセット
                          << std::endl;
            }
        } else {
            // 生バイナリ出力
            std::cout << "\nRaw Binary Output:" << std::endl;
            for (const auto& code : assembler.getMachineCode()) {
                for (int i = 16; i >= 0; --i) {
                    std::cout << ((code >> i) & 1);
                }
                std::cout << std::endl;
            }
        }
    }
    
    // ALUのテスト用ヘルパー関数
    void alu_test(ALU& alu, ALU_Opcode op, uint8_t a, uint8_t b, const std::string& name) {
        std::cout << "Test: " << Colors::YELLOW << Colors::BOLD << name << Colors::RESET << std::endl;
        std::cout << "  Input  : A=" << +a << ", B=" << +b << std::endl;
        std::cout << "  Result : " << Colors::GREEN << +alu.execute(op, a, b) << Colors::RESET << " (0x" << std::hex << std::setw(2) << std::setfill('0') << +alu.result << std::dec << ")" << std::endl;
        std::cout << "  ";
        alu.print_flags();
        std::cout << "\n" << std::endl;
    }
    
    void reg_write_test(Register &reg, uint8_t addr, uint8_t data, const std::string &operation_name) {
        std::cout << "Executing " << operation_name << "..." << std::flush;
        reg.write(addr, data);
        std::cout << " Done.\n";
    }
    
    void reg_read_test(Register &reg, uint8_t addr_a, uint8_t addr_b, const std::string &operation_name) {
        std::cout << "Executing " << operation_name << "..." << std::flush;
        auto [value_a, value_b] = reg.read(addr_a, addr_b);
        std::cout << " Done.\n";
        std::cout << "  -> read: r" << +addr_a << " = " << +value_a << ", "
                  << "r" << +addr_b << " = " << +value_b << "\n";
    }
    
    void combined_test(ALU &alu, Register &reg, uint8_t addr_a, uint8_t addr_b, uint8_t result_addr, ALU_Opcode opcode, const std::string &operation_name) {
        std::cout << "Executing " << operation_name << "..." << std::flush;

        // レジスタから値を読み出し
        auto [val_a, val_b] = reg.read(addr_a, addr_b);
        
        // 演算し結果をレジスタに書き込み
        reg.write(result_addr, alu.execute(opcode, val_a, val_b));
    
        std::cout << " Done.\n";
        std::cout << "  -> operands: r" << +addr_a << "=" << +val_a << ", r" << +addr_b << "=" << +val_b << "\n";
        std::cout << "  -> result: " << +alu.result << " (0x" << std::hex << std::setw(2)
                  << std::setfill('0') << +alu.result << std::dec << ") -> r" << +result_addr << "\n";
        std::cout << "  -> flags: ";
        alu.print_flags();
        std::cout << "\n";
    }
    
    // 遅延
    void halt(double time_sec) {
        std::this_thread::sleep_for(std::chrono::duration<double>(time_sec));
    }
    
    // 改行（Line breaks）
    void lb() {
        std::cout << "\n";
    }
    
    // 文字列を大文字に変換する関数
    std::string toUpper(const std::string &s) {
        std::string res = s;
        std::transform(res.begin(), res.end(), res.begin(), ::toupper);
        return res;
    }
};

class TestRunner {
private:
    // テストケースを保持する構造体
    struct TestCase {
        std::string name;
        std::string description;
        std::function<void()> function;
    };

    std::map<std::string, TestCase> tests;
    Helper helper;

public:
    // テストケースを登録する
    void register_test(const std::string& name, const std::string& description, std::function<void()> func) {
        std::string upper_name = name;
        std::transform(upper_name.begin(), upper_name.end(), upper_name.begin(),
            [](unsigned char c){ return std::toupper(c); });
        tests[upper_name] = {name, description, func};
    }

    // テストランナーを実行する
    void run() {
        while (true) {
            std::cout << "\nどのテストプログラムを実行しますか？\n";
            std::cout << Colors::BOLD << "選択肢:" << Colors::RESET << std::endl;
            for (const auto& pair : tests) {
                std::cout << std::setfill(' ') 
                          << "  - " << std::setw(10) << std::left << pair.second.name
                          << ": " << pair.second.description << std::endl;
            }
            std::cout << "複数選択可（スペースで区切る）、終了する場合は " << Colors::YELLOW << "EXIT" << Colors::RESET << " と入力: ";

            std::string line;
            std::getline(std::cin, line);
            
            std::string upper_line = line;
            std::transform(upper_line.begin(), upper_line.end(), upper_line.begin(),
                [](unsigned char c){ return std::toupper(c); });

            if (upper_line == "EXIT") break;

            std::stringstream ss(line);
            std::string token;
            std::vector<std::string> selections;
            while (ss >> token) {
                selections.push_back(token);
            }

            for (size_t i = 0; i < selections.size(); ++i) {
                std::string upper_token = selections[i];
                std::transform(upper_token.begin(), upper_token.end(), upper_token.begin(),
                    [](unsigned char c){ return std::toupper(c); });

                if (tests.count(upper_token)) {
                    tests.at(upper_token).function(); // 登録された関数を実行
                } else {
                    std::cout << Colors::RED << "不明な選択: " << selections[i] << Colors::RESET << "\n";
                }

                if (i + 1 < selections.size()) {
                    helper.halt(1.0);
                }
            }
        }
        std::cout << "テストを終了します。\n";
    }
};

void ASM_TEST() {
    Assembler assembler;
    Helper helper;

    std::string source = R"(
    ; シンプルなカウントダウンプログラム
    START:
        CAL RESET      ; レジスタ初期化
        JMP LOOP       ; メインループへ

    RESET:
        LDI r1, 10     ; r1にカウンタの初期値10を設定
        LDI r2, 1      ; r2に減算用の1を設定
        SLD r3, 3
        RET

    LOOP:
        PST r0, 15, r1 ; r1の値をポート15に出力 (デバッグ用)
        SUB r1, r2, r1 ; r1 = r1 - r2
        CMP r2, r1     ; r1とr2を比較 (実質r1が0より大きいかチェック)
        BRH >=, STOP   ; r1 >= r2 (つまり r1 > 0) ならループ継続
        JMP LOOP

    STOP:
        HLT            ; 停止
    )";

    assembler.assemble(source);
    helper.print_assembly(assembler, false);
    std::cout << std::endl;
}


void ALU_TESTS() {
    Helper helper;
    ALU alu(0.1);

    std::cout << Colors::CYAN << Colors::BOLD << "\n==== ALU Test Suite for Custom ISA ====" << Colors::RESET << std::endl;

    // 算術演算テスト
    helper.alu_test(alu, ALU_Opcode::ADD, 200, 100, "ADD (200 + 100 = 44)"); // C=1, Z=0, P=0
    helper.alu_test(alu, ALU_Opcode::ADD, 10, 20, "ADD (10 + 20 = 30)");     // C=0, Z=0, P=0
    helper.alu_test(alu, ALU_Opcode::ADC, 255, 0, "ADC (255 + 0 + 1 = 0)");  // C=1, Z=1, P=0
    helper.alu_test(alu, ALU_Opcode::SUB, 10, 5, "SUB (10 - 5 = 5)");        // C=1, Z=0, P=1
    helper.alu_test(alu, ALU_Opcode::SUB, 5, 10, "SUB (5 - 10 = 251)");      // C=0, Z=0, P=1
    helper.alu_test(alu, ALU_Opcode::SBC, 10, 8, "SBC (10 - 8 - 1 = 1)");    // C=1, Z=0, P=1
    helper.alu_test(alu, ALU_Opcode::SBC, 10, 9, "SBC (10 - 9 - 1 = 0)");    // C=1, Z=1, P=0

    // 論理演算テスト
    helper.alu_test(alu, ALU_Opcode::AND, 0b11001010, 0b10101100, "AND (202 & 172 = 136)"); // C=1, Z=0, P=0
    helper.alu_test(alu, ALU_Opcode::NOR, 0b10100000, 0b01010000, "NOR (~(160 | 80) = 15)"); // C=1, Z=1, P=0
    helper.alu_test(alu, ALU_Opcode::XOR, 0b11110000, 0b01010101, "XOR (240 ^ 85 = 165)"); // C=1, Z=0, P=1

    // シフト・ビット演算テスト
    helper.alu_test(alu, ALU_Opcode::RSH, 0b10001000, 7, "RSH (136 >> 3 = 17)");    // C=1, Z=0, P=0
    helper.alu_test(alu, ALU_Opcode::LRO, 0b11000001, 2, "LRO (193 -> 7)");   // C=1, Z=0, P=1
    helper.alu_test(alu, ALU_Opcode::RRO, 0b11000001, 4, "LRO (193 -> 28)");   // C=1, Z=0, P=1
    helper.alu_test(alu, ALU_Opcode::BSET, 0b10101010, 0, "BSET (170 -> 171)"); // C=1, Z=0, P=1
    helper.alu_test(alu, ALU_Opcode::BCLR, 0b10101011, 0, "BCLR (171 -> 170)"); // C=1, Z=0, P=0
    helper.alu_test(alu, ALU_Opcode::BNOT, 0b00000001, 0, "BNOT (1 -> 0)"); // C=1, Z=1, P=0

    std::cout << Colors::GREEN << Colors::BOLD << "All ALU tests completed." << Colors::RESET << std::endl;
}

void REG_TESTS(){
    Helper helper;
    Register reg(CPUConfig::RegCount, CPUConfig::UseZeroReg, 0.1, 0.1);
    
    std::cout << Colors::CYAN << Colors::BOLD << "\n==== REGISTER TESTS ====" << Colors::RESET << std::endl;
    std::cout << std::endl;

    std::cout << Colors::YELLOW << "--- Write Operations ---" << Colors::RESET << std::endl;
    helper.reg_write_test(reg, 1, 100, "Write 100 to r1");
    helper.reg_write_test(reg, 2, 200, "Write 200 to r2");
    helper.reg_write_test(reg, 0, 255, "Attempt write 255 to r0 (should be ignored)");
    std::cout << std::endl;
    reg.dump();

    std::cout << std::endl << Colors::YELLOW << "--- Read Operations ---" << Colors::RESET << std::endl;
    helper.reg_read_test(reg, 1, 2, "Read from r1 and r2");
    helper.reg_read_test(reg, 0, 0, "Read from r0 twice");
    helper.reg_read_test(reg, 0, 1, "Read from r0 and r1");

    std::cout << std::endl << Colors::YELLOW << "--- Clear Operation ---" << Colors::RESET << std::endl;
    reg.clear();
    reg.dump();

    std::cout << std::endl << Colors::GREEN << Colors::BOLD << "✓ Register tests completed." << Colors::RESET << std::endl;
}

void STACK_TESTS() {
    Helper helper;
    // 深さ8の小さなスタックでテスト
    Stack stack(8, 0.1, 0.1);

    std::cout << Colors::CYAN << Colors::BOLD << "\n==== STACK TESTS ====" << Colors::RESET << std::endl;
    std::cout << std::endl;

    std::cout << Colors::YELLOW << "--- Initial State & Underflow Test ---" << Colors::RESET << std::endl;
    stack.dump("Initial Stack");
    uint8_t val = stack.pop();
    std::cout << "Popped from empty stack. Value returned: " << +val << " (expected 0)" << std::endl;
    stack.dump("After Underflow Attempt");
    helper.lb();

    std::cout << Colors::YELLOW << "--- Push Operations ---" << Colors::RESET << std::endl;
    stack.push(11);
    stack.push(22);
    stack.push(33);
    stack.dump("After pushing 11, 22, 33");
    helper.lb();

    std::cout << Colors::YELLOW << "--- Pop Operation (with value clearing) ---" << Colors::RESET << std::endl;
    val = stack.pop();
    std::cout << "Popped value: " << +val << " (expected 33)" << std::endl;
    stack.dump("After one pop");
    helper.lb();

    std::cout << Colors::YELLOW << "--- Set Pointer (SPS) Operation ---" << Colors::RESET << std::endl;
    std::cout << "Setting pointer to 0..." << std::endl;
    stack.set_pointer(0);
    stack.dump("After set_pointer(0)");
    std::cout << "Pushing 99..." << std::endl;
    stack.push(99);
    stack.dump("After pushing 99 (overwrites old value)");
    helper.lb();

    std::cout << Colors::YELLOW << "--- Overflow Test ---" << Colors::RESET << std::endl;
    // 現在 sp=1, stack[0]=99, stack[1]=22
    stack.set_pointer(stack.depth); // spを8に設定して満杯にする
    std::cout << "Stack pointer set to " << stack.get_pointer() << " (full)." << std::endl;
    stack.dump("Full Stack");
    std::cout << "Attempting to push 123 to a full stack..." << std::endl;
    stack.push(123); // この操作は無視されるはず
    stack.dump("After Overflow Attempt");
    helper.lb();

    std::cout << Colors::YELLOW << "--- Range Dump Test ---" << Colors::RESET << std::endl;
    // テスト用にスタックを再設定
    stack.clear();
    for (uint8_t i = 0; i < 8; ++i) {
        stack.push((i + 1) * 10);
    }
    std::cout << "Stack filled with test data." << std::endl;
    stack.dump("Full Stack", 0, 4); // 先頭4つを表示
    stack.dump("Full Stack", 4);    // 4から最後まで表示

    std::cout << std::endl << Colors::GREEN << Colors::BOLD << "✓ Stack tests completed." << Colors::RESET << std::endl;
}

void COMBINED_TESTS() {
    Helper helper;
    ALU alu(0.1);
    Register reg(CPUConfig::RegCount, CPUConfig::UseZeroReg, 0.1, 0.1);

    std::cout << Colors::CYAN << Colors::BOLD << "\n==== COMBINED ALU + REGISTER TESTS ====" << Colors::RESET << std::endl;
    std::cout << std::endl;

    std::cout << Colors::YELLOW << "--- Setup: Initialize registers ---" << Colors::RESET << std::endl;
    // テスト用の初期値をレジスタに設定
    std::cout << Colors::DIM << "Setting up test values..." << Colors::RESET << std::endl;
    reg.write(1, 150);  // r1 = 150
    reg.write(2, 100);  // r2 = 100
    reg.write(3, 50);   // r3 = 50
    reg.write(4, 255);  // r4 = 255

    std::cout << std::endl << Colors::BOLD << "Initial register state:" << Colors::RESET << std::endl;
    reg.dump();

    std::cout << std::endl << Colors::YELLOW << "--- ALU + Register Operations ---" << Colors::RESET << std::endl;
    // 組み合わせテストの実行
    helper.combined_test(alu, reg, 1, 2, 5, ALU_Opcode::ADD, "ADD r1+r2 -> r5 (150+100)");
    std::cout << std::endl;
    helper.combined_test(alu, reg, 1, 3, 6, ALU_Opcode::SUB, "SUB r1-r3 -> r6 (150-50)");
    std::cout << std::endl;
    helper.combined_test(alu, reg, 2, 4, 7, ALU_Opcode::AND, "AND r2&r4 -> r7 (100&255)");
    std::cout << std::endl;
    helper.combined_test(alu, reg, 5, 6, 1, ALU_Opcode::XOR, "XOR r5^r6 -> r1 (result^result)");

    std::cout << std::endl << Colors::BOLD << "Final register state:" << Colors::RESET << std::endl;
    reg.dump();

    std::cout << std::endl << Colors::GREEN << Colors::BOLD << "✓ Combined ALU+Register tests completed." << Colors::RESET << std::endl;
}


int main() {
    TestRunner runner;

    // テストケースを登録
    runner.register_test("ASM", "Assemblerのテスト", ASM_TEST);
    runner.register_test("ALU", "ALUの単体テスト", ALU_TESTS);
    runner.register_test("REG", "Registerの単体テスト", REG_TESTS);
    runner.register_test("STACK", "Stackの単体テスト", STACK_TESTS);
    runner.register_test("COMBINED", "ALUとRegisterの結合テスト", COMBINED_TESTS);
    
    // 新しいテストを追加する場合:
    // runner.register_test("NEW_TEST", "新しいテストの説明", NEW_TEST_FUNCTION);

    // テストランナーを実行
    runner.run();
    
    return 0;
}