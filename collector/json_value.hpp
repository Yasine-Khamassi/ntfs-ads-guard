#pragma once

#include <cctype>
#include <cmath>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>
#include <utility>

class JsonValue {
public:
    using Array = std::vector<JsonValue>;
    using Object = std::map<std::string, JsonValue>;
    using Storage = std::variant<std::nullptr_t, bool, double, std::string, Array, Object>;

    explicit JsonValue(Storage value) : value_(std::move(value)) {}
    const Object& object() const { return std::get<Object>(value_); }
    const Array& array() const { return std::get<Array>(value_); }
    const std::string& string() const { return std::get<std::string>(value_); }
    double number() const { return std::get<double>(value_); }
    bool isObject() const { return std::holds_alternative<Object>(value_); }
    bool isArray() const { return std::holds_alternative<Array>(value_); }
    bool isString() const { return std::holds_alternative<std::string>(value_); }
    bool isNumber() const { return std::holds_alternative<double>(value_); }
private:
    Storage value_;
};

class JsonParser {
public:
    explicit JsonParser(const std::string& input) : input_(input) {}
    JsonValue parse() {
        skip(); auto v = value(); skip();
        if (position_ != input_.size()) fail("trailing content");
        return v;
    }
private:
    const std::string& input_;
    size_t position_ = 0;
    [[noreturn]] void fail(const char* reason) const {
        throw std::runtime_error(std::string("JSON at byte ") + std::to_string(position_) + ": " + reason);
    }
    void skip() { while (position_ < input_.size() && (input_[position_] == ' ' || input_[position_] == '\t' || input_[position_] == '\r' || input_[position_] == '\n')) ++position_; }
    bool take(char c) { skip(); if (position_ < input_.size() && input_[position_] == c) { ++position_; return true; } return false; }
    static void utf8(std::string& out, uint32_t cp) {
        if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
        else if (cp <= 0x7ff) { out.push_back(char(0xc0 | (cp >> 6))); out.push_back(char(0x80 | (cp & 0x3f))); }
        else if (cp <= 0xffff) { out.push_back(char(0xe0 | (cp >> 12))); out.push_back(char(0x80 | ((cp >> 6) & 0x3f))); out.push_back(char(0x80 | (cp & 0x3f))); }
        else { out.push_back(char(0xf0 | (cp >> 18))); out.push_back(char(0x80 | ((cp >> 12) & 0x3f))); out.push_back(char(0x80 | ((cp >> 6) & 0x3f))); out.push_back(char(0x80 | (cp & 0x3f))); }
    }
    uint32_t hex4() {
        if (position_ + 4 > input_.size()) fail("incomplete unicode escape");
        uint32_t n = 0;
        for (int i=0;i<4;++i) {
            char c=input_[position_++]; n <<= 4;
            if (c>='0'&&c<='9') n |= c-'0'; else if (c>='a'&&c<='f') n |= c-'a'+10;
            else if (c>='A'&&c<='F') n |= c-'A'+10; else fail("invalid unicode escape");
        }
        return n;
    }
    std::string string() {
        if (!take('"')) fail("expected string");
        std::string out;
        while (position_ < input_.size()) {
            unsigned char c = static_cast<unsigned char>(input_[position_++]);
            if (c == '"') return out;
            if (c < 0x20) fail("control character in string");
            if (c != '\\') { out.push_back(static_cast<char>(c)); continue; }
            if (position_ == input_.size()) fail("incomplete escape");
            switch (input_[position_++]) {
                case '"': out.push_back('"'); break; case '\\': out.push_back('\\'); break; case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break; case 'f': out.push_back('\f'); break; case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break; case 't': out.push_back('\t'); break;
                case 'u': {
                    uint32_t cp = hex4();
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        if (position_ + 2 > input_.size() || input_[position_] != '\\' || input_[position_+1] != 'u') fail("unpaired high surrogate");
                        position_ += 2; uint32_t low = hex4();
                        if (low < 0xdc00 || low > 0xdfff) fail("invalid low surrogate");
                        cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                    } else if (cp >= 0xdc00 && cp <= 0xdfff) fail("unpaired low surrogate");
                    utf8(out, cp); break;
                }
                default: fail("invalid escape");
            }
        }
        fail("unterminated string");
    }
    JsonValue value() {
        skip(); if (position_ == input_.size()) fail("expected value");
        char c=input_[position_];
        if (c=='{') {
            ++position_; JsonValue::Object o; skip(); if (take('}')) return JsonValue(o);
            for (;;) {
                skip(); if (position_ == input_.size() || input_[position_] != '"') fail("expected object key");
                auto key=string(); if (!take(':')) fail("expected colon");
                if (!o.emplace(key,value()).second) fail("duplicate object key");
                if (take('}')) break; if (!take(',')) fail("expected comma");
            }
            return JsonValue(o);
        }
        if (c=='[') {
            ++position_; JsonValue::Array a; skip(); if (take(']')) return JsonValue(a);
            for (;;) { a.push_back(value()); if (take(']')) break; if (!take(',')) fail("expected comma"); }
            return JsonValue(a);
        }
        if (c=='"') return JsonValue(string());
        if (input_.compare(position_,4,"true")==0) { position_+=4; return JsonValue(true); }
        if (input_.compare(position_,5,"false")==0) { position_+=5; return JsonValue(false); }
        if (input_.compare(position_,4,"null")==0) { position_+=4; return JsonValue(nullptr); }
        size_t start=position_; if (input_[position_]=='-') ++position_;
        if (position_==input_.size()) fail("invalid number");
        if (input_[position_]=='0') ++position_; else { if (!std::isdigit(static_cast<unsigned char>(input_[position_]))) fail("invalid value"); while(position_<input_.size()&&std::isdigit(static_cast<unsigned char>(input_[position_])))++position_; }
        if (position_<input_.size()&&input_[position_]=='.') { ++position_; size_t p=position_; while(position_<input_.size()&&std::isdigit(static_cast<unsigned char>(input_[position_])))++position_; if(p==position_)fail("invalid fraction"); }
        if (position_<input_.size()&&(input_[position_]=='e'||input_[position_]=='E')) { ++position_; if(position_<input_.size()&&(input_[position_]=='+'||input_[position_]=='-'))++position_; size_t p=position_; while(position_<input_.size()&&std::isdigit(static_cast<unsigned char>(input_[position_])))++position_; if(p==position_)fail("invalid exponent"); }
        try { double n=std::stod(input_.substr(start,position_-start)); if(!std::isfinite(n))fail("non-finite number"); return JsonValue(n); } catch (...) { fail("invalid number"); }
    }
};
