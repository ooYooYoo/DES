#include <vector>
#include <algorithm>
// 其他需要的头文件
#include <iostream>
#include <string>
#include <sstream>
#include <bitset>
#include <thread>
#include <mutex>
#include <chrono>

using namespace std;

// 定义全局锁用于多线程
mutex mtx;

// S-Box表
int S0[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 3, 2}
};

int S1[4][4] = {
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 0},
    {2, 1, 0, 3}
};

// P-Box
int P4_final[4] = { 2, 4, 3, 1 };

// P10置换
int P10[10] = { 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 };

// P8置换
int P8[8] = { 6, 3, 7, 4, 8, 5, 10, 9 };

// 初始置换IP
int IP[8] = { 2, 6, 3, 1, 4, 8, 5, 7 };

// 逆初始置换IP^-1
int IP_INV[8] = { 4, 1, 3, 5, 7, 2, 8, 6 };

// 扩展置换E/P
int EP[8] = { 4, 1, 2, 3, 2, 3, 4, 1 };

// 左移函数（循环左移）
string left_shift(string key, int n) {
    return key.substr(n) + key.substr(0, n);
}

// 置换函数
string permute(const string& bits, const int* table, int n) {
    string permuted = "";
    for (int i = 0; i < n; i++) {
        permuted += bits[table[i] - 1];
    }
    return permuted;
}

// XOR函数
string xor_bits(const string& a, const string& b) {
    string result = "";
    for (int i = 0; i < a.size(); i++) {
        result += (a[i] == b[i]) ? '0' : '1';
    }
    return result;
}

// S-Box替换
string sbox_replace(const string& input, int sbox[4][4]) {
    // 输入为4位二进制字符串
    // 行由首位和末位确定，列由中间两位确定
    int row = 2 * (input[0] - '0') + (input[3] - '0');
    int col = 2 * (input[1] - '0') + (input[2] - '0');
    int val = sbox[row][col];
    string binary = bitset<2>(val).to_string();
    return binary;
}

// 密钥生成
pair<string, string> generate_keys(const string& key) {
    // P10置换
    string permuted = permute(key, P10, 10);

    // 分成两部分
    string left = permuted.substr(0, 5);
    string right = permuted.substr(5, 5);

    // 左移1
    left = left_shift(left, 1);
    right = left_shift(right, 1);

    // 合并并进行P8置换，得到K1
    string K1 = permute(left + right, P8, 8);

    // 左移2
    left = left_shift(left, 2);
    right = left_shift(right, 2);

    // 合并并进行P8置换，得到K2
    string K2 = permute(left + right, P8, 8);

    return { K1, K2 };
}

// Feistel函数
string feistel(const string& half, const string& key) {
    // 扩展置换E/P
    string expanded = permute(half, EP, 8);

    // XOR with key
    string xored = xor_bits(expanded, key);

    // 分成两部分
    string left = xored.substr(0, 4);
    string right = xored.substr(4, 4);

    // S-Box替换
    string s0 = sbox_replace(left, S0);
    string s1 = sbox_replace(right, S1);

    // P4置换
    string combined = s0 + s1;
    string p4 = permute(combined, P4_final, 4);

    return p4;
}

// 加密函数
string sdes_encrypt(const string& plaintext, const string& key) {
    pair<string, string> keys = generate_keys(key);
    string K1 = keys.first;
    string K2 = keys.second;

    // 初始置换IP
    string permuted = permute(plaintext, IP, 8);

    // 分成两部分
    string left = permuted.substr(0, 4);
    string right = permuted.substr(4, 4);

    // 第一轮
    string f = feistel(right, K1);
    string new_left = xor_bits(left, f);
    string new_right = right;

    // 交换
    swap(new_left, new_right);

    // 第二轮
    f = feistel(new_right, K2);
    new_left = xor_bits(new_left, f);
    // new_right remains the same

    // 合并
    string preoutput = new_left + new_right;

    // 逆初始置换IP^-1
    string ciphertext = permute(preoutput, IP_INV, 8);

    return ciphertext;
}

// 解密函数
string sdes_decrypt(const string& ciphertext, const string& key) {
    pair<string, string> keys = generate_keys(key);
    string K1 = keys.first;
    string K2 = keys.second;

    // 初始置换IP
    string permuted = permute(ciphertext, IP, 8);

    // 分成两部分
    string left = permuted.substr(0, 4);
    string right = permuted.substr(4, 4);

    // 第一轮（使用K2）
    string f = feistel(right, K2);
    string new_left = xor_bits(left, f);
    string new_right = right;

    // 交换
    swap(new_left, new_right);

    // 第二轮（使用K1）
    f = feistel(new_right, K1);
    new_left = xor_bits(new_left, f);
    // new_right remains the same

    // 合并
    string preoutput = new_left + new_right;

    // 逆初始置换IP^-1
    string plaintext = permute(preoutput, IP_INV, 8);

    return plaintext;
}

// ASCII字符串转换为二进制
string string_to_binary(const string& s) {
    string binary = "";
    for (char c : s) {
        binary += bitset<8>(c).to_string();
    }
    return binary;
}

// 二进制转换为ASCII字符串
string binary_to_string(const string& b) {
    string s = "";
    for (size_t i = 0; i + 8 <= b.size(); i += 8) {
        string byte = b.substr(i, 8);
        char c = static_cast<char>(bitset<8>(byte).to_ulong());
        s += c;
    }
    return s;
}

// 暴力破解线程函数
void brute_force_crack_thread(const string& plaintext, const string& ciphertext, string& found_key, int start, int end) {
    for (int key = start; key < end; key++) {
        // 如果已经找到，提前退出
        if (!found_key.empty()) return;

        string key_bin = bitset<10>(key).to_string();
        string encrypted = sdes_encrypt(plaintext, key_bin);
        if (encrypted == ciphertext) {
            lock_guard<mutex> lock(mtx);
            if (found_key.empty()) {
                found_key = key_bin;
            }
            return;
        }
    }
}

// 暴力破解主函数
string brute_force_crack(const string& plaintext, const string& ciphertext, int num_threads = 8) {
    string found_key = "";
    vector<thread> threads;
    int keys_per_thread = 1024 / num_threads;

    auto start_time = chrono::high_resolution_clock::now();

    for (int i = 0; i < num_threads; i++) {
        int start_key = i * keys_per_thread;
        int end_key = (i == num_threads - 1) ? 1024 : (i + 1) * keys_per_thread;
        threads.emplace_back(brute_force_crack_thread, plaintext, ciphertext, ref(found_key), start_key, end_key);
    }

    for (auto& t : threads) {
        t.join();
    }

    auto end_time = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end_time - start_time;

    if (!found_key.empty()) {
        cout << "密钥找到: " << found_key << "，耗时: " << duration.count() << " 秒\n";
    }
    else {
        cout << "未找到匹配的密钥，耗时: " << duration.count() << " 秒\n";
    }

    return found_key;
}

// 暴力破解查找所有匹配密钥
vector<string> brute_force_all_keys(const string& plaintext, const string& ciphertext) {
    vector<string> matching_keys;
    for (int key = 0; key < 1024; key++) {
        string key_bin = bitset<10>(key).to_string();
        string encrypted = sdes_encrypt(plaintext, key_bin);
        if (encrypted == ciphertext) {
            matching_keys.push_back(key_bin);
        }
    }
    return matching_keys;
}

int main() {
    int choice;
    while (true) {
        cout << "================= S-DES 加密解密工具 =================\n";
        cout << "1. 加密 8-bit 数据\n";
        cout << "2. 解密 8-bit 密文\n";
        cout << "3. 加密 ASCII 字符串\n";
        cout << "4. 解密 ASCII 字符串\n";
        cout << "5. 暴力破解密钥\n";
        cout << "6. 密钥唯一性分析\n";
        cout << "0. 退出\n";
        cout << "请输入选择: ";
        cin >> choice;
        cin.ignore(); // 忽略换行符

        if (choice == 0) {
            cout << "退出程序。\n";
            break;
        }
        else if (choice == 1) { // 加密8-bit数据
            string plaintext, key;
            cout << "请输入8-bit明文（二进制字符串，如10101010）: ";
            cin >> plaintext;
            cout << "请输入10-bit密钥（二进制字符串，如1010000010）: ";
            cin >> key;
            if (plaintext.size() != 8 || key.size() != 10 ||
                !all_of(plaintext.begin(), plaintext.end(), [](char c) {return c == '0' || c == '1'; }) ||
                !all_of(key.begin(), key.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "输入格式错误！请确保明文为8位，密钥为10位的二进制字符串。\n";
                continue;
            }
            string ciphertext = sdes_encrypt(plaintext, key);
            cout << "密文: " << ciphertext << "\n";
        }
        else if (choice == 2) { // 解密8-bit密文
            string ciphertext, key;
            cout << "请输入8-bit密文（二进制字符串，如01010101）: ";
            cin >> ciphertext;
            cout << "请输入10-bit密钥（二进制字符串，如1010000010）: ";
            cin >> key;
            if (ciphertext.size() != 8 || key.size() != 10 ||
                !all_of(ciphertext.begin(), ciphertext.end(), [](char c) {return c == '0' || c == '1'; }) ||
                !all_of(key.begin(), key.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "输入格式错误！请确保密文为8位，密钥为10位的二进制字符串。\n";
                continue;
            }
            string plaintext = sdes_decrypt(ciphertext, key);
            cout << "明文: " << plaintext << "\n";
        }
        else if (choice == 3) { // 加密ASCII字符串
            string plaintext_str, key;
            cout << "请输入ASCII明文字符串: ";
            getline(cin, plaintext_str);
            if (plaintext_str.empty()) {
                // 如果上一个cin >>读取后没有清除换行符
                getline(cin, plaintext_str);
            }
            cout << "请输入10-bit密钥（二进制字符串，如1010000010）: ";
            cin >> key;
            if (key.size() != 10 ||
                !all_of(key.begin(), key.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "输入格式错误！请确保密钥为10位的二进制字符串。\n";
                continue;
            }
            string binary_plaintext = string_to_binary(plaintext_str);
            string binary_ciphertext = "";
            for (size_t i = 0; i < binary_plaintext.size(); i += 8) {
                string byte = binary_plaintext.substr(i, 8);
                if (byte.size() < 8) byte = byte + string(8 - byte.size(), '0'); // 填充
                binary_ciphertext += sdes_encrypt(byte, key);
            }
            string ciphertext_str = binary_to_string(binary_ciphertext);
            cout << "密文（可能为乱码）: " << ciphertext_str << "\n";
        }
        else if (choice == 4) { // 解密ASCII字符串
            string ciphertext_str, key;
            cout << "请输入ASCII密文字符串: ";
            getline(cin, ciphertext_str);
            if (ciphertext_str.empty()) {
                // 如果上一个cin >>读取后没有清除换行符
                getline(cin, ciphertext_str);
            }
            cout << "请输入10-bit密钥（二进制字符串，如1010000010）: ";
            cin >> key;
            if (key.size() != 10 ||
                !all_of(key.begin(), key.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "输入格式错误！请确保密钥为10位的二进制字符串。\n";
                continue;
            }
            string binary_ciphertext = string_to_binary(ciphertext_str);
            string binary_plaintext = "";
            for (size_t i = 0; i < binary_ciphertext.size(); i += 8) {
                string byte = binary_ciphertext.substr(i, 8);
                if (byte.size() < 8) byte = byte + string(8 - byte.size(), '0'); // 填充
                binary_plaintext += sdes_decrypt(byte, key);
            }
            string plaintext_str = binary_to_string(binary_plaintext);
            cout << "明文: " << plaintext_str << "\n";
        }
        else if (choice == 5) { // 暴力破解
            string plaintext, ciphertext;
            cout << "请输入已知的8-bit明文（二进制字符串，如10101010）: ";
            cin >> plaintext;
            cout << "请输入对应的8-bit密文（二进制字符串，如01100100）: ";
            cin >> ciphertext;
            if (plaintext.size() != 8 || ciphertext.size() != 8 ||
                !all_of(plaintext.begin(), plaintext.end(), [](char c) {return c == '0' || c == '1'; }) ||
                !all_of(ciphertext.begin(), ciphertext.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "输入格式错误！请确保明文和密文均为8位的二进制字符串。\n";
                continue;
            }
            string found_key = brute_force_crack(plaintext, ciphertext);
            if (found_key.empty()) {
                cout << "未找到匹配的密钥。\n";
            }
            else {
                cout << "找到的密钥: " << found_key << "\n";
            }
        }
        else if (choice == 6) { // 密钥唯一性分析
            string plaintext, ciphertext;
            cout << "请输入明文（8-bit 二进制字符串）: ";
            cin >> plaintext;
            cout << "请输入对应的密文（8-bit 二进制字符串）: ";
            cin >> ciphertext;
            if (plaintext.size() != 8 || ciphertext.size() != 8 ||
                !all_of(plaintext.begin(), plaintext.end(), [](char c) {return c == '0' || c == '1'; }) ||
                !all_of(ciphertext.begin(), ciphertext.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "输入格式错误！请确保明文和密文均为8位的二进制字符串。\n";
                continue;
            }
            vector<string> matching_keys = brute_force_all_keys(plaintext, ciphertext);
            cout << "匹配的密钥数量: " << matching_keys.size() << "\n";
            for (auto& k : matching_keys) {
                cout << "密钥: " << k << "\n";
            }
            if (matching_keys.size() > 1) {
                cout << "存在多个密钥生成相同的密文。\n";
            }
            else {
                cout << "密钥唯一。\n";
            }
        }
        else {
            cout << "无效的选择，请重新输入。\n";
        }
        cout << "======================================================\n\n";
    }
    return 0;
}
