#include <vector>
#include <algorithm>
// ������Ҫ��ͷ�ļ�
#include <iostream>
#include <string>
#include <sstream>
#include <bitset>
#include <thread>
#include <mutex>
#include <chrono>

using namespace std;

// ����ȫ�������ڶ��߳�
mutex mtx;

// S-Box��
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

// P10�û�
int P10[10] = { 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 };

// P8�û�
int P8[8] = { 6, 3, 7, 4, 8, 5, 10, 9 };

// ��ʼ�û�IP
int IP[8] = { 2, 6, 3, 1, 4, 8, 5, 7 };

// ���ʼ�û�IP^-1
int IP_INV[8] = { 4, 1, 3, 5, 7, 2, 8, 6 };

// ��չ�û�E/P
int EP[8] = { 4, 1, 2, 3, 2, 3, 4, 1 };

// ���ƺ�����ѭ�����ƣ�
string left_shift(string key, int n) {
    return key.substr(n) + key.substr(0, n);
}

// �û�����
string permute(const string& bits, const int* table, int n) {
    string permuted = "";
    for (int i = 0; i < n; i++) {
        permuted += bits[table[i] - 1];
    }
    return permuted;
}

// XOR����
string xor_bits(const string& a, const string& b) {
    string result = "";
    for (int i = 0; i < a.size(); i++) {
        result += (a[i] == b[i]) ? '0' : '1';
    }
    return result;
}

// S-Box�滻
string sbox_replace(const string& input, int sbox[4][4]) {
    // ����Ϊ4λ�������ַ���
    // ������λ��ĩλȷ���������м���λȷ��
    int row = 2 * (input[0] - '0') + (input[3] - '0');
    int col = 2 * (input[1] - '0') + (input[2] - '0');
    int val = sbox[row][col];
    string binary = bitset<2>(val).to_string();
    return binary;
}

// ��Կ����
pair<string, string> generate_keys(const string& key) {
    // P10�û�
    string permuted = permute(key, P10, 10);

    // �ֳ�������
    string left = permuted.substr(0, 5);
    string right = permuted.substr(5, 5);

    // ����1
    left = left_shift(left, 1);
    right = left_shift(right, 1);

    // �ϲ�������P8�û����õ�K1
    string K1 = permute(left + right, P8, 8);

    // ����2
    left = left_shift(left, 2);
    right = left_shift(right, 2);

    // �ϲ�������P8�û����õ�K2
    string K2 = permute(left + right, P8, 8);

    return { K1, K2 };
}

// Feistel����
string feistel(const string& half, const string& key) {
    // ��չ�û�E/P
    string expanded = permute(half, EP, 8);

    // XOR with key
    string xored = xor_bits(expanded, key);

    // �ֳ�������
    string left = xored.substr(0, 4);
    string right = xored.substr(4, 4);

    // S-Box�滻
    string s0 = sbox_replace(left, S0);
    string s1 = sbox_replace(right, S1);

    // P4�û�
    string combined = s0 + s1;
    string p4 = permute(combined, P4_final, 4);

    return p4;
}

// ���ܺ���
string sdes_encrypt(const string& plaintext, const string& key) {
    pair<string, string> keys = generate_keys(key);
    string K1 = keys.first;
    string K2 = keys.second;

    // ��ʼ�û�IP
    string permuted = permute(plaintext, IP, 8);

    // �ֳ�������
    string left = permuted.substr(0, 4);
    string right = permuted.substr(4, 4);

    // ��һ��
    string f = feistel(right, K1);
    string new_left = xor_bits(left, f);
    string new_right = right;

    // ����
    swap(new_left, new_right);

    // �ڶ���
    f = feistel(new_right, K2);
    new_left = xor_bits(new_left, f);
    // new_right remains the same

    // �ϲ�
    string preoutput = new_left + new_right;

    // ���ʼ�û�IP^-1
    string ciphertext = permute(preoutput, IP_INV, 8);

    return ciphertext;
}

// ���ܺ���
string sdes_decrypt(const string& ciphertext, const string& key) {
    pair<string, string> keys = generate_keys(key);
    string K1 = keys.first;
    string K2 = keys.second;

    // ��ʼ�û�IP
    string permuted = permute(ciphertext, IP, 8);

    // �ֳ�������
    string left = permuted.substr(0, 4);
    string right = permuted.substr(4, 4);

    // ��һ�֣�ʹ��K2��
    string f = feistel(right, K2);
    string new_left = xor_bits(left, f);
    string new_right = right;

    // ����
    swap(new_left, new_right);

    // �ڶ��֣�ʹ��K1��
    f = feistel(new_right, K1);
    new_left = xor_bits(new_left, f);
    // new_right remains the same

    // �ϲ�
    string preoutput = new_left + new_right;

    // ���ʼ�û�IP^-1
    string plaintext = permute(preoutput, IP_INV, 8);

    return plaintext;
}

// ASCII�ַ���ת��Ϊ������
string string_to_binary(const string& s) {
    string binary = "";
    for (char c : s) {
        binary += bitset<8>(c).to_string();
    }
    return binary;
}

// ������ת��ΪASCII�ַ���
string binary_to_string(const string& b) {
    string s = "";
    for (size_t i = 0; i + 8 <= b.size(); i += 8) {
        string byte = b.substr(i, 8);
        char c = static_cast<char>(bitset<8>(byte).to_ulong());
        s += c;
    }
    return s;
}

// �����ƽ��̺߳���
void brute_force_crack_thread(const string& plaintext, const string& ciphertext, string& found_key, int start, int end) {
    for (int key = start; key < end; key++) {
        // ����Ѿ��ҵ�����ǰ�˳�
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

// �����ƽ�������
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
        cout << "��Կ�ҵ�: " << found_key << "����ʱ: " << duration.count() << " ��\n";
    }
    else {
        cout << "δ�ҵ�ƥ�����Կ����ʱ: " << duration.count() << " ��\n";
    }

    return found_key;
}

// �����ƽ��������ƥ����Կ
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
        cout << "================= S-DES ���ܽ��ܹ��� =================\n";
        cout << "1. ���� 8-bit ����\n";
        cout << "2. ���� 8-bit ����\n";
        cout << "3. ���� ASCII �ַ���\n";
        cout << "4. ���� ASCII �ַ���\n";
        cout << "5. �����ƽ���Կ\n";
        cout << "6. ��ԿΨһ�Է���\n";
        cout << "0. �˳�\n";
        cout << "������ѡ��: ";
        cin >> choice;
        cin.ignore(); // ���Ի��з�

        if (choice == 0) {
            cout << "�˳�����\n";
            break;
        }
        else if (choice == 1) { // ����8-bit����
            string plaintext, key;
            cout << "������8-bit���ģ��������ַ�������10101010��: ";
            cin >> plaintext;
            cout << "������10-bit��Կ���������ַ�������1010000010��: ";
            cin >> key;
            if (plaintext.size() != 8 || key.size() != 10 ||
                !all_of(plaintext.begin(), plaintext.end(), [](char c) {return c == '0' || c == '1'; }) ||
                !all_of(key.begin(), key.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "�����ʽ������ȷ������Ϊ8λ����ԿΪ10λ�Ķ������ַ�����\n";
                continue;
            }
            string ciphertext = sdes_encrypt(plaintext, key);
            cout << "����: " << ciphertext << "\n";
        }
        else if (choice == 2) { // ����8-bit����
            string ciphertext, key;
            cout << "������8-bit���ģ��������ַ�������01010101��: ";
            cin >> ciphertext;
            cout << "������10-bit��Կ���������ַ�������1010000010��: ";
            cin >> key;
            if (ciphertext.size() != 8 || key.size() != 10 ||
                !all_of(ciphertext.begin(), ciphertext.end(), [](char c) {return c == '0' || c == '1'; }) ||
                !all_of(key.begin(), key.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "�����ʽ������ȷ������Ϊ8λ����ԿΪ10λ�Ķ������ַ�����\n";
                continue;
            }
            string plaintext = sdes_decrypt(ciphertext, key);
            cout << "����: " << plaintext << "\n";
        }
        else if (choice == 3) { // ����ASCII�ַ���
            string plaintext_str, key;
            cout << "������ASCII�����ַ���: ";
            getline(cin, plaintext_str);
            if (plaintext_str.empty()) {
                // �����һ��cin >>��ȡ��û��������з�
                getline(cin, plaintext_str);
            }
            cout << "������10-bit��Կ���������ַ�������1010000010��: ";
            cin >> key;
            if (key.size() != 10 ||
                !all_of(key.begin(), key.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "�����ʽ������ȷ����ԿΪ10λ�Ķ������ַ�����\n";
                continue;
            }
            string binary_plaintext = string_to_binary(plaintext_str);
            string binary_ciphertext = "";
            for (size_t i = 0; i < binary_plaintext.size(); i += 8) {
                string byte = binary_plaintext.substr(i, 8);
                if (byte.size() < 8) byte = byte + string(8 - byte.size(), '0'); // ���
                binary_ciphertext += sdes_encrypt(byte, key);
            }
            string ciphertext_str = binary_to_string(binary_ciphertext);
            cout << "���ģ�����Ϊ���룩: " << ciphertext_str << "\n";
        }
        else if (choice == 4) { // ����ASCII�ַ���
            string ciphertext_str, key;
            cout << "������ASCII�����ַ���: ";
            getline(cin, ciphertext_str);
            if (ciphertext_str.empty()) {
                // �����һ��cin >>��ȡ��û��������з�
                getline(cin, ciphertext_str);
            }
            cout << "������10-bit��Կ���������ַ�������1010000010��: ";
            cin >> key;
            if (key.size() != 10 ||
                !all_of(key.begin(), key.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "�����ʽ������ȷ����ԿΪ10λ�Ķ������ַ�����\n";
                continue;
            }
            string binary_ciphertext = string_to_binary(ciphertext_str);
            string binary_plaintext = "";
            for (size_t i = 0; i < binary_ciphertext.size(); i += 8) {
                string byte = binary_ciphertext.substr(i, 8);
                if (byte.size() < 8) byte = byte + string(8 - byte.size(), '0'); // ���
                binary_plaintext += sdes_decrypt(byte, key);
            }
            string plaintext_str = binary_to_string(binary_plaintext);
            cout << "����: " << plaintext_str << "\n";
        }
        else if (choice == 5) { // �����ƽ�
            string plaintext, ciphertext;
            cout << "��������֪��8-bit���ģ��������ַ�������10101010��: ";
            cin >> plaintext;
            cout << "�������Ӧ��8-bit���ģ��������ַ�������01100100��: ";
            cin >> ciphertext;
            if (plaintext.size() != 8 || ciphertext.size() != 8 ||
                !all_of(plaintext.begin(), plaintext.end(), [](char c) {return c == '0' || c == '1'; }) ||
                !all_of(ciphertext.begin(), ciphertext.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "�����ʽ������ȷ�����ĺ����ľ�Ϊ8λ�Ķ������ַ�����\n";
                continue;
            }
            string found_key = brute_force_crack(plaintext, ciphertext);
            if (found_key.empty()) {
                cout << "δ�ҵ�ƥ�����Կ��\n";
            }
            else {
                cout << "�ҵ�����Կ: " << found_key << "\n";
            }
        }
        else if (choice == 6) { // ��ԿΨһ�Է���
            string plaintext, ciphertext;
            cout << "���������ģ�8-bit �������ַ�����: ";
            cin >> plaintext;
            cout << "�������Ӧ�����ģ�8-bit �������ַ�����: ";
            cin >> ciphertext;
            if (plaintext.size() != 8 || ciphertext.size() != 8 ||
                !all_of(plaintext.begin(), plaintext.end(), [](char c) {return c == '0' || c == '1'; }) ||
                !all_of(ciphertext.begin(), ciphertext.end(), [](char c) {return c == '0' || c == '1'; })) {
                cout << "�����ʽ������ȷ�����ĺ����ľ�Ϊ8λ�Ķ������ַ�����\n";
                continue;
            }
            vector<string> matching_keys = brute_force_all_keys(plaintext, ciphertext);
            cout << "ƥ�����Կ����: " << matching_keys.size() << "\n";
            for (auto& k : matching_keys) {
                cout << "��Կ: " << k << "\n";
            }
            if (matching_keys.size() > 1) {
                cout << "���ڶ����Կ������ͬ�����ġ�\n";
            }
            else {
                cout << "��ԿΨһ��\n";
            }
        }
        else {
            cout << "��Ч��ѡ�����������롣\n";
        }
        cout << "======================================================\n\n";
    }
    return 0;
}
