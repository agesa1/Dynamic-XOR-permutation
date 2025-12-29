#include <iostream>
#include <iomanip>
#include "memoryenc.h"

int globalHealth = 100;
static int staticScore = 9999;

struct PlayerData {
    int health;
    int mana;
    float x, y, z;
};

void printHex(const char* label, void* ptr, size_t size) {
    std::cout << label;
    uint8_t* bytes = static_cast<uint8_t*>(ptr);
    for (size_t i = 0; i < size; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(bytes[i]) << " ";
    }
    std::cout << std::dec << std::endl;
}

int main() {
    MemoryEncryption enc;

    std::cout << "=== Stack Variable ===" << std::endl;
    int stackVar = 42;
    std::cout << "original: " << stackVar << std::endl;
    printHex("raw memory: ", &stackVar, sizeof(stackVar));

    enc.encryptValue(stackVar);
    std::cout << "encrypted value: " << stackVar << std::endl;
    printHex("encrypted memory: ", &stackVar, sizeof(stackVar));

    enc.decryptValue(stackVar);
    std::cout << "decrypted: " << stackVar << std::endl;
    std::cout << std::endl;

    std::cout << "=== Heap Allocated ===" << std::endl;
    int* heapVar = new int(1024);
    std::cout << "original: " << *heapVar << std::endl;
    printHex("raw memory: ", heapVar, sizeof(int));

    enc.encryptMemory(heapVar, sizeof(int));
    std::cout << "encrypted value: " << *heapVar << std::endl;
    printHex("encrypted memory: ", heapVar, sizeof(int));

    enc.decryptMemory(heapVar, sizeof(int));
    std::cout << "decrypted: " << *heapVar << std::endl;
    delete heapVar;
    std::cout << std::endl;

    std::cout << "=== Global Variable ===" << std::endl;
    std::cout << "original: " << globalHealth << std::endl;
    printHex("raw memory: ", &globalHealth, sizeof(globalHealth));

    enc.encryptValue(globalHealth);
    std::cout << "encrypted value: " << globalHealth << std::endl;
    printHex("encrypted memory: ", &globalHealth, sizeof(globalHealth));

    enc.decryptValue(globalHealth);
    std::cout << "decrypted: " << globalHealth << std::endl;
    std::cout << std::endl;

    std::cout << "=== Static Variable ===" << std::endl;
    std::cout << "original: " << staticScore << std::endl;
    printHex("raw memory: ", &staticScore, sizeof(staticScore));

    enc.encryptValue(staticScore);
    std::cout << "encrypted value: " << staticScore << std::endl;
    printHex("encrypted memory: ", &staticScore, sizeof(staticScore));

    enc.decryptValue(staticScore);
    std::cout << "decrypted: " << staticScore << std::endl;
    std::cout << std::endl;

    std::cout << "=== Struct Encryption ===" << std::endl;
    PlayerData player = { 100, 50, 10.5f, 20.3f, 5.0f };
    std::cout << "original: hp=" << player.health << " mana=" << player.mana
        << " pos=(" << player.x << "," << player.y << "," << player.z << ")" << std::endl;
    printHex("raw memory: ", &player, sizeof(player));

    enc.encryptMemory(&player, sizeof(player));
    std::cout << "encrypted: hp=" << player.health << " mana=" << player.mana << std::endl;
    printHex("encrypted memory: ", &player, sizeof(player));

    enc.decryptMemory(&player, sizeof(player));
    std::cout << "decrypted: hp=" << player.health << " mana=" << player.mana
        << " pos=(" << player.x << "," << player.y << "," << player.z << ")" << std::endl;
    std::cout << std::endl;

    std::cout << "=== SecureValue Template ===" << std::endl;
    SecureValue<int> secureGold(5000);
    std::cout << "secure gold: " << secureGold.get() << std::endl;

    secureGold.set(7500);
    std::cout << "updated gold: " << secureGold.get() << std::endl;

    int normalValue = secureGold;
    std::cout << "implicit conversion: " << normalValue << std::endl;

    return 0;
}
