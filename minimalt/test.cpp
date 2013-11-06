#include <iostream>
#include <sodium.h>
#include <easylogging++.h>
#include <string>
#include <iomanip>
#include <stdexcept>
#include <cstdint>
#include "crypto.h"

_INITIALIZE_EASYLOGGINGPP

std::string to_hex(std::string s) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < s.size(); ++i)
    {
        ss << std::setw(2) << (static_cast<unsigned>(s[i]) & 0xff);
    }
    return ss.str();
}

int main(int argc, const char ** argv) {
    sodium_init();  

    std::string pk_sender, sk_sender;
    std::string pk_receiver, sk_receiver;
    
    pk_sender = box_keypair(sk_sender);
    pk_receiver = box_keypair(sk_receiver);

    LOG(INFO) << std::setw(30) << "Public key sender: " << to_hex(pk_sender);
    LOG(INFO) << std::setw(30) << "Secret key sender: " << to_hex(sk_sender);
    LOG(INFO) << std::setw(30) << "Public key receiver: " << to_hex(pk_receiver);
    LOG(INFO) << std::setw(30) << "Secret key receiver: " << to_hex(sk_receiver);
    
    std::string message = "Hello, world!";
    LOG(INFO) << std::setw(30) << "Message: " << to_hex(message);
    std::string nonce = box_nonce_random();
    LOG(INFO) << std::setw(30) << "Nonce: " << to_hex(nonce);
    std::string key_sender = box_keyexchange(pk_receiver, sk_sender);
    LOG(INFO) << std::setw(30) << "Shared key sender: " << to_hex(key_sender);
    std::string key_receiver = box_keyexchange(pk_sender, sk_receiver);
    LOG(INFO) << std::setw(30) << "Shared key receiver: " << to_hex(key_receiver);
    std::string ciphertext = secretbox(message, nonce, key_sender);
    LOG(INFO) << std::setw(30) << "Ciphertext: " << to_hex(ciphertext);
    try {
        std::string message_decrypted = secretbox_open(ciphertext, nonce, key_receiver);
        LOG(INFO) << std::setw(30) << "Message (decrypted): " << to_hex(message_decrypted);
    } catch(box_error& e) {
        LOG(ERROR) << "Failed to decrypt message";
    }

    std::string pk_sign, sk_sign;
    pk_sign = sign_keypair(sk_sign);
    LOG(INFO) << std::setw(30) << "Public signing key: " << to_hex(pk_sign);
    LOG(INFO) << std::setw(30) << "Secret signing key: " << to_hex(sk_sign);

    std::string signed_message = sign(message, sk_sign);
    LOG(INFO) << std::setw(30) << "Signed message: " << to_hex(signed_message);
    try {
        std::string verified_message = sign_open(signed_message, pk_sign);
        LOG(INFO) << std::setw(30) << "Message (verified): " << to_hex(verified_message);
    } catch(sign_error& e) {
        LOG(ERROR) << "Failed to verify message";
    }

    return 0;
}
