#include <iostream>
#include <sodium.h>
#include <easylogging++.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>

_INITIALIZE_EASYLOGGINGPP

class box_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::string to_hex(std::string s) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < s.size(); ++i)
    {
        ss << std::setw(2) << (static_cast<unsigned>(s[i]) & 0xff);
    }
    return ss.str();
}

std::string box_keypair(std::string& sk) {
    std::string pk(crypto_box_PUBLICKEYBYTES, 0);
    sk.resize(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(reinterpret_cast<unsigned char *>(&pk[0]), reinterpret_cast<unsigned char *>(&sk[0]));
    return pk;
}

std::string box_keyexchange(std::string pk, std::string sk) {
    if(sk.size() != crypto_box_SECRETKEYBYTES 
    || pk.size() != crypto_box_PUBLICKEYBYTES) {
        throw std::invalid_argument("Invalid argument length for pk or sk");
    }

    std::string k(crypto_box_BEFORENMBYTES, 0);
    crypto_box_beforenm(
        reinterpret_cast<unsigned char *>(&k[0]),
        reinterpret_cast<unsigned char *>(&pk[0]),
        reinterpret_cast<unsigned char *>(&sk[0])
    );

    return k;
}

std::string box(std::string message, std::string nonce, std::string pk_receiver, std::string sk_sender) {
    if(sk_sender.size() != crypto_box_SECRETKEYBYTES 
    || pk_receiver.size() != crypto_box_PUBLICKEYBYTES
    || nonce.size() != crypto_box_NONCEBYTES) {
        throw std::invalid_argument("Invalid argument length for sk_sender, pk_receiver or nonce");
    }
    std::string ciphertext_padded(crypto_box_ZEROBYTES+message.size(), 0);
    std::string message_padded(crypto_box_ZEROBYTES+message.size(), 0);
    std::copy(message.begin(), message.end(), message_padded.begin()+crypto_box_ZEROBYTES);
    crypto_box(
        reinterpret_cast<unsigned char *>(&ciphertext_padded[0]), 
        reinterpret_cast<unsigned char *>(&message_padded[0]), 
        message_padded.size(), 
        reinterpret_cast<unsigned char *>(&nonce[0]), 
        reinterpret_cast<unsigned char *>(&pk_receiver[0]), 
        reinterpret_cast<unsigned char *>(&sk_sender[0])
    );
    return ciphertext_padded.substr(crypto_box_BOXZEROBYTES, ciphertext_padded.size() - crypto_box_BOXZEROBYTES);
}

std::string secretbox(std::string message, std::string nonce, std::string key) {
    if(key.size() != crypto_box_BEFORENMBYTES 
    || nonce.size() != crypto_box_NONCEBYTES) {
        throw std::invalid_argument("Invalid argument length for sk_sender, pk_receiver or nonce");
    }
    std::string ciphertext_padded(crypto_box_ZEROBYTES+message.size(), 0);
    std::string message_padded(crypto_box_ZEROBYTES+message.size(), 0);
    std::copy(message.begin(), message.end(), message_padded.begin()+crypto_box_ZEROBYTES);
    crypto_box_afternm(
        reinterpret_cast<unsigned char *>(&ciphertext_padded[0]), 
        reinterpret_cast<unsigned char *>(&message_padded[0]), 
        message_padded.size(), 
        reinterpret_cast<unsigned char *>(&nonce[0]), 
        reinterpret_cast<unsigned char *>(&key[0])
    );
    return ciphertext_padded.substr(crypto_box_BOXZEROBYTES, ciphertext_padded.size() - crypto_box_BOXZEROBYTES);
}

std::string box_nonce_random() {
    std::string nonce(crypto_box_NONCEBYTES, 0);
    randombytes_buf(&nonce[0], crypto_box_NONCEBYTES);
    return nonce;
}

std::string box_open(std::string ciphertext, std::string nonce, std::string pk_sender, std::string sk_receiver) {
    if(pk_sender.size() != crypto_box_PUBLICKEYBYTES 
    || sk_receiver.size() != crypto_box_SECRETKEYBYTES
    || nonce.size() != crypto_box_NONCEBYTES) {
        throw std::invalid_argument("Invalid argument length for key or nonce");
    }
    std::string ciphertext_padded(crypto_box_BOXZEROBYTES+ciphertext.size(), 0);
    std::string message_padded(crypto_box_BOXZEROBYTES+ciphertext.size(), 0);
    std::copy(ciphertext.begin(), ciphertext.end(), ciphertext_padded.begin()+crypto_box_BOXZEROBYTES);
    int error = crypto_box_open(
        reinterpret_cast<unsigned char *>(&message_padded[0]), 
        reinterpret_cast<unsigned char *>(&ciphertext_padded[0]), 
        ciphertext_padded.size(), 
        reinterpret_cast<unsigned char *>(&nonce[0]), 
        reinterpret_cast<unsigned char *>(&pk_sender[0]), 
        reinterpret_cast<unsigned char *>(&sk_receiver[0])
    );
    if(error != 0) {
        throw box_error("box_open failed");
    }
    return message_padded.substr(crypto_box_ZEROBYTES, message_padded.size()-crypto_box_ZEROBYTES);
}

std::string secretbox_open(std::string ciphertext, std::string nonce, std::string key) {
    if(key.size() != crypto_box_BEFORENMBYTES 
    || nonce.size() != crypto_box_NONCEBYTES) {
        throw std::invalid_argument("Invalid argument length for key or nonce");
    }
    std::string ciphertext_padded(crypto_box_BOXZEROBYTES+ciphertext.size(), 0);
    std::string message_padded(crypto_box_BOXZEROBYTES+ciphertext.size(), 0);
    std::copy(ciphertext.begin(), ciphertext.end(), ciphertext_padded.begin()+crypto_box_BOXZEROBYTES);
    int error = crypto_box_open_afternm(
        reinterpret_cast<unsigned char *>(&message_padded[0]), 
        reinterpret_cast<unsigned char *>(&ciphertext_padded[0]), 
        ciphertext_padded.size(), 
        reinterpret_cast<unsigned char *>(&nonce[0]), 
        reinterpret_cast<unsigned char *>(&key[0])
    );
    if(error != 0) {
        throw box_error("box_open failed");
    }
    return message_padded.substr(crypto_box_ZEROBYTES, message_padded.size()-crypto_box_ZEROBYTES);
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
    
    std::string message = "Hello, world! From Ruben.";
    LOG(INFO) << std::setw(30) << "Message: " << to_hex(message);
    std::string nonce = box_nonce_random();
    LOG(INFO) << std::setw(30) << "Nonce: " << to_hex(nonce);
    std::string key_sender = box_keyexchange(pk_receiver, sk_sender);
    LOG(INFO) << std::setw(30) << "Key sender: " << to_hex(key_sender);
    std::string key_receiver = box_keyexchange(pk_sender, sk_receiver);
    LOG(INFO) << std::setw(30) << "Key receiver: " << to_hex(key_receiver);
    std::string ciphertext = secretbox(message, nonce, key_sender);
    LOG(INFO) << std::setw(30) << "Ciphertext: " << to_hex(ciphertext);
    try {
        std::string message_decrypted = secretbox_open(ciphertext, nonce, key_receiver);
        LOG(INFO) << std::setw(30) << "Message (decrypted): " << to_hex(message_decrypted);
    } catch(box_error& e) {
        LOG(ERROR) << "Failed to decrypt message";
    }
    return 0;
}
