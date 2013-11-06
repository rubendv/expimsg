#ifndef EXPIMSG_CRYPTO_H
#define EXPIMSG_CRYPTO_H
#include <stdexcept>
#include <string>

class box_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class sign_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::string box_keypair(std::string& sk);
std::string box_keyexchange(std::string pk, std::string sk);
std::string box_nonce_random();

std::string box(std::string message, std::string nonce, std::string pk_receiver, std::string sk_sender);
std::string secretbox(std::string message, std::string nonce, std::string key);
std::string box_open(std::string ciphertext, std::string nonce, std::string pk_sender, std::string sk_receiver);
std::string secretbox_open(std::string ciphertext, std::string nonce, std::string key);

std::string sign_keypair(std::string& sk);
std::string sign(std::string m, std::string sk);
std::string sign_open(std::string sm, std::string pk);
#endif
