#include <iostream>
#include <sodium.h>
#include <easylogging++.h>
#include <string>
#include <iomanip>
#include <stdexcept>
#include <cstdint>
#include "crypto.h"
#include <map>
#include <optional>
#include <algorithm>
#include <functional>

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

class PublicKey {
public:
    std::string box_pk;
    std::string sign_pk;
    PublicKey(const std::string& box_pk, const std::string& sign_pk="") 
    : box_pk(box_pk), sign_pk(sign_pk) {}
    bool has_sign_pk() {
        return sign_pk.size() == crypto_sign_PUBLICKEYBYTES;
    }
};

class Certificate {
public:
    std::string box_pk_signed;
    std::string sign_pk_signed;
    const PublicKey& authority_pk;
    PublicKey(const std::string& box_pk_signed, const std::string& sign_pk_signed, const PublicKey& authority_pk) 
    : box_pk_signed(box_pk_signed), sign_pk_signed(sign_pk_signed), authority_pk(authority_pk) {}
    std::string box_pk() const {
        return sign_open(box_signed, authority_pk.sign_pk);
    }
    std::string sign_pk() const {
        return sign_open(sign_signed, authority_pk.sign_pk);
    }
};

class Key {
public:
    std::string box_pk, box_sk, sign_pk, sign_sk;
    Key() {
        box_pk = box_keypair(box_sk);
        sign_pk = sign_keypair(sign_pk);
    }
    PublicKey publicPart() {
        return PublicKey(box_pk, sign_pk);
    }
    Certificate certificate(const PublicKey& pk) {
        return Certificate(sign(pk.box, sign_sk), sign(pk.sign, sign_sk), this->publicPart());
    }
};

std::uint64_t htonll(std::uint64_t value) {
    int num = 42;
    if(*reinterpret_cast<char *>(&num) == 42) {
        uint32_t high_part = htonl((uint32_t)(value >> 32));
        uint32_t low_part = htonl((uint32_t)(value & 0xFFFFFFFFLL));
        return (((uint64_t)low_part) << 32) | high_part;
    } else {
        return value;
    }
}

std::uint64_t ntohll(std::uint64_t value) {
    return htonll(value);
}


class Message {
public:
    bool ephemeral_pk_present;
    bool puzzle_or_solution_present:1;
    std::uint64_t tunnel_id;
    std::string nonce;
    std::string ephemeral_box_pk;
    std::string puzzle_or_solution;
    std::string boxed;

    PublicMessage() {}

    PublicMessage(std::string packet) {
        std::uint64_t index = 0;
        std::uint64_t first8 = ntohll(*reinterpret_cast<std::uint64_t *>(&packet[index]));
        index += 8;
        ephemeral_pk_present = (first8 & (1 << 63)) != 0;
        puzzle_or_solution_present = (first8 & (1 << 62)) != 0;
        tunnel_id = (first8 & (~(3 << 62)));
        nonce.resize(crypto_box_NONCEBYTES, 0);
        std::copy(
            packet.begin()+index, 
            packet.begin()+index+nonce.size(), 
            nonce.begin()
        );
        index += nonce.size();
        if(ephemeral_pk_present) {
            ephemeral_box_pk.resize(crypto_box_PUBLICKEYBYTES, 0);
            std::copy(
                packet.begin()+index, 
                packet.begin()+index+ephemeral_box_pk.size(), 
                ephemeral_box_pk.begin()
            );
            index += ephemeral_box_pk.size();
        }
        if(puzzle_or_solution_present) {
            puzzle_or_solution.resize(148, 0);
            std::copy(
                packet.begin()+index, 
                packet.begin()+index+puzzle_or_solution.size(), 
                puzzle_or_solution.begin()
            );
            index += puzzle_or_solution.size();
        }
        boxed.resize(packet.size()-index, 0);
        std::copy(
            packet.begin()+index,
            packet.end(),
            boxed.begin()
        );
    }

    std::string packetize() {
        std::stringstream packet;
        std::uint64_t first8 = ((std::uint64_t)ephemeral_pk_present << 63)
                             | ((std::uint64_t)puzzle_or_solution_present << 63)
                             | ((std::uint64_t)tunnel_id & (~(3 << 62)));
        first8 = htonll(first8);
        packet << reinterpret_cast<char *>(&first8);
        packet << nonce;
        if(ephemeral_pk_present) {
            packet << ephemeral_box_pk;
        }
        if(puzzle_or_solution_present) {
            packet << puzzle_or_solution;
        }
        packet << boxed;
        return packet.str();
    }
}

class Unboxed {
public:
    std::uint32_t connection_id;
    bool is_reliable;
    std::uint32_t sequence_number;
    std::uint32_t acknowledgment;
    std::string message;

    Unboxed() {}

    Unboxed(const std::string& boxed, const std::string& nonce, const std::string& key, std::function<bool (std::uint32_t)> check_is_reliable) {
        std::uint64_t index = 0;
        std::string unboxed = secretbox_open(boxed, nonce, key);
        connection_id = ntohl(reinterpret_cast<std::uint32_t *>(&boxed[index]));
        index += 4;
        is_reliable = check_is_reliable(connection_id);
        if(is_reliable) {
            sequence_number = ntohl(reinterpret_cast<std::uint32_t *>(&boxed[index]));
            index += 4;
            acknowledgment = ntohl(reinterpret_cast<std::uint32_t *>(&boxed[index]));
            index += 4;
        } 
        message.resize(unboxed.size()-index, 0);
        std::copy(
            unboxed.begin()+index,
            unboxed.end(),
            message.begin()
        );
    }

    std::string box(const std::string& nonce, const std::string& key) {
        std::stringstream unboxed;
        unboxed << reinterpret_cast<char *>(&connection_id);
        if(is_reliable) {
            unboxed << reinterpret_cast<char *>(&sequence_number);
            unboxed << reinterpret_cast<char *>(&acknowledgment);
        }
        unboxed << message;
        return secretbox(boxed.str(), nonce, key);
    }
}

int main(int argc, const char ** argv) {
    sodium_init();  

    Key directory_long;
    Key directory_ephemeral;
    
    std::map<std::string, PublicKey> directory_publickeys;
    
    Key rubendvbe_long;
    Key rubendvbe_ephemeral;
    directory_server_certificates["rubendv.be:80"] = directory_long.certificate(rubendvbe_ephemeral.publicPart());

    Key client_long;
    Key client_ephemeral;
    PublicKey directory_long_public = directory_long.publicPart();

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
