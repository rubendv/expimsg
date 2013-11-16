#ifndef EXPIMSG_MINIMALT_H
#define EXPIMSG_MINIMALT_H
#include <string>
#include <sstream>
#include <easylogging++.h>
#include <stdexcept>
#include <cstdint>
#include <iomanip>
#include "util.h"

class PublicKey {
public:
    std::string box_pk;
    std::string sign_pk;
    PublicKey() {}
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
    PublicKey authority_pk;
    Certificate() {}
    Certificate(const std::string& box_pk_signed, const std::string& sign_pk_signed, const PublicKey& authority_pk) 
    : box_pk_signed(box_pk_signed), sign_pk_signed(sign_pk_signed), authority_pk(authority_pk) {}
    std::string box_pk() const {
        return sign_open(box_pk_signed, authority_pk.sign_pk);
    }
    std::string sign_pk() const {
        return sign_open(sign_pk_signed, authority_pk.sign_pk);
    }
    std::string packetize() const {
        std::ostringstream packet;
        //packet << base64_encode(box_pk_signed) << "::" << base64_encode(sign_pk_signed);
        packet << box_pk_signed << sign_pk_signed;
        return packet.str();
    }
};

class Key {
public:
    std::string box_pk, box_sk, sign_pk, sign_sk;
    Key() {
        box_pk = box_keypair(box_sk);
        sign_pk = sign_keypair(sign_sk);
    }
    PublicKey publicPart() {
        return PublicKey(box_pk, sign_pk);
    }
    Certificate certificate(const PublicKey& pk) {
        return Certificate(sign(pk.box_pk, sign_sk), sign(pk.sign_pk, sign_sk), this->publicPart());
    }
    ~Key() {
        sodium_memzero(&box_sk[0], box_sk.size());
        sodium_memzero(&sign_sk[0], sign_sk.size());
    }
};

class Unboxed {
public:
    bool is_reliable;
    std::uint32_t connection_id;
    std::uint32_t sequence_number;
    std::uint32_t acknowledgment;
    std::string message;

    Unboxed() {}

    Unboxed(const std::string& boxed, const std::string& nonce, const std::string& key) {
        std::string unboxed = secretbox_open(boxed, nonce, key);
        std::istringstream unboxedstream(unboxed);
        unboxedstream.read(reinterpret_cast<char *>(&connection_id), sizeof(connection_id));
        connection_id = ntohl(connection_id);
        is_reliable = (connection_id & (1 << 31)) != 0;
        connection_id &= ~(1 << 31);
        if(is_reliable) {
            unboxedstream.read(reinterpret_cast<char *>(&sequence_number), sizeof(sequence_number));
            sequence_number = ntohl(sequence_number);
            unboxedstream.read(reinterpret_cast<char *>(&acknowledgment), sizeof(acknowledgment));
            acknowledgment = ntohl(acknowledgment);
        } 
        message.resize(unboxed.size()-unboxedstream.tellg(), 0);
        unboxedstream.read(&message[0], message.size());
    }

    std::string box(const std::string& nonce, const std::string& key) {
        std::ostringstream unboxed;
        if((connection_id & (1 << 31)) != 0) {
            throw std::invalid_argument("the high bit of connection_id is reserved for is_reliable");
        }
        std::uint32_t packed_connection_id = htonl(((std::uint32_t)is_reliable << 31) | connection_id);
        unboxed.write(reinterpret_cast<char *>(&packed_connection_id), sizeof(packed_connection_id));
        if(is_reliable) {
            std::uint32_t sequence_number_converted = htonl(sequence_number);
            unboxed.write(reinterpret_cast<char *>(&sequence_number_converted), sizeof(sequence_number_converted));
            std::uint32_t acknowledgment_converted = htonl(acknowledgment);
            unboxed.write(reinterpret_cast<char *>(&acknowledgment_converted), sizeof(acknowledgment_converted));
        }
        unboxed << message;
        return secretbox(unboxed.str(), nonce, key);
    }
    friend std::ostream& operator<< (std::ostream& stream, const Unboxed& unboxed);
};

std::ostream& operator<< (std::ostream& stream, const Unboxed& unboxed) {
    stream << "Unboxed:" << std::endl;
    stream << "connection_id: " << std::hex << unboxed.connection_id << std::endl;
    if(unboxed.is_reliable) {
        stream << "sequence_number: " << std::hex << unboxed.sequence_number << std::endl;
        stream << "acknowledgment: " << std::hex << unboxed.acknowledgment << std::endl;
    }
    stream << "message: " << std::dec << unboxed.message.size() << " bytes";
    return stream;
}


class PublicMessage {
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
        std::istringstream packetstream(packet);
        std::uint64_t first8;
        packetstream.read(reinterpret_cast<char *>(&first8), sizeof(first8));
        first8 = ntohll(first8);
        ephemeral_pk_present = (first8 & (1LL << 63)) != 0;
        puzzle_or_solution_present = (first8 & (1LL << 62)) != 0;
        tunnel_id = (first8 & (~(3LL << 62)));
        
        nonce.resize(crypto_box_NONCEBYTES, 0);
        packetstream.read(&nonce[0], nonce.size());
        if(ephemeral_pk_present) {
            ephemeral_box_pk.resize(crypto_box_PUBLICKEYBYTES, 0);
            packetstream.read(&ephemeral_box_pk[0], ephemeral_box_pk.size());
        }
        if(puzzle_or_solution_present) {
            puzzle_or_solution.resize(148, 0);
            packetstream.read(&puzzle_or_solution[0], puzzle_or_solution.size());
        }
        boxed.resize(packet.size()-packetstream.tellg(), 0);
        packetstream.read(&boxed[0], boxed.size());
    }

    std::string packetize() {
        std::ostringstream packet;
        std::uint64_t first8 = ((std::uint64_t)ephemeral_pk_present << 63)
                             | ((std::uint64_t)puzzle_or_solution_present << 62)
                             | ((std::uint64_t)tunnel_id & (~(3LL << 62)));
        first8 = htonll(first8);
        packet.write(reinterpret_cast<char *>(&first8), sizeof(first8));
        packet << nonce;
        if(ephemeral_pk_present) {
            if(ephemeral_box_pk.size() != crypto_box_PUBLICKEYBYTES) {
                throw std::invalid_argument("ephemeral_box_pk has incorrect size");
            }
            packet << ephemeral_box_pk;
        }
        if(puzzle_or_solution_present) {
            if(puzzle_or_solution.size() != 148) {
                throw std::invalid_argument("puzzle_or_solution has incorrect size");
            }
            packet << puzzle_or_solution;
        }
        packet << boxed;
        return packet.str();
    }

    Unboxed unbox(const Key& receiver_key) {
        std::string secretbox_key = box_keyexchange(ephemeral_box_pk, receiver_key.box_sk);
        return Unboxed(boxed, nonce, secretbox_key);
    }
    Unboxed unbox(const Key& receiver_key, const PublicKey& sender_pk) {
        std::string secretbox_key = box_keyexchange(sender_pk.box_pk, receiver_key.box_sk);
        return Unboxed(boxed, nonce, secretbox_key);
    }

    friend std::ostream& operator<< (std::ostream& stream, const PublicMessage& message);
};

std::ostream& operator<< (std::ostream& stream, const PublicMessage& message) {
    stream << "PublicMessage:" << std::endl;
    stream << "tunnel_id: " << std::hex << (message.tunnel_id & (~(3LL << 62))) << std::endl;
    if(message.ephemeral_pk_present) {
        stream << "ephemeral_pk: " << base64_encode(message.ephemeral_box_pk) << std::endl;
    }
    if(message.puzzle_or_solution_present) {
        stream << "puzzle_or_solution: " << base64_encode(message.puzzle_or_solution) << std::endl;
    }
    stream << "nonce: " << base64_encode(message.nonce);
    return stream;
}

enum class ControlMessage : char {
    provideCert='R',
    requestCert='P',
    nextTid='T'
};

PublicMessage makeRequestCertMessage(std::uint64_t tunnel_id, const std::string& identifier, const Key& sender_key, const PublicKey& receiver_pk) {
    Unboxed unboxed;
    unboxed.connection_id = 0;
    unboxed.is_reliable = false;
    std::stringstream innermessage;
    innermessage << static_cast<char>(ControlMessage::requestCert) << identifier; 
    unboxed.message = innermessage.str();

    PublicMessage message;
    message.ephemeral_pk_present = true;
    message.ephemeral_box_pk = sender_key.box_pk;
    message.puzzle_or_solution_present = false;
    message.tunnel_id = tunnel_id;
    message.nonce = box_nonce_random();
    std::string secretbox_key = box_keyexchange(receiver_pk.box_pk, sender_key.box_sk);
    message.boxed = unboxed.box(message.nonce, secretbox_key); 

    return message;
}

PublicMessage makeProvideCertMessage(std::uint64_t tunnel_id, const Certificate& certificate, const Key& sender_key, const PublicKey& receiver_pk) {
    Unboxed unboxed;
    unboxed.connection_id = 0;
    unboxed.is_reliable = false;
    std::stringstream innermessage;
    innermessage << static_cast<char>(ControlMessage::provideCert);
    innermessage << certificate.packetize();
    unboxed.message = innermessage.str();

    PublicMessage message;
    message.ephemeral_pk_present = false;
    message.puzzle_or_solution_present = false;
    message.tunnel_id = tunnel_id;
    message.nonce = box_nonce_random();
    std::string secretbox_key = box_keyexchange(receiver_pk.box_pk, sender_key.box_sk);
    message.boxed = unboxed.box(message.nonce, secretbox_key); 

    return message;
}


#endif
