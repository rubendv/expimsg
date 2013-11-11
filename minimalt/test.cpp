#include <iostream>
#include <sodium.h>
#include <easylogging++.h>
#include <string>
#include <iomanip>
#include <stdexcept>
#include <cstdint>
#include "crypto.h"
#include <map>
#include <algorithm>
#include <functional>
#include <arpa/inet.h>

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

class Unboxed {
public:
    bool is_reliable;
    std::uint32_t connection_id;
    std::uint32_t sequence_number;
    std::uint32_t acknowledgment;
    std::string message;

    Unboxed() {}

    Unboxed(const std::string& boxed, const std::string& nonce, const std::string& key) {
        std::uint64_t index = 0;
        std::string unboxed = secretbox_open(boxed, nonce, key);
        connection_id = ntohl(*reinterpret_cast<std::uint32_t *>(&unboxed[index]));
        is_reliable = (connection_id & (1 << 31)) != 0;
        connection_id &= ~(1 << 31);
        index += 4;
        if(is_reliable) {
            sequence_number = ntohl(*reinterpret_cast<std::uint32_t *>(&unboxed[index]));
            index += 4;
            acknowledgment = ntohl(*reinterpret_cast<std::uint32_t *>(&unboxed[index]));
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
        std::uint32_t packed_connection_id = htonl(((std::uint32_t)is_reliable << 31) | connection_id);
        unboxed << std::string(reinterpret_cast<char *>(&packed_connection_id), sizeof(packed_connection_id));
        if(is_reliable) {
            std::uint32_t sequence_number_converted = htonl(sequence_number);
            unboxed << std::string(reinterpret_cast<char *>(&sequence_number_converted), sizeof(sequence_number_converted));
            std::uint32_t acknowledgment_converted = htonl(acknowledgment);
            unboxed << std::string(reinterpret_cast<char *>(&acknowledgment_converted), sizeof(acknowledgment_converted));
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
    stream << "message: " << unboxed.message;
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
        std::uint64_t index = 0;
        std::uint64_t first8 = ntohll(*reinterpret_cast<std::uint64_t *>(&packet[index]));
        index += 8;
        ephemeral_pk_present = (first8 & (1LL << 63)) != 0;
        puzzle_or_solution_present = (first8 & (1LL << 62)) != 0;
        tunnel_id = (first8 & (~(3LL << 62)));
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
                             | ((std::uint64_t)puzzle_or_solution_present << 62)
                             | ((std::uint64_t)tunnel_id & (~(3LL << 62)));
        first8 = htonll(first8);
        packet << std::string(reinterpret_cast<char *>(&first8), 8);
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
        stream << "ephemeral_pk: " << to_hex(message.ephemeral_box_pk) << std::endl;
    }
    if(message.puzzle_or_solution_present) {
        stream << "puzzle_or_solution: " << to_hex(message.puzzle_or_solution) << std::endl;
    }
    stream << "nonce: " << to_hex(message.nonce);
    return stream;
}


PublicMessage makeRequestCertMessage(const std::string& identifier, const Key& sender_key, const PublicKey& receiver_pk) {
    Unboxed unboxed;
    unboxed.connection_id = 0;
    unboxed.is_reliable = false;
    std::stringstream innermessage;
    innermessage << "requestCert:" << identifier; 
    unboxed.message = innermessage.str();

    PublicMessage message;
    message.ephemeral_pk_present = true;
    message.ephemeral_box_pk = sender_key.box_pk;
    message.puzzle_or_solution_present = false;
    randombytes_buf(reinterpret_cast<char *>(&message.tunnel_id), 8);
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
    innermessage << "provideCert:box:" << to_hex(certificate.box_pk_signed) << ":sign:" << to_hex(certificate.sign_pk_signed);
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

int main(int argc, const char ** argv) {
    sodium_init();  

    Key directory_long;
    Key directory_ephemeral;
    
    std::map<std::string, Certificate> directory_certificates;
    
    Key rubendvbe_long;
    Key rubendvbe_ephemeral;
    directory_certificates.insert(std::make_pair<std::string, Certificate>("directory", directory_long.certificate(directory_ephemeral.publicPart())));
    directory_certificates.insert(std::make_pair<std::string, Certificate>("rubendv.be:80", directory_long.certificate(rubendvbe_ephemeral.publicPart())));

    Key client_long;
    Key client_ephemeral;
    PublicKey directory_long_public = directory_long.publicPart();
    
    std::string identifier = "directory";
    PublicMessage requestCertMessage = makeRequestCertMessage(identifier, client_ephemeral, directory_long_public);
    PublicMessage requestCertMessageReceived(requestCertMessage.packetize());

    LOG(INFO) << requestCertMessage;
    LOG(INFO) << requestCertMessageReceived;
    Unboxed requestCertMessageReceivedUnboxed = requestCertMessageReceived.unbox(directory_long);
    LOG(INFO) << requestCertMessageReceivedUnboxed;

    PublicKey client_pk(requestCertMessageReceived.ephemeral_box_pk);

    PublicMessage provideCertMessage = makeProvideCertMessage(
        requestCertMessageReceived.tunnel_id, 
        directory_certificates[requestCertMessageReceivedUnboxed.message.substr(std::string("requestCert:").size())],
        directory_long,
        client_pk
    );
    std::string provideCertPacket = provideCertMessage.packetize();
    LOG(INFO) << "provideCertPacket: " << std::dec << provideCertPacket.size() << " bytes";
    PublicMessage provideCertMessageReceived = PublicMessage(provideCertPacket);
    
    LOG(INFO) << provideCertMessage;
    LOG(INFO) << provideCertMessageReceived;
    Unboxed provideCertMessageReceivedUnboxed = provideCertMessageReceived.unbox(client_ephemeral, directory_long_public);
    LOG(INFO) << provideCertMessageReceivedUnboxed;

    return 0;
}
