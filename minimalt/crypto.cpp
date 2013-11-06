#include "crypto.h"
#include <sodium.h>
#include <algorithm>

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

std::string sign_keypair(std::string& sk) {
    std::string pk(crypto_sign_PUBLICKEYBYTES, 0);
    sk.resize(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(
        reinterpret_cast<unsigned char *>(&pk[0]),
        reinterpret_cast<unsigned char *>(&sk[0])
    );
    return pk;
}

std::string sign(std::string m, std::string sk) {
    if(sk.size() != crypto_sign_SECRETKEYBYTES) {
        throw std::invalid_argument("Invalid argument length for signing key");
    }
    unsigned long long smlen;
    std::string sm(m.size() + crypto_sign_BYTES, 0);
    crypto_sign(
        reinterpret_cast<unsigned char *>(&sm[0]),
        &smlen,
        reinterpret_cast<unsigned char *>(&m[0]),
        m.size(),
        reinterpret_cast<unsigned char *>(&sk[0])
    );
    sm.resize(smlen);
    return sm;
}

std::string sign_open(std::string sm, std::string pk) {
    if(pk.size() != crypto_sign_PUBLICKEYBYTES) {
        throw std::invalid_argument("Invalid argument length for verify key");
    }
    unsigned long long mlen;
    std::string m(sm.size(), 0);
    int error = crypto_sign_open(
        reinterpret_cast<unsigned char *>(&m[0]),
        &mlen,
        reinterpret_cast<unsigned char *>(&sm[0]),
        sm.size(),
        reinterpret_cast<unsigned char *>(&pk[0])
    );
    if(error != 0) {
        throw sign_error("sign_open failed");
    }
    m.resize(mlen);
    return m;
}




