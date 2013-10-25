#ifndef EXPIVMG_MINIMALT_H
#define EXPIMSG_MINIMALT_H
#include <stdint.h>

typedef struct minimalt_message_t {
    uint64_t has_ephemeral_pk:1;
    uint64_t has_puzzle_solution:1;
    uint64_t tunnel_id:62;
    uint64_t nonce;
    uint8_t ephemeral_pk[32];
    uint8_t puzzle_solution[148];
    uint32_t sequence_number;
    uint32_t acknowledgment;
    uint32_t connection;
    uint8_t * rpc;
    uint64_t * rpc_length;
} minimalt_message_t;

typedef struct minimalt_tunnel_t {
    uint8_t * address
}

epmsg_minimalt_send(

#endif
