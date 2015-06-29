#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef uint8_t key_t;

typedef struct {
  uint8_t k0[32];
} key_t;

typedef struct {
  uint64_t my_seqno;
  uint64_t their_seqno;
  // my_bit indicates which of *their* keys is the most recent
  uint64_t my_bit;
  uint64_t their_bit;
  key_t my_privatekeys[2];
  key_t their_pubkeys[2];
  key_t my_nextpub;
  key_t* send_nextpub;
} state;

typedef struct {
  uint64_t seqno;
  key_t* nextpub;
  uint8_t* payload;
} message;

bool decrypt(message* m, uint8_t* c, key_t* k);
bool encrypt(uint8_t* p, message* m, key_t* k);
void genkey(void*, void*);
void __mfence(void);

int s(state* state, void* ciphertext, void* plaintext);
int r(state* state, message* m, void* ciphertext);
