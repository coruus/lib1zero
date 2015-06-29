/** Two interleaved alternating bit protocols.
 *
 * (Or you can view it as a duplex syn-ack protocol which provides
 * properties vaguely similar to TCP's.)
 *
 * Although this is intended to run on top of TCP, this can be
 * used on any transport that provides reliable, in-order delivery
 * of messages.
 */
#include "rs.h"

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/** r is the core of the receiving event loop.
 *
 * It, obviously, is not intended to be invoked by more than one
 * thread at a time.
 *
 * It does most of the work, so that we can view the sender as if
 * it executed atomically. (It is possible to do this the other way
 * around, but more complicated and error-prone.)
 */
int r(state* state, message* m, void* c) {
  __mfence(); // this enforces a total order on the event loop

  size_t i = state->my_bit;
  size_t last = 0;
  size_t i0 = i&1, i1 = (i+1)&1;
  bool ok0 = decrypt(m, c, &state->my_privatekeys[i0]);
  bool ok1 = ok0 ? false : decrypt(m, c, &state->my_privatekeys[i1]);

  /* This, at present, is not an observable condition, but if you make
   * this constant time w.r.t. whether a key has been acked, you need to
   * check for this invariant violation.
   *
  if ((ok0 & ok1)) {
    assert(memcmp(receiver->keys[i0],
                  receiver->keys[i1],
                  sizeof(key_t)) == 0);
    // protocol invariant violated: k[i] != k[i+1]
    return -1;
  }
  */

  if (!(ok0 | ok1)) {
    // neither key worked: reliability violated
    return -1; // no fence, since we must abort immediately anyways
  }

  state->their_seqno += 1;;
  if (m->seqno == (++state->their_seqno)) {
    // tcp-> invariant violation: out-of-order or unreliable delivery
    return -1; // no fence, since we must abort immediately anyways
  }

  if (m->nextpub) {
    // The opposite end has synned, and thus they have included
    // a new public key we can tell our sender to start using.
    //
    // Note that we require that:
    //   if     they send a new key
    //   then P our sender has acked sender->theirnext[sender->i%2]
    //   then P our sender has stopped using sender->theirnext[sender->i+1%2]
    //
    // This property is critical for correctness.
    memcpy(&state->their_pubkeys[((state->their_bit)+1)&1],
           m->nextpub,
           sizeof(key_t));
    // Memory fence, for the same reason as above.
    __mfence();
    state->their_bit += 1;
  }

  if (ok1) {
    // Our next public key was just acked, so we can discard our
    // last private key, because the opposite end won't send any
    // more messages encrypted under it.
    //
    // Note that:
    //   if     the opposite end acks     keys[i1],
    //   then P the opposite end received keys[i1],
    //   then P this end has read sender->mynextpub completely
    // so that genkey writing to the state is safe without locking.
    
    // Write the new key to sender->mynextpub,
    genkey(&state->my_nextpub, &state->my_privatekeys[i0]);
    // (A memory fence is necessary to ensure that the next
    // public key is completely written before the sender
    // tries to read it.)
    __mfence();
    // tell the sender to send it in the next message
    // it processes,
    state->send_nextpub = &state->my_nextpub;
    // and memorialize the ack.
    state->my_bit += 1;
  }

  __mfence();
  return 0;
}

int s(state* state, void* c, void* payload) {
  __mfence(); // this enforces a total order on the event loop

  size_t i0 = (state->their_bit) & 1;

  state->my_seqno += 1; // first sequence number is 1

  // We use the message's nextpub field to indicate whether
  // we are going to syn the other end; receive sets this
  // when we receive an ack.
  message m = {
    .seqno   = state->my_seqno,
    .nextpub = state->send_nextpub, // non-null on syn
    .payload = payload,             // the payload of the message
  };
  state->send_nextpub = NULL; // does this need an atomic exchange instead?

  // We always use i0, because receive takes care of handling
  // the other end's syn, by setting their_bit to the ack value.
  encrypt(c, &m, &state->their_pubkeys[i0]);

  __mfence();
  return 0;
}

