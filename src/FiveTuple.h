#ifndef _5tuple_H_
#define _5tuple_H_

#include <stdint.h>

struct FiveTuple {
public:
        /*uint32_t saddr;
        uint32_t daddr;
        uint16_t sport;
        uint16_t dport;
        uint8_t protocol;
*/
        int saddr;
        int daddr;
        int sport;
        int dport;
        int protocol;
//	FiveTuple():saddr(0),daddr(0),sport(0),dport(0),protocol(0);
};

typedef struct FiveTuple FiveTuple;

#endif
