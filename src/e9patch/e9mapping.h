/*
 * e9mapping.h
 *
 * Physical address space allocation and optimization.
 */

#ifndef __E9MAPPING_H
#define __E9MAPPING_H

#include <vector>

#include <cstdint>

#include "e9alloc.h"

#include <bitset>

typedef std::bitset<4096> Key4096;
typedef std::bitset<2048> Key2048;
typedef std::bitset<1024> Key1024;
typedef std::bitset<512> Key512;
typedef std::bitset<256> Key256;
typedef unsigned __int128 Key128;
typedef uint64_t Key64;

/*
 * Representation of a mapping.
 */
struct Mapping
{
    // Occupancy:
    intptr_t lb;                // Occupancy lower bound.
    intptr_t ub;                // Occupancy upper bound.

    // Virtual memory:
    intptr_t base;              // Virtual base address.
    size_t size;                // Size of mapping in bytes.
    Allocator::iterator i;      // Virtual memory contents.
    int prot;                   // Protections.
    bool preload;               // Preload mapping?

    // Physical memory:
    off_t offset;               // Physical file offet.

    // Grouping:
    Mapping *next;              // Next mapping.
    Mapping *merged;            // Next merged mapping.
};

typedef std::vector<Mapping *> MappingSet;

void buildMappings(const Allocator &allocator, const size_t MAPPING_SIZE,
    MappingSet &mappings);
void flattenMapping(const Binary *B, uint8_t *buf, const Mapping *mapping,
    uint8_t fill);
void getVirtualBounds(const Mapping *mapping, size_t granularity,
    std::vector<Bounds> &bounds);

template <typename Key>
void optimizeMappings(const Allocator &allocator, const size_t MAPPING_SIZE,
    size_t granularity, MappingSet &mappings);

#endif
