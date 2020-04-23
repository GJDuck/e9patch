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

/*
 * Representation of a mapping.
 */
struct Mapping
{
    // Occupancy:
    uint64_t key;               // Occupancy bitmap key.
    intptr_t lb;                // Occupancy lower bound.
    intptr_t ub;                // Occupancy Upper bound.

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
void optimizeMappings(MappingSet &mappings);
void flattenMapping(uint8_t *buf, const Mapping *mapping, uint8_t fill);
void getVirtualBounds(const Mapping *mapping, std::vector<Bounds> &bounds);

#endif
