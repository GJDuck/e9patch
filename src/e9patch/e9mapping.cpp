/*
 * e9mapping.cpp
 * Copyright (C) 2021 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Physical address space allocation and optimization.
 *
 * Here, a "mapping" represents a chunk of memory that is mmap'ed from the
 * modified binary file into the program's virtual address space.
 */

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <sys/mman.h>

#include "e9alloc.h"
#include "e9mapping.h"
#include "e9patch.h"
#include "e9trampoline.h"

#define BRANCH_BITS                     2
#define BRANCH_MAX                      (1 << BRANCH_BITS)

/*
 * Size.
 */
template <typename Key>
static size_t size(Key key)
{
    return key.size();
}
template <>
size_t size<Key128>(Key128 key)
{
    return 8 * sizeof(key);
}

/*
 * Trailing zero count.
 */
template <typename Key>
static unsigned tzcount(Key key)
{
    if (key.none())
        return key.size();
    Key mask = 0xFFFFFFFFFFFFFFFFull;
    for (unsigned count = 0; ; count += 64)
    {
        uint64_t key64 = (key & mask).to_ullong();
        if (key64 != 0)
            return count + __builtin_ctzll(key64);
        key >>= 64;
    }
}
template <>
unsigned tzcount<Key128>(Key128 key)
{
    uint64_t lo = (uint64_t)key;
    uint64_t hi = (uint64_t)(key >> 64);
    return (lo == 0? __builtin_ctzll(hi) + 64:
                     __builtin_ctzll(lo));
}

/*
 * Bits to string.
 */
template <typename Key>
static void bitstring(Key key, std::string &str)
{
    Key mask = 0xFFFFFFFFFFFFFFFFull;
    for (unsigned i = 0; i < size(key); i += 2 * 64)
    {
        const char digs[] = "0123456789ABCDEF";
        size_t count = 0;
        for (unsigned j = 0; j < 2; j++)
        {
            uint64_t key64 = (key & mask).to_ullong();
            count += __builtin_popcountll(key64);
            key >>= 64;
        }
        switch (count)
        {
            case 0: case 1:
                break;
            default:
                count = 1 + (count - 2) / 9; break;
        }
        str += digs[count];
    }
}
template <>
void bitstring<Key128>(Key128 key, std::string &str)
{
    for (unsigned i = 0; i < size(key); i += 64)
    {
        char buf[32];
        snprintf(buf, sizeof(buf)-1, "%.16lX", (uint64_t)key);
        str += buf;
        key >>= 64;
    }
}

/*
 * Calculate the occupancy key of a mapping.
 */
template <typename Key>
static Key calculateKey(const Allocator &allocator, const size_t MAPPING_SIZE,
    const Mapping *mapping)
{
    const Key KEY_ZERO = 0;
    const size_t KEY_BITS = size(KEY_ZERO);
    const size_t UNIT_SIZE = MAPPING_SIZE / KEY_BITS;
    const intptr_t BASE = mapping->base;
    const intptr_t END  = BASE + (ssize_t)MAPPING_SIZE;
    const Key KEY_ONES = ~KEY_ZERO;

    Key key = 0;
    auto i = mapping->i, iend = allocator.end();
    const Alloc *a = *i;
    if (a->lb < BASE)
    {
        if (a->ub >= END)
            return KEY_ONES;
        size_t overlap = MAPPING_SIZE - (END - a->ub);
        overlap = (overlap + UNIT_SIZE - 1) / UNIT_SIZE;
        if (overlap >= KEY_BITS)
            return KEY_ONES;
        key = ~(KEY_ONES << overlap);
        ++i;
    }

    for (; i != iend; ++i)
    {
        a = *i;
        assert(a->lb >= BASE);
        if (a->lb >= END)
            return key;
        if (a->T == nullptr)
            continue;

        size_t prologue   = a->lb - BASE;
        size_t postscript = (a->ub >= END? 0: END - a->ub);

        prologue   = prologue / UNIT_SIZE;
        postscript = postscript / UNIT_SIZE;
        assert(prologue < KEY_BITS);
        assert(postscript < KEY_BITS);

        Key tmp = (KEY_ONES << prologue);
        tmp    &= (KEY_ONES >> postscript);
        key    |= tmp;
    }

    return key;
}

/*
 * Calculate the occupancy bounds of a mapping.
 */
static Bounds calculateBounds(const Mapping *mapping)
{
    intptr_t lb = INTPTR_MAX, ub = INTPTR_MIN;
    const size_t   SIZE = mapping->size;
    const intptr_t BASE = mapping->base;
    const intptr_t END  = BASE + SIZE;
    auto iend = Allocator::end();
    for (auto i = mapping->i; i != iend; ++i)
    {
        const Alloc *a = *i;
        if (a->lb >= END)
            break;
        if (a->T == nullptr)
            continue;
        intptr_t lb1 = (a->lb < BASE? 0: a->lb - BASE);
        intptr_t ub1 = (a->ub > END ? END - BASE: a->ub - BASE);
        lb = std::min(lb, lb1);
        ub = std::max(ub, ub1);
    }
    return {lb, ub};
}

/*
 * Calculate the protections of a mapping.
 */
static int calculateProtections(const Mapping *mapping)
{
    int prot = PROT_NONE;
    const size_t   SIZE = mapping->size;
    const intptr_t BASE = mapping->base;
    const intptr_t END  = BASE + SIZE;
    auto iend = Allocator::end();
    for (auto i = mapping->i; i != iend; ++i)
    {
        const Alloc *a = *i;
        if (a->lb >= END)
            break;
        if (a->T == nullptr)
            continue;
        prot |= a->T->prot;
    }
    return prot;
}

/*
 * Calculate the PRELOAD flag of a mapping.
 */
static bool calculatePreload(const Mapping *mapping)
{
    const size_t   SIZE = mapping->size;
    const intptr_t BASE = mapping->base;
    const intptr_t END  = BASE + SIZE;
    auto iend = Allocator::end();
    for (auto i = mapping->i; i != iend; ++i)
    {
        const Alloc *a = *i;
        if (a->lb >= END)
            break;
        if (a->T == nullptr)
            continue;
        if (a->T->preload)
            return true;
    }
    return false;
}

/*
 * Allocate a new mapping.
 */
static Mapping *allocMapping(Allocator::iterator i, size_t size, intptr_t base)
{
    Mapping *mapping = new Mapping;
    mapping->base    = base;
    mapping->size    = size;
    mapping->lb      = 0;
    mapping->ub      = size;
    mapping->offset  = -1;
    mapping->prot    = PROT_NONE;
    mapping->preload = false;
    mapping->i       = i;
    mapping->next    = nullptr;
    mapping->merged  = nullptr;
    return mapping;
}

/*
 * Insert a mapping into the set.
 */
static void insertMapping(Mapping *mapping, MappingSet &mappings)
{
    mappings.push_back(mapping);
}

/*
 * Save a mapping into the set.
 */
static void saveMapping(Mapping *mapping, MappingSet &mappings)
{
    if (mapping == nullptr)
        return;
    Bounds b = calculateBounds(mapping);
    mapping->lb = b.lb;
    mapping->ub = b.ub;
    mapping->prot = calculateProtections(mapping);
    mapping->preload = calculatePreload(mapping);
    insertMapping(mapping, mappings);
    stat_num_virtual_mappings++;
}

/*
 * Build the initial set of (unmerged) mappings from the virtual address
 * layout described by `allocator`.
 */
void buildMappings(const Allocator &allocator, const size_t MAPPING_SIZE,
    MappingSet &mappings)
{
    intptr_t base    = INTPTR_MIN;
    Mapping *mapping = nullptr;

    mappings.clear();
    for (auto i = allocator.begin(), iend = allocator.end(); i != iend; ++i)
    {
        const Alloc *a = *i;
        if (a->T == nullptr)
            continue;
        if (a->lb >= base + (intptr_t)MAPPING_SIZE)
        {
            base = a->lb - a->lb % MAPPING_SIZE;
            saveMapping(mapping, mappings);
            mapping = allocMapping(i, MAPPING_SIZE, base);
        }
        while (base + (ssize_t)MAPPING_SIZE < a->ub)
        {
            base += MAPPING_SIZE;
            saveMapping(mapping, mappings);
            mapping = allocMapping(i, MAPPING_SIZE, base);
        }
    }
    saveMapping(mapping, mappings);
}

/**************************************************************************/
/* PHYSICAL PAGE GROUPING                                                 */
/**************************************************************************/

/*
 * For physical page grouping, we need to merge mappings that do not
 * overlap.  For speed, we approximate the occupancy using a bitmap, and
 * merge based on bit complement ((key1 & key2) == 0).  We also arrange the
 * mappings into a radix tree based on the occupancy bitmap.  This makes it
 * possible to efficiently find candidates for merging.  The algorithm is
 * greedy and not theoretically optimal, but is fast and gives reasonable
 * results in practice.
 */

namespace Radix
{

/*
 * Radix tree leaf.
 */
struct Leaf
{
    Mapping *mappings;              // List of all mappings with same key
};

/*
 * Radix-tree node.
 */
template <typename Key>
struct Node
{
    Key key;                        // Node key
    uint64_t inner:1;               // Inner or leaf node?
    uint64_t shift:63;              // Shift for branch mask
    union
    {
        Node *child[BRANCH_MAX];    // Inner node children
        Leaf leaf;                  // Leaf node data
    };
};

/*
 * Given a node and key, return the child index.
 */
template <typename Key>
static unsigned index(Radix::Node<Key> *node, Key key)
{
    size_t shift = BRANCH_BITS * node->shift;
    Key BRANCH_MASK = BRANCH_MAX - 1;
    return ((key & (BRANCH_MASK << shift)) >> shift).to_ullong();
}
template <>
unsigned index<Key128>(Radix::Node<Key128> *node, Key128 key)
{
    size_t shift = BRANCH_BITS * node->shift;
    Key128 BRANCH_MASK = BRANCH_MAX - 1;
    return (unsigned)((key & (BRANCH_MASK << shift)) >> shift);
}

}       // namespace Mapping

/*
 * Fix the tree invariant after insertion/deletion.
 */
template <typename Key>
static void fix(Radix::Node<Key> *node)
{
    Key key = ~(Key)0;

    for (unsigned i = 0; i < BRANCH_MAX; i++)
    {
        Radix::Node<Key> *child = node->child[i];
        if (child == nullptr)
            continue;
        key = (key & child->key);
    }

    node->key = key;
}

/*
 * Find the leaf node for the given key.
 */
template <typename Key>
static Radix::Node<Key> *find(Radix::Node<Key> *node, Key key)
{
    while (true)
    {
        if (node == nullptr)
            return nullptr;
        if (!node->inner)
            return (node->key == key? node: nullptr);
        unsigned idx = index(node, key);
        node = node->child[idx];
    }
}

/*
 * Find any leaf node matching (key & leaf->key) == 0.
 */
template <typename Key>
static Radix::Node<Key> *findAnyComplement(Radix::Node<Key> *node, Key key)
{
    if (node == nullptr)
        return nullptr;
    if (!node->inner)
        return ((node->key & key) == 0? node: nullptr);
    for (unsigned i = 0; i < BRANCH_MAX; i++)
    {
        Radix::Node<Key> *child = node->child[i];
        if (child == nullptr)
            continue;
        if ((key & child->key) != 0)
            continue;
        Radix::Node<Key> *result = findAnyComplement(child, key);
        if (result != nullptr)
            return result;
    }

    return nullptr;
}

/*
 * Insert a new mapping into the tree.
 */
template <typename Key>
static Radix::Node<Key> *insert(Radix::Node<Key> *node, Key key,
    Mapping *mapping)
{
    if (node == nullptr)
    {
        Radix::Node<Key> *leaf = new Radix::Node<Key>();
        leaf->inner         = false;
        leaf->shift         = 0;
        leaf->key           = key;
        leaf->leaf.mappings = mapping;
        return leaf;
    }

    if (!node->inner)
    {
        Key diff = node->key ^ key;
        if (diff == 0)
        {
            // Add to existing node:
            mapping->next       = node->leaf.mappings;
            node->leaf.mappings = mapping;
            return node;
        }

        // Add new branch:
        unsigned shift = tzcount(diff) / BRANCH_BITS;
        Radix::Node<Key> *inner  = new Radix::Node<Key>();
        inner->inner = true;
        inner->shift = shift;
        for (unsigned i = 0; i < BRANCH_MAX; i++)
            inner->child[i] = nullptr;
        inner->child[index(inner, node->key)] = node;

        Radix::Node<Key> *leaf = new Radix::Node<Key>();
        leaf->inner         = false;
        leaf->shift         = 0;
        leaf->key           = key;
        leaf->leaf.mappings = mapping;
        inner->child[index(inner, leaf->key)] = leaf;

        fix(inner); 
        return inner;
    }

    unsigned idx = index(node, key);
    node->child[idx] = insert(node->child[idx], key, mapping);
    fix(node);

    return node;
}

/*
 * Remove the leaf node matching `key`.
 */
template <typename Key>
static Radix::Node<Key> *remove(Radix::Node<Key> *node, Key key)
{
    if (node == nullptr)
        return nullptr;

    if (!node->inner)
    {
        if (node->key != key)
            return node;
        delete node;
        return nullptr;
    }

    unsigned idx = index(node, key);
    Radix::Node<Key> *child = remove(node->child[idx], key);
    node->child[idx] = child;
    if (child != nullptr)
    {
        fix(node);
        return node;
    }

    // If the number of child is reduced to 1, then delete the inner node:
    Radix::Node<Key> *seen = nullptr;
    for (int i = 0; i < BRANCH_MAX; i++)
    {
        if (node->child[i] == nullptr)
            continue;
        if (seen != nullptr)
            return node;    // 2 or more...
        seen = node->child[i];
    }
    delete node;
    return seen;
}

/*
 * Merge a mapping with an existing mapping (if possible).
 */
template <typename Key>
static Radix::Node<Key> *merge(Radix::Node<Key> *tree, Key key,
    Mapping *mapping)
{
    Radix::Node<Key> *node = find(tree, key);
    if (node != nullptr)
    {
        // Add to existing node for key:
        mapping->next = node->leaf.mappings;
        node->leaf.mappings = mapping;
        log(COLOR_NONE, '+');
        return tree;
    }

    node = findAnyComplement(tree, key);
    if (node != nullptr)
    {
        // Merge with negated node:
        Mapping *mappingCmp = node->leaf.mappings;
        node->leaf.mappings = mappingCmp->next;
        mappingCmp->next    = nullptr;
        mapping->merged     = mappingCmp;
        key                |= node->key;
        if (node->leaf.mappings == nullptr)
        {
            // Leaf node is now empty, so remove it.
            tree = remove(tree, node->key);
        }
        log(COLOR_GREEN, 'M');
    }
    else
        log(COLOR_NONE, '+');

    // Insert a new node:
    tree = insert(tree, key, mapping);
    return tree;
}

/*
 * Collect all (optimized) mappings and free the tree.
 */
template <typename Key>
static void collectMappings(Radix::Node<Key> *node, MappingSet &mappings)
{
    if (node == nullptr)
        return;
    if (!node->inner)
    {
        for (auto mapping = node->leaf.mappings; mapping != nullptr;
            mapping = mapping->next)
        {
            std::string str;
            bitstring(node->key, str);
            log(COLOR_NONE, '[');
            log(COLOR_YELLOW, str.c_str());
            log(COLOR_NONE, ']');
            insertMapping(mapping, mappings);
            stat_num_physical_mappings++;
        }
    }
    else
    {
        for (unsigned i = 0; i < BRANCH_MAX; i++)
            collectMappings(node->child[i], mappings);
    }
    delete node;
}

/*
 * Shrink a mapping (if possible).
 */
static void shrinkMapping(Mapping *mapping0, size_t granularity)
{
    if (mapping0->size == granularity)
        return;

    intptr_t lb = INTPTR_MAX, ub = INTPTR_MIN;
    for (auto mapping = mapping0; mapping != nullptr;
        mapping = mapping->merged)
    {
        lb = std::min(lb, mapping->lb);
        ub = std::max(ub, mapping->ub);
    }

    lb = lb - lb % granularity;
    if (ub % granularity != 0)
    {
        ub += granularity;
        ub = ub - ub % granularity;
    }
    size_t size = ub - lb;
    if (size >= mapping0->size)
        return;

    for (auto mapping = mapping0; mapping != nullptr;
        mapping = mapping->merged)
    {
        mapping->base += lb;
        mapping->size  = size;
        mapping->lb   -= lb;
        mapping->ub   -= lb;
    }
}

/*
 * Optimize the given set of mappings.
 */
template <typename Key>
void optimizeMappings(const Allocator &allocator, const size_t MAPPING_SIZE,
    size_t granularity, MappingSet &mappings)
{
    Radix::Node<Key> *tree = nullptr;
    for (auto mapping: mappings)
    {
        Key key = calculateKey<Key>(allocator, MAPPING_SIZE, mapping);
        tree = merge(tree, key, mapping);
    }
    log(COLOR_NONE, '\n');

    mappings.clear();
    collectMappings(tree, mappings);
    log(COLOR_NONE, '\n');

    for (auto mapping: mappings)
        shrinkMapping(mapping, granularity);
}
template
void optimizeMappings<Key128>(const Allocator &allocator,
    const size_t MAPPING_SIZE, size_t granularity, MappingSet &mappings);
template
void optimizeMappings<Key4096>(const Allocator &allocator,
    const size_t MAPPING_SIZE, size_t granularity, MappingSet &mappings);

/**************************************************************************/
/* FLATTEN MAPPINGS                                                       */
/**************************************************************************/

/*
 * Flatten a mapping into a memory buffer.
 */
void flattenMapping(const Binary *B, uint8_t *buf, const Mapping *mapping,
    uint8_t fill)
{
    memset(buf, fill, mapping->size);
    
    auto iend = Allocator::end();
    for (; mapping != nullptr; mapping = mapping->merged)
    {
        auto i = mapping->i;
        const Alloc *a = *i;
        const size_t   SIZE = mapping->size;
        const intptr_t BASE = mapping->base;
        const intptr_t END  = BASE + SIZE;
        for (; i != iend; ++i)
        {
            a = *i;
            if (a->lb >= END)
                break;
            if (a->bytes == nullptr)
                continue;

            intptr_t lb = a->lb, ub = a->ub;
            off_t offset = (lb < BASE? BASE - lb: 0);
            lb = (lb < BASE? BASE: lb);
            ub = (ub > END? END: ub);
            memcpy(buf + (lb - BASE), a->bytes + offset, (ub - lb));
        }
    }
}

/*
 * Get the virtual bounds of a mapping.
 */
static void pushBounds(intptr_t lb, intptr_t ub, size_t granularity,
    std::vector<Bounds> &bounds)
{
    if (lb == INTPTR_MAX || ub == INTPTR_MIN)
        return;
    lb = lb - lb % granularity;
    if (ub % granularity != 0)
        ub = (ub + granularity) - (ub % granularity);
    bounds.push_back({lb, ub});
}
void getVirtualBounds(const Mapping *mapping, size_t granularity,
    std::vector<Bounds> &bounds)
{
    intptr_t lb = INTPTR_MAX, ub = INTPTR_MIN;
    const size_t   SIZE = mapping->size;
    const intptr_t BASE = mapping->base;
    const intptr_t END  = BASE + SIZE;
    auto iend = Allocator::end();
    for (auto i = mapping->i; i != iend; ++i)
    {
        const Alloc *a = *i;
        if (a->lb >= END)
            break;
        if (a->bytes == nullptr)
        {
            // Reserved memory.  We must split into two separate mappings.
            pushBounds(lb, ub, granularity, bounds);
            lb = INTPTR_MAX;
            ub = INTPTR_MIN;
            continue;
        }
        intptr_t lb1 = (a->lb < BASE? 0: a->lb - BASE);
        intptr_t ub1 = (a->ub > END ? END - BASE: a->ub - BASE);
        lb = std::min(lb, lb1);
        ub = std::max(ub, ub1);
    }
    pushBounds(lb, ub, granularity, bounds);
}

