/*
 * e9mapping.cpp
 * Copyright (C) 2020 National University of Singapore
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
#define BRANCH_MASK                     ((Key)(BRANCH_MAX - 1))
#define KEY_BITS                        (sizeof(Key) * 8)

#ifdef KEY128
/*
 * 128-bit keys.
 */
typedef unsigned __int128 Key;

/*
 * Trailing zero count.
 */
static unsigned tzcount(Key key)
{
    uint64_t lo = (uint64_t)key;
    uint64_t hi = (uint64_t)(key >> 64);
    return (lo == 0? __builtin_ctzll(hi) + 64:
                     __builtin_ctzll(lo));
}

#define KEY_FORMAT_STRING           "%.16lX%.16lX"
#define KEY_FORMAT(x)               (uint64_t)((x) >> 64), (uint64_t)(x)

#else   /* KEY128 */

/*
 * 64bit keys.
 */
typedef uint64_t Key;

static unsigned tzcount(Key key)
{
    return __builtin_ctzll(key);
}

#define KEY_FORMAT_STRING           "%.16lX"
#define KEY_FORMAT(x)               (x)

#endif  /* KEY128 */

/*
 * Calculate the occupancy key of a mapping.
 */
static Key calculateKey(const Allocator &allocator, const size_t MAPPING_SIZE,
    const Mapping *mapping)
{
    const size_t UNIT_SIZE = MAPPING_SIZE / KEY_BITS;
    const Key KEY_ONES = (Key)-1;
    const intptr_t BASE = mapping->base;
    const intptr_t END  = BASE + (ssize_t)MAPPING_SIZE;

    Key key = 0;
    auto i = mapping->i, iend = allocator.end();
    const Alloc *a = *i;
    if (a->lb < BASE)
    {
        if (a->ub >= END)
            return KEY_ONES;
        size_t overlap = MAPPING_SIZE - (END - a->ub);
        overlap = (overlap + UNIT_SIZE - 1) / UNIT_SIZE;
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

        size_t preamble   = a->lb - BASE;
        size_t postscript = (a->ub >= END? 0: END - a->ub);

        preamble   = preamble / UNIT_SIZE;
        postscript = postscript / UNIT_SIZE;

        Key tmp = (KEY_ONES << preamble);
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
    mapping->key     = 0;
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
static void saveMapping(const Allocator &allocator, const size_t MAPPING_SIZE,
    Mapping *mapping, MappingSet &mappings)
{
    if (mapping == nullptr)
        return;
    mapping->key = calculateKey(allocator, MAPPING_SIZE, mapping);
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
            saveMapping(allocator, MAPPING_SIZE, mapping, mappings);
            mapping = allocMapping(i, MAPPING_SIZE, base);
        }
        while (base + (ssize_t)MAPPING_SIZE < a->ub)
        {
            base += MAPPING_SIZE;
            saveMapping(allocator, MAPPING_SIZE, mapping, mappings);
            mapping = allocMapping(i, MAPPING_SIZE, base);
        }
    }
    saveMapping(allocator, MAPPING_SIZE, mapping, mappings);
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
static unsigned index(Node *node, Key key)
{
    size_t shift = BRANCH_BITS * node->shift;
    return (unsigned)((key & (BRANCH_MASK << shift)) >> shift);
}

}       // namespace Mapping

/*
 * Fix the tree invariant after insertion/deletion.
 */
static void fix(Radix::Node *node)
{
    Key key = ~(Key)0;

    for (unsigned i = 0; i < BRANCH_MAX; i++)
    {
        Radix::Node *child = node->child[i];
        if (child == nullptr)
            continue;
        key = (key & child->key);
    }

    node->key = key;
}

/*
 * Find the leaf node for the given key.
 */
static Radix::Node *find(Radix::Node *node, Key key)
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
static Radix::Node *findAnyComplement(Radix::Node *node, Key key)
{
    if (node == nullptr)
        return nullptr;
    if (!node->inner)
        return ((node->key & key) == 0? node: nullptr);
    for (unsigned i = 0; i < BRANCH_MAX; i++)
    {
        Radix::Node *child = node->child[i];
        if (child == nullptr)
            continue;
        if ((key & child->key) != 0)
            continue;
        Radix::Node *result = findAnyComplement(child, key);
        if (result != nullptr)
            return result;
    }

    return nullptr;
}

/*
 * Insert a new mapping into the tree.
 */
static Radix::Node *insert(Radix::Node *node, Mapping *mapping)
{
    if (node == nullptr)
    {
        Radix::Node *leaf = new Radix::Node();
        leaf->inner         = false;
        leaf->shift         = 0;
        leaf->key           = mapping->key;
        leaf->leaf.mappings = mapping;
        return leaf;
    }

    if (!node->inner)
    {
        Key diff = node->key ^ mapping->key;
        if (diff == 0)
        {
            // Add to existing node:
            mapping->next       = node->leaf.mappings;
            node->leaf.mappings = mapping;
            return node;
        }

        // Add new branch:
        unsigned shift = tzcount(diff) / BRANCH_BITS;
        Radix::Node *inner  = new Radix::Node();
        inner->inner = true;
        inner->shift = shift;
        for (unsigned i = 0; i < BRANCH_MAX; i++)
            inner->child[i] = nullptr;
        inner->child[index(inner, node->key)] = node;

        Radix::Node *leaf = new Radix::Node();
        leaf->inner         = false;
        leaf->shift         = 0;
        leaf->key           = mapping->key;
        leaf->leaf.mappings = mapping;
        inner->child[index(inner, leaf->key)] = leaf;

        fix(inner); 
        return inner;
    }

    unsigned idx = index(node, mapping->key);
    node->child[idx] = insert(node->child[idx], mapping);
    fix(node);

    return node;
}

/*
 * Remove the leaf node matching `key`.
 */
static Radix::Node *remove(Radix::Node *node, Key key)
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
    Radix::Node *child = remove(node->child[idx], key);
    node->child[idx] = child;
    if (child != nullptr)
    {
        fix(node);
        return node;
    }

    // If the number of child is reduced to 1, then delete the inner node:
    Radix::Node *seen = nullptr;
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
static Radix::Node *merge(Radix::Node *tree, Mapping *mapping)
{
    Radix::Node *node = find(tree, mapping->key);
    if (node != nullptr)
    {
        // Add to existing node for key:
        mapping->next = node->leaf.mappings;
        node->leaf.mappings = mapping;
        putchar('+');
        return tree;
    }

    node = findAnyComplement(tree, mapping->key);
    if (node != nullptr)
    {
        // Merge with negated node:
        Mapping *mappingCmp = node->leaf.mappings;
        node->leaf.mappings = mappingCmp->next;
        mappingCmp->next    = nullptr;
        mapping->key        = mapping->key | mappingCmp->key;
        mapping->merged     = mappingCmp;
        if (node->leaf.mappings == nullptr)
        {
            // Leaf node is now empty, so remove it.
            tree = remove(tree, node->key);
        }
        printf("\33[32mM\33[0m");
    }
    else
        printf("+");

    // Insert a new node:
    tree = insert(tree, mapping);
    return tree;
}

/*
 * Collect all (optimized) mappings and free the tree.
 */
static void collectMappings(Radix::Node *node, MappingSet &mappings)
{
    if (node == nullptr)
        return;
    if (!node->inner)
    {
        for (auto mapping = node->leaf.mappings; mapping != nullptr;
            mapping = mapping->next)
        {
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
static void shrinkMapping(Mapping *mapping0)
{
    if (mapping0->size == PAGE_SIZE)
        return;

    intptr_t lb = INTPTR_MAX, ub = INTPTR_MIN;
    for (auto mapping = mapping0; mapping != nullptr;
        mapping = mapping->merged)
    {
        lb = std::min(lb, mapping->lb);
        ub = std::max(ub, mapping->ub);
    }

    lb = lb - lb % PAGE_SIZE;
    if (ub % PAGE_SIZE != 0)
    {
        ub += PAGE_SIZE;
        ub = ub - ub % PAGE_SIZE;
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
void optimizeMappings(MappingSet &mappings)
{
    Radix::Node *tree = nullptr;
    for (auto mapping: mappings)
        tree = merge(tree, mapping);

    mappings.clear();
    collectMappings(tree, mappings);

    for (auto mapping: mappings)
        shrinkMapping(mapping);
}

/**************************************************************************/
/* FLATTEN MAPPINGS                                                       */
/**************************************************************************/

/*
 * Flatten a trampoline helper.
 */
void flattenTrampoline(uint8_t *buf, size_t size, intptr_t base, intptr_t end,
    intptr_t lb, intptr_t ub, const Trampoline *T, const Instr *I)
{
    off_t offset = (I == nullptr? 0: lb - I->addr);
    assert(offset >= INT32_MIN);
    assert(offset <= INT32_MAX);
    int32_t offset32 = (int32_t)offset;

    if (lb >= base && ub <= end)
    {
        // Common case where the entire trampoline fits into the buffer.
        // There is no need to use temporary memory.
        flattenTrampoline(buf + (lb - base), (ub - lb), offset32, T, I);
        return;
    }

    // The edge case where only part of the trampoline overlaps with the
    // mapping.  We use a temporary buffer & copy the overlap.
    uint8_t tmp_buf[ub - lb];
    flattenTrampoline(tmp_buf, (ub - lb), offset32, T, I);
    offset = (lb < base? base - lb: 0);
    lb = (lb < base? base: lb);
    ub = (ub > end? end: ub);
    memcpy(buf + (lb - base), tmp_buf + offset, (ub - lb));
}

/*
 * Flatten a mapping into a memory buffer.
 */
void flattenMapping(uint8_t *buf, const Mapping *mapping, uint8_t fill)
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
            if (a->T == nullptr)
                continue;

            flattenTrampoline(buf, SIZE, BASE, END, a->lb, a->ub, a->T, a->I);
        }
    }
}

/*
 * Get the virtual bounds of a mapping.
 */
static void pushBounds(intptr_t lb, intptr_t ub, std::vector<Bounds> &bounds)
{
    if (lb == INTPTR_MAX || ub == INTPTR_MIN)
        return;
    lb = lb - lb % PAGE_SIZE;
    if (ub % PAGE_SIZE != 0)
        ub = (ub + PAGE_SIZE) - (ub % PAGE_SIZE);
    bounds.push_back({lb, ub});
}
void getVirtualBounds(const Mapping *mapping, std::vector<Bounds> &bounds)
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
        {
            // Reserved memory.  We must split into two separate mappings.
            pushBounds(lb, ub, bounds);
            lb = INTPTR_MAX;
            ub = INTPTR_MIN;
            continue;
        }
        intptr_t lb1 = (a->lb < BASE? 0: a->lb - BASE);
        intptr_t ub1 = (a->ub > END ? END - BASE: a->ub - BASE);
        lb = std::min(lb, lb1);
        ub = std::max(ub, ub1);
    }
    pushBounds(lb, ub, bounds);
}

