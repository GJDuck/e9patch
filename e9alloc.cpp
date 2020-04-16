/*
 * e9alloc.cpp
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

#include <algorithm>

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/mman.h>

#include "e9rbtree.h"
#include "e9alloc.h"
#include "e9patch.h"
#include "e9trampoline.h"

#define BLACK       0       // RB-tree black
#define RED         1       // RB-tree red

#define MIN_SIZE    /*sizeof(jmpq)=*/5

/*
 * Interval tree node.
 */
struct Node
{
    Alloc alloc;            // Allocation
    RB_ENTRY(Node) entry;   // RB-tree entry
    uint64_t full:63;       // Number of allocation bytes in (ub - lb)
    uint64_t color:1;       // RB-tree node color
    intptr_t lb;            // tree lower bound
    intptr_t ub;            // tree upper bound
};

/*
 * Node comparison.
 */
static inline int compare(const Node *a, const Node *b)
{
    if (a->alloc.ub <= b->alloc.lb)
        return -1;
    else if (a->alloc.lb >= b->alloc.ub)
        return 1;
    return 0;
}

/*
 * Restore interval-tree invariants after a node after child node modification.
 */
static void fix(Node *n)
{
    if (n == nullptr)
        return;
    Node *l = n->entry.left, *r = n->entry.right;
    intptr_t llb = (l != nullptr? l->lb: INTPTR_MAX);
    intptr_t rub = (r != nullptr? r->ub: INTPTR_MIN);
    n->lb = std::min(llb, n->alloc.lb);
    n->ub = std::max(rub, n->alloc.ub);
    uint64_t lfull = (l == nullptr? 0: l->full);
    uint64_t rfull = (r == nullptr? 0: r->full);
    n->full = (n->alloc.ub - n->alloc.lb) + lfull + rfull;
}

/*
 * Interval-tree definition.
 */
#define RB_AUGMENT(n)               fix(n)
RB_GENERATE_STATIC(Tree, Node, entry, compare);
#define rebalanceInsert(t, n)       Tree_RB_INSERT_COLOR((t), (n))
#define rebalanceRemove(t, n)       Tree_RB_REMOVE((t), (n))

template <bool LEFT>
static Node *insert(Node *root, intptr_t lb, intptr_t ub, size_t size);

/*
 * Allocate a node.
 */
static Node *alloc()
{
    Node *n = (Node *)malloc(sizeof(Node));
    if (n == nullptr)
        error("failed to allocate %zu bytes for interval tree node: %s",
            sizeof(Node), strerror(ENOMEM));
    n->alloc.T = nullptr;
    n->alloc.I = nullptr;
    return n;
}

/*
 * Allocate and initialize a new interval tree node.
 */
static Node *node(Node *parent, bool left, intptr_t lb, intptr_t ub,
    size_t size)
{
    Node *n = alloc();
    if (left)
    {
        n->alloc.lb = lb;
        n->alloc.ub = lb + size;
        n->lb       = lb;
        n->ub       = lb + size;
    }
    else
    {
        n->alloc.lb = ub - size;
        n->alloc.ub = ub;
        n->lb       = ub - size;
        n->ub       = ub;
    }
    n->entry.parent = parent;
    n->entry.left   = nullptr;
    n->entry.right  = nullptr;
    n->color        = RB_RED;
    n->full         = size;
    return n;
}

/*
 * Insert left-child helper.
 */
template <bool LEFT>
static Node *insertLeftChild(Node *root, intptr_t lb, intptr_t ub, size_t size)
{
    if ((intptr_t)size > ub - lb)
        return nullptr;
    Node *n;
    if (root->entry.left == nullptr)
        n = root->entry.left = node(root, LEFT, lb, ub, size);
    else
        n = insert<LEFT>(root->entry.left, lb, ub, size);
    return n;
}

/*
 * Insert right-child helper.
 */
template <bool LEFT>
static Node *insertRightChild(Node *root, intptr_t lb, intptr_t ub, size_t size)
{
    if ((intptr_t)size > ub - lb)
        return nullptr;
    Node *n;
    if (root->entry.right == nullptr)
        n = root->entry.right = node(root, LEFT, lb, ub, size);
    else
        n = insert<LEFT>(root->entry.right, lb, ub, size);
    return n;
}

/*
 * Insert a new allocation or reservation into the interval tree node `root`.
 */
template <bool LEFT>
static Node *insert(Node *root, intptr_t lb, intptr_t ub, size_t size)
{
    if ((intptr_t)size > ub - lb)
        return nullptr;
    if (root == nullptr)
        return node(nullptr, LEFT, lb, ub, size);

    Node *n = nullptr;
    if (n == nullptr && ub <= root->lb)
        n = insertLeftChild<LEFT>(root, lb, ub, size);
    if (n == nullptr && lb >= root->ub)
        n = insertRightChild<LEFT>(root, lb, ub, size);
    if (n == nullptr && lb < root->lb)
        n = insertLeftChild</*LEFT=*/false>(root, lb, root->lb, size);
    if (n == nullptr && ub > root->ub)
        n = insertRightChild</*LEFT=*/true>(root, root->ub, ub, size);
    if (n == nullptr)
    {
        uint64_t range = (uint64_t)root->ub - (uint64_t)root->lb;
        uint64_t full  = root->full;
        bool internal  = (range - full >= size);
        if (internal)
        {
            // As an optimization, we may only explore one branch if the node
            // is too full:
            bool once = (range >= UINT32_MAX? false:
                100 * full >= option_aggressiveness * range);

            if (LEFT)
            {
                if (n == nullptr && internal)
                    n = insertLeftChild</*LEFT=*/false>(root,
                        lb, std::min(ub, root->alloc.lb), size);
                if (n == nullptr && internal && !once)
                    n = insertRightChild</*LEFT=*/true>(root,
                        std::max(lb, root->alloc.ub), ub, size);
            }
            else
            {
                if (n == nullptr && internal)
                    n = insertRightChild</*LEFT=*/true>(root,
                        std::max(lb, root->alloc.ub), ub, size);
                if (n == nullptr && internal && !once)
                    n = insertLeftChild</*LEFT=*/false>(root,
                        lb, std::min(ub, root->alloc.lb), size);
            }
        }
    }

    if (n != nullptr)
        fix(root);

    return n;
}

/*
 * Verify bounds.
 */
static bool verify(intptr_t lb, intptr_t ub)
{
    if (lb > ub)
        return false;
    if (IS_RELATIVE(lb))
        return IS_RELATIVE(ub);
    if (IS_ABSOLUTE(lb))
        return IS_ABSOLUTE(ub);
    return false;
}

/*
 * Allocates a chunk of virtual address space of size `size` and within the
 * range [lb..ub].  Returns the allocation, or nullptr on failure.
 */
const Alloc *allocate(Allocator &allocator, intptr_t lb, intptr_t ub,
    const Trampoline *T, const Instr *I)
{
    if (!verify(lb, ub + TRAMPOLINE_MAX))
        return nullptr;
    int r = getTrampolineSize(T, I);
    if (r < 0)
        return nullptr;
    size_t size = (size_t)r;
    ub += size;
    Node *n = insert</*LEFT=*/true>(allocator.tree.root, lb, ub, size);
    if (n == nullptr)
        return nullptr;
    if (allocator.tree.root == nullptr)
        allocator.tree.root = n;
    rebalanceInsert(&allocator.tree, n);

    Alloc *A = &n->alloc;
    A->T = T;
    A->I = I;
    return A;
}

/*
 * Reserves a chunk of the virtual address space spanning the range [lb..ub].
 * Returns `true` on success, `false` on failure.
 */
bool reserve(Allocator &allocator, intptr_t lb, intptr_t ub)
{
    if (!verify(lb, ub))
        return false;
    lb -= (lb % PAGE_SIZE);
    ub += (ub % PAGE_SIZE == 0? 0: PAGE_SIZE - ub % PAGE_SIZE);
    if (ub - lb <= 0)
        return false;
    Node *n = insert</*LEFT=*/true>(allocator.tree.root, lb, ub, (ub - lb));
    if (n == nullptr)
        return false;
    if (allocator.tree.root == nullptr)
        allocator.tree.root = n;
    rebalanceInsert(&allocator.tree, n);

    Alloc *A = &n->alloc;
    A->T = nullptr;
    A->I = nullptr;
    return true;
}

/*
 * Deallocate an existing allocation.
 */
void deallocate(Allocator &allocator, const Alloc *a)
{
    if (a == nullptr)
        return;
    Node *n = (Node *)(a);
    assert(n->alloc.T != nullptr);
    rebalanceRemove(&allocator.tree, n);
    free(n);
}

/*
 * Iterators.
 */
const Alloc *Allocator::iterator::operator*()
{
    return &node->alloc;
}

static Node *next(Node *n)
{
    if (n == nullptr)
        return n;
    if (n->entry.right != nullptr)
    {
        n = n->entry.right;
        while (n->entry.left != nullptr)
            n = n->entry.left;
        return n;
    }
    else
    {
        while (true)
        {
            Node *parent = n->entry.parent;
            if (parent == nullptr)
                return nullptr;
            if (parent->entry.left == n)
                return parent;
            n = parent;
        }
    }
}

void Allocator::iterator::operator++()
{
    node = next(node);
}

Allocator::iterator Allocator::begin() const
{
    Node *n = tree.root;
    if (n == nullptr)
        return end();
    while (n->entry.left != nullptr)
        n = n->entry.left;
    Allocator::iterator i = {n};
    return i;
}

Allocator::iterator Allocator::find(intptr_t addr) const
{
    Node *n = this->tree.root;
    while (n != nullptr)
    {
        if (addr < n->alloc.lb)
            n = n->entry.left;
        else if (addr >= n->alloc.ub)
            n = n->entry.right;
        else
            break;
    }
    Allocator::iterator i = {n};
    return i;
}

