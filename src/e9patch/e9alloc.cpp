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

#include "e9alloc.h"
#include "e9patch.h"
#include "e9trampoline.h"

/*
 * Interval tree node.
 */
struct Node
{
    Alloc alloc;            // Allocation
    struct
    {
        Node *parent;       // RB-tree parent
        Node *left;         // RB-tree left
        Node *right;        // RB-tree right
    } entry;
    uint64_t gap:63;        // Largest free gap in sub-tree (ub - lb)
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
    uint64_t lgap = (l == nullptr? 0: l->gap);
    uint64_t rgap = (r == nullptr? 0: r->gap);
    uint64_t gap  = std::max(lgap, rgap);
    gap = std::max(gap, (uint64_t)(l == nullptr? 0: n->alloc.lb - l->ub));
    gap = std::max(gap, (uint64_t)(r == nullptr? 0: r->lb - n->alloc.ub));
    n->gap = gap;
}

/****************************************************************************/
/* INTERVAL TREES                                                           */
/****************************************************************************/

/*
 * The implementation uses code that is dervied from Niels Provos' red-black
 * tree implementation.  See the copyright and license (BSD) below.
 */

/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define RB_BLACK                    0
#define RB_RED                      1
#define RB_PARENT(N)                (N)->entry.parent
#define RB_LEFT(N)                  (N)->entry.left
#define RB_RIGHT(N)                 (N)->entry.right
#define RB_COLOR(N)                 (N)->color

static void rotateLeft(Tree *t, Node *n)
{
    Node *tmp = RB_RIGHT(n);
    if ((RB_RIGHT(n) = RB_LEFT(tmp)) != nullptr)
        RB_PARENT(RB_LEFT(tmp)) = n;
    fix(n);
    if ((RB_PARENT(tmp) = RB_PARENT(n)) != nullptr)
    {
        if (n == RB_LEFT(RB_PARENT(n)))
            RB_LEFT(RB_PARENT(n)) = tmp;
        else
            RB_RIGHT(RB_PARENT(n)) = tmp;
    }
    else
        t->root = tmp;
    RB_LEFT(tmp) = n;
    RB_PARENT(n) = tmp;
    fix(tmp);
    if (RB_PARENT(tmp) != nullptr)
        fix(RB_PARENT(tmp));
}

static void rotateRight(Tree *t, Node *n)
{
    Node *tmp = RB_LEFT(n);
    if ((RB_LEFT(n) = RB_RIGHT(tmp)) != nullptr)
        RB_PARENT(RB_RIGHT(tmp)) = n;
    fix(n);
    if ((RB_PARENT(tmp) = RB_PARENT(n)) != nullptr)
    {
        if (n == RB_LEFT(RB_PARENT(n)))
            RB_LEFT(RB_PARENT(n)) = tmp;
        else
            RB_RIGHT(RB_PARENT(n)) = tmp;
    } else
        t->root = tmp;
    RB_RIGHT(tmp) = n;
    RB_PARENT(n) = tmp;
    fix(tmp);
    if (RB_PARENT(tmp) != nullptr)
        fix(RB_PARENT(tmp));
}

static void rebalanceInsert(Tree *t, Node *n)
{
    Node *parent, *gparent, *tmp;
    for (Node *m = n; m != nullptr; m = RB_PARENT(m))
        fix(m);
    while ((parent = RB_PARENT(n)) != nullptr &&
                RB_COLOR(parent) == RB_RED)
    {
        gparent = RB_PARENT(parent);
        if (parent == RB_LEFT(gparent))
        {
            tmp = RB_RIGHT(gparent);
            if (tmp != nullptr && RB_COLOR(tmp) == RB_RED)
            {
                RB_COLOR(tmp)     = RB_BLACK;
                RB_COLOR(parent)  = RB_BLACK;
                RB_COLOR(gparent) = RB_RED;
                n = gparent;
                continue;
            }
            if (RB_RIGHT(parent) == n)
            {
                rotateLeft(t, parent);
                tmp = parent;
                parent = n;
                n = tmp;
            }
            RB_COLOR(parent)  = RB_BLACK;
            RB_COLOR(gparent) = RB_RED;
            rotateRight(t, gparent);
        }
        else
        {
            tmp = RB_LEFT(gparent);
            if (tmp != nullptr && RB_COLOR(tmp) == RB_RED)
            {
                RB_COLOR(tmp)     = RB_BLACK;
                RB_COLOR(parent)  = RB_BLACK;
                RB_COLOR(gparent) = RB_RED;
                n = gparent;
                continue;
            }
            if (RB_LEFT(parent) == n)
            {
                rotateRight(t, parent);
                tmp = parent;
                parent = n;
                n = tmp;
            }
            RB_COLOR(parent)  = RB_BLACK;
            RB_COLOR(gparent) = RB_RED;
            rotateLeft(t, gparent);
        }
    }
    RB_COLOR(t->root) = RB_BLACK;
}

static void rebalanceRemove(Tree *t, Node *parent, Node *n)
{
    Node *tmp;
    while ((n == nullptr || RB_COLOR(n) == RB_BLACK) && n != t->root)
    {
        if (RB_LEFT(parent) == n)
        {
            tmp = RB_RIGHT(parent);
            if (RB_COLOR(tmp) == RB_RED)
            {
                RB_COLOR(tmp) = RB_BLACK;
                RB_COLOR(parent) = RB_RED;
                rotateLeft(t, parent);
                tmp = RB_RIGHT(parent);
            }
            if ((RB_LEFT(tmp) == nullptr ||
                    RB_COLOR(RB_LEFT(tmp)) == RB_BLACK) &&
                (RB_RIGHT(tmp) == nullptr ||
                    RB_COLOR(RB_RIGHT(tmp)) == RB_BLACK))
            {
                RB_COLOR(tmp) = RB_RED;
                n = parent;
                parent = RB_PARENT(n);
            }
            else
            {
                if (RB_RIGHT(tmp) == nullptr ||
                    RB_COLOR(RB_RIGHT(tmp)) == RB_BLACK)
                {
                    Node *oleft;
                    if ((oleft = RB_LEFT(tmp)) != nullptr)
                        RB_COLOR(oleft) = RB_BLACK;
                    RB_COLOR(tmp) = RB_RED;
                    rotateRight(t, tmp);
                    tmp = RB_RIGHT(parent);
                }
                RB_COLOR(tmp) = RB_COLOR(parent);
                RB_COLOR(parent) = RB_BLACK;
                if (RB_RIGHT(tmp))
                    RB_COLOR(RB_RIGHT(tmp)) = RB_BLACK;
                rotateLeft(t, parent);
                n = t->root;
                break;
            }
        }
        else
        {
            tmp = RB_LEFT(parent);
            if (RB_COLOR(tmp) == RB_RED)
            {
                RB_COLOR(tmp) = RB_BLACK;
                RB_COLOR(parent) = RB_RED;
                rotateRight(t, parent);
                tmp = RB_LEFT(parent);
            }
            if ((RB_LEFT(tmp) == nullptr ||
                    RB_COLOR(RB_LEFT(tmp)) == RB_BLACK) &&
                (RB_RIGHT(tmp) == nullptr ||
                    RB_COLOR(RB_RIGHT(tmp)) == RB_BLACK))
            {
                RB_COLOR(tmp) = RB_RED;
                n = parent;
                parent = RB_PARENT(n);
            }
            else
            {
                if (RB_LEFT(tmp) == nullptr ||
                    RB_COLOR(RB_LEFT(tmp)) == RB_BLACK)
                {
                    Node *oright;
                    if ((oright = RB_RIGHT(tmp)) != nullptr)
                        RB_COLOR(oright) = RB_BLACK;
                    RB_COLOR(tmp) = RB_RED;
                    rotateLeft(t, tmp);
                    tmp = RB_LEFT(parent);
                }
                RB_COLOR(tmp) = RB_COLOR(parent);
                RB_COLOR(parent) = RB_BLACK;
                if (RB_LEFT(tmp))
                    RB_COLOR(RB_LEFT(tmp)) = RB_BLACK;
                rotateRight(t, parent);
                n = t->root;
                break;
            }
        }
    }
    if (n != nullptr)
        RB_COLOR(n) = RB_BLACK;
}

static Node *remove(Tree *t, Node *n)
{
    Node *child, *parent, *old = n;
    size_t color;
    if (RB_LEFT(n) == nullptr)
        child = RB_RIGHT(n);
    else if (RB_RIGHT(n) == nullptr)
        child = RB_LEFT(n);
    else
    {
        Node *left;
        n = RB_RIGHT(n);
        while ((left = RB_LEFT(n)) != nullptr)
            n = left;
        child = RB_RIGHT(n);
        parent = RB_PARENT(n);
        color = RB_COLOR(n);
        if (child != nullptr)
            RB_PARENT(child) = parent;
        if (parent != nullptr)
        {
            if (RB_LEFT(parent) == n)
                RB_LEFT(parent) = child;
            else
                RB_RIGHT(parent) = child;
            fix(parent);
        }
        else
            t->root = child;
        if (RB_PARENT(n) == old)
            parent = n;
        RB_PARENT(n) = RB_PARENT(old);
        RB_LEFT(n)   = RB_LEFT(old);
        RB_RIGHT(n)  = RB_RIGHT(old);
        RB_COLOR(n)  = RB_COLOR(old);
        if (RB_PARENT(old) != nullptr)
        {
            if (RB_LEFT(RB_PARENT(old)) == old)
                RB_LEFT(RB_PARENT(old)) = n;
            else
                RB_RIGHT(RB_PARENT(old)) = n;
            fix(RB_PARENT(old));
        }
        else
            t->root = n;
        RB_PARENT(RB_LEFT(old)) = n;
        if (RB_RIGHT(old) != nullptr)
            RB_PARENT(RB_RIGHT(old)) = n;
        if (parent)
        {
            left = parent;
            do
            {
                fix(left);
            }
            while ((left = RB_PARENT(left)) != nullptr);
        }
        goto color;
    }
    parent = RB_PARENT(n);
    color = RB_COLOR(n);
    if (child != nullptr)
        RB_PARENT(child) = parent;
    if (parent)
    {
        if (RB_LEFT(parent) == n)
            RB_LEFT(parent) = child;
        else
            RB_RIGHT(parent) = child;
        n = parent;
        do
        {
            fix(n);
        }
        while ((n = RB_PARENT(n)) != nullptr);
    }
    else
        t->root = child;
color:
    if (color == RB_BLACK)
        rebalanceRemove(t, parent, child);
    return old;
}



/****************************************************************************/

#define FLAG_LB                     0x1
#define FLAG_UB                     0x2
#define FLAG_RIGHT                  0x4
#define FLAG_SAME_PAGE              0x8

#define flag_set(flags, flag, val)  \
    ((val)? (flags) | (flag): (flags) & ~(flag))

static Node *insert(Node *root, intptr_t lb, intptr_t ub, size_t size,
    uint32_t flags);

/*
 * Allocate a node.
 */
static Node *alloc()
{
    Node *n        = new Node;
    n->alloc.T     = nullptr;
    n->alloc.I     = nullptr;
    n->alloc.entry = 0;
    return n;
}

/*
 * Allocate and initialize a new interval tree node.
 */
static Node *node(Node *parent, intptr_t lb, intptr_t ub, size_t size,
    uint32_t flags)
{
    bool alloc_left = ((flags & FLAG_RIGHT) != 0? false:
        ((flags & FLAG_LB) != 0 || (flags & FLAG_UB) == 0));
    intptr_t LB, UB;
    if (alloc_left)
    {
        LB = lb;
        UB = lb + size;
    }
    else
    {
        LB = ub - size;
        UB = ub;
    }

    bool same_page   = ((flags & FLAG_SAME_PAGE) != 0);
    bool spans_pages = (LB / PAGE_SIZE != (UB-1) / PAGE_SIZE);
    if (same_page && spans_pages)
    {
        off_t offset = (alloc_left?
            (off_t)PAGE_SIZE - std::abs((intptr_t)(lb % PAGE_SIZE)):
            -std::abs((intptr_t)(ub % PAGE_SIZE)));
        LB += offset;
        UB += offset;
        assert(LB / PAGE_SIZE == (UB-1) / PAGE_SIZE);
        if (LB < lb || UB > ub)
        {
            // Cannot fit into the current page == fail.
            return nullptr;
        }
    }

    Node *n = alloc();
    n->alloc.lb     = LB;
    n->alloc.ub     = UB;
    n->lb           = LB;
    n->ub           = UB;
    n->entry.parent = parent;
    n->entry.left   = nullptr;
    n->entry.right  = nullptr;
    n->color        = RB_RED;
    n->gap          = 0;
    return n;
}

/*
 * Insert left-child helper.
 */
static Node *insertLeftChild(Node *root, intptr_t lb, intptr_t ub, size_t size,
    uint32_t flags)
{
    ub = std::min(ub, root->alloc.lb);
    if ((intptr_t)size > ub - lb)
        return nullptr;
    flags = flag_set(flags, FLAG_UB,
        (root->alloc.lb - ub < (ssize_t)PAGE_SIZE));
    Node *n;
    if (root->entry.left == nullptr)
        n = root->entry.left = node(root, lb, ub, size, flags);
    else
        n = insert(root->entry.left, lb, ub, size, flags);
    return n;
}

/*
 * Insert right-child helper.
 */
static Node *insertRightChild(Node *root, intptr_t lb, intptr_t ub, size_t size,
    uint32_t flags)
{
    lb = std::max(lb, root->alloc.ub);
    if ((intptr_t)size > ub - lb)
        return nullptr;
    flags = flag_set(flags, FLAG_LB,
        (lb - root->alloc.ub < (ssize_t)PAGE_SIZE));
    Node *n;
    if (root->entry.right == nullptr)
        n = root->entry.right = node(root, lb, ub, size, flags);
    else
        n = insert(root->entry.right, lb, ub, size, flags);
    return n;
}

/*
 * Insert a new allocation or reservation into the interval tree node `root`.
 */
static Node *insert(Node *root, intptr_t lb, intptr_t ub,
    size_t size, uint32_t flags)
{
    if ((intptr_t)size > ub - lb)
        return nullptr;
    if (root == nullptr)
        return node(nullptr, lb, ub, size, flags);

    Node *n = nullptr;
    if (size <= root->gap)
    {
        intptr_t rlb = std::max(lb, root->lb);
        intptr_t rub = std::min(ub, root->ub);
        if (n == nullptr)
            n = insertRightChild(root, rlb, rub, size, flags);
        if (n == nullptr)
            n = insertLeftChild(root, rlb, rub, size, flags);
    }
    if (n == nullptr && ub > root->ub)
        n = insertRightChild(root, std::max(lb, root->ub), ub, size, flags);
    if (n == nullptr && lb < root->lb)
        n = insertLeftChild(root, lb, std::min(ub, root->lb), size, flags);

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
const Alloc *allocate(Binary *B, intptr_t lb, intptr_t ub,
    const Trampoline *T, const Instr *I, bool same_page)
{
    Allocator &allocator = B->allocator;
    if (!verify(lb, ub + TRAMPOLINE_MAX))
        return nullptr;
    int presize = getTrampolinePrologueSize(B, I);
    int tmpsize = getTrampolineSize(B, T, I);
    if (tmpsize < 0)
        return nullptr;
    lb -= (intptr_t)presize;
    ub += (intptr_t)tmpsize;
    size_t size = (size_t)presize + (size_t)tmpsize;
    uint32_t flags = (same_page? FLAG_SAME_PAGE: 0);
    Node *n = nullptr;
    const intptr_t target = 0x70C00000;
    if (option_Oorder && ub > target)
        n = insert(allocator.tree.root, lb, target, size, flags | FLAG_RIGHT);
    if (n == nullptr)
        n = insert(allocator.tree.root, lb, ub, size, flags);
    if (n == nullptr)
        return nullptr;
    if (allocator.tree.root == nullptr)
        allocator.tree.root = n;
    rebalanceInsert(&allocator.tree, n);

    Alloc *A = &n->alloc;
    A->T     = T;
    A->I     = I;
    A->entry = (unsigned)presize;
    return A;
}

/*
 * Reserves a chunk of the virtual address space spanning the range [lb..ub].
 * Returns `true` on success, `false` on failure.
 */
bool reserve(Binary *B, intptr_t lb, intptr_t ub)
{
    Allocator &allocator = B->allocator;
    if (!verify(lb, ub))
        return false;
    lb -= (lb % PAGE_SIZE);
    ub += (ub % PAGE_SIZE == 0? 0: PAGE_SIZE - ub % PAGE_SIZE);
    if (ub - lb <= 0)
        return false;
    uint32_t flags = 0;
    Node *n = insert(allocator.tree.root, lb, ub, (ub - lb), flags);
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
void deallocate(Binary *B, const Alloc *a)
{
    Allocator &allocator = B->allocator;
    if (a == nullptr)
        return;
    Node *n = (Node *)(a);
    assert(n->alloc.T != nullptr);
    remove(&allocator.tree, n);
    delete n;
}

/*
 * Iterators.
 */
Alloc *Allocator::iterator::operator*()
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

