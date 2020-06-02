/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  Blocks are never coalesced or reused.  The size of
 * a block is found at the first aligned word before the block (we need
 * it for realloc).
 *
 * This code is correct and blazingly fast, but very bad usage-wise since
 * it never frees anything.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
#define DEBUG
#ifdef DEBUG
#define debug(...) printf(__VA_ARGS__)
#else
#define debug(...)
#endif

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

typedef int32_t word_t;

typedef struct
{
    int32_t header;
    /*
   * We don't know what the size of the payload will be, so we will
   * declare it as a zero-length array.  This allow us to obtain a
   * pointer to the start of the payload.
   */
    uint8_t payload[];
} block_t;

static block_t *heap_first_block;

static bool is_allocated(block_t *block)
{
    return block->header & 1;
}

static size_t round_up(size_t size)
{
    size += 2 * sizeof(word_t);
    return (size + ALIGNMENT - 1) & -ALIGNMENT;
}

static size_t get_size(block_t *block)
{
    return block->header & -2;
}

static size_t get_size_footer(word_t *footer)
{
    return (*footer) & -2;
}

static block_t *next_block(block_t *block)
{
    uint8_t *result = (uint8_t *)block;
    result += get_size(block);
    return (block_t *)result;
}

static block_t *prev_block(block_t *block)
{
    if (block == heap_first_block)
    {
        return NULL;
    }
    uint8_t *ptr = (uint8_t *)block;
    word_t *prev_footer = (word_t *)block - 1;
    size_t prev_size = get_size_footer(prev_footer);
    uint8_t *result = ptr - prev_size;
    return (block_t *)result;
}

static word_t *footer_ptr(block_t *block)
{
    return ((word_t *)next_block(block)) - 1;
}

static void set_header(block_t *block, size_t size, bool allocated)
{
    block->header = size | allocated;
    word_t *footer = footer_ptr(block);
    *footer = block->header;
}

static bool on_heap(block_t *block)
{
    if (block == NULL)
    {
        return false;
    }
    if (block >= heap_first_block && block < (block_t *)mem_heap_hi())
    {
        return true;
    }
    else
    {
        return false;
    }
}

// void print_block(block_t *block)
// {
//     if (block != NULL)
//     {
//         printf("Block[0x%lx, %lx, %d]\n", (size_t)block, get_size(block), is_allocated(block));
//     }
// }

static void join_next(block_t *block)
{
    if (!on_heap(block))
    {
        return;
    }
    if (is_allocated(block))
    {
        return;
    }
    block_t *next = next_block(block);
    if (!on_heap(next))
    {
        return;
    }
    if (is_allocated(next))
    {
        return;
    }
    size_t new_size = get_size(block) + get_size(next);
    set_header(block, new_size, false);
}

void split_block(block_t *block, size_t size)
{
    size_t remaining_size = get_size(block) - size;
    set_header(block, size, true);
    block_t *remaining_block = next_block(block);
    set_header(remaining_block, remaining_size, false);
}

/*
 * mm_init - Called when a new trace starts.
 */
int mm_init(void)
{
    /* Pad heap start so first payload is at ALIGNMENT. */
    size_t offset = ALIGNMENT - offsetof(block_t, payload);
    long heap_start = (long)mem_sbrk(ALIGNMENT - offsetof(block_t, payload));
    if (heap_start < 0)
        return -1;

    heap_first_block = (block_t *)((uint8_t *)heap_start + offset);
    return 0;
}

/*
 * malloc 
 *      
 */
void *malloc(size_t size)
{
    size = round_up(size);
    block_t *block = heap_first_block;
    while (block < (block_t *)mem_heap_hi())
    {
        if (!is_allocated(block) && get_size(block) >= size)
        {
            if (get_size(block) == size)
            {
                set_header(block, get_size(block), true);
            }
            else
            {
                split_block(block, size);
            }

            return block->payload;
        }
        block = next_block(block);
    }

    block = mem_sbrk(size);
    if ((long)block < 0)
        return NULL;

    set_header(block, size, true);
    return block->payload;
}

/*
 * free 
 */
void free(void *ptr)
{    
    block_t *block = ptr - offsetof(block_t, payload);
    set_header(block, get_size(block), false);
    join_next(block);
    block_t *prev = prev_block(block);
    join_next(prev);
}

/*
 * realloc - Change the size of the block by mallocing a new block,
 *      copying its data, and freeing the old block.
 **/
void *realloc(void *old_ptr, size_t size)
{
    /* If size == 0 then this is just free, and we return NULL. */
    if (size == 0)
    {
        free(old_ptr);
        return NULL;
    }

    /* If old_ptr is NULL, then this is just malloc. */
    if (!old_ptr)
        return malloc(size);

    block_t *block = old_ptr - offsetof(block_t, payload);
    size_t new_size = round_up(size);
    size_t old_size = get_size(block);

    if (new_size == old_size)
    {
        return block->payload;
    }
    else if (new_size < old_size)
    {
        split_block(block, new_size);
        return block->payload;
    }
    else
    {
        size_t size_diff = new_size - old_size;
        block_t *next = next_block(block);
        if (!on_heap(next))
        {
            next = mem_sbrk((long)size_diff);
            set_header(block, new_size, true);
            return block->payload;
        }
        else if (!is_allocated(next) && get_size(next) >= size_diff)
        {
            if (get_size(next) == size_diff)
            {
                set_header(block, new_size, true);
                return block->payload;
            }
            else
            {
                split_block(next, size_diff);
                set_header(block, new_size, true);
                return block->payload;
            }
        }
        else
        {
            void *new_ptr = malloc(size);

            /* If malloc() fails, the original block is left untouched. */
            if (!new_ptr)
                return NULL;

            /* Copy the old data. */
            size_t old_size = get_size(block);
            if (size < old_size)
                old_size = size;
            memcpy(new_ptr, old_ptr, old_size);

            /* Free the old block. */
            free(old_ptr);

            return new_ptr;
        }
    }
}

/*
 * calloc - Allocate the block and set it to zero.
 */
void *calloc(size_t nmemb, size_t size)
{
    size_t bytes = nmemb * size;
    void *new_ptr = malloc(bytes);

    /* If malloc() fails, skip zeroing out the memory. */
    if (new_ptr)
        memset(new_ptr, 0, bytes);

    return new_ptr;
}

/*
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(int verbose)
{
}
