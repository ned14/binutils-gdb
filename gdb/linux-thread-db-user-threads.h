/* libthread_db implementation helper library

   Copyright (C) 1992-2024 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License
   as published by the Free Software Foundation; either version 2, or
   (at your option) any later version.

   In addition to the permissions in the GNU Library General Public
   License, the Free Software Foundation gives you unlimited
   permission to link the compiled version of this file into
   combinations with other programs, and to distribute those
   combinations without any restriction coming from the use of this
   file.  (The Library Public License restrictions do apply in other
   respects; for example, they cover modification of the file, and
   distribution when not linked into a combined executable.)

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#ifndef LINUX_THREAD_DB_USER_THREADS_H
#define LINUX_THREAD_DB_USER_THREADS_H

// #define LINUX_THREAD_DB_USER_THREADS_AM_LIBTHREAD_DB 1

/* linux-thread-db's support for user space threads (aka 'green threads',
'threadlets', 'coroutines' et al) requires a custom `libthread_db.so.1`
to be specified to GDB using `set libthread-db-search-path` so it gets
found before the system libthread_db.so. The custom `libthread_db.so.1`
must do the following:

1. `maint check libthread-db` must pass without error.

2. Threads returned by `td_ta_thr_iter()` must have at least one with
type `TD_THR_SYSTEM` as returned by `td_thr_get_info()`. This declares
to GDB that this custom libthread-db supports user space threads (NPTL's
libthread-db always returns `TD_THR_USER` for kernel threads).

If the above two conditions are met, linux-thread-db will now additionally
query `td_ta_thr_iter()` for userspace threads when it refreshes the
thread list. It will do this with the filter `state = TD_THR_RUN` to
indicate it only wants to receive threads which are runnable but not on
a LWP yet (NPTL's libthread-db only responds to `state = TD_THR_ANY_STATE`).

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A long standing problem with the Solaris `td_ta_thr_iter()` interface is
that it is fundamentally racy, which is why linux-thread-db doesn't use it
if `/proc/pid/task` is available. This header is supplied to help you
implement your `td_ta_thr_iter(state = TD_THR_RUN)` in a race free way.
You don't HAVE to use it, but it will make things easier if you do. Do note
the LGPL license above, this allows incorporation into most codebases.

Bear in mind that your custom `libthread_db.so.1` cannot access the inferior
directly, it must use the functions below starting with `ps_*`. This means
that your inferior must expose data structures to be read by the `ps_*`
functions in a race free way. Note that the `ps_*` functions provide no
atomic ordering, there is no equivalent to mutexs, and everything can be
acting over a network connection with considerable latency. This tends to
particularly show up races as a result.

The way the below works is that the inferior must define a symbol
`_thread_db_userspace_threads` which is a
`thread_db_userspace_threads_t`. This is a sparse array of
pointers to information about each user space thread
(`userspace_thread_db_userspace_thread_info_t`). If a user space thread is
currently not suspended running code, its pointer gets zeroed and should be
ignored by `td_ta_thr_iter()`.

The structure chosen to represent info about suspended user space threads
`userspace_thread_db_userspace_thread_info_t` has a bare minimum viable
set of fields. There are helper functions provided to help fill out some
of those fields from a `ucontext_t` and a `jmp_buf`.

For example, on x64 glibc `jmp_buf` is eight 64 bit registers. If you
examine the setjmp implementation, the following registers are saved:
rbx, rbp, r12, r13, r14, r15, rsp, pc in that order. If you know this,
the relevant members of `mcontext_t.gregs` can be set and everything else
zeroed, and GDB will show the right backtrace when the current thread
is set to a userspace thread.

The entire structure is a single, contiguous range of data to enable a
single `ps_pdread()` call to pull everything at once efficiently. The
reason we have an array of pointers to the structures underneath is to
act as signifier that the structure's contents have been updated in full
and are valid. This assumes that a pointer value is updated atomically
and is not subject to torn reads, which is the case on most modern
architectures, even most modern tiny embedded microcontrollers.
*/
#if !_GNU_SOURCE
#error "Need macro _GNU_SOURCE set!"
#endif

#include <sys/procfs.h> // for elf_greg_t
#include <unistd.h>

#if LINUX_THREAD_DB_USER_THREADS_AM_LIBTHREAD_DB
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC(...) __VA_ARGS__
#else
#ifdef __cplusplus
#include <atomic>
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC(...) std::atomic<__VA_ARGS__>
#else
#include <stdatomic.h>
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC(...) _Atomic (__VA_ARGS__)
#endif
#endif

#ifndef LINUX_THREAD_DB_USER_THREADS_HAVE_ASAN
#ifndef __clang__
#if defined(__SANITIZE_ADDRESS__)
#define LINUX_THREAD_DB_USER_THREADS_HAVE_ASAN 1
#elif defined(__SANITIZE_THREAD__)
#define LINUX_THREAD_DB_USER_THREADS_HAVE_TSAN 1
#elif defined(__SANITIZE_UNDEFINED__)
#define LINUX_THREAD_DB_USER_THREADS_HAVE_UBSAN 1
#endif
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define LINUX_THREAD_DB_USER_THREADS_HAVE_ASAN 1
#elif __has_feature(thread_sanitizer)
#define LINUX_THREAD_DB_USER_THREADS_HAVE_TSAN 1
#elif defined(__SANITIZE_UNDEFINED__)
#define LINUX_THREAD_DB_USER_THREADS_HAVE_UBSAN 1
#endif
#endif
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /* Information representing a currently suspended running context.
   */
  typedef struct userspace_thread_db_userspace_thread_info_t
  {
    uint8_t salt : 5; /* Five bits of salt to create unique tids, do NOT set
                         this */
    pid_t lwp_id;     /* A Linux LWP associated with the userspace thread,
                         mandatory. Set for you by  */

    /* The following must be set by the inferior codebase.  */
    void (*startfunc) ();    /* The start function of the userspace thread */
    void *stack_sp;          /* The base of the stack */
    size_t stack_size;       /* The size of the stack */
    elf_greg_t suspended_fp; /* The frame pointer when suspended */
    elf_greg_t suspended_sp; /* The stack register when suspended */
    elf_greg_t suspended_pc; /* The instruction pointer when suspended */
  } userspace_thread_db_userspace_thread_info_t;
#if __STDC_VERSION__ >= 202300L || defined(__cplusplus)
  static_assert (sizeof (userspace_thread_db_userspace_thread_info_t) >= 32);
#endif

  /* A variant storing one of:

  - NULL, in which case the userspace thread is currently not in use.
  - All bits set, in which case this slot is not currently in use.
  - If bit 0 is set, bits 1-max is the LWP the userspace thread is currently
  running upon. The max LWP id Linux can do is 2^22.
  - If bit 0 is clear, a pointer to the valid and immutable thread info for
  this suspended userspace thread.
  */
  typedef union userspace_thread_db_userspace_thread_info_slot_t
  {
    void *null_ptr;
    uintptr_t all_bits_set;

    struct
    {
      uintptr_t is_lwp : 1;
      uintptr_t id : ((__CHAR_BIT__ * sizeof (uintptr_t)) - 1);
    } lwp;

    userspace_thread_db_userspace_thread_info_t *thread_info;
  } userspace_thread_db_userspace_thread_info_slot_t;
#if __STDC_VERSION__ >= 202300L || defined(__cplusplus)
  static_assert (sizeof (userspace_thread_db_userspace_thread_info_slot_t)
                 == sizeof (void *));
#endif

  /* A sparse array of currently suspended running contexts. Do NOT
  modify directly, use the helper functions. */
  typedef struct thread_db_userspace_threads_t
  {
    const size_t total_bytes; /* The total length of this allocation */
    const size_t max_length;  /* The length of the infos array */
    LINUX_THREAD_DB_USER_THREADS_ATOMIC (unsigned) monotonic_count;

    LINUX_THREAD_DB_USER_THREADS_ATOMIC (int)
    lock;          /* only used when allocating or deallocating slots */
    size_t length; /* The number of infos currently in use */
    size_t first_unused;
    LINUX_THREAD_DB_USER_THREADS_ATOMIC (void *) infos[/*max_length*/];
    /* After the above array comes an array of
     * userspace_thread_db_userspace_thread_info_t[max_length] */
  } thread_db_userspace_threads_t;

#ifdef __cplusplus
}
#endif

#if !LINUX_THREAD_DB_USER_THREADS_AM_LIBTHREAD_DB

/*********************** Functions for userspace **************************/

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ucontext.h>
#if defined(__x86_64__) || defined(__aarch64__)
#include <setjmp.h>
#endif

#ifdef __cplusplus
extern "C"
{
/* Some platforms e.g. ARM Cortex M0 will need custom implementations
here. Anything modern and multi-core capable should have at least atomic
compare-exchange. */
#ifndef LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD(x)                           \
  (x).load (std::memory_order_acquire)
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE(x, v)                       \
  (x).store ((v), std::memory_order_release)
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC_INCR(x)                           \
  (x).fetch_add (1, std::memory_order_acq_rel)
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC_DECR(x)                           \
  (x).fetch_sub (1, std::memory_order_acq_rel)
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC_COMPARE_EXCHANGE(x, e, v)         \
  (x).compare_exchange_weak ((e), (v), std::memory_order_acq_rel,             \
                             std::memory_order_relaxed)
#endif
#else
#ifndef LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD(x)                           \
  atomic_load_explicit (&(x), memory_order_acquire)
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE(x, v)                       \
  atomic_store_explicit (&(x), (v), memory_order_release)
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC_INCR(x)                           \
  atomic_fetch_add_explicit (&(x), 1, memory_order_acq_rel)
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC_DECR(x)                           \
  atomic_fetch_sub_explicit (&(x), 1, memory_order_acq_rel)
#define LINUX_THREAD_DB_USER_THREADS_ATOMIC_COMPARE_EXCHANGE(x, e, v)         \
  atomic_compare_exchange_weak_explicit (                                     \
      &(x), &(e), (v), memory_order_acq_rel, memory_order_relaxed)
#endif
#endif
#ifndef LINUX_THREAD_DB_USER_THREADS_MFENCE
#if LINUX_THREAD_DB_USER_THREADS_HAVE_TSAN
#define LINUX_THREAD_DB_USER_THREADS_MFENCE                                   \
  atomic_thread_fence (memory_order_acq_rel);
#define LINUX_THREAD_DB_USER_THREADS_SHUTUP_TSAN_LOCK_UNLOCK                  \
  {                                                                           \
    thread_db_userspace_threads_t *current;                                   \
    for (;;)                                                                  \
      {                                                                       \
        current = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (                  \
            _thread_db_userspace_threads[0]);                                 \
        if (current != NULL)                                                  \
          {                                                                   \
            if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (current->lock)      \
                != 0)                                                         \
              {                                                               \
                continue;                                                     \
              }                                                               \
            int expected = 0;                                                 \
            if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_COMPARE_EXCHANGE (        \
                    current->lock, expected, 1))                              \
              {                                                               \
                break;                                                        \
              }                                                               \
          }                                                                   \
        else                                                                  \
          {                                                                   \
            break;                                                            \
          }                                                                   \
      }                                                                       \
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->lock, 0);             \
  }
#else
/* We only care about preventing compiler reordering, not processor
 * reordering.
 */
#define LINUX_THREAD_DB_USER_THREADS_MFENCE                                   \
  __asm__ volatile ("" : : : "memory")
#define LINUX_THREAD_DB_USER_THREADS_SHUTUP_TSAN_LOCK_UNLOCK
#endif
#endif

  /* Implemented by you. Older versions of the structure are kept around
  for a while in case they are currently being read by libthread_db.
  */
  extern LINUX_THREAD_DB_USER_THREADS_ATOMIC (thread_db_userspace_threads_t *)
      _thread_db_userspace_threads[4];

  /* Set a userspace_thread_db_userspace_thread_info_t from a ucontext_t
   */
  static inline void
  userspace_thread_set_from_ucontext (
      userspace_thread_db_userspace_thread_info_t *ti, const ucontext_t *uc)
  {
    ti->stack_sp = uc->uc_stack.ss_sp;
    ti->stack_size = uc->uc_stack.ss_size;
#if defined(__aarch64__)
    ti->suspended_fp = uc->uc_mcontext.regs[29];
    ti->suspended_sp = uc->uc_mcontext.sp;
    ti->suspended_pc = uc->uc_mcontext.pc;
#elif defined(__x86_64__)
  ti->suspended_fp = uc->uc_mcontext.gregs[REG_RBP];
  ti->suspended_sp = uc->uc_mcontext.gregs[REG_RSP];
  ti->suspended_pc = uc->uc_mcontext.gregs[REG_RIP];
#else
  ti->suspended_fp = 0;
  ti->suspended_sp = 0;
  ti->suspended_pc = 0;
#endif
  }

/* Set a userspace_thread_db_userspace_thread_info_t from the current
execution frame.
*/
#define USERSPACE_THREAD_SET_FROM_HERE(ti)                                    \
  (ti)->suspended_fp = (elf_greg_t)(uintptr_t)__builtin_frame_address (0);    \
  (ti)->suspended_sp                                                          \
      = 0; /* __builtin_stack_address() appears to not be available? */       \
  (ti)->suspended_pc = (elf_greg_t)(uintptr_t)__builtin_extract_return_addr ( \
      __builtin_return_address (0));

  /* Expand storage for thread_db_userspace_threads in a way not racy to
  concurrent reads by libthread_db. *mem and *bytes if not null
  on return, you must deallocate.
  */
  static inline bool
  expand_thread_db_userspace_threads (void **mem, size_t *bytes)
  {
    assert (*bytes
            >= sizeof (thread_db_userspace_threads_t)
                   + sizeof (userspace_thread_db_userspace_thread_info_slot_t)
                   + sizeof (userspace_thread_db_userspace_thread_info_t));
    thread_db_userspace_threads_t *current;
    for (;;)
      {
        current = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
            _thread_db_userspace_threads[0]);
        if (current != NULL)
          {
            if (current->total_bytes > *bytes)
              {
                return false;
              }
            if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (current->lock) != 0)
              {
                continue;
              }
            int expected = 0;
            if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_COMPARE_EXCHANGE (
                    current->lock, expected, 1))
              {
                break;
              }
          }
        else
          {
            break;
          }
      }
    thread_db_userspace_threads_t *replacement
        = (thread_db_userspace_threads_t *)*mem;
    *(size_t *)&replacement->total_bytes = *bytes;
    *(size_t *)&replacement->max_length
        = (*bytes - sizeof (thread_db_userspace_threads_t))
          / (sizeof (userspace_thread_db_userspace_thread_info_slot_t)
             + sizeof (userspace_thread_db_userspace_thread_info_t));
    if (current != NULL)
      {
        LINUX_THREAD_DB_USER_THREADS_MFENCE;
        memcpy (
            replacement->infos, current->infos,
            current->max_length
                * sizeof (userspace_thread_db_userspace_thread_info_slot_t));
        memset (
            &replacement->infos[current->max_length], 0xff,
            (replacement->max_length - current->max_length)
                * sizeof (userspace_thread_db_userspace_thread_info_slot_t));
        memcpy (&replacement->infos[replacement->max_length],
                &current->infos[current->max_length],
                current->max_length
                    * sizeof (userspace_thread_db_userspace_thread_info_t));
        char *tozeromem
            = ((char *)&replacement->infos[replacement->max_length])
              + current->max_length
                    * sizeof (userspace_thread_db_userspace_thread_info_t);
        size_t tozerolen = (size_t)(((char *)replacement)
                                    + replacement->total_bytes - tozeromem);
        memset (tozeromem, 0, tozerolen);
        LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (
            replacement->monotonic_count,
            LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
                current->monotonic_count));
        replacement->length = current->length;
        replacement->first_unused = current->first_unused;
        LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (replacement->lock, 0);
        LINUX_THREAD_DB_USER_THREADS_MFENCE;
        thread_db_userspace_threads_t *old
            = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
                _thread_db_userspace_threads[3]);
        *bytes = (old != NULL) ? old->total_bytes : 0;
        *mem = old;
        LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (
            _thread_db_userspace_threads[3],
            LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
                _thread_db_userspace_threads[2]));
        LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (
            _thread_db_userspace_threads[2],
            LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
                _thread_db_userspace_threads[1]));
        LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (
            _thread_db_userspace_threads[1],
            LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
                _thread_db_userspace_threads[0]));
      }
    else
      {
        memset (
            replacement->infos, 0xff,
            replacement->max_length
                * sizeof (userspace_thread_db_userspace_thread_info_slot_t));
        char *tozeromem
            = ((char *)&replacement->infos[replacement->max_length]);
        size_t tozerolen = (size_t)(((char *)replacement)
                                    + replacement->total_bytes - tozeromem);
        memset (tozeromem, 0, tozerolen);
        replacement->monotonic_count = 1;
        replacement->length = 0;
        replacement->first_unused = 0;
        LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (replacement->lock, 0);
        LINUX_THREAD_DB_USER_THREADS_MFENCE;
        *mem = NULL;
        *bytes = 0;
      }
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (_thread_db_userspace_threads[0],
                                               replacement);
    return true;
  }

  /* Allocate a slot for a userspace thread in the array. */
  static inline size_t
  allocate_thread_db_userspace_thread_index ()
  {
    thread_db_userspace_threads_t *current;
    for (;;)
      {
        current = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
            _thread_db_userspace_threads[0]);
        if (current == NULL)
          {
            abort ();
          }
        if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (current->lock) != 0)
          {
            continue;
          }
        int expected = 0;
        if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_COMPARE_EXCHANGE (
                current->lock, expected, 1))
          {
            break;
          }
      }
    if (current->first_unused == current->length)
      {
        if (current->length == current->max_length)
          {
            LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->lock, 0);
            return (size_t)-1;
          }
        current->length++;
      }
    size_t ret = current->first_unused;
    for (current->first_unused += 1;
         current->first_unused < current->length
         && current->infos[current->first_unused] != (void *)(uintptr_t)-1;
         current->first_unused++)
      {
        ;
      }
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->infos[ret], NULL);
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_INCR (current->monotonic_count);
    LINUX_THREAD_DB_USER_THREADS_MFENCE;
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->lock, 0);
    return ret;
  }

  /* Deallocate a slot for a userspace thread in the array. */
  static inline void
  deallocate_thread_db_userspace_thread_index (size_t idx)
  {
    thread_db_userspace_threads_t *current;
    for (;;)
      {
        current = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
            _thread_db_userspace_threads[0]);
        if (current == NULL)
          {
            abort ();
          }
        if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (current->lock) != 0)
          {
            continue;
          }
        int expected = 0;
        if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_COMPARE_EXCHANGE (
                current->lock, expected, 1))
          {
            break;
          }
      }
    assert (idx < current->length);
    ((userspace_thread_db_userspace_thread_info_t *)&current
         ->infos[current->max_length])[idx]
        .salt++;
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->infos[idx],
                                               (void *)(uintptr_t)-1);
    if (idx < current->first_unused)
      {
        current->first_unused = idx;
      }
    while (current->length > 0
           && current->infos[current->length - 1] == (void *)(uintptr_t)-1)
      {
        current->length--;
      }
    if (current->first_unused > current->length)
      {
        current->first_unused = current->length;
      }
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_INCR (current->monotonic_count);
    LINUX_THREAD_DB_USER_THREADS_MFENCE;
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->lock, 0);
  }

  /* Get the thread info for a userspace thread slot. It must not be marked
  suspended (i.e. in use) */
  static inline userspace_thread_db_userspace_thread_info_t *
  get_thread_db_userspace_thread_info (size_t idx)
  {
    thread_db_userspace_threads_t *current
        = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
            _thread_db_userspace_threads[0]);
#if !LINUX_THREAD_DB_USER_THREADS_HAVE_TSAN
    assert (idx < current->length);
#endif
    userspace_thread_db_userspace_thread_info_slot_t v;
    v.null_ptr
        = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (current->infos[idx]);
    if (!v.lwp.is_lwp && v.all_bits_set != 0)
      {
        return NULL;
      }
    return &((userspace_thread_db_userspace_thread_info_t *)&current
                 ->infos[current->max_length])[idx];
  }

  /* Set a userspace thread slot as currently suspended. Only use if there
  could be concurrent use of `expand_thread_db_userspace_threads()` */
  static inline void
  set_thread_db_userspace_thread_suspended_locking (
      size_t idx, userspace_thread_db_userspace_thread_info_t *info)
  {
    thread_db_userspace_threads_t *current;
    for (;;)
      {
        current = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
            _thread_db_userspace_threads[0]);
        if (current == NULL)
          {
            abort ();
          }
        if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (current->lock) != 0)
          {
            continue;
          }
        int expected = 0;
        if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_COMPARE_EXCHANGE (
                current->lock, expected, 1))
          {
            break;
          }
      }
    assert (idx < current->length);
    // Any changes to the thread info need writing out before we update the
    // pointer
    LINUX_THREAD_DB_USER_THREADS_MFENCE;
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->infos[idx], info);
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_INCR (current->monotonic_count);
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->lock, 0);
  }

  /* Set a userspace thread slot as currently running. Only use if there could
  be concurrent use of `expand_thread_db_userspace_threads()` */
  static inline void
  set_thread_db_userspace_thread_running_locking (size_t idx, pid_t lwp_id)
  {
    thread_db_userspace_threads_t *current;
    for (;;)
      {
        current = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
            _thread_db_userspace_threads[0]);
        if (current == NULL)
          {
            abort ();
          }
        if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (current->lock) != 0)
          {
            continue;
          }
        int expected = 0;
        if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_COMPARE_EXCHANGE (
                current->lock, expected, 1))
          {
            break;
          }
      }
    assert (idx < current->length);
    ((userspace_thread_db_userspace_thread_info_t *)&current
         ->infos[current->max_length])[idx]
        .lwp_id
        = lwp_id;
    userspace_thread_db_userspace_thread_info_slot_t v;
    v.lwp.id = (unsigned)lwp_id;
    v.lwp.is_lwp = 1;
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->infos[idx],
                                               v.null_ptr);
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_INCR (current->monotonic_count);
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->lock, 0);
    // Any changes to the thread info must not be reordered before the pointer
    // null
    LINUX_THREAD_DB_USER_THREADS_MFENCE;
  }

  /* Set a userspace thread slot to say that the thread has exited. You would
  use this if your userspace threads actually are a loop which executes
  invocables passed in and you want GDB to destroy-create a new thread for
  every invocable. Only use if there could be concurrent use of
  `expand_thread_db_userspace_threads()` */
  static inline void
  set_thread_db_userspace_thread_exited_locking (size_t idx)
  {
    thread_db_userspace_threads_t *current;
    for (;;)
      {
        current = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
            _thread_db_userspace_threads[0]);
        if (current == NULL)
          {
            abort ();
          }
        if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (current->lock) != 0)
          {
            continue;
          }
        int expected = 0;
        if (LINUX_THREAD_DB_USER_THREADS_ATOMIC_COMPARE_EXCHANGE (
                current->lock, expected, 1))
          {
            break;
          }
      }
    assert (idx < current->length);
    userspace_thread_db_userspace_thread_info_slot_t v;
    v.null_ptr = NULL;
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->infos[idx],
                                               v.null_ptr);
    ((userspace_thread_db_userspace_thread_info_t *)&current
         ->infos[current->max_length])[idx]
        .salt++;
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_INCR (current->monotonic_count);
    LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->lock, 0);
    // Any changes to the thread info must not be reordered before the pointer
    // null
    LINUX_THREAD_DB_USER_THREADS_MFENCE;
  }

  /* Set a userspace thread slot as currently suspended. You MUST have
  completed in full all changes to the the thread info before calling this. */
  static inline void
  set_thread_db_userspace_thread_suspended_nonlocking (
      size_t idx, userspace_thread_db_userspace_thread_info_t *info)
  {
#if LINUX_THREAD_DB_USER_THREADS_HAVE_TSAN
    set_thread_db_userspace_thread_suspended_locking (idx, info);
#else
  thread_db_userspace_threads_t *current
      = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
          _thread_db_userspace_threads[0]);
  assert (idx < current->length);
  // Any changes to the thread info need writing out before we update the
  // pointer
  LINUX_THREAD_DB_USER_THREADS_MFENCE;
  LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->infos[idx],
                                             (void *)info);
  LINUX_THREAD_DB_USER_THREADS_ATOMIC_INCR (current->monotonic_count);
#endif
  }

  /* Set a userspace thread slot as currently running. */
  static inline void
  set_thread_db_userspace_thread_running_nonlocking (size_t idx, pid_t lwp_id)
  {
#if LINUX_THREAD_DB_USER_THREADS_HAVE_TSAN
    set_thread_db_userspace_thread_running_locking (idx, lwp_id);
#else
  thread_db_userspace_threads_t *current
      = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
          _thread_db_userspace_threads[0]);
  assert (idx < current->length);
  ((userspace_thread_db_userspace_thread_info_t *)&current
       ->infos[current->max_length])[idx]
      .lwp_id
      = lwp_id;
  userspace_thread_db_userspace_thread_info_slot_t v;
  v.lwp.id = (unsigned)lwp_id;
  v.lwp.is_lwp = 1;
  LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->infos[idx], v.null_ptr);
  LINUX_THREAD_DB_USER_THREADS_ATOMIC_INCR (current->monotonic_count);
  // Any changes to the thread info must not be reordered before the pointer
  // null
  LINUX_THREAD_DB_USER_THREADS_MFENCE;
#endif
  }

  /* Set a userspace thread slot to say that the thread has exited. You would
  use this if your userspace threads actually are a loop which executes
  invocables passed in and you want GDB to destroy-create a new thread for
  every invocable. */
  static inline void
  set_thread_db_userspace_thread_exited_nonlocking (size_t idx)
  {
#if LINUX_THREAD_DB_USER_THREADS_HAVE_TSAN
    set_thread_db_userspace_thread_exited_locking (idx);
#else
  thread_db_userspace_threads_t *current
      = LINUX_THREAD_DB_USER_THREADS_ATOMIC_LOAD (
          _thread_db_userspace_threads[0]);
  assert (idx < current->length);
  userspace_thread_db_userspace_thread_info_slot_t v;
  v.null_ptr = NULL;
  LINUX_THREAD_DB_USER_THREADS_ATOMIC_STORE (current->infos[idx], v.null_ptr);
  ((userspace_thread_db_userspace_thread_info_t *)&current
       ->infos[current->max_length])[idx]
      .salt++;
  LINUX_THREAD_DB_USER_THREADS_ATOMIC_INCR (current->monotonic_count);
  // Any changes to the thread info must not be reordered before the pointer
  // null
  LINUX_THREAD_DB_USER_THREADS_MFENCE;
#endif
  }

#ifdef __cplusplus
}
#endif

#else /* LINUX_THREAD_DB_USER_THREADS_AM_LIBTHREAD_DB */

/********************* Functions for libthread_db ************************/

#include <assert.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <search.h>
#include <time.h>

/* The definitions in this file must correspond to those in the debugger. */
#include <sys/procfs.h>
#include <sys/user.h>

#if defined(__x86_64__)
#include <sys/reg.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

  /* Functions in this interface return one of these status codes.  */
  typedef enum
  {
    PS_OK,      /* Generic "call succeeded".  */
    PS_ERR,     /* Generic error. */
    PS_BADPID,  /* Bad process handle.  */
    PS_BADLID,  /* Bad LWP identifier.  */
    PS_BADADDR, /* Bad address.  */
    PS_NOSYM,   /* Could not find given symbol.  */
    PS_NOFREGS  /* FPU register set not available for given LWP.  */
  } ps_err_e;

  /* This type is opaque in this interface.
     It's defined by the user of libthread_db.  */
  struct ps_prochandle;

  /* Read or write process memory at the given address.  */
  extern ps_err_e ps_pdread (struct ps_prochandle *, psaddr_t, void *, size_t);
  extern ps_err_e ps_pdwrite (struct ps_prochandle *, psaddr_t, const void *,
                              size_t);
  extern ps_err_e ps_ptread (struct ps_prochandle *, psaddr_t, void *, size_t);
  extern ps_err_e ps_ptwrite (struct ps_prochandle *, psaddr_t, const void *,
                              size_t);

  /* Get and set the given LWP's general or FPU register set.  */
  extern ps_err_e ps_lgetregs (struct ps_prochandle *, lwpid_t, prgregset_t);
  extern ps_err_e ps_lsetregs (struct ps_prochandle *, lwpid_t,
                               const prgregset_t);
  extern ps_err_e ps_lgetfpregs (struct ps_prochandle *, lwpid_t,
                                 prfpregset_t *);
  extern ps_err_e ps_lsetfpregs (struct ps_prochandle *, lwpid_t,
                                 const prfpregset_t *);

  /* Return the PID of the process.  */
  extern pid_t ps_getpid (struct ps_prochandle *);

  /* Fetch the special per-thread address associated with the given LWP.
     This call is only used on a few platforms (most use a normal register).
     The meaning of the `int' parameter is machine-dependent.  */
  extern ps_err_e ps_get_thread_area (struct ps_prochandle *, lwpid_t, int,
                                      psaddr_t *);

  /* Look up the named symbol in the named DSO in the symbol tables
     associated with the process being debugged, filling in *SYM_ADDR
     with the corresponding run-time address.  */
  extern ps_err_e ps_pglobal_lookup (struct ps_prochandle *,
                                     const char *object_name,
                                     const char *sym_name, psaddr_t *sym_addr);

  /* Stop or continue the entire process.  */
  extern ps_err_e ps_pstop (struct ps_prochandle *);
  extern ps_err_e ps_pcontinue (struct ps_prochandle *);

  /* Stop or continue the given LWP alone.  */
  extern ps_err_e ps_lstop (struct ps_prochandle *, lwpid_t);
  extern ps_err_e ps_lcontinue (struct ps_prochandle *, lwpid_t);

  /* Error codes of the library.  */
  typedef enum
  {
    TD_OK,          /* No error.  */
    TD_ERR,         /* No further specified error.  */
    TD_NOTHR,       /* No matching thread found.  */
    TD_NOSV,        /* No matching synchronization handle found.  */
    TD_NOLWP,       /* No matching light-weighted process found.  */
    TD_BADPH,       /* Invalid process handle.  */
    TD_BADTH,       /* Invalid thread handle.  */
    TD_BADSH,       /* Invalid synchronization handle.  */
    TD_BADTA,       /* Invalid thread agent.  */
    TD_BADKEY,      /* Invalid key.  */
    TD_NOMSG,       /* No event available.  */
    TD_NOFPREGS,    /* No floating-point register content available.  */
    TD_NOLIBTHREAD, /* Application not linked with thread library.  */
    TD_NOEVENT,     /* Requested event is not supported.  */
    TD_NOCAPAB,     /* Capability not available.  */
    TD_DBERR,       /* Internal debug library error.  */
    TD_NOAPLIC,     /* Operation is not applicable.  */
    TD_NOTSD,       /* No thread-specific data available.  */
    TD_MALLOC,      /* Out of memory.  */
    TD_PARTIALREG,  /* Not entire register set was read or written.  */
    TD_NOXREGS,     /* X register set not available for given thread.  */
    TD_TLSDEFER,    /* Thread has not yet allocated TLS for given module.  */
    TD_NOTALLOC = TD_TLSDEFER,
    TD_VERSION, /* Version if libpthread and libthread_db do not match.  */
    TD_NOTLS    /* There is no TLS segment in the given module.  */
  } td_err_e;

  /* Possible thread states.  TD_THR_ANY_STATE is a pseudo-state used to
     select threads regardless of state in td_ta_thr_iter().  */
  typedef enum
  {
    TD_THR_ANY_STATE,
    TD_THR_UNKNOWN,
    TD_THR_STOPPED,
    TD_THR_RUN,
    TD_THR_ACTIVE,
    TD_THR_ZOMBIE,
    TD_THR_SLEEP,
    TD_THR_STOPPED_ASLEEP
  } td_thr_state_e;

  /* Thread type: user or system.  TD_THR_ANY_TYPE is a pseudo-type used
     to select threads regardless of type in td_ta_thr_iter().  */
  typedef enum
  {
    TD_THR_ANY_TYPE,
    TD_THR_USER,
    TD_THR_SYSTEM
  } td_thr_type_e;

  /* Types of the debugging library.  */

  /* Handle for a process.  This type is opaque.  */
  typedef struct td_thragent td_thragent_t;

  /* The actual thread handle type.  This is also opaque.  */
  typedef struct td_thrhandle
  {
    td_thragent_t *th_ta_p;
    psaddr_t th_unique;
  } td_thrhandle_t;

  /* Forward declaration of a type defined by and for the dynamic linker.  */
  struct link_map;

/* Flags for `td_ta_thr_iter'.  */
#define TD_THR_ANY_USER_FLAGS 0xffffffff
#define TD_THR_LOWEST_PRIORITY -20
#define TD_SIGNO_MASK NULL

#define TD_EVENTSIZE 2
#define BT_UISHIFT 5 /* log base 2 of BT_NBIPUI, to extract word index */
#define BT_NBIPUI (1 << BT_UISHIFT) /* n bits per uint */
#define BT_UIMASK (BT_NBIPUI - 1)   /* to extract bit index */

  /* Bitmask of enabled events. */
  typedef struct td_thr_events
  {
    uint32_t event_bits[TD_EVENTSIZE];
  } td_thr_events_t;

/* Event set manipulation macros. */
#define __td_eventmask(n) (UINT32_C (1) << (((n) - 1) & BT_UIMASK))
#define __td_eventword(n) ((UINT32_C ((n) - 1)) >> BT_UISHIFT)

#define td_event_emptyset(setp)                                               \
  do                                                                          \
    {                                                                         \
      int __i;                                                                \
      for (__i = TD_EVENTSIZE; __i > 0; --__i)                                \
        (setp)->event_bits[__i - 1] = 0;                                      \
    }                                                                         \
  while (0)

#define td_event_fillset(setp)                                                \
  do                                                                          \
    {                                                                         \
      int __i;                                                                \
      for (__i = TD_EVENTSIZE; __i > 0; --__i)                                \
        (setp)->event_bits[__i - 1] = UINT32_C (0xffffffff);                  \
    }                                                                         \
  while (0)

#define td_event_addset(setp, n)                                              \
  (((setp)->event_bits[__td_eventword (n)]) |= __td_eventmask (n))
#define td_event_delset(setp, n)                                              \
  (((setp)->event_bits[__td_eventword (n)]) &= ~__td_eventmask (n))
#define td_eventismember(setp, n)                                             \
  (__td_eventmask (n) & ((setp)->event_bits[__td_eventword (n)]))
#if TD_EVENTSIZE == 2
#define td_eventisempty(setp)                                                 \
  (!((setp)->event_bits[0]) && !((setp)->event_bits[1]))
#else
#error "td_eventisempty must be changed to match TD_EVENTSIZE"
#endif

  /* Events reportable by the thread implementation.  */
  typedef enum
  {
    TD_ALL_EVENTS,                 /* Pseudo-event number.  */
    TD_EVENT_NONE = TD_ALL_EVENTS, /* Depends on context.  */
    TD_READY,                      /* Is executable now. */
    TD_SLEEP,                      /* Blocked in a synchronization obj.  */
    TD_SWITCHTO,                   /* Now assigned to a process.  */
    TD_SWITCHFROM,                 /* Not anymore assigned to a process.  */
    TD_LOCK_TRY,                   /* Trying to get an unavailable lock.  */
    TD_CATCHSIG,                   /* Signal posted to the thread.  */
    TD_IDLE,                       /* Process getting idle.  */
    TD_CREATE,                     /* New thread created.  */
    TD_DEATH,                      /* Thread terminated.  */
    TD_PREEMPT,                    /* Preempted.  */
    TD_PRI_INHERIT,                /* Inherited elevated priority.  */
    TD_REAP,                       /* Reaped.  */
    TD_CONCURRENCY,                /* Number of processes changing.  */
    TD_TIMEOUT,                    /* Conditional variable wait timed out.  */
    TD_MIN_EVENT_NUM = TD_READY,
    TD_MAX_EVENT_NUM = TD_TIMEOUT,
    TD_EVENTS_ENABLE = 31 /* Event reporting enabled.  */
  } td_event_e;

  /* Values representing the different ways events are reported.  */
  typedef enum
  {
    NOTIFY_BPT,     /* User must insert breakpoint at u.bptaddr. */
    NOTIFY_AUTOBPT, /* Breakpoint at u.bptaddr is automatically
                       inserted.  */
    NOTIFY_SYSCALL  /* System call u.syscallno will be invoked.  */
  } td_notify_e;

  /* Description how event type is reported.  */
  typedef struct td_notify
  {
    td_notify_e type; /* Way the event is reported.  */

    union
    {
      psaddr_t bptaddr; /* Address of breakpoint.  */
      int syscallno;    /* Number of system call used.  */
    } u;
  } td_notify_t;

  /* Structure used to report event.  */
  typedef struct td_event_msg
  {
    td_event_e event;           /* Event type being reported.  */
    const td_thrhandle_t *th_p; /* Thread reporting the event.  */
    union
    {
#if 0
    td_synchandle_t *sh;	/* Handle of synchronization object.  */
#endif
      uintptr_t data; /* Event specific data.  */
    } msg;
  } td_event_msg_t;

  /* Structure containing event data available in each thread structure.  */
  typedef struct
  {
    td_thr_events_t eventmask; /* Mask of enabled events.  */
    td_event_e eventnum;       /* Number of last event.  */
    void *eventdata;           /* Data associated with event.  */
  } td_eventbuf_t;

  /* Gathered statistics about the process.  */
  typedef struct td_ta_stats
  {
    int nthreads;          /* Total number of threads in use.  */
    int r_concurrency;     /* Concurrency level requested by user.  */
    int nrunnable_num;     /* Average runnable threads, numerator.  */
    int nrunnable_den;     /* Average runnable threads, denominator.  */
    int a_concurrency_num; /* Achieved concurrency level, numerator.  */
    int a_concurrency_den; /* Achieved concurrency level, denominator.  */
    int nlwps_num;         /* Average number of processes in use,
                              numerator.  */
    int nlwps_den;         /* Average number of processes in use,
                              denominator.  */
    int nidle_num;         /* Average number of idling processes,
                              numerator.  */
    int nidle_den;         /* Average number of idling processes,
                              denominator.  */
  } td_ta_stats_t;

  /* Since Sun's library is based on Solaris threads we have to define a few
     types to map them to POSIX threads.  */
  typedef pthread_t thread_t;
  typedef pthread_key_t thread_key_t;

  /* Callback for iteration over threads.  */
  typedef int td_thr_iter_f (const td_thrhandle_t *, void *);

  /* Callback for iteration over thread local data.  */
  typedef int td_key_iter_f (thread_key_t, void (*) (void *), void *);

  /* Forward declaration.  This has to be defined by the user.  */
  struct ps_prochandle;

  /* Information about the thread.  */
  typedef struct td_thrinfo
  {
    td_thragent_t *ti_ta_p;        /* Process handle.  */
    unsigned int ti_user_flags;    /* Unused.  */
    thread_t ti_tid;               /* Thread ID returned by
                                      pthread_create().  */
    char *ti_tls;                  /* Pointer to thread-local data.  */
    psaddr_t ti_startfunc;         /* Start function passed to
                                      pthread_create().  */
    psaddr_t ti_stkbase;           /* Base of thread's stack.  */
    long int ti_stksize;           /* Size of thread's stack.  */
    psaddr_t ti_ro_area;           /* Unused.  */
    int ti_ro_size;                /* Unused.  */
    td_thr_state_e ti_state;       /* Thread state.  */
    unsigned char ti_db_suspended; /* Nonzero if suspended by debugger. */
    td_thr_type_e ti_type;         /* Type of the thread (system vs
                                      user thread).  */
    intptr_t ti_pc;                /* Unused.  */
    intptr_t ti_sp;                /* Unused.  */
    short int ti_flags;            /* Unused.  */
    int ti_pri;                    /* Thread priority.  */
    lwpid_t ti_lid;                /* Kernel PID for this thread.  */
    sigset_t ti_sigmask;           /* Signal mask.  */
    unsigned char ti_traceme;      /* Nonzero if event reporting
                                      enabled.  */
    unsigned char ti_preemptflag;  /* Unused.  */
    unsigned char ti_pirecflag;    /* Unused.  */
    sigset_t ti_pending;           /* Set of pending signals.  */
    td_thr_events_t ti_events;     /* Set of enabled events.  */
  } td_thrinfo_t;

  /* Prototypes for exported library functions.  */

  /* Initialize the thread debug support library.  */
  extern td_err_e td_init (void);

  /* Historical relict.  Should not be used anymore.  */
  extern td_err_e td_log (void);

  /* Return list of symbols the library can request.  */
  extern const char **td_symbol_list (void);

  /* Generate new thread debug library handle for process PS.  */
  extern td_err_e td_ta_new (struct ps_prochandle *__ps, td_thragent_t **__ta);

  /* Free resources allocated for TA.  */
  extern td_err_e td_ta_delete (td_thragent_t *__ta);

  /* Get number of currently running threads in process associated with TA.
   */
  extern td_err_e td_ta_get_nthreads (const td_thragent_t *__ta, int *__np);

  /* Return process handle passed in `td_ta_new' for process associated with
     TA.  */
  extern td_err_e td_ta_get_ph (const td_thragent_t *__ta,
                                struct ps_prochandle **__ph);

  /* Map thread library handle PT to thread debug library handle for process
     associated with TA and store result in *TH.  */
  extern td_err_e td_ta_map_id2thr (const td_thragent_t *__ta, pthread_t __pt,
                                    td_thrhandle_t *__th);

  /* Map process ID LWPID to thread debug library handle for process
     associated with TA and store result in *TH.  */
  extern td_err_e td_ta_map_lwp2thr (const td_thragent_t *__ta,
                                     lwpid_t __lwpid, td_thrhandle_t *__th);

  /* Call for each thread in a process associated with TA the callback
     function CALLBACK.  */
  extern td_err_e td_ta_thr_iter (const td_thragent_t *__ta,
                                  td_thr_iter_f *__callback, void *__cbdata_p,
                                  td_thr_state_e __state, int __ti_pri,
                                  sigset_t *__ti_sigmask_p,
                                  unsigned int __ti_user_flags);

  /* Call for each defined thread local data entry the callback function KI.
   */
  extern td_err_e td_ta_tsd_iter (const td_thragent_t *__ta,
                                  td_key_iter_f *__ki, void *__p);

  /* Get event address for EVENT.  */
  extern td_err_e td_ta_event_addr (const td_thragent_t *__ta,
                                    td_event_e __event, td_notify_t *__ptr);

  /* Enable EVENT in global mask.  */
  extern td_err_e td_ta_set_event (const td_thragent_t *__ta,
                                   td_thr_events_t *__event);

  /* Disable EVENT in global mask.  */
  extern td_err_e td_ta_clear_event (const td_thragent_t *__ta,
                                     td_thr_events_t *__event);

  /* Return information about last event.  */
  extern td_err_e td_ta_event_getmsg (const td_thragent_t *__ta,
                                      td_event_msg_t *__msg);

  /* Set suggested concurrency level for process associated with TA.  */
  extern td_err_e td_ta_setconcurrency (const td_thragent_t *__ta,
                                        int __level);

  /* Enable collecting statistics for process associated with TA.  */
  extern td_err_e td_ta_enable_stats (const td_thragent_t *__ta, int __enable);

  /* Reset statistics.  */
  extern td_err_e td_ta_reset_stats (const td_thragent_t *__ta);

  /* Retrieve statistics from process associated with TA.  */
  extern td_err_e td_ta_get_stats (const td_thragent_t *__ta,
                                   td_ta_stats_t *__statsp);

  /* Validate that TH is a thread handle.  */
  extern td_err_e td_thr_validate (const td_thrhandle_t *__th);

  /* Return information about thread TH.  */
  extern td_err_e td_thr_get_info (const td_thrhandle_t *__th,
                                   td_thrinfo_t *__infop);

  /* Retrieve floating-point register contents of process running thread TH.
   */
  extern td_err_e td_thr_getfpregs (const td_thrhandle_t *__th,
                                    prfpregset_t *__regset);

  /* Retrieve general register contents of process running thread TH.  */
  extern td_err_e td_thr_getgregs (const td_thrhandle_t *__th,
                                   prgregset_t __gregs);

  /* Retrieve extended register contents of process running thread TH.  */
  extern td_err_e td_thr_getxregs (const td_thrhandle_t *__th, void *__xregs);

  /* Get size of extended register set of process running thread TH.  */
  extern td_err_e td_thr_getxregsize (const td_thrhandle_t *__th,
                                      int *__sizep);

  /* Set floating-point register contents of process running thread TH.  */
  extern td_err_e td_thr_setfpregs (const td_thrhandle_t *__th,
                                    const prfpregset_t *__fpregs);

  /* Set general register contents of process running thread TH.  */
  extern td_err_e td_thr_setgregs (const td_thrhandle_t *__th,
                                   prgregset_t __gregs);

  /* Set extended register contents of process running thread TH.  */
  extern td_err_e td_thr_setxregs (const td_thrhandle_t *__th,
                                   const void *__addr);

  /* Get address of the given module's TLS storage area for the given thread.
   */
  extern td_err_e td_thr_tlsbase (const td_thrhandle_t *__th,
                                  unsigned long int __modid, psaddr_t *__base);

  /* Get address of thread local variable.  */
  extern td_err_e td_thr_tls_get_addr (const td_thrhandle_t *__th,
                                       psaddr_t __map_address, size_t __offset,
                                       psaddr_t *__address);

  /* Enable reporting for EVENT for thread TH.  */
  extern td_err_e td_thr_event_enable (const td_thrhandle_t *__th,
                                       int __event);

  /* Enable EVENT for thread TH.  */
  extern td_err_e td_thr_set_event (const td_thrhandle_t *__th,
                                    td_thr_events_t *__event);

  /* Disable EVENT for thread TH.  */
  extern td_err_e td_thr_clear_event (const td_thrhandle_t *__th,
                                      td_thr_events_t *__event);

  /* Get event message for thread TH.  */
  extern td_err_e td_thr_event_getmsg (const td_thrhandle_t *__th,
                                       td_event_msg_t *__msg);

  /* Set priority of thread TH.  */
  extern td_err_e td_thr_setprio (const td_thrhandle_t *__th, int __prio);

  /* Set pending signals for thread TH.  */
  extern td_err_e td_thr_setsigpending (const td_thrhandle_t *__th,
                                        unsigned char __n,
                                        const sigset_t *__ss);

  /* Set signal mask for thread TH.  */
  extern td_err_e td_thr_sigsetmask (const td_thrhandle_t *__th,
                                     const sigset_t *__ss);

  /* Return thread local data associated with key TK in thread TH.  */
  extern td_err_e td_thr_tsd (const td_thrhandle_t *__th,
                              const thread_key_t __tk, void **__data);

  /* Suspend execution of thread TH.  */
  extern td_err_e td_thr_dbsuspend (const td_thrhandle_t *__th);

  /* Resume execution of thread TH.  */
  extern td_err_e td_thr_dbresume (const td_thrhandle_t *__th);

  /* Types of the libthread_db functions.  */

  typedef td_err_e (td_init_ftype) (void);

  typedef td_err_e (td_ta_new_ftype) (struct ps_prochandle *ps,
                                      td_thragent_t **ta);
  typedef td_err_e (td_ta_delete_ftype) (td_thragent_t *ta_p);
  typedef td_err_e (td_ta_map_lwp2thr_ftype) (const td_thragent_t *ta,
                                              lwpid_t lwpid,
                                              td_thrhandle_t *th);
  typedef td_err_e (td_ta_thr_iter_ftype) (const td_thragent_t *ta,
                                           td_thr_iter_f *callback,
                                           void *cbdata_p,
                                           td_thr_state_e state, int ti_pri,
                                           sigset_t *ti_sigmask_p,
                                           unsigned int ti_user_flags);
  typedef td_err_e (td_ta_event_addr_ftype) (const td_thragent_t *ta,
                                             td_event_e event,
                                             td_notify_t *ptr);
  typedef td_err_e (td_ta_set_event_ftype) (const td_thragent_t *ta,
                                            td_thr_events_t *event);
  typedef td_err_e (td_ta_clear_event_ftype) (const td_thragent_t *ta,
                                              td_thr_events_t *event);
  typedef td_err_e (td_ta_event_getmsg_ftype) (const td_thragent_t *ta,
                                               td_event_msg_t *msg);

  typedef td_err_e (td_thr_get_info_ftype) (const td_thrhandle_t *th,
                                            td_thrinfo_t *infop);
  typedef td_err_e (td_thr_event_enable_ftype) (const td_thrhandle_t *th,
                                                int event);

  typedef td_err_e (td_thr_tls_get_addr_ftype) (const td_thrhandle_t *th,
                                                psaddr_t map_address,
                                                size_t offset,
                                                psaddr_t *address);
  typedef td_err_e (td_thr_tlsbase_ftype) (const td_thrhandle_t *th,
                                           unsigned long int modid,
                                           psaddr_t *base);

  typedef const char **(td_symbol_list_ftype)(void);
  typedef td_err_e (td_ta_delete_ftype) (td_thragent_t *);

  typedef td_err_e (td_log_ftype) ();
  typedef td_err_e (td_ta_delete_ftype) (td_thragent_t *ta_p);
  typedef td_err_e (td_init_ftype) (void);
  typedef td_err_e (td_ta_get_ph_ftype) (const td_thragent_t *ta_p,
                                         struct ps_prochandle **ph_pp);
  typedef td_err_e (td_ta_get_nthreads_ftype) (const td_thragent_t *ta_p,
                                               int *nthread_p);
  typedef td_err_e (td_ta_tsd_iter_ftype) (const td_thragent_t *ta_p,
                                           td_key_iter_f *cb, void *cbdata_p);
  typedef td_err_e (td_ta_thr_iter_ftype) (const td_thragent_t *ta_p,
                                           td_thr_iter_f *cb, void *cbdata_p,
                                           td_thr_state_e state, int ti_pri,
                                           sigset_t *ti_sigmask_p,
                                           unsigned ti_user_flags);
  typedef td_err_e (td_thr_validate_ftype) (const td_thrhandle_t *th_p);
  typedef td_err_e (td_thr_tsd_ftype) (const td_thrhandle_t *th_p,
                                       const thread_key_t key, void **data_pp);
  typedef td_err_e (td_thr_get_info_ftype) (const td_thrhandle_t *th_p,
                                            td_thrinfo_t *ti_p);
  typedef td_err_e (td_thr_getfpregs_ftype) (const td_thrhandle_t *th_p,
                                             prfpregset_t *fpregset);
  typedef td_err_e (td_thr_getxregsize_ftype) (const td_thrhandle_t *th_p,
                                               int *xregsize);
  typedef td_err_e (td_thr_getxregs_ftype) (const td_thrhandle_t *th_p,
                                            const caddr_t xregset);
  typedef td_err_e (td_thr_sigsetmask_ftype) (const td_thrhandle_t *th_p,
                                              const sigset_t *ti_sigmask);
  typedef td_err_e (td_thr_setprio_ftype) (const td_thrhandle_t *th_p,
                                           const int ti_pri);
  typedef td_err_e (td_thr_setsigpending_ftype) (
      const td_thrhandle_t *th_p, const unsigned char ti_pending_flag,
      const sigset_t *ti_pending);
  typedef td_err_e (td_thr_setfpregs_ftype) (const td_thrhandle_t *th_p,
                                             const prfpregset_t *fpregset);
  typedef td_err_e (td_thr_setxregs_ftype) (const td_thrhandle_t *th_p,
                                            const void *xregset);
  typedef td_err_e (td_ta_map_id2thr_ftype) (const td_thragent_t *ta_p,
                                             thread_t tid,
                                             td_thrhandle_t *th_p);
  typedef td_err_e (td_ta_map_lwp2thr_ftype) (const td_thragent_t *ta_p,
                                              lwpid_t lwpid,
                                              td_thrhandle_t *th_p);
  typedef td_err_e (td_thr_getgregs_ftype) (const td_thrhandle_t *th_p,
                                            prgregset_t regset);
  typedef td_err_e (td_thr_setgregs_ftype) (const td_thrhandle_t *th_p,
                                            const prgregset_t regset);
  typedef td_err_e (td_ta_enable_stats_ftype) (const td_thragent_t *__ta,
                                               int __enable);
  typedef td_err_e (td_ta_reset_stats_ftype) (const td_thragent_t *__ta);
  typedef td_err_e (td_ta_get_stats_ftype) (const td_thragent_t *__ta,
                                            td_ta_stats_t *__statsp);
  typedef td_err_e (td_ta_setconcurrency_ftype) (const td_thragent_t *__ta,
                                                 int __level);
  typedef td_err_e (td_thr_clear_event_ftype) (const td_thrhandle_t *__th,
                                               td_thr_events_t *__event);
  typedef td_err_e (td_thr_dbresume_ftype) (const td_thrhandle_t *__th);
  typedef td_err_e (td_thr_dbsuspend_ftype) (const td_thrhandle_t *__th);
  typedef td_err_e (td_thr_event_getmsg_ftype) (const td_thrhandle_t *__th,
                                                td_event_msg_t *__msg);
  typedef td_err_e (td_thr_set_event_ftype) (const td_thrhandle_t *__th,
                                             td_thr_events_t *__event);

  typedef struct thread_db_userspace_threads_state_t
  {
    unsigned last_monotonic_count;
    thread_db_userspace_threads_t *current;
    uintptr_t th_unique_base;
    struct hsearch_data lwp2thr;
    char *lwp2thr_keys;
  } thread_db_userspace_threads_state_t;

  extern thread_db_userspace_threads_state_t
      current_thread_db_userspace_threads;

  static inline const userspace_thread_db_userspace_thread_info_t *
  get_thread_db_userspace_thread_info (size_t idx)
  {
    thread_db_userspace_threads_t *current
        = current_thread_db_userspace_threads.current;
    assert (idx < current->length);
    userspace_thread_db_userspace_thread_info_slot_t v;
    v.null_ptr = current->infos[idx];
    if (v.lwp.is_lwp || v.null_ptr == NULL)
      {
        return NULL;
      }
    return &((userspace_thread_db_userspace_thread_info_t *)&current
                 ->infos[current->max_length])[idx];
  }

  static inline psaddr_t
  th_unique_from_thread_db_userspace_threads_idx (size_t idx)
  {
    thread_db_userspace_threads_t *current
        = current_thread_db_userspace_threads.current;
    assert (idx < current->length);
    userspace_thread_db_userspace_thread_info_t *ti
        = &((userspace_thread_db_userspace_thread_info_t *)&current
                ->infos[current->max_length])[idx];
    return (psaddr_t)(current_thread_db_userspace_threads.th_unique_base
                      + (idx << 5) + ti->salt);
  }

  static inline size_t
  thread_db_userspace_threads_idx_from_th_unique (psaddr_t th_unique)
  {
    const size_t idx
        = (size_t)((uintptr_t)th_unique
                   - current_thread_db_userspace_threads.th_unique_base)
          >> 5;
    thread_db_userspace_threads_t *current
        = current_thread_db_userspace_threads.current;
    if (current == NULL || idx >= current->max_length)
      {
        return (size_t)-1;
      }
    return idx;
  }

  /* Safely read the latest snapshot of thread_db_userspace_threads_t from
  the inferior */
  static inline ps_err_e
  thread_db_userspace_threads_read_current_thread_db_userspace_threads (
      struct ps_prochandle *ph, psaddr_t _thread_db_userspace_threads_addr)
  {
    psaddr_t thread_db_userspace_threads = NULL;
    if (current_thread_db_userspace_threads.th_unique_base == 0)
      {
        /* We need a base address for the th_unique values we return which
         * could not possibly ever be close to those returned by the
         * libthread_db.so beneath us. We used to use
         * &current_thread_db_userspace_threads, but if the id gets big
         * enough it'll extend past the end of this shared object and that
         * could land within a memory allocation done by the inferior
         * libthread_db.so (thankfully this actually turned up in testing).
         *
         * I am unsure how initialised glibc is at this point, so let's XOR
         * with the current monotonic count.
         */
        union ptr_integer
        {
          void *ptr;
          uintptr_t integer;
        } a, b;
        a.ptr = (void *)&current_thread_db_userspace_threads;
        struct timespec ts;
        clock_gettime (CLOCK_MONOTONIC, &ts);
        b.integer = (uintptr_t)(ts.tv_sec * 1000000000ULL + ts.tv_nsec);
        current_thread_db_userspace_threads.th_unique_base
            = a.integer ^ b.integer;
      }
    for (;;)
      {
        // Read [0]
        ps_err_e err = ps_pdread (ph, _thread_db_userspace_threads_addr,
                                  &thread_db_userspace_threads,
                                  sizeof (thread_db_userspace_threads));
        if (err != PS_OK)
          {
            return err;
          }
        if (thread_db_userspace_threads == NULL)
          {
            current_thread_db_userspace_threads.last_monotonic_count = 0;
            current_thread_db_userspace_threads.current = NULL;
            return PS_OK;
          }
        // Read the header at the beginning
        alignas (thread_db_userspace_threads_t) char
            header_storage[sizeof (thread_db_userspace_threads_t)];
        memset (header_storage, 0, sizeof (header_storage));
        thread_db_userspace_threads_t *header
            = (thread_db_userspace_threads_t *)header_storage;
        err = ps_pdread (ph, thread_db_userspace_threads, header,
                         sizeof (thread_db_userspace_threads_t));
        if (err != PS_OK)
          {
            return err;
          }
        if (header->monotonic_count
            == current_thread_db_userspace_threads.last_monotonic_count)
          {
            // nothing has changed
            return PS_OK;
          }
        thread_db_userspace_threads_t *storage
            = (thread_db_userspace_threads_t *)malloc (header->total_bytes);
        if (storage == NULL)
          {
            return PS_ERR;
          }
        err = ps_pdread (ph, thread_db_userspace_threads, storage,
                         header->total_bytes);
        if (err != PS_OK)
          {
            return err;
          }
        if (storage->total_bytes != header->total_bytes)
          {
            // It changed during the read
            free (storage);
            continue;
          }
        // Fix up the pointers
        if (current_thread_db_userspace_threads.current != NULL)
          {
            free (current_thread_db_userspace_threads.current);
            hdestroy_r (&current_thread_db_userspace_threads.lwp2thr);
            free (current_thread_db_userspace_threads.lwp2thr_keys);
            current_thread_db_userspace_threads.current = NULL;
          }
        memset (&current_thread_db_userspace_threads.lwp2thr, 0,
                sizeof (current_thread_db_userspace_threads.lwp2thr));
        if (0
            == hcreate_r (storage->length,
                          &current_thread_db_userspace_threads.lwp2thr))
          {
            return PS_ERR;
          }
        current_thread_db_userspace_threads.lwp2thr_keys
            = (char *)calloc (storage->length, 4);
        if (current_thread_db_userspace_threads.lwp2thr_keys == NULL)
          {
            hdestroy_r (&current_thread_db_userspace_threads.lwp2thr);
            return PS_ERR;
          }
        current_thread_db_userspace_threads.current = storage;
        current_thread_db_userspace_threads.last_monotonic_count = 0;
        char *lwp2thr_keys_p
            = current_thread_db_userspace_threads.lwp2thr_keys;
        for (size_t n = 0; n < storage->length; n++)
          {
            userspace_thread_db_userspace_thread_info_slot_t v;
            v.null_ptr = storage->infos[n];
            if (v.all_bits_set == (uintptr_t)-1 || v.null_ptr == NULL)
              {
                continue;
              }
            if (v.lwp.is_lwp)
              {
                ENTRY e;
                e.data = th_unique_from_thread_db_userspace_threads_idx (n);
                e.key = lwp2thr_keys_p;
                lwp2thr_keys_p[0] = (char)((((unsigned)v.lwp.id) >> 0) & 0xff);
                lwp2thr_keys_p[1] = (char)((((unsigned)v.lwp.id) >> 8) & 0xff);
                lwp2thr_keys_p[2]
                    = (char)((((unsigned)v.lwp.id) >> 16) & 0xff);
                lwp2thr_keys_p[3] = 0;
                ENTRY *o;
                if (0
                    == hsearch_r (
                        e, ENTER, &o,
                        &current_thread_db_userspace_threads.lwp2thr))
                  {
                    return PS_ERR;
                  }
                lwp2thr_keys_p += 4;
                continue;
              }
            storage->infos[n] = (void *)(&(
                (userspace_thread_db_userspace_thread_info_t *)&storage
                    ->infos[storage->max_length])[n]);
          }
        current_thread_db_userspace_threads.last_monotonic_count
            = header->monotonic_count;
        return PS_OK;
      }
  }

  /* Implementation of `td_ta_map_lwp2thr()`. Requires
  `thread_db_userspace_threads_read_current_thread_db_userspace_threads()` to
  have been called recently.
  */
  static inline td_err_e
  thread_db_userspace_threads_td_ta_map_lwp2thr (
      td_ta_map_lwp2thr_ftype *td_ta_map_lwp2thr_orig,
      td_thragent_t const *ta_p, lwpid_t lwpid, td_thrhandle_t *th_p)
  {
    if (current_thread_db_userspace_threads.current != NULL)
      {
        char keystr[4];
        keystr[0] = (char)((((unsigned)lwpid) >> 0) & 0xff);
        keystr[1] = (char)((((unsigned)lwpid) >> 8) & 0xff);
        keystr[2] = (char)((((unsigned)lwpid) >> 16) & 0xff);
        keystr[3] = 0;
        ENTRY key, *value = NULL;
        key.key = keystr;
        key.data = NULL;
        if (0
            != hsearch_r (key, FIND, &value,
                          &current_thread_db_userspace_threads.lwp2thr))
          {
            th_p->th_ta_p = (td_thragent_t *)ta_p;
            th_p->th_unique = value->data;
            return TD_OK;
          }
      }
    return td_ta_map_lwp2thr_orig (ta_p, lwpid, th_p);
  }

  /* Implementation of `td_ta_thr_iter()`. Requires
  `thread_db_userspace_threads_read_current_thread_db_userspace_threads()` to
  have been called recently.
  */
  static inline td_err_e
  thread_db_userspace_threads_td_ta_thr_iter (
      td_ta_thr_iter_ftype *td_ta_thr_iter_orig, td_thragent_t const *ta_p,
      td_thr_iter_f *cb, void *cbdata_p, td_thr_state_e state, int ti_pri,
      sigset_t *ti_sigmask_p, unsigned ti_user_flags)
  {
    if (current_thread_db_userspace_threads.current != NULL)
      {
        if (state == TD_THR_ANY_STATE || state == TD_THR_RUN)
          {
            struct td_thrhandle th;
            for (size_t n = 0;
                 n < current_thread_db_userspace_threads.current->length; n++)
              {
                userspace_thread_db_userspace_thread_info_slot_t v;
                v.null_ptr
                    = current_thread_db_userspace_threads.current->infos[n];
                if (v.null_ptr == (void *)(uintptr_t)-1 || v.null_ptr == NULL)
                  {
                    continue;
                  }
                th.th_ta_p = (td_thragent_t *)ta_p;
                th.th_unique
                    = th_unique_from_thread_db_userspace_threads_idx (n);
                if (cb (&th, cbdata_p) != 0)
                  {
                    return TD_DBERR;
                  }
              }
          }
      }
    return td_ta_thr_iter_orig (ta_p, cb, cbdata_p, state, ti_pri,
                                ti_sigmask_p, ti_user_flags);
  }

  /* Implementation of `td_thr_get_info()`. Requires
  `thread_db_userspace_threads_read_current_thread_db_userspace_threads()` to
  have been called recently.
  */
  static inline td_err_e
  thread_db_userspace_threads_td_thr_get_info (
      td_thr_get_info_ftype *td_thr_get_info_orig,
      td_ta_map_lwp2thr_ftype *td_ta_map_lwp2thr_orig,
      td_thrhandle_t const *th_p, td_thrinfo_t *ti_p)
  {
    const size_t idx
        = thread_db_userspace_threads_idx_from_th_unique (th_p->th_unique);
    userspace_thread_db_userspace_thread_info_slot_t v;
    bool userspace_thread_is_currently_running = false;
    td_thrhandle_t th_copy;
    memcpy (&th_copy, th_p, sizeof (td_thrhandle_t));
    if (current_thread_db_userspace_threads.current != NULL
        && idx < current_thread_db_userspace_threads.current->max_length)
      {
        v.null_ptr = current_thread_db_userspace_threads.current->infos[idx];
        if (idx >= current_thread_db_userspace_threads.current->length
            || v.all_bits_set == (uintptr_t)-1)
          {
            return TD_NOTHR;
          }
        if (v.null_ptr == NULL)
          {
            return TD_ERR;
          }
        if (!v.lwp.is_lwp)
          {
            memset (ti_p, 0, sizeof (td_thrinfo_t));
            ti_p->ti_ta_p = th_p->th_ta_p;
            ti_p->ti_tid = (pthread_t)th_p->th_unique;
            ti_p->ti_startfunc = (psaddr_t)v.thread_info->startfunc;
            ti_p->ti_stkbase = v.thread_info->stack_sp;
            ti_p->ti_stksize = v.thread_info->stack_size;
            ti_p->ti_state = TD_THR_RUN;
            ti_p->ti_type = TD_THR_USER;
            ti_p->ti_pc = v.thread_info->suspended_pc;
            ti_p->ti_sp = v.thread_info->suspended_sp;
            ti_p->ti_lid = v.thread_info->lwp_id;
            return TD_OK;
          }
        userspace_thread_is_currently_running = true;
        td_err_e e
            = td_ta_map_lwp2thr_orig (th_copy.th_ta_p, v.lwp.id, &th_copy);
        if (e != TD_OK)
          {
            return e;
          }
      }
    td_err_e ret = td_thr_get_info_orig (&th_copy, ti_p);
    if (ret == TD_OK)
      {
        if (userspace_thread_is_currently_running)
          {
            ti_p->ti_tid = (pthread_t)th_p->th_unique;
            ti_p->ti_type = TD_THR_USER;
          }
        else
          {
            // All kernel threads shall have type TD_THR_SYSTEM, NPTL always
            // returns TD_THR_USER.
            if (ti_p->ti_type == TD_THR_USER)
              {
                ti_p->ti_type = TD_THR_SYSTEM;
              }
          }
      }
    return ret;
  }

  /* Implementation of `td_thr_getgregs()`. Requires
  `thread_db_userspace_threads_read_current_thread_db_userspace_threads()` to
  have been called recently.
  */
  static inline td_err_e
  thread_db_userspace_threads_td_thr_getgregs (
      td_thr_getgregs_ftype *td_thr_getgregs_orig, td_thrhandle_t const *th_p,
      prgregset_t gregs)
  {
    const size_t idx
        = thread_db_userspace_threads_idx_from_th_unique (th_p->th_unique);
    userspace_thread_db_userspace_thread_info_slot_t v;
    td_thrhandle_t th_copy;
    memcpy (&th_copy, th_p, sizeof (td_thrhandle_t));
    if (current_thread_db_userspace_threads.current != NULL
        && idx < current_thread_db_userspace_threads.current->max_length)
      {
        v.null_ptr = current_thread_db_userspace_threads.current->infos[idx];
        if (idx >= current_thread_db_userspace_threads.current->length
            || v.all_bits_set == (uintptr_t)-1)
          {
            return TD_NOTHR;
          }
        if (v.null_ptr == NULL)
          {
            return TD_ERR;
          }
        memset (gregs, 0, sizeof (prgregset_t));
        if (!v.lwp.is_lwp)
          {
#if defined(__aarch64__)
            struct user_regs_struct *ur = (struct user_regs_struct *)gregs;
            ur->regs[29] = v.thread_info->suspended_fp;
            ur->sp = v.thread_info->suspended_sp;
            ur->pc = v.thread_info->suspended_pc;
#elif defined(__x86_64__)
          /* This bit definitely needs a comment :)

             Firstly here are the x64 registers in order as according to
             instruction bit encoding:

             rax [0], rcx [1], rdx [2], rbx [3], rsp [4], rbp [5], rsi [6],
             rdi [7], r8-15; rip [16]

             ucontext's x64 gregset_t goes in this order:

             r8-r15, rdi [8], rsi [9], rbp [10], rbx [11], rdx [12], rax
             [13], rcx [14], rsp [15]; rip [16]

             As to _why_ it is this order, who knows. It seems mainly in
             reverse order, but with rsp hoisted out to the end.

             ptrace's user_regs_struct from <sys/user.h> on x64 has this
             order:

             r15-r12, rbp [4], rbx [5], r11-r8, rax [10], rcx [11], rdx [12],
             rsi [13], rdi [14], orig_rax; rip [16]


             GDB's supply_gregset() appears to do this mapping:

             0 => 10 (rax)
             1 => 5 (rbx)
             2 => 11 (rcx)
             3 => 12 (rdx)
             4 => 13 (rsi)
             5 => 14 (rdi)
             6 => 4 (rbp)
             7 => 19
             8 => 9 (r8)
             9 => 8 (r9)
             10 => 7 (r10)
             11 => 6 (r11)
             12 => 3 (r12)
             13 => 2 (r13)
             14 => 1 (r14)
             15 => 0 (r15)
             16 => 16 (rip)
             17 => 18
             18 => 17
             19 => 20

             Missing: rsp. Weirdly, this looks like alphabetical order is the
             native GDB ordering.

             When retrieving where a thread is at, GDB fetches [16] first
             (pc), then [6] which I think should be rbp.

             <sys/reg.h> defines macro RBP as 4, that would "do the right
             thing" for supply_gregset(), so let's use those.
          */
          gregs[RBP] = v.thread_info->suspended_fp;
          gregs[RSP] = v.thread_info->suspended_sp;
          gregs[RIP] = v.thread_info->suspended_pc;
#endif
            return TD_OK;
          }
        // Caller needs to use the LWP as it's running this right now
        return TD_PARTIALREG;
      }
    return td_thr_getgregs_orig (th_p, gregs);
  }

#ifdef __cplusplus
}
#endif

#endif /* LINUX_THREAD_DB_USER_THREADS_AM_LIBTHREAD_DB */

#endif
