/* This testcase is part of GDB, the GNU debugger.

   Copyright 2011-2024 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#define _GNU_SOURCE 1

#include <ucontext.h>

#include "../../linux-thread-db-user-threads.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* How we tell libthread_db about our userspace threads */
LINUX_THREAD_DB_USER_THREADS_ATOMIC (thread_db_userspace_threads_t *)
_thread_db_userspace_threads[4];

static char _thread_db_userspace_threads_storage[4096];

static void
user_thread (size_t my_id, ucontext_t *self, ucontext_t *main)
{
  set_thread_db_userspace_thread_running_nonlocking (my_id, gettid ());
  /* break here 2 */
  for (size_t n = 0;; n++)
    {
      printf ("I am the user thread count = %zu.\n", n);
      swapcontext (self, main);
      set_thread_db_userspace_thread_running_nonlocking (my_id, gettid ());
    }
}

int
main (void)
{
  {
    void *mem = (void *)_thread_db_userspace_threads_storage;
    size_t bytes = sizeof (_thread_db_userspace_threads_storage);

    if (!expand_thread_db_userspace_threads (&mem, &bytes))
      {
        abort ();
      }
    printf ("_thread_db_userspace_threads[0] = %p\n",
            _thread_db_userspace_threads[0]);
  }

  ucontext_t ctx, main_;
  memset (&ctx, 0, sizeof (ctx));
  getcontext (&ctx);

  char *stack = aligned_alloc (16, 4096);
  ctx.uc_stack.ss_sp = (stack + 4096);
  ctx.uc_stack.ss_size = 4096;
  size_t thread_id = allocate_thread_db_userspace_thread_index ();
  makecontext (&ctx, (void (*) (void))user_thread, 3, thread_id, &ctx, &main_);
  userspace_thread_db_userspace_thread_info_t *ti
      = get_thread_db_userspace_thread_info (thread_id);
  ti->startfunc = (void (*) ())user_thread;
  ti->lwp_id = gettid ();
  userspace_thread_set_from_ucontext (ti, &ctx);
  set_thread_db_userspace_thread_suspended_nonlocking (thread_id, ti);
  /* break here 1 */
  printf ("I am the main thread count = 0\n");
  swapcontext (&main_, &ctx);
  userspace_thread_set_from_ucontext (ti, &ctx);
  set_thread_db_userspace_thread_suspended_nonlocking (thread_id, ti);
  /* break here 3 */
  printf ("I am the main thread count = 1\n");
  swapcontext (&main_, &ctx);
  userspace_thread_set_from_ucontext (ti, &ctx);
  set_thread_db_userspace_thread_suspended_nonlocking (thread_id, ti);
  /* break here 4 */
  deallocate_thread_db_userspace_thread_index (thread_id);
  thread_id = allocate_thread_db_userspace_thread_index ();
  ti = get_thread_db_userspace_thread_info (thread_id);
  ti->startfunc = (void (*) ())user_thread;
  ti->lwp_id = gettid ();
  userspace_thread_set_from_ucontext (ti, &ctx);
  set_thread_db_userspace_thread_suspended_nonlocking (thread_id, ti);
  printf ("I am the main thread count = 2\n");
  swapcontext (&main_, &ctx);
  userspace_thread_set_from_ucontext (ti, &ctx);
  set_thread_db_userspace_thread_suspended_nonlocking (thread_id, ti);
  /* break here 5 */
  deallocate_thread_db_userspace_thread_index (thread_id);
  free (stack);
  /* break here 6 */

  printf ("Exiting.\n");
  return 0;
}
