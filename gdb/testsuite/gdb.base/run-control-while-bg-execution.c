/* This testcase is part of GDB, the GNU debugger.

   Copyright 2020-2022 Free Software Foundation, Inc.

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
					       //
#include <unistd.h>

static pid_t mypid = -1;

static void
after_getpid (void)
{
}

int
main (void)
{
  mypid = getpid ();
  after_getpid ();
  sleep (30);
}
