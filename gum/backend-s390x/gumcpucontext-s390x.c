/*
 * Copyright (C) 2014-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdefs.h"

gpointer
gum_cpu_context_get_nth_argument (GumCpuContext * self,
                                  guint n)
{
  if (n < 5)
  {
    return (gpointer) self->gprs[2 + n];
  }
  else
  {
    gpointer * stack_arguments = (gpointer *) (self->gprs[15] + 160);

    return stack_arguments[n - 5];
  }

  return NULL;
}

void
gum_cpu_context_replace_nth_argument (GumCpuContext * self,
                                      guint n,
                                      gpointer value)
{
  if (n < 5)
  {
    self->gprs[2 + n] = (guint64) value;
  }
  else
  {
    gpointer * stack_arguments = (gpointer *) (self->gprs[15] + 160);

    stack_arguments[n - 5] = value;
  }
}

gpointer
gum_cpu_context_get_return_value (GumCpuContext * self)
{
  return (gpointer) self->gprs[2];
}

void
gum_cpu_context_replace_return_value (GumCpuContext * self,
                                      gpointer value)
{
  self->gprs[2] = GPOINTER_TO_SIZE (value);
}
