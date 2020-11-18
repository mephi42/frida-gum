/*
 * Copyright (C) 2014-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_S390X_RELOCATOR_H__
#define __GUN_S390X_RELOCATOR_H__

#include "gums390xwriter.h"

#include <capstone.h>

G_BEGIN_DECLS

typedef struct _GumS390xRelocator GumS390xRelocator;

struct _GumS390xRelocator
{
  volatile gint ref_count;

  csh capstone;

  const guint8 * input_start;
  const guint8 * input_cur;
  cs_insn ** input_insns;
  GumS390xWriter * output;

  guint inpos;
  guint outpos;

  gboolean eob;
  gboolean eoi;
};

GUM_API GumS390xRelocator * gum_s390x_relocator_new (gconstpointer input_code,
    GumS390xWriter * output);
GUM_API GumS390xRelocator * gum_s390x_relocator_ref (
    GumS390xRelocator * relocator);
GUM_API void gum_s390x_relocator_unref (GumS390xRelocator * relocator);

GUM_API void gum_s390x_relocator_init (GumS390xRelocator * relocator,
    gconstpointer input_code, GumS390xWriter * output);
GUM_API void gum_s390x_relocator_clear (GumS390xRelocator * relocator);

GUM_API void gum_s390x_relocator_reset (GumS390xRelocator * relocator,
    gconstpointer input_code, GumS390xWriter * output);

GUM_API guint gum_s390x_relocator_read_one (GumS390xRelocator * self,
    const cs_insn ** instruction);

GUM_API gboolean gum_s390x_relocator_write_one (GumS390xRelocator * self);
GUM_API void gum_s390x_relocator_write_all (GumS390xRelocator * self);

GUM_API gboolean gum_s390x_relocator_eob (GumS390xRelocator * self);
GUM_API gboolean gum_s390x_relocator_eoi (GumS390xRelocator * self);

GUM_API gboolean gum_s390x_relocator_can_relocate (gpointer address,
    guint min_bytes, guint * maximum);

G_END_DECLS

#endif
