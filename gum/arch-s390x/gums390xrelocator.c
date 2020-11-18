/*
 * Copyright (C) 2014-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gums390xrelocator.h"

#include "gumlibc.h"
#include "gummemory.h"

#define GUM_MAX_INPUT_INSN_COUNT 100

GumS390xRelocator *
gum_s390x_relocator_new (gconstpointer input_code, GumS390xWriter * output)
{
  GumS390xRelocator * relocator;

  relocator = g_slice_new (GumS390xRelocator);

  gum_s390x_relocator_init (relocator, input_code, output);

  return relocator;
}

GumS390xRelocator *
gum_s390x_relocator_ref (GumS390xRelocator * relocator)
{
  g_atomic_int_inc (&relocator->ref_count);

  return relocator;
}

void
gum_s390x_relocator_unref (GumS390xRelocator * relocator)
{
  if (g_atomic_int_dec_and_test (&relocator->ref_count))
  {
    gum_s390x_relocator_clear (relocator);

    g_slice_free (GumS390xRelocator, relocator);
  }
}

void
gum_s390x_relocator_init (GumS390xRelocator * relocator,
    gconstpointer input_code, GumS390xWriter * output)
{
  relocator->ref_count = 1;

  cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &relocator->capstone);
  cs_option (relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  relocator->input_insns = g_new0 (cs_insn *, GUM_MAX_INPUT_INSN_COUNT);

  relocator->output = NULL;

  gum_s390x_relocator_reset (relocator, input_code, output);
}

void
gum_s390x_relocator_clear (GumS390xRelocator * relocator)
{
  guint i;

  gum_s390x_relocator_reset (relocator, NULL, NULL);

  for (i = 0; i != GUM_MAX_INPUT_INSN_COUNT; i++)
  {
    cs_insn * insn = relocator->input_insns[i];
    if (insn != NULL)
    {
      cs_free (insn, 1);
      relocator->input_insns[i] = NULL;
    }
  }
  g_free (relocator->input_insns);

  cs_close (&relocator->capstone);
}

void
gum_s390x_relocator_reset (GumS390xRelocator * relocator,
                           gconstpointer input_code,
                           GumS390xWriter * output)
{
  relocator->input_start = input_code;
  relocator->input_cur = input_code;

  if (output != NULL)
    gum_s390x_writer_ref (output);
  if (relocator->output != NULL)
    gum_s390x_writer_unref (relocator->output);
  relocator->output = output;

  relocator->inpos = 0;
  relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

static guint
gum_s390x_relocator_inpos (GumS390xRelocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_s390x_relocator_outpos (GumS390xRelocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_s390x_relocator_increment_inpos (GumS390xRelocator * self)
{
  self->inpos++;
  g_assert (self->inpos > self->outpos);
}

static void
gum_s390x_relocator_increment_outpos (GumS390xRelocator * self)
{
  self->outpos++;
  g_assert (self->outpos <= self->inpos);
}

guint
gum_s390x_relocator_read_one (GumS390xRelocator * self,
    const cs_insn ** instruction)
{
  cs_insn ** insn_ptr, * insn;
  const uint8_t * code;
  size_t size;
  uint64_t address;

  if (self->eoi)
    return 0;

  insn_ptr = &self->input_insns[gum_s390x_relocator_inpos (self)];

  if (*insn_ptr == NULL)
    *insn_ptr = cs_malloc (self->capstone);

  code = self->input_cur;
  size = GUM_S390X_MAX_INSN_SIZE;
  address = GPOINTER_TO_SIZE (self->input_cur);
  insn = *insn_ptr;

  if (!cs_disasm_iter (self->capstone, &code, &size, &address, insn))
    return 0;

  switch (insn->id)
  {
    case SYSZ_INS_STMG:
    case SYSZ_INS_LGR:
    case SYSZ_INS_LGRL:
    case SYSZ_INS_LHI:
      break;
    case SYSZ_INS_CGIJE:
      self->eob = TRUE;
      break;
    default:
      return 0;
  }

  gum_s390x_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur += insn->size;

  return self->input_cur - self->input_start;
}

cs_insn *
gum_s390x_relocator_peek_next_write_insn (GumS390xRelocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return self->input_insns[gum_s390x_relocator_outpos (self)];
}

gboolean
gum_s390x_relocator_write_one (GumS390xRelocator * self)
{
  cs_insn * cur;
  guint8 relocated[6];
  gint16 * ri4 = (gint16 *) &relocated[2];
  GumAddress target;

  if ((cur = gum_s390x_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_s390x_relocator_increment_outpos (self);

  switch (cur->id)
  {
    case SYSZ_INS_STMG:
    case SYSZ_INS_LGR:
    case SYSZ_INS_LHI:
      gum_s390x_writer_put_bytes (self->output, (const guint8 *) cur->address,
          cur->size);
      break;
    case SYSZ_INS_CGIJE:
      gum_memcpy (relocated, (const guint8 *) cur->address, 6);
      target = cur->address + (*ri4 << 1);
      relocated[1] ^= 0x0f;
      *ri4 = 6;
      gum_s390x_writer_put_bytes (self->output, relocated, 6);
      gum_s390x_writer_put_brcl (self->output, 15, target);
      break;
    case SYSZ_INS_LGRL:
      gum_memcpy (relocated, (const guint8 *) cur->address, 6);
      *(gint32 *) &relocated[2] += (cur->address - self->output->pc) >> 1;
      gum_s390x_writer_put_bytes (self->output, relocated, 6);
      break;
    default:
      return FALSE;
  }

  return TRUE;
}

void
gum_s390x_relocator_write_all (GumS390xRelocator * self)
{
  guint count = 0;

  while (gum_s390x_relocator_write_one (self))
    count++;

  g_assert (count > 0);
}

gboolean
gum_s390x_relocator_eob (GumS390xRelocator * self)
{
  return self->eob;
}

gboolean
gum_s390x_relocator_eoi (GumS390xRelocator * self)
{
  return self->eoi;
}

gboolean
gum_s390x_relocator_can_relocate (gpointer address, guint min_bytes,
    guint * maximum)
{
  guint n = 0;
  guint8 * buf;
  GumS390xWriter cw;
  GumS390xRelocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_s390x_writer_init (&cw, buf);

  gum_s390x_relocator_init (&rl, address, &cw);

  do
  {
    reloc_bytes = gum_s390x_relocator_read_one (&rl, NULL);
    if (reloc_bytes == 0)
      break;

    n = reloc_bytes;
  }
  while (reloc_bytes < min_bytes);

  gum_s390x_relocator_clear (&rl);

  gum_s390x_writer_clear (&cw);

  if (maximum != NULL)
    *maximum = n;

  return n >= min_bytes;
}
