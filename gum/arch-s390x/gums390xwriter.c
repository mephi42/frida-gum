/*
 * Copyright (C) 2014-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gums390xwriter.h"

#include "gumlibc.h"
#include "gummemory.h"

GumS390xWriter *
gum_s390x_writer_new (gpointer code_address)
{
  GumS390xWriter * writer;

  writer = g_slice_new (GumS390xWriter);

  gum_s390x_writer_init (writer, code_address);

  return writer;
}

GumS390xWriter *
gum_s390x_writer_ref (GumS390xWriter * writer)
{
  g_atomic_int_inc (&writer->ref_count);

  return writer;
}

void
gum_s390x_writer_unref (GumS390xWriter * writer)
{
  if (g_atomic_int_dec_and_test (&writer->ref_count))
  {
    gum_s390x_writer_clear (writer);

    g_slice_free (GumS390xWriter, writer);
  }
}

void
gum_s390x_writer_init (GumS390xWriter * writer, gpointer code_address)
{
  writer->ref_count = 1;

  gum_s390x_writer_reset (writer, code_address);
}

void
gum_s390x_writer_clear (GumS390xWriter * writer)
{
  gum_s390x_writer_flush (writer);
}

void
gum_s390x_writer_reset (GumS390xWriter * writer, gpointer code_address)
{
  writer->base = code_address;
  writer->code = code_address;
  writer->pc = GUM_ADDRESS (code_address);
}

gpointer
gum_s390x_writer_cur (GumS390xWriter * self)
{
  return self->code;
}

guint
gum_s390x_writer_offset (GumS390xWriter * self)
{
  return (guint) (self->code - self->base);
}

static void
gum_s390x_writer_commit (GumS390xWriter * self, guint n)
{
  self->code += n;
  self->pc += n;
}


void
gum_s390x_writer_skip (GumS390xWriter * self, guint n_bytes)
{
  gum_s390x_writer_commit (self, n_bytes);
}

gboolean
gum_s390x_writer_flush (GumS390xWriter * self)
{
  return TRUE;
}

void
gum_s390x_writer_put_basr (GumS390xWriter * self, sysz_reg r1, sysz_reg r2)
{
  self->code[0] = 0x0D;
  self->code[1] = ((r1 - SYSZ_REG_0) << 4) | (r2 - SYSZ_REG_0);
  gum_s390x_writer_commit (self, 2);
}

void
gum_s390x_writer_put_bcr (GumS390xWriter * self, guint8 m1, sysz_reg r2)
{
  self->code[0] = 0x07;
  self->code[1] = (m1 << 4) | (r2 - SYSZ_REG_0);
  gum_s390x_writer_commit (self, 2);
}

void
gum_s390x_writer_put_brasl (GumS390xWriter * self, sysz_reg r1,
    GumAddress ri2)
{
  self->code[0] = 0xC0;
  self->code[1] = ((r1 - SYSZ_REG_0) << 4) | 0x5;
  *(guint32 *) &self->code[2] = (ri2 - self->pc) >> 1;
  gum_s390x_writer_commit (self, 6);
}

void
gum_s390x_writer_put_brcl (GumS390xWriter * self, guint8 m1, GumAddress ri2)
{
  self->code[0] = 0xC0;
  self->code[1] = (m1 << 4) | 0x4;
  *(guint32 *) &self->code[2] = (ri2 - self->pc) >> 1;
  gum_s390x_writer_commit (self, 6);
}

void
gum_s390x_writer_put_cg (GumS390xWriter * self, sysz_reg r1, gint32 d2,
    sysz_reg x2, sysz_reg b2)
{
  self->code[0] = 0xE3;
  self->code[1] = ((r1 - SYSZ_REG_0) << 4) | (x2 - SYSZ_REG_0);
  self->code[2] = ((b2 - SYSZ_REG_0) << 4) | ((d2 >> 8) & 0xf);
  self->code[3] = d2 & 0xff;
  self->code[4] = (d2 >> 12) & 0xff;
  self->code[5] = 0x20;
  gum_s390x_writer_commit (self, 6);
}

void
gum_s390x_writer_put_ipm (GumS390xWriter * self, sysz_reg r1)
{
  self->code[0] = 0xB2;
  self->code[1] = 0x22;
  self->code[2] = 0x00;
  self->code[3] = (r1 - SYSZ_REG_0) << 4;
  gum_s390x_writer_commit (self, 4);
}

void
gum_s390x_writer_put_la (GumS390xWriter * self, sysz_reg r1, guint16 d2,
    sysz_reg x2, sysz_reg b2)
{
  self->code[0] = 0x41;
  self->code[1] = ((r1 - SYSZ_REG_0) << 4) | (x2 - SYSZ_REG_0);
  self->code[2] = ((b2 - SYSZ_REG_0) << 4) | ((d2 >> 8) & 0xf);
  self->code[3] = d2 & 0xff;
  gum_s390x_writer_commit (self, 4);
}

void
gum_s390x_writer_put_larl (GumS390xWriter * self, sysz_reg r1,
    GumAddress ri2)
{
  self->code[0] = 0xC0;
  self->code[1] = (r1 - SYSZ_REG_0) << 4;
  *(guint32 *) &self->code[2] = (ri2 - self->pc) >> 1;
  gum_s390x_writer_commit (self, 6);
}

void
gum_s390x_writer_put_lay (GumS390xWriter * self, sysz_reg r1, gint32 d2,
    sysz_reg x2, sysz_reg b2)
{
  self->code[0] = 0xE3;
  self->code[1] = ((r1 - SYSZ_REG_0) << 4) | (x2 - SYSZ_REG_0);
  self->code[2] = ((b2 - SYSZ_REG_0) << 4) | ((d2 >> 8) & 0xf);
  self->code[3] = d2 & 0xff;
  self->code[4] = (d2 >> 12) & 0xff;
  self->code[5] = 0x71;
  gum_s390x_writer_commit (self, 6);
}

void
gum_s390x_writer_put_lg (GumS390xWriter * self, sysz_reg r1, gint32 d2,
    sysz_reg x2, sysz_reg b2)
{
  self->code[0] = 0xE3;
  self->code[1] = ((r1 - SYSZ_REG_0) << 4) | (x2 - SYSZ_REG_0);
  self->code[2] = ((b2 - SYSZ_REG_0) << 4) | ((d2 >> 8) & 0xf);
  self->code[3] = d2 & 0xff;
  self->code[4] = (d2 >> 12) & 0xff;
  self->code[5] = 0x04;
  gum_s390x_writer_commit (self, 6);
}

void
gum_s390x_writer_put_lgr (GumS390xWriter * self, sysz_reg r1, sysz_reg r2)
{
  self->code[0] = 0xB9;
  self->code[1] = 0x04;
  self->code[2] = 0x00;
  self->code[3] = ((r1 - SYSZ_REG_0) << 4) | (r2 - SYSZ_REG_0);
  gum_s390x_writer_commit (self, 4);
}

void
gum_s390x_writer_put_lghi (GumS390xWriter * self, sysz_reg r1, gint16 i2)
{
  self->code[0] = 0xA7;
  self->code[1] = ((r1 - SYSZ_REG_0) << 4) | 0x9;
  *(gint16 *)&self->code[2] = i2;
  gum_s390x_writer_commit (self, 4);
}

void
gum_s390x_writer_put_lmg (GumS390xWriter * self, sysz_reg r1, sysz_reg r3,
    gint32 d2, sysz_reg b2)
{
  self->code[0] = 0xEB;
  self->code[1] = ((r1 - SYSZ_REG_0) << 4) | (r3 - SYSZ_REG_0);
  self->code[2] = ((b2 - SYSZ_REG_0) << 4) | ((d2 >> 8) & 0xf);
  self->code[3] = d2 & 0xff;
  self->code[4] = (d2 >> 12) & 0xff;
  self->code[5] = 0x04;
  gum_s390x_writer_commit (self, 6);
}

void
gum_s390x_writer_put_lgrl (GumS390xWriter * self, sysz_reg r1, GumAddress ri2)
{
  self->code[0] = 0xC4;
  self->code[1] = ((r1 - SYSZ_REG_0) << 4) | 0x8;
  *(guint32 *) &self->code[2] = (ri2 - self->pc) >> 1;
  gum_s390x_writer_commit (self, 6);
}

void
gum_s390x_writer_put_mvghi (GumS390xWriter * self, guint16 d1, sysz_reg b1,
    guint16 i2)
{
  self->code[0] = 0xE5;
  self->code[1] = 0x48;
  self->code[2] = ((b1 - SYSZ_REG_0) << 4) | ((d1 >> 8) & 0xf);
  self->code[3] = d1 & 0xff;
  self->code[4] = (i2 >> 8) & 0xff;
  self->code[5] = i2 & 0xff;
  gum_s390x_writer_commit (self, 6);
}

void
gum_s390x_writer_put_nops (GumS390xWriter * self, guint n_bytes)
{
  gum_memset (self->code, 0x07, n_bytes);
  gum_s390x_writer_commit (self, n_bytes);
}

void
gum_s390x_writer_put_spm (GumS390xWriter * self, sysz_reg r1)
{
  self->code[0] = 0x04;
  self->code[1] = (r1 - SYSZ_REG_0) << 4;
  gum_s390x_writer_commit (self, 2);
}

void
gum_s390x_writer_put_stg (GumS390xWriter * self, sysz_reg r1, gint32 d2,
    sysz_reg x2, sysz_reg b2)
{
  self->code[0] = 0xE3;
  self->code[1] = ((r1 - SYSZ_REG_0) << 4) | (x2 - SYSZ_REG_0);
  self->code[2] = ((b2 - SYSZ_REG_0) << 4) | ((d2 >> 8) & 0xf);
  self->code[3] = d2 & 0xff;
  self->code[4] = (d2 >> 12) & 0xff;
  self->code[5] = 0x24;
  gum_s390x_writer_commit (self, 6);
}

void
gum_s390x_writer_put_stmg (GumS390xWriter * self, sysz_reg r1, sysz_reg r3,
    gint32 d2, sysz_reg b2)
{
  self->code[0] = 0xEB;
  self->code[1] = ((r1 - SYSZ_REG_0) << 4) | (r3 - SYSZ_REG_0);
  self->code[2] = ((b2 - SYSZ_REG_0) << 4) | ((d2 >> 8) & 0xf);
  self->code[3] = d2 & 0xff;
  self->code[4] = (d2 >> 12) & 0xff;
  self->code[5] = 0x24;
  gum_s390x_writer_commit (self, 6);
}

void
gum_s390x_writer_put_xgr (GumS390xWriter * self, sysz_reg r1, sysz_reg r2)
{
  self->code[0] = 0xB9;
  self->code[1] = 0x82;
  self->code[2] = 0x00;
  self->code[3] = ((r1 - SYSZ_REG_0) << 4) | (r2 - SYSZ_REG_0);
  gum_s390x_writer_commit (self, 4);
}

void
gum_s390x_writer_put_padding (GumS390xWriter * self, guint alignment)
{
  GumAddress aligned_pc = (self->pc + ((GumAddress) alignment - 1)) &
      ~((GumAddress) alignment - 1);

  gum_s390x_writer_skip (self, aligned_pc - self->pc);
}

void gum_s390x_writer_put_bytes (GumS390xWriter * self, const guint8 * data,
    guint n)
{
  gum_memcpy (self->code, data, n);
  gum_s390x_writer_commit (self, n);
}

void
gum_s390x_writer_put_break (GumS390xWriter * self)
{
  guint8 insn[2] = {0, 1};

  gum_s390x_writer_put_bytes (self, insn, sizeof (insn));
}
