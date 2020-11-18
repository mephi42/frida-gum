/*
 * Copyright (C) 2014-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_S390X_WRITER_H__
#define __GUM_S390X_WRITER_H__

#include <capstone.h>
#include <gum/gumdefs.h>

#define GUM_S390X_BRCL_MAX_DISTANCE 0xfffffffe
#define GUM_S390X_MAX_INSN_SIZE 6

G_BEGIN_DECLS

typedef struct _GumS390xWriter GumS390xWriter;

struct _GumS390xWriter
{
  volatile gint ref_count;

  guint8 * base;
  guint8 * code;
  GumAddress pc;
};

GUM_API GumS390xWriter * gum_s390x_writer_new (gpointer code_address);
GUM_API GumS390xWriter * gum_s390x_writer_ref (GumS390xWriter * writer);
GUM_API void gum_s390x_writer_unref (GumS390xWriter * writer);

GUM_API void gum_s390x_writer_init (GumS390xWriter * writer,
    gpointer code_address);
GUM_API void gum_s390x_writer_clear (GumS390xWriter * writer);

GUM_API void gum_s390x_writer_reset (GumS390xWriter * writer,
    gpointer code_address);

GUM_API gpointer gum_s390x_writer_cur (GumS390xWriter * self);
GUM_API guint gum_s390x_writer_offset (GumS390xWriter * self);
GUM_API void gum_s390x_writer_skip (GumS390xWriter * self, guint n_bytes);

GUM_API gboolean gum_s390x_writer_flush (GumS390xWriter * self);

GUM_API void gum_s390x_writer_put_basr (GumS390xWriter * self, sysz_reg r1,
    sysz_reg r2);
GUM_API void gum_s390x_writer_put_bcr (GumS390xWriter * self, guint8 m1,
    sysz_reg r2);
GUM_API void gum_s390x_writer_put_brasl (GumS390xWriter * self, sysz_reg r1,
    GumAddress ri2);
GUM_API void gum_s390x_writer_put_brcl (GumS390xWriter * self, guint8 m1,
    GumAddress ri2);
GUM_API void gum_s390x_writer_put_cg (GumS390xWriter * self, sysz_reg r1,
    gint32 d2, sysz_reg x2, sysz_reg b2);
GUM_API void gum_s390x_writer_put_ipm (GumS390xWriter * self, sysz_reg r1);
GUM_API void gum_s390x_writer_put_la (GumS390xWriter * self, sysz_reg r1,
    guint16 d2, sysz_reg x2, sysz_reg b2);
GUM_API void gum_s390x_writer_put_larl (GumS390xWriter * self, sysz_reg r1,
    GumAddress ri2);
GUM_API void gum_s390x_writer_put_lay (GumS390xWriter * self, sysz_reg r1,
    gint32 d2, sysz_reg x2, sysz_reg b2);
GUM_API void gum_s390x_writer_put_lg (GumS390xWriter * self, sysz_reg r1,
    gint32 d2, sysz_reg x2, sysz_reg b2);
GUM_API void gum_s390x_writer_put_lgr (GumS390xWriter * self, sysz_reg r1,
    sysz_reg r2);
GUM_API void gum_s390x_writer_put_lghi (GumS390xWriter * self, sysz_reg r1,
    gint16 i2);
GUM_API void gum_s390x_writer_put_lmg (GumS390xWriter * self, sysz_reg r1,
    sysz_reg r3, gint32 d2, sysz_reg b2);
GUM_API void gum_s390x_writer_put_lgrl (GumS390xWriter * self, sysz_reg r1,
    GumAddress ri2);
GUM_API void gum_s390x_writer_put_mvghi (GumS390xWriter * self, guint16 d1,
    sysz_reg b1, guint16 i2);
GUM_API void gum_s390x_writer_put_nops (GumS390xWriter * self, guint n_bytes);
GUM_API void gum_s390x_writer_put_spm (GumS390xWriter * self, sysz_reg r1);
GUM_API void gum_s390x_writer_put_stg (GumS390xWriter * self, sysz_reg r1,
    gint32 d2, sysz_reg x2, sysz_reg b2);
GUM_API void gum_s390x_writer_put_stmg (GumS390xWriter * self, sysz_reg r1,
    sysz_reg r3, gint32 d2, sysz_reg b2);
GUM_API void gum_s390x_writer_put_xgr (GumS390xWriter * self, sysz_reg r1,
    sysz_reg r2);

GUM_API void gum_s390x_writer_put_padding (GumS390xWriter * self,
    guint alignment);
GUM_API void gum_s390x_writer_put_bytes (GumS390xWriter * self,
    const guint8 * data, guint n);
GUM_API void gum_s390x_writer_put_break (GumS390xWriter * self);

G_END_DECLS

#endif
