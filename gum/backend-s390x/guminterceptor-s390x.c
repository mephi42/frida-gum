/*
 * Copyright (C) 2014-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gums390xrelocator.h"
#include "gums390xwriter.h"
#include "gumlibc.h"
#include "gummemory.h"

#include <string.h>
#include <unistd.h>

#define GUM_INTERCEPTOR_REDIRECT_CODE_SIZE 6

struct _GumInterceptorBackend
{
  GumCodeAllocator * allocator;

  GumS390xWriter writer;
  GumS390xRelocator relocator;

  GumCodeSlice * thunks;

  gpointer enter_thunk;
  gpointer leave_thunk;
};

struct _GumS390xFrame
{
  guint8 for_c[160];
  GumCpuContext cpu_context;
};

typedef struct _GumS390xFrame GumS390xFrame;

static void
gum_emit_prologue (GumS390xWriter * cw)
{
  gum_s390x_writer_put_ipm (cw, SYSZ_REG_1);
  gum_s390x_writer_put_stg (cw, SYSZ_REG_1,
      offsetof (GumS390xFrame, cpu_context.pswm), SYSZ_REG_0, SYSZ_REG_15);
}

static void
gum_emit_epilogue (GumS390xWriter * cw)
{
  gum_s390x_writer_put_lg (cw, SYSZ_REG_1,
      offsetof (GumS390xFrame, cpu_context.pswm), SYSZ_REG_0, SYSZ_REG_15);
  gum_s390x_writer_put_spm (cw, SYSZ_REG_1);
  gum_s390x_writer_put_lmg (cw, SYSZ_REG_0, SYSZ_REG_15,
      offsetof (GumS390xFrame, cpu_context.gprs), SYSZ_REG_15);
  gum_s390x_writer_put_lay (cw, SYSZ_REG_15, (gint32) sizeof (GumS390xFrame),
      SYSZ_REG_0, SYSZ_REG_15);
  gum_s390x_writer_put_bcr (cw, 15, SYSZ_REG_1);
}

static gpointer
gum_emit_enter_thunk (GumS390xWriter * cw)
{
  gpointer target = _gum_function_context_begin_invocation;
  gpointer target_addr;
  gpointer result;

  gum_s390x_writer_put_padding (cw, 8);
  target_addr = gum_s390x_writer_cur (cw);
  gum_s390x_writer_put_bytes (cw, (guint8 *) &target, sizeof (target));

  result = gum_s390x_writer_cur (cw);
  gum_emit_prologue (cw);

  gum_s390x_writer_put_lgrl (cw, SYSZ_REG_1, GUM_ADDRESS (target_addr));
  gum_s390x_writer_put_la (cw, SYSZ_REG_3,
      offsetof (GumS390xFrame, cpu_context), SYSZ_REG_0, SYSZ_REG_15);
  gum_s390x_writer_put_la (cw, SYSZ_REG_4,
      offsetof (GumS390xFrame, cpu_context.gprs[14]), SYSZ_REG_0, SYSZ_REG_15);
  gum_s390x_writer_put_la (cw, SYSZ_REG_5,
      offsetof (GumS390xFrame, cpu_context.gprs[1]), SYSZ_REG_0, SYSZ_REG_15);
  gum_s390x_writer_put_basr (cw, SYSZ_REG_14, SYSZ_REG_1);

  gum_emit_epilogue (cw);

  return result;
}

static gpointer
gum_emit_leave_thunk (GumS390xWriter * cw)
{
  gpointer target = _gum_function_context_end_invocation;
  gpointer target_addr;
  gpointer result;

  gum_s390x_writer_put_padding (cw, 8);
  target_addr = gum_s390x_writer_cur (cw);
  gum_s390x_writer_put_bytes (cw, (guint8 *) &target, sizeof (target));

  result = gum_s390x_writer_cur (cw);
  gum_emit_prologue (cw);

  gum_s390x_writer_put_lgrl (cw, SYSZ_REG_1, GUM_ADDRESS (target_addr));
  gum_s390x_writer_put_la (cw, SYSZ_REG_3,
      offsetof (GumS390xFrame, cpu_context), SYSZ_REG_0, SYSZ_REG_15);
  gum_s390x_writer_put_la (cw, SYSZ_REG_4,
      offsetof (GumS390xFrame, cpu_context.gprs[1]), SYSZ_REG_0, SYSZ_REG_15);
  gum_s390x_writer_put_basr (cw, SYSZ_REG_14, SYSZ_REG_1);

  gum_emit_epilogue (cw);

  return result;
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumS390xWriter * cw = &self->writer;

  self->thunks = gum_code_allocator_alloc_slice (self->allocator);
  gum_s390x_writer_reset (cw, self->thunks->data);

  self->enter_thunk = gum_emit_enter_thunk (cw);
  gum_s390x_writer_flush (cw);
  g_assert (gum_s390x_writer_offset (cw) <= self->enter_thunk->size);

  self->leave_thunk = gum_emit_leave_thunk (cw);
  gum_s390x_writer_flush (cw);
  g_assert (gum_s390x_writer_offset (cw) <= self->leave_thunk->size);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_code_slice_free (self->thunks);
}

GumInterceptorBackend *
_gum_interceptor_backend_create (GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new (GumInterceptorBackend);
  backend->allocator = allocator;

  gum_s390x_writer_init (&backend->writer, NULL);
  gum_s390x_relocator_init (&backend->relocator, NULL, &backend->writer);

  gum_interceptor_backend_create_thunks (backend);

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_interceptor_backend_destroy_thunks (backend);

  gum_s390x_relocator_clear (&backend->relocator);
  gum_s390x_writer_clear (&backend->writer);

  g_slice_free (GumInterceptorBackend, backend);
}

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumAddressSpec spec;
  gsize default_alignment = 2;

  spec.near_address = ctx->function_address;
  spec.max_distance = GUM_S390X_BRCL_MAX_DISTANCE;
  ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
      self->allocator, &spec, default_alignment);

  return ctx->trampoline_slice != NULL;
}

static gpointer
gum_emit_trampoline (GumS390xWriter * cw, GumAddress target,
    GumAddress function_ctx_ptr)
{
  gpointer target_addr;
  gpointer result;

  gum_s390x_writer_put_padding (cw, 8);
  target_addr = gum_s390x_writer_cur (cw);
  gum_s390x_writer_put_bytes (cw, (guint8 *) &target, sizeof (target));

  result = gum_s390x_writer_cur (cw);
  gum_s390x_writer_put_lay (cw, SYSZ_REG_15, -(gint32) sizeof (GumS390xFrame),
      SYSZ_REG_0, SYSZ_REG_15);
  gum_s390x_writer_put_stmg (cw, SYSZ_REG_0, SYSZ_REG_15,
      offsetof (GumS390xFrame, cpu_context.gprs), SYSZ_REG_15);
  gum_s390x_writer_put_lgrl (cw, SYSZ_REG_1, GUM_ADDRESS (target_addr));
  gum_s390x_writer_put_lgrl (cw, SYSZ_REG_2, function_ctx_ptr);
  gum_s390x_writer_put_bcr (cw, 15, SYSZ_REG_1);
  return result;
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumS390xWriter * cw = &self->writer;
  GumS390xRelocator * rl = &self->relocator;
  GumAddress function_ctx_ptr;
  guint reloc_bytes;

  if (!gum_s390x_relocator_can_relocate (ctx->function_address,
      GUM_INTERCEPTOR_REDIRECT_CODE_SIZE, NULL))
    return FALSE;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_s390x_writer_reset (cw, ctx->trampoline_slice->data);

  gum_s390x_writer_put_padding (cw, 8);
  function_ctx_ptr = GUM_ADDRESS (gum_s390x_writer_cur (cw));
  gum_s390x_writer_put_bytes (cw, (guint8 *) &ctx, sizeof (ctx));

  ctx->on_enter_trampoline = gum_emit_trampoline (cw,
      GUM_ADDRESS (self->enter_thunk), function_ctx_ptr);
  ctx->on_leave_trampoline = gum_emit_trampoline (cw,
      GUM_ADDRESS (self->leave_thunk), function_ctx_ptr);

  gum_s390x_writer_flush (cw);
  g_assert (gum_s390x_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->on_invoke_trampoline = gum_s390x_writer_cur (cw);
  gum_s390x_relocator_reset (rl, (guint8 *) ctx->function_address, cw);

  do
  {
    reloc_bytes = gum_s390x_relocator_read_one (rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < GUM_INTERCEPTOR_REDIRECT_CODE_SIZE);
  gum_s390x_relocator_write_all (rl);

  if (!gum_s390x_relocator_eoi (rl))
  {
    gum_s390x_writer_put_brcl (cw, 15,
        GUM_ADDRESS (ctx->function_address) + reloc_bytes);
  }

  gum_s390x_writer_flush (cw);
  g_assert (gum_s390x_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  gum_memcpy (ctx->overwritten_prologue, ctx->function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
  gum_code_slice_free (ctx->trampoline_slice);
  ctx->trampoline_slice = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumS390xWriter * cw = &self->writer;

  gum_s390x_writer_reset (cw, prologue);
  cw->pc = GPOINTER_TO_SIZE (ctx->function_address);
  gum_s390x_writer_put_brcl (cw, 15, GUM_ADDRESS (ctx->on_enter_trampoline));
  gum_s390x_writer_flush (cw);
  g_assert (
      gum_s390x_writer_offset (cw) <= GUM_INTERCEPTOR_REDIRECT_CODE_SIZE);

  gum_s390x_writer_put_nops (cw,
      ctx->overwritten_prologue_len - gum_s390x_writer_offset (cw));
  gum_s390x_writer_flush (cw);
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx,
                                                gpointer prologue)
{
  gum_memcpy (prologue, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}

gpointer
_gum_interceptor_backend_get_function_address (GumFunctionContext * ctx)
{
  return ctx->function_address;
}

gpointer
_gum_interceptor_backend_resolve_redirect (GumInterceptorBackend * self,
                                           gpointer address)
{
  /* TODO: implement resolve redirect */
  return NULL;
}
