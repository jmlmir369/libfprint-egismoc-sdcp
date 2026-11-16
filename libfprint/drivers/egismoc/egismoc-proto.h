/* Bounded parsing for untrusted Egis USB responses. */
#pragma once

#include <string.h>
#include "fpi-sdcp-device.h"

static inline gboolean
egismoc_has_prefix (const guint8 *data, gsize size, gsize offset,
                    const guint8 *prefix, gsize prefix_size)
{
  return data && prefix && offset <= size && prefix_size <= size - offset &&
    memcmp (data + offset, prefix, prefix_size) == 0;
}

static inline gboolean
egismoc_has_suffix (const guint8 *data, gsize size,
                    const guint8 *suffix, gsize suffix_size)
{
  return size >= suffix_size &&
    egismoc_has_prefix (data, size, size - suffix_size, suffix, suffix_size);
}

/* The caller removes the vendor prefix/suffix before passing this payload. */
static inline gboolean
egismoc_parse_connect (const guint8 *data, gsize size,
                       GBytes **random, FpiSdcpClaim **claim_out, GBytes **mac)
{
  const gsize fixed_size = SDCP_RANDOM_SIZE + 2 + 2 * SDCP_PUBLIC_KEY_SIZE +
    SDCP_MAC_SIZE + 2 * SDCP_SIGNATURE_SIZE + SDCP_MAC_SIZE;
  gsize certificate_size, pos = 0;
  g_autoptr(FpiSdcpClaim) claim = NULL;

  if (!data || !random || !claim_out || !mac || size < fixed_size)
    return FALSE;
  certificate_size = ((gsize) data[SDCP_RANDOM_SIZE] << 8) | data[SDCP_RANDOM_SIZE + 1];
  if (!certificate_size || certificate_size != size - fixed_size)
    return FALSE;
  claim = g_new0 (FpiSdcpClaim, 1);
  *random = g_bytes_new (data, SDCP_RANDOM_SIZE);
  pos = SDCP_RANDOM_SIZE + 2;
  claim->model_certificate = g_bytes_new (data + pos, certificate_size);
  pos += certificate_size;
  claim->device_public_key = g_bytes_new (data + pos, SDCP_PUBLIC_KEY_SIZE);
  pos += SDCP_PUBLIC_KEY_SIZE;
  claim->firmware_public_key = g_bytes_new (data + pos, SDCP_PUBLIC_KEY_SIZE);
  pos += SDCP_PUBLIC_KEY_SIZE;
  claim->firmware_hash = g_bytes_new (data + pos, SDCP_MAC_SIZE);
  pos += SDCP_MAC_SIZE;
  claim->model_signature = g_bytes_new (data + pos, SDCP_SIGNATURE_SIZE);
  pos += SDCP_SIGNATURE_SIZE;
  claim->device_signature = g_bytes_new (data + pos, SDCP_SIGNATURE_SIZE);
  pos += SDCP_SIGNATURE_SIZE;
  *mac = g_bytes_new (data + pos, SDCP_MAC_SIZE);
  *claim_out = g_steal_pointer (&claim);
  return TRUE;
}
