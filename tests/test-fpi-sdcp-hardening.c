/* Security regression tests: independently signed claims and hostile packets. */
#include "fpi-sdcp.h"
#include "fp-sdcp-device-private.h"
#include "drivers/egismoc/egismoc-proto.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ecdsa.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>

static GBytes *
public_bytes (EVP_PKEY *key)
{
  guint8 raw[65];
  gsize size = sizeof (raw);
  g_assert_cmpint (EVP_PKEY_get_octet_string_param (key, OSSL_PKEY_PARAM_PUB_KEY,
                                                   raw, sizeof (raw), &size), ==, 1);
  g_assert_cmpuint (size, ==, sizeof (raw));
  return g_bytes_new (raw, size);
}

static GBytes *
sign_bytes (EVP_PKEY *key, const guint8 *prefix, gsize prefix_size, GBytes *a, GBytes *b)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  gsize der_size = 0;
  g_autofree guint8 *der = NULL;
  const guint8 *ptr;
  ECDSA_SIG *sig;
  guint8 raw[64];
  g_assert_cmpint (EVP_DigestSignInit (ctx, NULL, EVP_sha256 (), NULL, key), ==, 1);
  if (prefix_size)
    g_assert_cmpint (EVP_DigestSignUpdate (ctx, prefix, prefix_size), ==, 1);
  g_assert_cmpint (EVP_DigestSignUpdate (ctx, g_bytes_get_data (a, NULL), g_bytes_get_size (a)), ==, 1);
  if (b)
    g_assert_cmpint (EVP_DigestSignUpdate (ctx, g_bytes_get_data (b, NULL), g_bytes_get_size (b)), ==, 1);
  g_assert_cmpint (EVP_DigestSignFinal (ctx, NULL, &der_size), ==, 1);
  der = g_malloc (der_size);
  g_assert_cmpint (EVP_DigestSignFinal (ctx, der, &der_size), ==, 1);
  ptr = der;
  sig = d2i_ECDSA_SIG (NULL, &ptr, der_size);
  g_assert_nonnull (sig);
  g_assert_cmpint (BN_bn2binpad (ECDSA_SIG_get0_r (sig), raw, 32), ==, 32);
  g_assert_cmpint (BN_bn2binpad (ECDSA_SIG_get0_s (sig), raw + 32, 32), ==, 32);
  ECDSA_SIG_free (sig);
  EVP_MD_CTX_free (ctx);
  return g_bytes_new (raw, sizeof (raw));
}

static FpiSdcpClaim *
signed_claim (gboolean wrong_prefix)
{
  static const guint8 prefix[] = {0xc0, 0x01};
  guint8 hash[32] = {0x42};
  EVP_PKEY *model = EVP_EC_gen ("prime256v1");
  EVP_PKEY *device = EVP_EC_gen ("prime256v1");
  EVP_PKEY *firmware = EVP_EC_gen ("prime256v1");
  X509 *cert = X509_new ();
  X509_NAME *name;
  guint8 *der = NULL;
  int size;
  FpiSdcpClaim *claim = g_new0 (FpiSdcpClaim, 1);
  g_assert_nonnull (model);
  g_assert_nonnull (device);
  g_assert_nonnull (firmware);
  g_assert_cmpint (X509_set_version (cert, 2), ==, 1);
  g_assert_cmpint (ASN1_INTEGER_set (X509_get_serialNumber (cert), 1), ==, 1);
  X509_gmtime_adj (X509_getm_notBefore (cert), -60);
  X509_gmtime_adj (X509_getm_notAfter (cert), 3600);
  name = X509_get_subject_name (cert);
  g_assert_cmpint (X509_NAME_add_entry_by_txt (name, "CN", MBSTRING_ASC,
                                              (const guint8 *) "SDCP regression test", -1, -1, 0), ==, 1);
  g_assert_cmpint (X509_set_issuer_name (cert, name), ==, 1);
  g_assert_cmpint (X509_set_pubkey (cert, model), ==, 1);
  g_assert_cmpint (X509_sign (cert, model, EVP_sha256 ()), >, 0);
  size = i2d_X509 (cert, &der);
  g_assert_cmpint (size, >, 0);
  claim->model_certificate = g_bytes_new (der, size);
  OPENSSL_free (der);
  claim->device_public_key = public_bytes (device);
  claim->firmware_public_key = public_bytes (firmware);
  claim->firmware_hash = g_bytes_new (hash, sizeof (hash));
  claim->model_signature = sign_bytes (model, NULL, 0, claim->device_public_key, NULL);
  claim->device_signature = sign_bytes (device,
    wrong_prefix ? (const guint8 *) "C001" : prefix, wrong_prefix ? 4 : sizeof (prefix),
    claim->firmware_hash, claim->firmware_public_key);
  X509_free (cert);
  EVP_PKEY_free (model);
  EVP_PKEY_free (device);
  EVP_PKEY_free (firmware);
  return claim;
}

static GBytes *
flip_byte (GBytes *bytes)
{
  gsize size;
  const guint8 *ptr = g_bytes_get_data (bytes, &size);
  guint8 *copy = g_memdup2 (ptr, size);
  copy[size - 1] ^= 1;
  return g_bytes_new_take (copy, size);
}

static void
test_signatures (void)
{
  g_autoptr(FpiSdcpClaim) claim = signed_claim (FALSE);
  g_autoptr(GError) error = NULL;
  GBytes **fields[] = {&claim->model_signature, &claim->device_signature,
    &claim->device_public_key, &claim->firmware_public_key, &claim->firmware_hash};
  g_assert_true (fpi_sdcp_verify_attestation (claim, FALSE, TRUE, &error));
  g_assert_no_error (error);
  for (guint i = 0; i < G_N_ELEMENTS (fields); i++)
    {
      GBytes *original = *fields[i];
      *fields[i] = flip_byte (original);
      g_assert_false (fpi_sdcp_verify_attestation (claim, FALSE, TRUE, &error));
      g_assert_nonnull (error);
      g_clear_error (&error);
      g_bytes_unref (*fields[i]);
      *fields[i] = original;
    }
  g_assert_false (fpi_sdcp_verify_attestation (claim, TRUE, TRUE, &error));
  g_assert_nonnull (error); /* A self-signed test certificate is never a trust anchor. */
}

static void
test_bad_prefix (void)
{
  g_autoptr(FpiSdcpClaim) claim = signed_claim (TRUE);
  g_autoptr(GError) error = NULL;
  g_assert_false (fpi_sdcp_verify_attestation (claim, FALSE, TRUE, &error));
  g_assert_nonnull (error);
}

static void
test_response_lengths (void)
{
  const gsize size = 32 + 2 + 1 + 65 + 65 + 32 + 64 + 64 + 32;
  g_autofree guint8 *data = g_malloc0 (size + 1);
  g_autoptr(GBytes) random = NULL, mac = NULL;
  g_autoptr(FpiSdcpClaim) claim = NULL;
  const guint8 suffix[] = {0x90, 0};
  data[33] = 1;
  for (gsize length = 0; length < size; length++)
    {
      g_autofree guint8 *short_data = g_memdup2 (data, length);
      g_assert_false (egismoc_parse_connect (short_data, length, &random, &claim, &mac));
      g_assert_null (random);
      g_assert_null (claim);
      g_assert_null (mac);
    }
  g_assert_false (egismoc_has_suffix (data, 0, suffix, sizeof (suffix)));
  g_assert_false (egismoc_has_prefix (data, 1, G_MAXSIZE, suffix, sizeof (suffix)));
  g_assert_false (egismoc_parse_connect (data, size + 1, &random, &claim, &mac));
  data[32] = 0xff;
  g_assert_false (egismoc_parse_connect (data, size, &random, &claim, &mac));
  data[32] = 0;
  g_assert_true (egismoc_parse_connect (data, size, &random, &claim, &mac));
}

static void
test_replayed_mac (void)
{
  guint8 old_key[32] = {1}, new_key[32] = {2}, nonce[32] = {0}, id[32] = {3};
  guint8 message[sizeof ("identify") + 64], digest[32];
  guint digest_size = sizeof (digest);
  g_autoptr(GBytes) old_secret = g_bytes_new (old_key, 32);
  g_autoptr(GBytes) new_secret = g_bytes_new (new_key, 32);
  g_autoptr(GBytes) zero_nonce = g_bytes_new (nonce, 32);
  g_autoptr(GBytes) print_id = g_bytes_new (id, 32);
  g_autoptr(GBytes) mac = NULL;
  g_autoptr(GError) error = NULL;
  memcpy (message, "identify", sizeof ("identify"));
  memcpy (message + sizeof ("identify"), nonce, 32);
  memcpy (message + sizeof ("identify") + 32, id, 32);
  g_assert_nonnull (HMAC (EVP_sha256 (), old_key, 32, message, sizeof (message), digest, &digest_size));
  mac = g_bytes_new (digest, digest_size);
  g_assert_true (fpi_sdcp_verify_identify (old_secret, zero_nonce, print_id, mac, &error));
  g_assert_no_error (error);
  g_assert_false (fpi_sdcp_verify_identify (new_secret, zero_nonce, print_id, mac, &error));
  g_assert_nonnull (error);
}

static guint32
read_le32 (const guint8 *data)
{
  guint32 value;
  memcpy (&value, data, sizeof (value));
  return GUINT32_FROM_LE (value);
}

static void
test_public_egis_capture (void)
{
  g_autofree gchar *path = g_test_build_filename (G_TEST_DIST, "egismoc", "custom.pcapng", NULL);
  g_autofree gchar *contents = NULL;
  g_autoptr(GError) error = NULL;
  gsize size, pos = 0;
  gboolean found = FALSE;
  g_assert_true (g_file_get_contents (path, &contents, &size, &error));
  while (pos + 28 <= size)
    {
      const guint8 *block = (const guint8 *) contents + pos;
      guint32 block_size = read_le32 (block + 4);
      g_assert_cmpuint (block_size, >=, 12);
      g_assert_cmpuint (block_size, <=, size - pos);
      if (read_le32 (block) == 6 && block_size >= 32)
        {
          guint32 captured = read_le32 (block + 20);
          const guint8 *packet = block + 28;
          g_assert_cmpuint (captured, <=, block_size - 32);
          for (gsize i = 0; i + 51 <= captured; i++)
            if (memcmp (packet + i, "SIGE", 4) == 0 &&
                packet[i + 49] == 0x30 && packet[i + 50] == 0x82)
              {
                g_autoptr(GBytes) random = NULL, mac = NULL;
                g_autoptr(FpiSdcpClaim) claim = NULL;
                g_assert_true (egismoc_parse_connect (packet + i + 15, captured - i - 17,
                                                       &random, &claim, &mac));
                g_assert_true (fpi_sdcp_verify_attestation (claim, TRUE, TRUE, &error));
                g_assert_no_error (error);
                found = TRUE;
              }
        }
      pos += block_size;
    }
  g_assert_true (found);
}

/* A failed handshake must never dispatch Identify or retain an old secret. */
#define TYPE_HANDSHAKE_DEVICE (handshake_device_get_type ())
G_DECLARE_FINAL_TYPE (HandshakeDevice, handshake_device, HANDSHAKE, DEVICE, FpSdcpDevice)
struct _HandshakeDevice
{
  FpSdcpDevice parent;
  GPtrArray *randoms;
  GPtrArray *public_keys;
  guint identifies;
  gboolean real_open;
};
G_DEFINE_TYPE (HandshakeDevice, handshake_device, FP_TYPE_SDCP_DEVICE)

static void
handshake_open (FpSdcpDevice *self)
{
  if (HANDSHAKE_DEVICE (self)->real_open)
    fpi_sdcp_device_open_complete (self, NULL);
  else
    fpi_device_open_complete (FP_DEVICE (self), NULL);
}

static void
handshake_close (FpDevice *device)
{
  fpi_device_close_complete (device, NULL);
}

static void
handshake_connect (FpSdcpDevice *self)
{
  HandshakeDevice *device = HANDSHAKE_DEVICE (self);
  GBytes *random = NULL, *public_key = NULL;
  g_autoptr(GBytes) old_secret = NULL;
  fpi_sdcp_device_get_application_secret (self, &old_secret);
  g_assert_null (old_secret);
  fpi_sdcp_device_get_connect_data (self, &random, &public_key);
  g_ptr_array_add (device->randoms, random);
  g_ptr_array_add (device->public_keys, public_key);
  fpi_sdcp_device_connect_complete (self, NULL, NULL, NULL,
    fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED, "Synthetic failed handshake"));
}

static void
handshake_identify (FpSdcpDevice *self)
{
  HANDSHAKE_DEVICE (self)->identifies++;
  fpi_sdcp_device_identify_complete (self, NULL, NULL, NULL);
}

static void
handshake_finalize (GObject *object)
{
  HandshakeDevice *self = HANDSHAKE_DEVICE (object);
  g_ptr_array_unref (self->randoms);
  g_ptr_array_unref (self->public_keys);
  G_OBJECT_CLASS (handshake_device_parent_class)->finalize (object);
}

static void
handshake_device_class_init (HandshakeDeviceClass *klass)
{
  FpDeviceClass *dev = FP_DEVICE_CLASS (klass);
  FpSdcpDeviceClass *sdcp = FP_SDCP_DEVICE_CLASS (klass);
  dev->id = "test-fresh-handshake";
  dev->full_name = "Fresh handshake regression test";
  dev->type = FP_DEVICE_TYPE_VIRTUAL;
  dev->scan_type = FP_SCAN_TYPE_PRESS;
  dev->close = handshake_close;
  sdcp->open = handshake_open;
  sdcp->connect = handshake_connect;
  sdcp->identify = handshake_identify;
  sdcp->require_fresh_connect = TRUE;
  G_OBJECT_CLASS (klass)->finalize = handshake_finalize;
  fpi_device_class_auto_initialize_features (dev);
}

static void
handshake_device_init (HandshakeDevice *self)
{
  self->randoms = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  self->public_keys = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
}

static void
test_fresh_handshake_failure (void)
{
  g_autoptr(HandshakeDevice) self = g_object_new (TYPE_HANDSHAKE_DEVICE, NULL);
  g_autoptr(FpPrint) print = g_object_ref_sink (fp_print_new (FP_DEVICE (self)));
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) old_secret = g_bytes_new_static ("01234567890123456789012345678901", 32);
  g_autoptr(GBytes) id = g_bytes_new_static ("01234567890123456789012345678901", 32);
  gboolean match;
  g_assert_true (fp_device_open_sync (FP_DEVICE (self), NULL, &error));
  g_assert_no_error (error);
  fpi_print_set_type (print, FPI_PRINT_SDCP);
  fpi_print_set_device_stored (print, TRUE);
  fpi_sdcp_device_set_print_id (print, id);
  fpi_sdcp_device_set_application_secret (FP_SDCP_DEVICE (self), old_secret);
  for (guint i = 0; i < 2; i++)
    {
      g_autoptr(GBytes) secret = NULL;
      g_assert_false (fp_device_verify_sync (FP_DEVICE (self), print, NULL, NULL, NULL,
                                             &match, NULL, &error));
      g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);
      g_clear_error (&error);
      fpi_sdcp_device_get_application_secret (FP_SDCP_DEVICE (self), &secret);
      g_assert_null (secret);
    }
  g_assert_cmpuint (self->identifies, ==, 0);
  g_assert_cmpuint (self->randoms->len, ==, 2);
  g_assert_false (g_bytes_equal (self->randoms->pdata[0], self->randoms->pdata[1]));
  g_assert_false (g_bytes_equal (self->public_keys->pdata[0], self->public_keys->pdata[1]));
  g_assert_true (fp_device_close_sync (FP_DEVICE (self), NULL, &error));
  g_assert_no_error (error);
  self->real_open = TRUE;
  fpi_sdcp_device_set_application_secret (FP_SDCP_DEVICE (self), old_secret);
  g_assert_false (fp_device_open_sync (FP_DEVICE (self), NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);
  g_assert_cmpuint (self->randoms->len, ==, 3);
}

int main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  /* Freshness must use real CSPRNG keys, never deterministic emulation keys. */
  g_unsetenv ("FP_DEVICE_EMULATION");
  g_test_add_func ("/hardening/signature-tampering", test_signatures);
  g_test_add_func ("/hardening/binary-signature-prefix", test_bad_prefix);
  g_test_add_func ("/hardening/response-lengths", test_response_lengths);
  g_test_add_func ("/hardening/old-mac-new-key", test_replayed_mac);
  g_test_add_func ("/hardening/public-egis-capture-attestation", test_public_egis_capture);
  g_test_add_func ("/hardening/fresh-handshake-failure-and-retry", test_fresh_handshake_failure);
  return g_test_run ();
}
