/*
 * Secure Device Connection Protocol (SDCP) support implementation
 * Copyright (C) 2025 Joshua Grisham <josh@joshuagrisham.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FP_COMPONENT "sdcp"
#include "fpi-log.h"

#include "fpi-sdcp.h"
#include "sdcp/fpi-sdcp-truststore-resource.h"

#include <openssl/core_names.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/ecdsa.h>
#include <openssl/crypto.h>

#define SDCP_PRIVATE_KEY_SIZE 32
#define SDCP_KEY_AGREEMENT_SIZE 32
#define SDCP_MASTER_SECRET_SIZE 32
#define SDCP_APPLICATION_KEYS_SIZE 64

/******************************************************************************/

static void
print_openssl_errors (void)
{
  gulong e = 0;

  e = ERR_get_error ();
  while (e != 0)
    {
      fp_dbg ("OpenSSL error: %s", ERR_error_string (e, NULL));
      e = ERR_get_error ();
    }
}

/******************************************************************************/

static gboolean
fpi_sdcp_verify_signature (EVP_PKEY    *pkey,
                           const guint8 *prefix,
                           gsize        prefix_len,
                           GBytes      *data_a,
                           GBytes      *data_b,
                           GBytes      *signature,
                           GError     **error)
{
  EVP_MD_CTX *mdctx = NULL;
  ECDSA_SIG *ec_signature = NULL;
  BIGNUM *r = NULL, *s = NULL;
  const guint8 *raw;
  unsigned char *der = NULL;
  int der_len;
  gboolean valid = FALSE;

  if (!pkey || !signature || g_bytes_get_size (signature) != SDCP_SIGNATURE_SIZE)
    goto out_error;
  raw = g_bytes_get_data (signature, NULL);
  r = BN_bin2bn (raw, 32, NULL);
  s = BN_bin2bn (raw + 32, 32, NULL);
  ec_signature = ECDSA_SIG_new ();
  if (!r || !s || !ec_signature || !ECDSA_SIG_set0 (ec_signature, r, s))
    goto out_error;
  r = s = NULL; /* ECDSA_SIG owns these values. */
  der_len = i2d_ECDSA_SIG (ec_signature, &der);
  mdctx = EVP_MD_CTX_new ();
  if (der_len <= 0 || !mdctx ||
      EVP_DigestVerifyInit (mdctx, NULL, EVP_sha256 (), NULL, pkey) != 1)
    goto out_error;
  if (prefix_len && (!prefix || EVP_DigestVerifyUpdate (mdctx, prefix, prefix_len) != 1))
    goto out_error;
  if (data_a && EVP_DigestVerifyUpdate (mdctx, g_bytes_get_data (data_a, NULL),
                                       g_bytes_get_size (data_a)) != 1)
    goto out_error;
  if (data_b && EVP_DigestVerifyUpdate (mdctx, g_bytes_get_data (data_b, NULL),
                                       g_bytes_get_size (data_b)) != 1)
    goto out_error;
  if (EVP_DigestVerifyFinal (mdctx, der, der_len) != 1)
    goto out_error;
  valid = TRUE;
  goto out;

out_error:
  g_propagate_error (error,
                     fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                               "SDCP ECDSA signature verification failed"));
  print_openssl_errors ();
out:
  BN_free (r);
  BN_free (s);
  ECDSA_SIG_free (ec_signature);
  OPENSSL_free (der);
  EVP_MD_CTX_free (mdctx);
  return valid;
}

static X509_STORE *
fpi_sdcp_get_truststore (GError **error)
{
  static gsize initialized = 0;
  const gchar *base = "/org/freedesktop/fprint/sdcp/truststore/";
  GResource *resource;
  g_auto(GStrv) names = NULL;
  X509_STORE *store = NULL;

  if (g_once_init_enter (&initialized))
    {
      fpi_sdcp_truststore_register_resource ();
      g_once_init_leave (&initialized, 1);
    }
  /* get_resource() is borrowed for the lifetime of the static resource. */
  resource = fpi_sdcp_truststore_get_resource ();
  names = g_resource_enumerate_children (resource, base, 0, error);
  if (!names)
    return NULL;
  store = X509_STORE_new ();
  if (!store)
    goto fail;
  for (guint i = 0; names[i]; i++)
    {
      g_autofree gchar *path = g_strconcat (base, names[i], NULL);
      g_autoptr(GBytes) bytes = g_resource_lookup_data (resource, path, 0, error);
      BIO *bio;
      X509 *certificate;
      int added;
      if (!bytes)
        goto fail;
      bio = BIO_new_mem_buf (g_bytes_get_data (bytes, NULL), g_bytes_get_size (bytes));
      if (!bio)
        goto fail;
      certificate = PEM_read_bio_X509 (bio, NULL, NULL, NULL);
      BIO_free (bio);
      if (!certificate)
        goto fail;
      added = X509_STORE_add_cert (store, certificate);
      X509_free (certificate);
      if (added != 1)
        goto fail;
    }
  return store;
fail:
  if (error && !*error)
    g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED,
                         "Unable to load complete SDCP trust store");
  X509_STORE_free (store);
  return NULL;
}

static gboolean
fpi_sdcp_verify_certificate (X509    *certificate,
                             GError **error)
{
  X509_STORE *sdcp_truststore = NULL;
  X509_VERIFY_PARAM *param = NULL;
  X509_STORE_CTX *ctx = NULL;

  sdcp_truststore = fpi_sdcp_get_truststore (error);
  if (*error)
    goto out_error;

  param = X509_VERIFY_PARAM_new ();
  if (!param)
    goto out_error;

  /*
   * Most model certificates expire after one year and are not renewed via a
   * vendor firmware update, so we should ignore the validity time check.
   */
  if (!X509_VERIFY_PARAM_set_flags (param, X509_V_FLAG_NO_CHECK_TIME))
    goto out_error;

  /* Do not allow broken certificates */
  if (!X509_VERIFY_PARAM_set_flags (param, X509_V_FLAG_X509_STRICT))
    goto out_error;

  /* set X509_V_FLAG_PARTIAL_CHAIN if we want to skip adding all root and intermediate certs */
  /*
     if (!X509_VERIFY_PARAM_set_flags (param, X509_V_FLAG_PARTIAL_CHAIN))
     goto out_error;
   */

  if (!X509_STORE_set1_param (sdcp_truststore, param))
    goto out_error;

  g_clear_pointer (&param, X509_VERIFY_PARAM_free);
  ctx = X509_STORE_CTX_new ();

  if(!X509_STORE_CTX_init (ctx, sdcp_truststore, certificate, NULL))
    goto out_verify_error;

  if (!X509_verify_cert (ctx))
    goto out_verify_error;

  X509_STORE_CTX_free (ctx);
  X509_STORE_free (sdcp_truststore);

  return TRUE;

out_error:
  g_propagate_error (error,
                     fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                               "OpenSSL error setting up certificate verification"));
  print_openssl_errors ();
  goto out;
out_verify_error:
  g_propagate_error (error,
                     fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                               "OpenSSL error verifying model certificate: %s",
                                               X509_verify_cert_error_string (X509_STORE_CTX_get_error (ctx))));
out:
  g_clear_pointer (&param, X509_VERIFY_PARAM_free);
  g_clear_pointer (&ctx, X509_STORE_CTX_free);
  X509_STORE_free (sdcp_truststore);
  return FALSE;
}

static GBytes *
fpi_sdcp_kdf (GBytes      *key,
              const gchar *label,
              GBytes      *context_a,
              GBytes      *context_b,
              gsize        length,
              GError     **error)
{
  g_autoptr(GBytes) res = NULL;
  guint8 *secret = NULL;
  EVP_KDF *kdf;
  EVP_KDF_CTX *kdf_ctx;
  OSSL_PARAM params[8];
  int i = 0;

  g_assert (key);
  g_assert (strlen (label) > 0);
  g_assert (length > 0);

  params[i++] = OSSL_PARAM_construct_utf8_string (OSSL_KDF_PARAM_MODE, (gchar *) "counter", 0);
  params[i++] = OSSL_PARAM_construct_utf8_string (OSSL_KDF_PARAM_MAC, (gchar *) "HMAC", 0);
  params[i++] = OSSL_PARAM_construct_utf8_string (OSSL_KDF_PARAM_DIGEST, (gchar *) "SHA2-256", 0);

  params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_KEY,
                                                   (void *) (g_bytes_get_data (key, NULL)),
                                                   g_bytes_get_size (key));

  params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_SALT,
                                                   (void *) label,
                                                   strlen (label));

  if (context_a)
    params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_INFO,
                                                     (void *) (g_bytes_get_data (context_a, NULL)),
                                                     g_bytes_get_size (context_a));

  if (context_b)
    params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_INFO,
                                                     (void *) (g_bytes_get_data (context_b, NULL)),
                                                     g_bytes_get_size (context_b));

  params[i++] = OSSL_PARAM_construct_end ();

  kdf = EVP_KDF_fetch (NULL, "KBKDF", NULL);
  kdf_ctx = EVP_KDF_CTX_new (kdf);

  secret = g_malloc0 (length);
  if (!EVP_KDF_derive (kdf_ctx, secret, length, params))
    {
      g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                          "OpenSSL error during key derivation "
                                                          "for label '%s'", label));
      g_free (secret);
      EVP_KDF_CTX_free (kdf_ctx);
      EVP_KDF_free (kdf);
      print_openssl_errors ();
      return NULL;
    }

  EVP_KDF_CTX_free (kdf_ctx);
  EVP_KDF_free (kdf);

  res = g_bytes_new_take (secret, length);

  return g_steal_pointer (&res);
}

static GBytes *
fpi_sdcp_mac (GBytes      *application_secret,
              const gchar *label,
              GBytes      *data_a,
              GBytes      *data_b,
              GError     **error)
{
  g_autoptr(GBytes) res = NULL;

  EVP_MAC *hmac;
  EVP_MAC_CTX *hmac_ctx;
  guint8 *mac = NULL;
  gsize mac_len = 0;

  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string (OSSL_MAC_PARAM_DIGEST, (gchar *) "SHA256", 0),
    OSSL_PARAM_construct_end (),
  };

  hmac = EVP_MAC_fetch (NULL, "hmac", NULL);
  hmac_ctx = EVP_MAC_CTX_new (hmac);

  if (!EVP_MAC_init (hmac_ctx,
                     g_bytes_get_data (application_secret, NULL),
                     g_bytes_get_size (application_secret),
                     params))
    goto out_error;

  if (label)
    if (!EVP_MAC_update (hmac_ctx, (guchar *) label, strlen (label) + 1)) /* +1 due to unsigned */
      goto out_error;

  if (data_a)
    if (!EVP_MAC_update (hmac_ctx, g_bytes_get_data (data_a, NULL), g_bytes_get_size (data_a)))
      goto out_error;

  if (data_b)
    if (!EVP_MAC_update (hmac_ctx, g_bytes_get_data (data_b, NULL), g_bytes_get_size (data_b)))
      goto out_error;

  mac = g_malloc0 (SDCP_MAC_SIZE);
  if (!EVP_MAC_final (hmac_ctx, mac, &mac_len, SDCP_MAC_SIZE))
    goto out_error;

  if (mac_len != SDCP_MAC_SIZE)
    goto out_error;

  EVP_MAC_CTX_free (hmac_ctx);
  EVP_MAC_free (hmac);

  res = g_bytes_new_take (mac, mac_len);
  return g_steal_pointer (&res);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error generating MAC for label '%s'",
                                                      label));
  print_openssl_errors ();
  g_clear_pointer (&mac, g_free);
  g_clear_pointer (&hmac_ctx, EVP_MAC_CTX_free);
  g_clear_pointer (&hmac, EVP_MAC_free);
  return NULL;
}

static GBytes *
fpi_sdcp_get_private_key (EVP_PKEY *pkey,
                          GError  **error)
{
  g_autoptr(GBytes) res = NULL;
  BIGNUM *priv_bn = NULL;
  guint8 *priv = NULL;
  gsize priv_len = 0;

  g_assert_nonnull (pkey);

  if (!EVP_PKEY_get_bn_param (pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn))
    goto out_error;

  priv_len = SDCP_PRIVATE_KEY_SIZE;
  priv = g_malloc0 (priv_len);
  if (BN_bn2binpad (priv_bn, priv, priv_len) != priv_len)
    goto out_error;

  BN_clear_free (priv_bn);

  res = g_bytes_new_take (priv, priv_len);

  return g_steal_pointer (&res);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error getting private key bytes"));
  print_openssl_errors ();
  g_clear_pointer (&priv, g_free);
  g_clear_pointer (&priv_bn, BN_clear_free);
  return NULL;
}

static GBytes *
fpi_sdcp_get_public_key (EVP_PKEY *pkey,
                         GError  **error)
{
  g_autoptr(GBytes) res = NULL;
  guint8 *pub = NULL;
  gsize pub_len = 0;

  g_assert_nonnull (pkey);

  pub = g_malloc0 (SDCP_PUBLIC_KEY_SIZE);
  if (!EVP_PKEY_get_octet_string_param (pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, SDCP_PUBLIC_KEY_SIZE, &pub_len))
    goto out_error;

  if (pub_len != SDCP_PUBLIC_KEY_SIZE)
    goto out_error;

  res = g_bytes_new_take (pub, pub_len);

  return g_steal_pointer (&res);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error getting public key bytes"));
  print_openssl_errors ();
  g_clear_pointer (&pub, g_free);
  return NULL;
}

static EVP_PKEY *
fpi_sdcp_get_private_pkey (GBytes  *private_key,
                           GError **error)
{
  BIGNUM *private_key_bn = NULL;
  EC_GROUP *group = NULL;
  EC_POINT *public_key_point = NULL;
  g_autofree guint8 *public_key_buf = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
  OSSL_PARAM_BLD *param_bld = NULL;
  OSSL_PARAM *params = NULL;

  if (g_bytes_get_size (private_key) != SDCP_PRIVATE_KEY_SIZE)
    goto out_error;

  /* import private key as a BIGNUM */
  private_key_bn = BN_bin2bn (g_bytes_get_data (private_key, NULL),
                              g_bytes_get_size (private_key),
                              NULL);

  /* set up public key based on imported private_key_bn */
  group = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
  public_key_point = EC_POINT_new (group);
  if (!EC_POINT_mul (group, public_key_point, private_key_bn, NULL, NULL, NULL))
    goto out_error;
  public_key_buf = g_malloc0 (SDCP_PUBLIC_KEY_SIZE);
  if (!EC_POINT_point2oct (group, public_key_point, POINT_CONVERSION_UNCOMPRESSED,
                           public_key_buf, SDCP_PUBLIC_KEY_SIZE, NULL))
    goto out_error;
  EC_POINT_free (public_key_point);
  EC_GROUP_free (group);

  /* set up parameters */

  param_bld = OSSL_PARAM_BLD_new ();
  if (!OSSL_PARAM_BLD_push_utf8_string (param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        SN_X9_62_prime256v1, sizeof (SN_X9_62_prime256v1)))
    goto out_error;
  if (!OSSL_PARAM_BLD_push_octet_string (param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         public_key_buf, SDCP_PUBLIC_KEY_SIZE))
    goto out_error;
  if (!OSSL_PARAM_BLD_push_BN (param_bld, OSSL_PKEY_PARAM_PRIV_KEY, private_key_bn))
    goto out_error;

  params = OSSL_PARAM_BLD_to_param (param_bld);

  /* import pkey from params */
  ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (!EVP_PKEY_fromdata_init (ctx))
    goto out_error;
  EVP_PKEY_fromdata (ctx, &key, EVP_PKEY_KEYPAIR, params);

  EVP_PKEY_CTX_free (ctx);
  OSSL_PARAM_free (params);
  OSSL_PARAM_BLD_free (param_bld);
  BN_clear_free (private_key_bn);

  return g_steal_pointer (&key);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error getting private key"));
  print_openssl_errors ();
  g_clear_pointer (&key, EVP_PKEY_free);
  g_clear_pointer (&ctx, EVP_PKEY_CTX_free);
  g_clear_pointer (&params, OSSL_PARAM_free);
  g_clear_pointer (&param_bld, OSSL_PARAM_BLD_free);
  g_clear_pointer (&public_key_point, EC_POINT_free);
  g_clear_pointer (&group, EC_GROUP_free);
  g_clear_pointer (&private_key_bn, BN_clear_free);
  return NULL;
}

static EVP_PKEY *
fpi_sdcp_get_public_pkey (GBytes  *public_key,
                          GError **error)
{
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
  OSSL_PARAM params[3];

  params[0] = OSSL_PARAM_construct_utf8_string (OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *) SN_X9_62_prime256v1,
                                                sizeof (SN_X9_62_prime256v1));
  params[1] = OSSL_PARAM_construct_octet_string (OSSL_PKEY_PARAM_PUB_KEY,
                                                 (char *) g_bytes_get_data (public_key, NULL),
                                                 g_bytes_get_size (public_key));
  params[2] = OSSL_PARAM_construct_end ();

  ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (!ctx)
    goto out_error;

  if (!EVP_PKEY_fromdata_init (ctx))
    goto out_error;

  if (!EVP_PKEY_fromdata (ctx, &key, EVP_PKEY_PUBLIC_KEY, params))
    goto out_error;

  EVP_PKEY_CTX_free (ctx);

  return g_steal_pointer (&key);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error getting public key"));
  print_openssl_errors ();
  g_clear_pointer (&key, EVP_PKEY_free);
  g_clear_pointer (&ctx, EVP_PKEY_CTX_free);
  return NULL;
}

static GBytes *
fpi_sdcp_hash_claim (FpiSdcpClaim *claim,
                     GError      **error)
{
  g_autoptr(GBytes) res = NULL;
  EVP_MD_CTX *sh256_ctx;
  EVP_MD *sha256;
  guint8 *hash = NULL;
  guint hash_len = 0;

  sh256_ctx = EVP_MD_CTX_create ();
  sha256 = EVP_MD_fetch (NULL, "SHA256", NULL);
  if (!EVP_DigestInit_ex (sh256_ctx, sha256, NULL))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->model_certificate, NULL),
                         g_bytes_get_size (claim->model_certificate)))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->device_public_key, NULL),
                         g_bytes_get_size (claim->device_public_key)))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->firmware_public_key, NULL),
                         g_bytes_get_size (claim->firmware_public_key)))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->firmware_hash, NULL),
                         g_bytes_get_size (claim->firmware_hash)))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->model_signature, NULL),
                         g_bytes_get_size (claim->model_signature)))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->device_signature, NULL),
                         g_bytes_get_size (claim->device_signature)))
    goto out_error;

  hash = g_malloc0 (EVP_MAX_MD_SIZE);
  if (!EVP_DigestFinal_ex (sh256_ctx, hash, &hash_len))
    goto out_error;

  EVP_MD_CTX_free (sh256_ctx);
  EVP_MD_free (sha256);

  res = g_bytes_new_take (hash, hash_len);
  return g_steal_pointer (&res);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error hashing the SDCP claim"));
  print_openssl_errors ();
  g_clear_pointer (&sh256_ctx, EVP_MD_CTX_free);
  g_clear_pointer (&sha256, EVP_MD_free);
  g_clear_pointer (&hash, g_free);
  return NULL;
}

static GBytes *
fpi_sdcp_key_agreement (GBytes  *host_private_key,
                        GBytes  *firmware_public_key,
                        GError **error)
{
  g_autoptr(GBytes) res = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *host_pkey = NULL;
  EVP_PKEY *device_pkey = NULL;
  guint8 *key_agreement = NULL;
  gsize key_agreement_len = 0;

  host_pkey = fpi_sdcp_get_private_pkey (host_private_key, error);
  if (*error)
    goto out;

  device_pkey = fpi_sdcp_get_public_pkey (firmware_public_key, error);
  if (*error)
    goto out;

  ctx = EVP_PKEY_CTX_new_from_pkey (NULL, host_pkey, NULL);

  if (!EVP_PKEY_derive_init (ctx))
    goto out_error;

  if (!EVP_PKEY_derive_set_peer (ctx, device_pkey))
    goto out_error;

  /* Get the size by passing NULL as the buffer */
  if (!EVP_PKEY_derive (ctx, NULL, &key_agreement_len))
    goto out_error;

  if (key_agreement_len != SDCP_KEY_AGREEMENT_SIZE)
    goto out_error;

  /* Then get the derived shared secret using the fetched size */
  key_agreement = g_malloc0 (key_agreement_len);
  if (!EVP_PKEY_derive (ctx, key_agreement, &key_agreement_len))
    goto out_error;

  EVP_PKEY_CTX_free (ctx);
  EVP_PKEY_free (device_pkey);
  EVP_PKEY_free (host_pkey);

  res = g_bytes_new_take (key_agreement, key_agreement_len);

  return g_steal_pointer (&res);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error deriving key agreement"));
  print_openssl_errors ();
out:
  g_clear_pointer (&key_agreement, g_free);
  g_clear_pointer (&ctx, EVP_PKEY_CTX_free);
  g_clear_pointer (&host_pkey, EVP_PKEY_free);
  g_clear_pointer (&device_pkey, EVP_PKEY_free);
  return NULL;
}

/******************************************************************************/

void
fpi_sdcp_generate_host_key (GBytes **private_key,
                            GBytes **public_key,
                            GError **error)
{
  EVP_PKEY *key = EVP_EC_gen ("P-256");

  if (*private_key)
    g_bytes_unref (*private_key);
  *private_key = fpi_sdcp_get_private_key (key, error);
  if (*error)
    goto out;

  if (*public_key)
    g_bytes_unref (*public_key);
  *public_key = fpi_sdcp_get_public_key (key, error);
  if (*error)
    goto out;

  EVP_PKEY_free (key);

  return;

out:
  print_openssl_errors ();
  g_clear_pointer (&key, EVP_PKEY_free);
  return;
}

GBytes *
fpi_sdcp_generate_random (GError **error)
{
  g_autoptr(GBytes) res = NULL;
  guint8 *random = g_malloc0 (SDCP_RANDOM_SIZE);

  if (!RAND_bytes (random, SDCP_RANDOM_SIZE))
    {
      g_propagate_error (error,
                         fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                   "OpenSSL error generating random"));
      print_openssl_errors ();
      g_free (random);
      return NULL;
    }

  res = g_bytes_new_take (random, SDCP_RANDOM_SIZE);

  return g_steal_pointer (&res);
}

static gboolean
sdcp_bytes_size (GBytes *bytes, gsize size)
{
  return bytes && g_bytes_get_size (bytes) == size;
}

static gboolean
sdcp_claim_has_valid_sizes (FpiSdcpClaim *claim)
{
  return claim && claim->model_certificate &&
    g_bytes_get_size (claim->model_certificate) > 0 &&
    g_bytes_get_size (claim->model_certificate) <= G_MAXUINT16 &&
    sdcp_bytes_size (claim->device_public_key, SDCP_PUBLIC_KEY_SIZE) &&
    sdcp_bytes_size (claim->firmware_public_key, SDCP_PUBLIC_KEY_SIZE) &&
    sdcp_bytes_size (claim->firmware_hash, SDCP_MAC_SIZE) &&
    sdcp_bytes_size (claim->model_signature, SDCP_SIGNATURE_SIZE) &&
    sdcp_bytes_size (claim->device_signature, SDCP_SIGNATURE_SIZE);
}

gboolean
fpi_sdcp_verify_attestation (FpiSdcpClaim *claim,
                              gboolean validate_certificate,
                              gboolean verify_signatures,
                              GError **error)
{
  static const guint8 firmware_prefix[] = { 0xc0, 0x01 };
  const guint8 *cert_data, *cert_end;
  gsize cert_len;
  X509 *cert = NULL;
  EVP_PKEY *model_key = NULL, *device_key = NULL;
  char group[80];
  gboolean valid = FALSE;

  if (!sdcp_claim_has_valid_sizes (claim))
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                           "Invalid SDCP claim field sizes");
      return FALSE;
    }
  cert_data = g_bytes_get_data (claim->model_certificate, &cert_len);
  cert_end = cert_data + cert_len;
  cert = d2i_X509 (NULL, &cert_data, cert_len);
  if (!cert || cert_data != cert_end)
    goto invalid;
  if (validate_certificate && !fpi_sdcp_verify_certificate (cert, error))
    goto out;
  if (verify_signatures)
    {
      model_key = X509_get_pubkey (cert);
      if (!model_key || !EVP_PKEY_is_a (model_key, "EC") ||
          !EVP_PKEY_get_group_name (model_key, group, sizeof (group), NULL) ||
          (g_strcmp0 (group, "prime256v1") != 0 && g_strcmp0 (group, "P-256") != 0))
        goto invalid;
      if (!fpi_sdcp_verify_signature (model_key, NULL, 0,
                                      claim->device_public_key, NULL,
                                      claim->model_signature, error))
        goto out;
      device_key = fpi_sdcp_get_public_pkey (claim->device_public_key, error);
      if (!device_key)
        goto out;
      if (!fpi_sdcp_verify_signature (device_key, firmware_prefix, sizeof (firmware_prefix),
                                      claim->firmware_hash, claim->firmware_public_key,
                                      claim->device_signature, error))
        goto out;
    }
  valid = TRUE;
  goto out;
invalid:
  g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED,
                       "Invalid SDCP model certificate or signing key");
out:
  EVP_PKEY_free (device_key);
  EVP_PKEY_free (model_key);
  X509_free (cert);
  return valid;
}

static gboolean
sdcp_mac_equal (GBytes *a, GBytes *b)
{
  return sdcp_bytes_size (a, SDCP_MAC_SIZE) && sdcp_bytes_size (b, SDCP_MAC_SIZE) &&
    CRYPTO_memcmp (g_bytes_get_data (a, NULL), g_bytes_get_data (b, NULL), SDCP_MAC_SIZE) == 0;
}

gboolean
fpi_sdcp_verify_connect (GBytes       *host_private_key,
                         GBytes       *host_random,
                         GBytes       *device_random,
                         FpiSdcpClaim *claim,
                         GBytes       *mac,
                         gboolean      validate_certificate,
                         gboolean      verify_signatures,
                         GBytes      **application_secret,
                         GError      **error)
{
  g_autoptr(GBytes) claim_hash = NULL;
  g_autoptr(GBytes) claim_mac = NULL;
  g_autoptr(GBytes) key_agreement = NULL;
  g_autoptr(GBytes) master_secret = NULL;
  g_autoptr(GBytes) application_keys = NULL;
  g_autoptr(GBytes) out_app_secret = NULL;
  guint8 *app_secret_buf = NULL;


  if (application_secret)
    g_clear_pointer (application_secret, g_bytes_unref);
  if (!application_secret || !sdcp_claim_has_valid_sizes (claim) ||
      !sdcp_bytes_size (host_private_key, SDCP_PRIVATE_KEY_SIZE) ||
      !sdcp_bytes_size (host_random, SDCP_RANDOM_SIZE) ||
      !sdcp_bytes_size (device_random, SDCP_RANDOM_SIZE) ||
      !sdcp_bytes_size (mac, SDCP_MAC_SIZE))
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                           "Invalid SDCP connection field sizes");
      return FALSE;
    }

  fp_dbg ("SDCP Verify ConnectResponse");

  /* SDCP Connect: 5.i. Perform key agreement */

  key_agreement = fpi_sdcp_key_agreement (host_private_key, claim->firmware_public_key, error);
  if (*error)
    goto out_error;


  /* SDCP Connect: 5.ii. Derive master secret */

  master_secret = fpi_sdcp_kdf (key_agreement, "master secret", host_random, device_random,
                                SDCP_MASTER_SECRET_SIZE, error);
  if (*error)
    goto out_error;


  /* SDCP Connect: 5.iii. Derive MAC secret and symetric key */

  application_keys = fpi_sdcp_kdf (master_secret, "application keys", NULL, NULL,
                                   SDCP_APPLICATION_KEYS_SIZE, error);
  if (*error)
    goto out_error;


  /* slice first half of application_keys as application_secret */
  g_assert (g_bytes_get_size (application_keys) >= SDCP_APPLICATION_SECRET_SIZE);
  app_secret_buf = g_malloc0 (SDCP_APPLICATION_SECRET_SIZE);
  memcpy (app_secret_buf,
          g_bytes_get_data (application_keys, NULL),
          SDCP_APPLICATION_SECRET_SIZE);

  out_app_secret = g_bytes_new_take (app_secret_buf, SDCP_APPLICATION_SECRET_SIZE);


  /* SDCP Connect: 5.iv. Validate the MAC over H(claim) */

  claim_hash = fpi_sdcp_hash_claim (claim, error);
  if (*error)
    goto out_error;

  claim_mac = fpi_sdcp_mac (out_app_secret, "connect", claim_hash, NULL, error);
  if (*error)
    goto out_error;

  fp_dbg ("Device MAC:");
  fp_dbg_hex_dump_gbytes (mac);

  fp_dbg ("Host MAC:");
  fp_dbg_hex_dump_gbytes (claim_mac);

  if (sdcp_mac_equal (mac, claim_mac))
    {
      fp_dbg ("SDCP ConnectResponse claim validated successfully");
    }
  else
    {
      g_propagate_error (error,
                         fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                   "SDCP ConnectResponse claim validation failed"));
      goto out;
    }


  /* SDCP Connect: 5.v. Unpack the claim (SKIP; already done) */
  /* SDCP Connect: 5.vi. Verify the claim */

  if ((validate_certificate || verify_signatures) &&
      !fpi_sdcp_verify_attestation (claim, validate_certificate, verify_signatures, error))
    goto out;

  /* output application_secret */

  if (*application_secret)
    g_bytes_unref (*application_secret);

  *application_secret = g_steal_pointer (&out_app_secret);

  return TRUE;

out_error:
  print_openssl_errors ();
out:
  if (!out_app_secret)
    g_clear_pointer (&app_secret_buf, g_free);
  return FALSE;
}

gboolean
fpi_sdcp_verify_reconnect (GBytes  *application_secret,
                           GBytes  *random,
                           GBytes  *mac,
                           GError **error)
{
  g_autoptr(GBytes) host_mac = NULL;

  if (!sdcp_bytes_size (application_secret, 32) ||
      !sdcp_bytes_size (random, 32) ||
      !sdcp_bytes_size (mac, 32))
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                           "Invalid SDCP authentication field sizes");
      return FALSE;
    }

  fp_dbg ("SDCP Verify ReconnectResponse");

  host_mac = fpi_sdcp_mac (application_secret, "reconnect", random, NULL, error);
  if (*error)
    return FALSE;

  fp_dbg ("Device MAC:");
  fp_dbg_hex_dump_gbytes (mac);

  fp_dbg ("Host MAC:");
  fp_dbg_hex_dump_gbytes (host_mac);

  if (sdcp_mac_equal (mac, host_mac))
    {
      fp_dbg ("SDCP ReconnectResponse verified successfully");
      return TRUE;
    }
  else
    {
      g_propagate_error (error,
                         fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                   "SDCP ReconnectResponse verification failed"));
      return FALSE;
    }
}

gboolean
fpi_sdcp_verify_identify (GBytes  *application_secret,
                          GBytes  *nonce,
                          GBytes  *id,
                          GBytes  *mac,
                          GError **error)
{
  g_autoptr(GBytes) host_mac = NULL;

  if (!sdcp_bytes_size (application_secret, 32) ||
      !sdcp_bytes_size (nonce, 32) ||
      !sdcp_bytes_size (id, 32) ||
      !sdcp_bytes_size (mac, 32))
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                           "Invalid SDCP authentication field sizes");
      return FALSE;
    }

  fp_dbg ("SDCP Verify AuthorizedIdentity");

  host_mac = fpi_sdcp_mac (application_secret, "identify", nonce, id, error);
  if (*error)
    return FALSE;

  fp_dbg ("Device MAC:");
  fp_dbg_hex_dump_gbytes (mac);

  fp_dbg ("Host MAC:");
  fp_dbg_hex_dump_gbytes (host_mac);

  if (sdcp_mac_equal (mac, host_mac))
    {
      fp_dbg ("SDCP AuthorizedIdentity verified successfully");
      return TRUE;
    }
  else
    {
      g_propagate_error (error,
                         fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                   "SDCP AuthorizedIdentity verification failed"));
      return FALSE;
    }
}

GBytes *
fpi_sdcp_generate_enrollment_id (GBytes  *application_secret,
                                 GBytes  *nonce,
                                 GError **error)
{
  g_autoptr(GBytes) id = NULL;

  id = fpi_sdcp_mac (application_secret, "enroll", nonce, NULL, error);
  if (*error)
    return NULL;

  fp_dbg ("Generated SDCP Enrollment ID:");
  fp_dbg_hex_dump_gbytes (id);

  return g_steal_pointer (&id);
}
