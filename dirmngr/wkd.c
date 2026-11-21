/* wkd.c - Web Key Directory helpers
 * Copyright (C) 2026 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#ifndef WITHOUT_NPTH
# include <npth.h>
#endif

#include "dirmngr.h"
#include "misc.h"
#include "http.h"
#include "../common/mbox-util.h"
#include "../common/zb32.h"
#include "wkd.h"


/* Number of buckets and limits for the in-process WKD result cache.  */
#define WKD_CACHE_BUCKETS 17
#define WKD_CACHE_MAX_ITEMS 64
#define WKD_CACHE_MAX_BYTES (2 * 1024 * 1024)


/* An item of the WKD result cache.  */
struct wkd_cache_s
{
  struct wkd_cache_s *next;
  char *url;
  void *data;
  size_t datalen;
  time_t expires;
};
typedef struct wkd_cache_s *wkd_cache_t;

static wkd_cache_t wkd_cache[WKD_CACHE_BUCKETS];
static size_t wkd_cache_items;
static size_t wkd_cache_bytes;

#ifndef WITHOUT_NPTH
static npth_mutex_t wkd_cache_lock = NPTH_MUTEX_INITIALIZER;

static void
lock_wkd_cache (void)
{
  int rc = npth_mutex_lock (&wkd_cache_lock);

  if (rc)
    log_fatal ("failed to acquire WKD cache lock: %s\n", strerror (rc));
}

static void
unlock_wkd_cache (void)
{
  int rc = npth_mutex_unlock (&wkd_cache_lock);

  if (rc)
    log_fatal ("failed to release WKD cache lock: %s\n", strerror (rc));
}
#else
# define lock_wkd_cache()   do { } while (0)
# define unlock_wkd_cache() do { } while (0)
#endif /* !WITHOUT_NPTH */


/* Return the hash bucket for URL.  */
static unsigned int
wkd_cache_bucket (const char *url)
{
  unsigned int hashval = 0;
  const unsigned char *s;

  for (s = (const unsigned char *)url; *s; s++)
    hashval = (hashval * 33) + *s;
  return hashval % WKD_CACHE_BUCKETS;
}


/* Return the WKD identifier for MAILBOX.  The caller must free the
 * result.  */
char *
wkd_make_hash (const char *mailbox)
{
  unsigned char digest[20];

  if (!mailbox || !*mailbox)
    return NULL;

  gcry_md_hash_buffer (GCRY_MD_SHA1, digest, mailbox, strlen (mailbox));
  return zb32_encode (digest, 8 * sizeof digest);
}


/* Build the URL for a WKD request.  MAILBOX is the canonical
 * local-part@domain address.  HOST is the host to contact and PORT is
 * the optional non-standard HTTPS port.  If WKD_DOMAIN is not NULL,
 * the advanced (openpgpkey sub-domain) layout is used.  */
gpg_error_t
wkd_make_url (const char *mailbox, wkd_request_t request,
              const char *host, unsigned int port,
              const char *wkd_domain, char **r_url)
{
  gpg_error_t err = 0;
  char *hash = NULL;
  char *escaped = NULL;
  char portstr[20] = { 0 };
  char *url = NULL;
  const char *leaf;
  const char *at;

  if (r_url)
    *r_url = NULL;
  if (!mailbox || !host || !r_url || port > 65535)
    return gpg_error (GPG_ERR_INV_ARG);
  at = strchr (mailbox, '@');
  if (!at || at == mailbox || !at[1] || strchr (at + 1, '@'))
    return gpg_error (GPG_ERR_INV_VALUE);

  switch (request)
    {
    case WKD_REQUEST_KEY:
      hash = wkd_make_hash (mailbox);
      if (!hash)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      escaped = http_escape_string (mailbox, "%;?&=+#");
      if (!escaped)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      leaf = "hu";
      break;

    case WKD_REQUEST_POLICY:
      leaf = "policy";
      break;

    case WKD_REQUEST_SUBMISSION:
      leaf = "submission-address";
      break;

    default:
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  if (wkd_domain)
    {
      if (!*wkd_domain || !is_valid_domain_name (wkd_domain))
        {
          err = gpg_error (GPG_ERR_INV_VALUE);
          goto leave;
        }
    }

  if (port)
    snprintf (portstr, sizeof portstr, ":%u", port);

  if (request == WKD_REQUEST_KEY)
    {
      if (wkd_domain)
        url = xtryasprintf
          ("https://%s%s/.well-known/openpgpkey/%s/%s/%s?l=%s",
           host, portstr, wkd_domain, leaf, hash, escaped);
      else
        url = xtryasprintf ("https://%s%s/.well-known/openpgpkey/%s/%s?l=%s",
                            host, portstr, leaf, hash, escaped);
    }
  else
    {
      if (wkd_domain)
        url = xtryasprintf ("https://%s%s/.well-known/openpgpkey/%s/%s",
                            host, portstr, wkd_domain, leaf);
      else
        url = xtryasprintf ("https://%s%s/.well-known/openpgpkey/%s",
                            host, portstr, leaf);
    }
  if (!url)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  *r_url = url;
  url = NULL;

 leave:
  xfree (url);
  xfree (escaped);
  xfree (hash);
  return err;
}


/* Lookup URL in the cache.  On success return a copy of the data at
 * R_DATA and its length at R_DATALEN.  */
gpg_error_t
wkd_cache_lookup (const char *url, void **r_data, size_t *r_datalen,
                  time_t now)
{
  gpg_error_t err;
  wkd_cache_t item;
  unsigned int bucket;

  if (!r_data || !r_datalen)
    return gpg_error (GPG_ERR_INV_ARG);
  *r_data = NULL;
  *r_datalen = 0;
  if (!url || !*url)
    return gpg_error (GPG_ERR_INV_ARG);

  bucket = wkd_cache_bucket (url);
  lock_wkd_cache ();
  for (item = wkd_cache[bucket]; item; item = item->next)
    if (!strcmp (item->url, url))
      break;

  if (!item || item->expires <= now || !item->datalen)
    {
      unlock_wkd_cache ();
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  *r_data = xtrymalloc (item->datalen);
  if (!*r_data)
    err = gpg_error_from_syserror ();
  else
    {
      memcpy (*r_data, item->data, item->datalen);
      *r_datalen = item->datalen;
      err = 0;
    }
  unlock_wkd_cache ();
  return err;
}


/* Remove ITEM from BUCKET.  The cache lock must be held.  */
static void
remove_cache_item (unsigned int bucket, wkd_cache_t item)
{
  wkd_cache_t *link;

  for (link = &wkd_cache[bucket]; *link; link = &(*link)->next)
    if (*link == item)
      {
        *link = item->next;
        wkd_cache_items--;
        wkd_cache_bytes -= item->datalen;
        xfree (item->url);
        xfree (item->data);
        xfree (item);
        return;
      }
}


/* Drop the item which expires first.  The cache lock must be held.  */
static void
evict_one_cache_item (void)
{
  wkd_cache_t item, victim = NULL;
  unsigned int bucket, victim_bucket = 0;

  for (bucket = 0; bucket < WKD_CACHE_BUCKETS; bucket++)
    for (item = wkd_cache[bucket]; item; item = item->next)
      if (!victim || item->expires < victim->expires)
        {
          victim = item;
          victim_bucket = bucket;
        }

  if (victim)
    remove_cache_item (victim_bucket, victim);
}


/* Store DATA under URL for TTL seconds.  Zero length data and data
 * larger than a WKD result are not cached.  */
gpg_error_t
wkd_cache_store (const char *url, const void *data, size_t datalen,
                 unsigned int ttl, time_t now)
{
  wkd_cache_t item, old;
  unsigned int bucket;

  if (!url || !*url || !data || !datalen || !ttl)
    return gpg_error (GPG_ERR_INV_ARG);
  if (datalen > WKD_MAX_RESULT_LENGTH)
    return gpg_error (GPG_ERR_TOO_LARGE);

  bucket = wkd_cache_bucket (url);
  item = xtrycalloc (1, sizeof *item);
  if (!item)
    return gpg_error_from_syserror ();
  item->url = xtrystrdup (url);
  item->data = xtrymalloc (datalen);
  if (!item->url || !item->data)
    {
      gpg_error_t err = gpg_error_from_syserror ();
      xfree (item->url);
      xfree (item->data);
      xfree (item);
      return err;
    }
  memcpy (item->data, data, datalen);
  item->datalen = datalen;
  item->expires = now + ttl;

  lock_wkd_cache ();
  for (old = wkd_cache[bucket]; old; old = old->next)
    if (!strcmp (old->url, url))
      {
        remove_cache_item (bucket, old);
        break;
      }

  while (wkd_cache_items >= WKD_CACHE_MAX_ITEMS
         || wkd_cache_bytes + datalen > WKD_CACHE_MAX_BYTES)
    evict_one_cache_item ();

  item->next = wkd_cache[bucket];
  wkd_cache[bucket] = item;
  wkd_cache_items++;
  wkd_cache_bytes += datalen;
  unlock_wkd_cache ();
  return 0;
}


/* Remove all cached WKD results.  */
void
wkd_cache_flush (void)
{
  wkd_cache_t item, next;
  unsigned int bucket;

  lock_wkd_cache ();
  for (bucket = 0; bucket < WKD_CACHE_BUCKETS; bucket++)
    {
      for (item = wkd_cache[bucket]; item; item = next)
        {
          next = item->next;
          xfree (item->url);
          xfree (item->data);
          xfree (item);
        }
      wkd_cache[bucket] = NULL;
    }
  wkd_cache_items = 0;
  wkd_cache_bytes = 0;
  unlock_wkd_cache ();
}


/* Fetch URL via FETCH, optionally using and updating the WKD result
 * cache.  If OUTFP is not NULL the result is copied to it.  R_CACHED
 * is set to true if the result came from the cache.
 *
 * Network errors are deliberately not cached.  This keeps a failed
 * WKD lookup from hiding a later keyserver fallback.  */
gpg_error_t
wkd_fetch_cached (ctrl_t ctrl, const char *url, unsigned int cache_ttl,
                  wkd_fetch_fn_t fetch, estream_t outfp,
                  int *r_cached, time_t now)
{
  gpg_error_t err;
  estream_t memfp = NULL;
  void *cached = NULL;
  size_t cachedlen = 0;
  char *buffer = NULL;
  size_t nread, ntotal;
  long length;

  if (r_cached)
    *r_cached = 0;
  if (!url || !fetch)
    return gpg_error (GPG_ERR_INV_ARG);

  if (cache_ttl
      && !wkd_cache_lookup (url, &cached, &cachedlen, now))
    {
      if (outfp)
        {
          memfp = es_fopenmem_init (0, "rb", cached, cachedlen);
          if (!memfp)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          err = copy_stream (memfp, outfp);
          if (err)
            goto leave;
        }
      if (r_cached)
        *r_cached = 1;
      err = 0;
      goto leave;
    }
  xfree (cached);
  cached = NULL;

  if (!cache_ttl)
    {
      err = fetch (ctrl, url, outfp);
      if (gpg_err_code (err) == GPG_ERR_ENOSPC)
        err = gpg_error (GPG_ERR_TOO_LARGE);
      return err;
    }

  memfp = es_fopenmem (WKD_MAX_RESULT_LENGTH, "w+b");
  if (!memfp)
    return gpg_error_from_syserror ();

  err = fetch (ctrl, url, memfp);
  if (gpg_err_code (err) == GPG_ERR_ENOSPC)
    err = gpg_error (GPG_ERR_TOO_LARGE);
  if (err)
    goto leave;

  length = es_ftell (memfp);
  if (length < 0)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if ((size_t)length > WKD_MAX_RESULT_LENGTH)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto leave;
    }
  if (es_fseek (memfp, 0, SEEK_SET))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (outfp)
    {
      err = copy_stream (memfp, outfp);
      if (err)
        goto leave;
    }

  if (length)
    {
      if (es_fseek (memfp, 0, SEEK_SET))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      buffer = xtrymalloc (length);
      if (!buffer)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      ntotal = 0;
      while (ntotal < (size_t)length)
        {
          if (es_read (memfp, buffer + ntotal, length - ntotal, &nread))
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          if (!nread)
            {
              err = gpg_error (GPG_ERR_EOF);
              goto leave;
            }
          ntotal += nread;
        }
      err = wkd_cache_store (url, buffer, ntotal, cache_ttl, now);
      if (gpg_err_code (err) == GPG_ERR_INV_ARG)
        err = 0;
      else if (err)
        {
          log_info ("failed to cache WKD result: %s\n", gpg_strerror (err));
          err = 0;
        }
    }

 leave:
  xfree (buffer);
  xfree (cached);
  es_fclose (memfp);
  return err;
}
