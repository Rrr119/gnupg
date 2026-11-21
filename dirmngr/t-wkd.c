/* t-wkd.c - Tests for the Web Key Directory helpers
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

#define INCLUDED_BY_MAIN_MODULE 1
#include "dirmngr.h"
#include "../common/util.h"
#include "t-support.h"
#include "wkd.h"

#define PGM "t-wkd"


struct mock_fetch_s
{
  int calls;
  int failures;
  const char *data;
};

static struct mock_fetch_s mock_fetch_state;


static gpg_error_t
mock_fetch (ctrl_t ctrl, const char *url, estream_t outfp)
{
  size_t nwritten;

  (void)ctrl;
  (void)url;
  mock_fetch_state.calls++;
  if (mock_fetch_state.failures)
    {
      mock_fetch_state.failures--;
      return gpg_error (GPG_ERR_NO_DATA);
    }
  if (outfp
      && es_write (outfp, mock_fetch_state.data,
                   strlen (mock_fetch_state.data), &nwritten))
    return gpg_error_from_syserror ();
  return 0;
}


static char *
stream_to_string (estream_t fp)
{
  long len;
  char *buffer;
  size_t nread;

  len = es_ftell (fp);
  if (len < 0 || es_fseek (fp, 0, SEEK_SET))
    return NULL;
  buffer = xtrymalloc (len + 1);
  if (!buffer)
    return NULL;
  if (len && es_read (fp, buffer, len, &nread))
    {
      xfree (buffer);
      return NULL;
    }
  buffer[len] = 0;
  return buffer;
}


static void
test_make_url (void)
{
  static const struct
  {
    const char *mailbox;
    wkd_request_t request;
    const char *host;
    unsigned int port;
    const char *wkd_domain;
    const char *expected;
    gpg_error_t expected_err;
  } tests[] = {
    { "foo@example.org", WKD_REQUEST_KEY, "openpgpkey.example.org", 0,
      NULL,
      "https://openpgpkey.example.org/.well-known/openpgpkey/hu/"
      "4d1d4dkkcsr3rffe85s1r3494ojjtwae?l=foo@example.org", 0 },
    { "foo@example.org", WKD_REQUEST_KEY, "openpgpkey.example.org", 444,
      "example.org",
      "https://openpgpkey.example.org:444/.well-known/openpgpkey/"
      "example.org/hu/4d1d4dkkcsr3rffe85s1r3494ojjtwae"
      "?l=foo@example.org", 0 },
    { "a+b@example.org", WKD_REQUEST_KEY, "openpgpkey.example.org", 0,
      NULL,
      "https://openpgpkey.example.org/.well-known/openpgpkey/hu/"
      "cbijmnujhwykxstodcnjnyo6cueohapi?l=a%2Bb@example.org", 0 },
    { "foo@example.org", WKD_REQUEST_POLICY, "openpgpkey.example.org", 0,
      "example.org",
      "https://openpgpkey.example.org/.well-known/openpgpkey/"
      "example.org/policy", 0 },
    { "foo@example.org", WKD_REQUEST_SUBMISSION, "example.org", 0,
      NULL,
      "https://example.org/.well-known/openpgpkey/submission-address", 0 },
    { "foo@example.org", WKD_REQUEST_KEY, "openpgpkey.example.org", 0,
      "bad/domain", NULL, GPG_ERR_INV_VALUE },
    { "foo", WKD_REQUEST_KEY, "openpgpkey.example.org", 0,
      NULL, NULL, GPG_ERR_INV_VALUE },
    { "foo@example.org", WKD_REQUEST_KEY, "openpgpkey.example.org", 65536,
      NULL, NULL, GPG_ERR_INV_ARG },
  };
  int idx;

  for (idx = 0; idx < DIM (tests); idx++)
    {
      gpg_error_t err;
      char *url = NULL;

      err = wkd_make_url (tests[idx].mailbox, tests[idx].request,
                          tests[idx].host, tests[idx].port,
                          tests[idx].wkd_domain, &url);
      if (gpg_err_code (err) != tests[idx].expected_err)
        fail (idx);
      if (err)
        {
          if (url)
            fail (idx);
          continue;
        }
      if (!url || strcmp (url, tests[idx].expected))
        {
          fprintf (stderr, "want: '%s'\n", tests[idx].expected);
          fprintf (stderr, "got : '%s'\n", url? url : "(null)");
          fail (idx);
        }
      xfree (url);
    }
}


static void
test_fetch_cache (void)
{
  gpg_error_t err;
  estream_t outfp;
  char *result;
  char *url = "https://openpgpkey.example.org/.well-known/openpgpkey/"
              "hu/4d1d4dkkcsr3rffe85s1r3494ojjtwae?l=foo@example.org";
  int cached;

  wkd_cache_flush ();
  mock_fetch_state.calls = 0;
  mock_fetch_state.failures = 0;
  mock_fetch_state.data = "mock-key";

  outfp = es_fopenmem (0, "w+b");
  if (!outfp)
    fail (100);
  err = wkd_fetch_cached (NULL, url, 60, mock_fetch, outfp, &cached, 100);
  if (err || cached || mock_fetch_state.calls != 1)
    fail (101);
  result = stream_to_string (outfp);
  if (!result || strcmp (result, "mock-key"))
    fail (102);
  xfree (result);
  es_fclose (outfp);

  outfp = es_fopenmem (0, "w+b");
  if (!outfp)
    fail (103);
  err = wkd_fetch_cached (NULL, url, 60, mock_fetch, outfp, &cached, 120);
  if (err || !cached || mock_fetch_state.calls != 1)
    fail (104);
  result = stream_to_string (outfp);
  if (!result || strcmp (result, "mock-key"))
    fail (105);
  xfree (result);
  es_fclose (outfp);

  outfp = es_fopenmem (0, "w+b");
  if (!outfp)
    fail (106);
  err = wkd_fetch_cached (NULL, url, 60, mock_fetch, outfp, &cached, 161);
  if (err || cached || mock_fetch_state.calls != 2)
    fail (107);
  es_fclose (outfp);

  err = wkd_fetch_cached (NULL, url, 60, mock_fetch, NULL, &cached, 170);
  if (err || !cached || mock_fetch_state.calls != 2)
    fail (108);

  wkd_cache_flush ();
  err = wkd_fetch_cached (NULL, url, 0, mock_fetch, NULL, &cached, 180);
  if (err || cached || mock_fetch_state.calls != 3)
    fail (109);

  wkd_cache_flush ();
}


static void
test_failed_fetch_not_cached (void)
{
  gpg_error_t err;
  const char *url = "https://openpgpkey.example.org/.well-known/openpgpkey/"
                    "hu/ug8isgf3edsnoc1fgenw6x5jnp9dhwqf"
                    "?l=joe.doe@example.org";
  int cached;

  wkd_cache_flush ();
  mock_fetch_state.calls = 0;
  mock_fetch_state.failures = 1;
  mock_fetch_state.data = "second-try";

  err = wkd_fetch_cached (NULL, url, 60, mock_fetch, NULL, &cached, 200);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA || cached
      || mock_fetch_state.calls != 1)
    fail (200);

  err = wkd_fetch_cached (NULL, url, 60, mock_fetch, NULL, &cached, 201);
  if (err || cached || mock_fetch_state.calls != 2)
    fail (201);

  err = wkd_fetch_cached (NULL, url, 60, mock_fetch, NULL, &cached, 202);
  if (err || !cached || mock_fetch_state.calls != 2)
    fail (202);

  wkd_cache_flush ();
}


static void
test_domain_status_cache (void)
{
  const char *domain = "cache-test.example.org";

  if (domaininfo_is_wkd_not_supported (domain))
    fail (250);

  domaininfo_set_wkd_not_supported (domain);
  if (!domaininfo_is_wkd_not_supported (domain))
    fail (251);

  domaininfo_set_wkd_supported (domain);
  if (domaininfo_is_wkd_not_supported (domain))
    fail (252);

  domain = "not-found-test.example.org";
  domaininfo_set_wkd_not_found (domain);
  if (domaininfo_is_wkd_not_supported (domain))
    fail (253);
}


static void
test_cache_isolation (void)
{
  gpg_error_t err;
  const char *url1 = "https://example.org/wkd/one";
  const char *url2 = "https://example.org/wkd/two";
  int cached;

  wkd_cache_flush ();
  mock_fetch_state.calls = 0;
  mock_fetch_state.failures = 0;
  mock_fetch_state.data = "one";

  err = wkd_fetch_cached (NULL, url1, 60, mock_fetch, NULL, &cached, 300);
  if (err || cached || mock_fetch_state.calls != 1)
    fail (300);
  mock_fetch_state.data = "two";
  err = wkd_fetch_cached (NULL, url2, 60, mock_fetch, NULL, &cached, 300);
  if (err || cached || mock_fetch_state.calls != 2)
    fail (301);

  err = wkd_fetch_cached (NULL, url1, 60, mock_fetch, NULL, &cached, 300);
  if (err || !cached || mock_fetch_state.calls != 2)
    fail (302);

  wkd_cache_flush ();
}


int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  test_make_url ();
  test_fetch_cache ();
  test_failed_fetch_not_cached ();
  test_domain_status_cache ();
  test_cache_isolation ();

  return 0;
}
