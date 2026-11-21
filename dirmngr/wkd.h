/* wkd.h - Web Key Directory helpers
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

#ifndef DIRMNGR_WKD_H
#define DIRMNGR_WKD_H 1

#include <time.h>

#include "../common/util.h"
#include "../common/fwddecl.h"


/* The maximum size of a key returned by the WKD.  */
#define WKD_MAX_RESULT_LENGTH (256 * 1024)

/* Default lifetime of a cached WKD key in seconds.  */
#define WKD_DEFAULT_CACHE_TTL 600


/* The kind of file to request from a WKD.  */
typedef enum
  {
    WKD_REQUEST_KEY = 0,
    WKD_REQUEST_POLICY,
    WKD_REQUEST_SUBMISSION
  } wkd_request_t;


/* Prototype of the network fetch function used by wkd_fetch_cached.  */
typedef gpg_error_t (*wkd_fetch_fn_t) (ctrl_t ctrl, const char *url,
                                       estream_t outfp);


char *wkd_make_hash (const char *mailbox);
gpg_error_t wkd_make_url (const char *mailbox, wkd_request_t request,
                          const char *host, unsigned int port,
                          const char *wkd_domain, char **r_url);

gpg_error_t wkd_fetch_cached (ctrl_t ctrl, const char *url,
                              unsigned int cache_ttl,
                              wkd_fetch_fn_t fetch, estream_t outfp,
                              int *r_cached, time_t now);

gpg_error_t wkd_cache_lookup (const char *url, void **r_data,
                              size_t *r_datalen, time_t now);
gpg_error_t wkd_cache_store (const char *url, const void *data,
                             size_t datalen, unsigned int ttl, time_t now);
void wkd_cache_flush (void);


#endif /* DIRMNGR_WKD_H */
