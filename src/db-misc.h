#pragma once

#include <jansson.h>

G_BEGIN_DECLS

#define IV_SIZE                 16
#define KDF_ITERATIONS          100000
#define KDF_SALT_SIZE           32
#define TAG_SIZE                16

gint encrypt_db      (const gchar *db_path, const gchar *password);

gint decrypt_db      (const gchar *db_path, const gchar *password);

G_END_DECLS