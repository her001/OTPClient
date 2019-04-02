#include <gtk/gtk.h>
#include <gcrypt.h>
#include <jansson.h>
#include "db-misc.h"

typedef struct _header_data {
    guint8 iv[IV_SIZE];
    guint8 salt[KDF_SALT_SIZE];
} HeaderData;

static guchar      *get_derived_key (const gchar *pwd, HeaderData *header_data);

static void         cleanup         (GFile *, gpointer, HeaderData *, GError *);

static              goffset get_file_size (const gchar *path);


int
encrypt_db (const gchar *db_path,
            const gchar *password)
{
    GError *err = NULL;
    gcry_cipher_hd_t hd;
    HeaderData *header_data = g_new0 (HeaderData, 1);

    gcry_create_nonce (header_data->iv, IV_SIZE);
    gcry_create_nonce (header_data->salt, KDF_SALT_SIZE);

    GFile *out_file = g_file_new_for_path ("/tmp/otpclient_db.enc");
    GFileOutputStream *out_stream = g_file_replace (out_file, NULL, FALSE, G_FILE_CREATE_REPLACE_DESTINATION, NULL, &err);
    if (err != NULL) {
        g_printerr ("%s\n", err->message);
        cleanup (out_file, NULL, header_data, err);
        return -1;
    }
    if (g_output_stream_write (G_OUTPUT_STREAM (out_stream), header_data, sizeof (HeaderData), NULL, &err) == -1) {
        g_printerr ("%s\n", err->message);
        cleanup (out_file, out_stream, header_data, err);
        return -1;
    }

    guchar *derived_key = get_derived_key (password, header_data);

    gsize input_data_len = get_file_size (db_path);
    guchar *enc_buffer = g_malloc0 (input_data_len);

    gcry_cipher_open (&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
    gcry_cipher_setkey (hd, derived_key, gcry_cipher_get_algo_keylen (GCRY_CIPHER_AES256));
    gcry_cipher_setiv (hd, header_data->iv, IV_SIZE);
    gcry_cipher_authenticate (hd, header_data, sizeof (HeaderData));
    gchar *input_data;
    g_file_get_contents (db_path, &input_data, NULL, NULL);
    gcry_cipher_encrypt (hd, enc_buffer, input_data_len, input_data, input_data_len);

    guchar tag[TAG_SIZE];
    gcry_cipher_gettag (hd, tag, TAG_SIZE); //append tag to outfile

    if (g_output_stream_write (G_OUTPUT_STREAM (out_stream), enc_buffer, input_data_len, NULL, &err) == -1) {
        cleanup (out_file, out_stream, header_data, err);
        gcry_cipher_close (hd);
        g_free (enc_buffer);
        gcry_free (derived_key);
        g_free (header_data);
        return -1;
    }
    if (g_output_stream_write (G_OUTPUT_STREAM (out_stream), tag, TAG_SIZE, NULL, &err) == -1) {
        cleanup (out_file, out_stream, header_data, err);
        gcry_cipher_close (hd);
        g_free (enc_buffer);
        gcry_free (derived_key);
        g_free (header_data);
        return -1;
    }
    g_object_unref (out_file);
    g_object_unref (out_stream);

    gcry_cipher_close (hd);
    gcry_free (derived_key);
    g_free (enc_buffer);
    g_free (header_data);

    return 0;
}


int
decrypt_db (const gchar *db_path,
            const gchar *password)
{
    GError *err = NULL;
    gcry_cipher_hd_t hd;
    HeaderData *header_data = g_new0 (HeaderData, 1);

    goffset input_file_size = get_file_size (db_path);

    GFile *in_file = g_file_new_for_path (db_path);
    GFileInputStream *in_stream = g_file_read (in_file, NULL, &err);
    if (err != NULL) {
        g_printerr ("%s\n", err->message);
        cleanup (in_file, NULL, header_data, err);
        return -1;
    }
    if (g_input_stream_read (G_INPUT_STREAM (in_stream), header_data, sizeof (HeaderData), NULL, &err) == -1) {
        g_printerr ("%s\n", err->message);
        cleanup (in_file, in_stream, header_data, err);
        return -1;
    }

    guchar tag[TAG_SIZE];
    if (!g_seekable_seek (G_SEEKABLE (in_stream), input_file_size - TAG_SIZE, G_SEEK_SET, NULL, &err)) {
        g_printerr ("%s\n", err->message);
        cleanup (in_file, in_stream, header_data, err);
        return -1;
    }
    if (g_input_stream_read (G_INPUT_STREAM (in_stream), tag, TAG_SIZE, NULL, &err) == -1) {
        g_printerr ("%s\n", err->message);
        cleanup (in_file, in_stream, header_data, err);
        return -1;
    }

    gsize enc_buf_size = input_file_size - sizeof (HeaderData) - TAG_SIZE;
    guchar *enc_buf = g_malloc0 (enc_buf_size);

    if (!g_seekable_seek (G_SEEKABLE (in_stream), sizeof (HeaderData), G_SEEK_SET, NULL, &err)) {
        g_printerr ("%s\n", err->message);
        cleanup (in_file, in_stream, header_data, err);
        g_free (enc_buf);
        return -1;
    }
    if (g_input_stream_read (G_INPUT_STREAM (in_stream), enc_buf, enc_buf_size, NULL, &err) == -1) {
        g_printerr ("%s\n", err->message);
        cleanup (in_file, in_stream, header_data, err);
        g_free (enc_buf);
        return -1;
    }
    g_object_unref (in_stream);
    g_object_unref (in_file);

    guchar *derived_key = get_derived_key (password, header_data);

    gcry_cipher_open (&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
    gcry_cipher_setkey (hd, derived_key, gcry_cipher_get_algo_keylen (GCRY_CIPHER_AES256));
    gcry_cipher_setiv (hd, header_data->iv, IV_SIZE);
    gcry_cipher_authenticate (hd, header_data, sizeof (HeaderData));

    gchar *dec_buf = gcry_calloc_secure (enc_buf_size, 1);
    gcry_cipher_decrypt (hd, dec_buf, enc_buf_size, enc_buf, enc_buf_size);
    if (gcry_err_code (gcry_cipher_checktag (hd, tag, TAG_SIZE)) == GPG_ERR_CHECKSUM) {
        g_printerr("Wrong password\n");
        gcry_cipher_close (hd);
        gcry_free (derived_key);
        g_free (header_data);
        g_free (enc_buf);
        return -2;
    }

    gcry_cipher_close (hd);
    gcry_free (derived_key);
    g_free (header_data);
    g_free (enc_buf);

    FILE *fp = fopen ("/tmp/otpclient_db_plaintext.json", "w");
    fwrite (dec_buf, enc_buf_size, 1, fp);
    fclose (fp);

    return 0;
}


static guchar *
get_derived_key (const gchar    *pwd,
                 HeaderData     *header_data)
{
    gsize key_len = gcry_cipher_get_algo_keylen (GCRY_CIPHER_AES256);
    gsize pwd_len = strlen (pwd) + 1;

    guchar *derived_key = gcry_malloc_secure (key_len);
    if (derived_key == NULL) {
        g_printerr ("Couldn't allocate secure memory\n");
        return NULL;
    }

    int ret = gcry_kdf_derive (pwd, pwd_len, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, header_data->salt, KDF_SALT_SIZE, KDF_ITERATIONS, key_len, derived_key);
    if (ret != 0) {
        gcry_free (derived_key);
        g_printerr ("Error during key derivation\n");
        return NULL;
    }
    return derived_key;
}


static void
cleanup (GFile      *in_file,
         gpointer    in_stream,
         HeaderData *header_data,
         GError     *err)
{
    g_object_unref (in_file);
    if (in_stream != NULL)
        g_object_unref (in_stream);
    g_free (header_data);
    g_clear_error (&err);
}


goffset
get_file_size (const gchar *file_path)
{
    GFileInfo *info;
    GFile *file;
    GError *error = NULL;
    const gchar *attributes = "standard::*";
    GFileQueryInfoFlags flags = G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS;
    GCancellable *cancellable = NULL;
    goffset file_size;

    file = g_file_new_for_path (file_path);
    info = g_file_query_info (G_FILE (file), attributes, flags, cancellable, &error);
    if (info == NULL) {
        g_printerr ("%s\n", error->message);
        g_clear_error (&error);
        return -1;
    }
    file_size = g_file_info_get_size (info);

    g_object_unref (file);

    return file_size;
}