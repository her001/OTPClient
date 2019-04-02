#include <glib.h>
#include <gcrypt.h>
#include <unistd.h>
#include "db-misc.h"

gint
main (gint    argc,
      gchar **argv)
{
    if (argc != 3 || g_utf8_strlen (argv[2], -1) < 3) {
        fprintf(stderr, "Usage: %s < -e | -d > <db_path>\n", argv[0]);
        return -1;
    }

    if (!gcry_check_version ("1.6.0")) {
        g_printerr ("The required version of GCrypt is 1.6.0 or greater.");
        return -1;
    }

    if (gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0)) {
        g_printerr ("Couldn't initialize secure memory.");
        return -1;
    }
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    gchar *tmppwd = getpass("Password for encryption and decryption: ");
    gchar *pwd = gcry_calloc_secure (strlen (tmppwd) + 1, 1);
    memcpy (pwd, tmppwd, strlen (tmppwd) + 1);
    memset (tmppwd, 0, strlen (tmppwd));

    if (g_strcmp0 (argv[1], "-d") == 0) {
        if (decrypt_db (argv[2], pwd) == 0) {
            g_print ("\n==> The unencrypted file has been saved to: /tmp/otpclient_db_plaintext.json\n");
        }
    } else if (g_strcmp0 (argv[1], "-e") == 0) {
        if (encrypt_db (argv[2], pwd) == 0) {
            g_print ("\n==> The encrypted file has been saved to: /tmp/otpclient_db.enc\n");
        }
    } else {
        fprintf(stderr, "Usage: %s < -e | -d > <db_path>\n", argv[0]);
        gcry_free (pwd);
        return -1;
    }

    gcry_free (pwd);

    return 0;
}