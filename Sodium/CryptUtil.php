<!-----------第二种加密方法------------------------- Encrypt a file using a key derived from a password:------------第一种加密方法----------------->
<!--API网址：https://www.php.net/manual/zh/intro.sodium.php-->
<?php
$password = 'password';
$input_file = '/tmp/example.original';
$encrypted_file = '/tmp/example.enc';
$chunk_size = 4096;

$alg = SODIUM_CRYPTO_PWHASH_ALG_DEFAULT;
$opslimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
$memlimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
$salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);

$secret_key = sodium_crypto_pwhash(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    $password, $salt, $opslimit, $memlimit, $alg);

$fd_in = fopen($input_file, 'rb');
$fd_out = fopen($encrypted_file, 'wb');

fwrite($fd_out, pack('C', $alg));
fwrite($fd_out, pack('P', $opslimit));
fwrite($fd_out, pack('P', $memlimit));
fwrite($fd_out, $salt);

list($stream, $header) = sodium_crypto_secretstream_xchacha20poly1305_init_push($secret_key);

fwrite($fd_out, $header);

$tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
do {
    $chunk = fread($fd_in, $chunk_size);
    if (stream_get_meta_data($fd_in)['unread_bytes'] <= 0) {
        $tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
    }
    $encrypted_chunk = sodium_crypto_secretstream_xchacha20poly1305_push($stream, $chunk, '', $tag);
    fwrite($fd_out, $encrypted_chunk);
} while ($tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);

fclose($fd_out);
fclose($fd_in);
?>

<!--Read the stored parameters and decrypt the file:-->

<?php
$decrypted_file = '/tmp/example.dec';

$fd_in = fopen($encrypted_file, 'rb');
$fd_out = fopen($decrypted_file, 'wb');

$alg = unpack('C', fread($fd_in, 1))[1];
$opslimit = unpack('P', fread($fd_in, 8))[1];
$memlimit = unpack('P', fread($fd_in, 8))[1];
$salt = fread($fd_in, SODIUM_CRYPTO_PWHASH_SALTBYTES);

$header = fread($fd_in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);

$secret_key = sodium_crypto_pwhash(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    $password, $salt, $opslimit, $memlimit, $alg);

$stream = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $secret_key);

$tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
while (stream_get_meta_data($fd_in)['unread_bytes'] > 0 &&
    $tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
    $chunk = fread($fd_in, $chunk_size + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
    $res = sodium_crypto_secretstream_xchacha20poly1305_pull($stream, $chunk);
    if ($res === FALSE) {
        break;
    }
    list($decrypted_chunk, $tag) = $res;
    fwrite($fd_out, $decrypted_chunk);
}
$ok = stream_get_meta_data($fd_in)['unread_bytes'] <= 0;

fclose($fd_out);
fclose($fd_in);

if (!$ok) {
    die('Invalid/corrupted input');
}
?>

<!--How it works:

A password cannot be directly used as a secret key. Passwords are
short, must be typable on a keyboard, and people who don't use a
password manager should be able to remember them.

A 8 characters password is thus way weaker than a 8 bytes key.

The `sodium_crypto_pwhash()` function perform a computationally
intensive operation on a password in order to derive a secret key.

By doing do, brute-forcing all possible passwords in order to find the
secret key used to encrypt the data becomes an expensive operation.

Multiple algorithms can be used to derive a key from a password, and
for each of them, different parameters can be chosen. It is important
to store all of these along with encrypted data. Using the same
algorithm and the same parameters, the same secret key can be
deterministically recomputed.-->


<!------------------第二种加密方法------------------------Encrypt a file using a secret key-------------------第二种加密方法------------------------>

<?php
$secret_key = sodium_crypto_secretstream_xchacha20poly1305_keygen();
$input_file = '/tmp/example.original';
$encrypted_file = '/tmp/example.enc';
$chunk_size = 4096;

$fd_in = fopen($input_file, 'rb');
$fd_out = fopen($encrypted_file, 'wb');

list($stream, $header) = sodium_crypto_secretstream_xchacha20poly1305_init_push($secret_key);

fwrite($fd_out, $header);

$tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
do {
    $chunk = fread($fd_in, $chunk_size);
    if (stream_get_meta_data($fd_in)['unread_bytes'] <= 0) {
        $tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
    }
    $encrypted_chunk = sodium_crypto_secretstream_xchacha20poly1305_push($stream, $chunk, '', $tag);
    fwrite($fd_out, $encrypted_chunk);
} while ($tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);

fclose($fd_out);
fclose($fd_in);
?>

<!--Decrypt the file:-->

<?php
$decrypted_file = '/tmp/example.dec';

$fd_in = fopen($encrypted_file, 'rb');
$fd_out = fopen($decrypted_file, 'wb');

$header = fread($fd_in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);

$stream = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $secret_key);

$tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
while (stream_get_meta_data($fd_in)['unread_bytes'] > 0 &&
    $tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
    $chunk = fread($fd_in, $chunk_size + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
    list($decrypted_chunk, $tag) = sodium_crypto_secretstream_xchacha20poly1305_pull($stream, $chunk);
    fwrite($fd_out, $decrypted_chunk);
}
$ok = stream_get_meta_data($fd_in)['unread_bytes'] <= 0;

fclose($fd_out);
fclose($fd_in);

if (!$ok) {
    die('Invalid/corrupted input');
}
?>

<!--How it works:

There's a little bit more code than in the previous examples.

In fact, `crypto_secretbox()` would work to encrypt as file, but only
if that file is pretty small. Since we have to provide the entire
content as a string, it has to fit in memory.

If the file is large, we can split it into small chunks, and encrypt
chunks individually.

By doing do, we can encrypt arbitrary large files. But we need to make
sure that chunks cannot be deleted, truncated, duplicated and
reordered. In other words, we don't have a single "message", but a
stream of messages, and during the decryption process, we need a way
to check that the whole stream matches what we encrypted.

So we create a new stream (`init_push`) and push a sequence of messages
into it (`push`). Each individual message has a tag attached to it, by
default `TAG_MESSAGE`. In order for the decryption process to know
where the end of the stream is, we tag the last message with the
`TAG_FINAL` tag.

When we consume the stream (`init_pull`, then `pull` for each
message), we check that they can be properly decrypted, and retrieve
both the decrypted chunks and the attached tags. If we read the last
chunk (`TAG_FINAL`) and we are at the end of the file, we know that we
completely recovered the original stream.-->

