The scripts, addon.py, decoding_helpers.py and logbatch_decode.py been extended to support Gboard logs. The original code can be found here: https://github.com/doug-leith/android-protobuf-decoding

The gboard.proto3 file presents a (partially) decoded protobuf definition for the LATIN_IME log source.

The script frida_hook_swiftkey7835.js was used to bypass the certificate pinning done by SwiftKey.

The schema swiftkey_schema.json was used to decode SwiftKey logs.