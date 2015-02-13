"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
    secrets: { /* Your secrets here */ },
    data: { /* Non-secret data here */ }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;

  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  /* Private helpers */

  function clear(){
    ready = false;
    priv.data = {}, priv.secrets = {};
    priv.data.version = "CS 255 Password Manager v1.0";
  }

  function generate_secrets(password){
    // We SHA256 the master key before using it in AES, because the master key is also used for HMAC.
    // We believe that using the same key for HMAC and AES does not jeopardize security,
    // but using different keys avoids the issue altogether.
    // This function is called only once per init/load so the slight extra runtime is not a concern.
    priv.secrets.master_key = KDF(password, priv.data.master_salt);
    priv.secrets.cipher = setup_cipher(bitarray_slice(SHA256(priv.secrets.master_key), 0, 128));
  }

  /* End helpers */

  /**
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    clear();

    // 64 bits of salt is sufficient to make |raw password space| / [salted password space] = 1 / 2^64 negligible.
    // We salt passwords with the corresponding domain name, so the fraction is actually even smaller.
    priv.data.master_salt = random_bitarray(64);
    priv.data.last_salt = priv.data.master_salt;
    priv.data.passwords = {};
    priv.data.salts = {};
    priv.data.master_salt_enc = HMAC(password, priv.data.master_salt);

    generate_secrets(password);

    ready = true;
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trusted_data_check) {
    clear();

    if(trusted_data_check && !bitarray_equal(trusted_data_check, SHA256(repr))) throw "Corruption or tampering detected. Stop.";

    var data;
    try {
      data = JSON.parse(repr);
    } catch(err) {
      throw "Invalid keychain format";
    }

    // Check master password correct
    if(!bitarray_equal(data.master_salt_enc, HMAC(password, data.master_salt))) return false; // TODO explain/justify

    priv.data = data;
    generate_secrets(password);
    ready = true;

    return true;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */
  keychain.dump = function() {
    if(!ready) return null;

    var contents = JSON.stringify(priv.data);
    return [contents, SHA256(contents)];
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    if(!ready) throw "Keychain not initialized.";

    var hmac = HMAC(priv.secrets.master_key, name);
    if(!(hmac in priv.data.passwords)) return null;

    var salt = priv.data.salts[hmac];
    var salt_with_url = bitarray_concat(string_to_bitarray(name), salt);
    var salted_pw = dec_gcm(priv.secrets.cipher, priv.data.passwords[hmac]);

    var len = bitarray_len(salted_pw);
    var salt_start = len - bitarray_len(salt_with_url);

    // Check for tampering. Including the url in the salt blocks swap attacks.
    if(!bitarray_equal(salt_with_url, bitarray_slice(salted_pw, salt_start, len))) throw "Corruption or tampering detected. Stop.";

    return bitarray_to_string(bitarray_slice(salted_pw, 0, salt_start));

  }

  /**
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
    if(!ready) throw "Keychain not initialized.";
    if(value.length > 64) throw "Password too long.";

    var hmac = HMAC(priv.secrets.master_key, name);
    var salt = priv.data.last_salt = SHA256(priv.data.last_salt);
    var salt_with_url = bitarray_concat(string_to_bitarray(name), salt);
    var salted_pw = bitarray_concat(string_to_bitarray(value), salt_with_url);
    var enc_pw = enc_gcm(priv.secrets.cipher, salted_pw);

    priv.data.salts[hmac] = salt;
    priv.data.passwords[hmac] = enc_pw;
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
    if(!ready) throw "Keychain not initialized.";

    var hmac = HMAC(priv.secrets.master_key, name);
    if(!(hmac in priv.data.passwords)) return false;

    delete priv.data.salts[hmac];
    delete priv.data.passwords[hmac];
    return true;
  }

  return keychain;
}

module.exports.keychain = keychain;
