"use strict";

function assert(condition, message) {
  if (!condition) {
    console.trace();
    throw message || "Assertion failed!";
  }
}

var password_manager = require("./password-manager");

var password = "password123!!";
var keychain = password_manager.keychain();

console.log("Initializing a toy password store");
keychain.init(password);

var kvs = { "service1": "value1",
            "service2": "value2",
            "service3": "value3" };

console.log("Adding keys to password manager");
for (var k in kvs) {
  keychain.set(k, kvs[k]);
}

console.log("Testing get");
for (var k in kvs) {
  assert(keychain.get(k) === kvs[k], "Get failed for key " + k);
}
assert(keychain.get("service4") === null);

console.log("Testing remove");
assert(keychain.remove("service1"));
assert(!keychain.remove("service4"));
assert(keychain.get("service4") === null);

console.log("Saving database");
var data = keychain.dump();

var contents = data[0];
var cksum = data[1];

console.log("Loading database");
var new_keychain = password_manager.keychain();
assert(new_keychain.load(password, contents, cksum) === true);

console.log("Checking contents of new database");
for (var k in kvs) {
  assert(keychain.get(k) === new_keychain.get(k));
}

console.log("All tests passed!");

console.log("Time for more tests!");

new_keychain = password_manager.keychain();
assert(new_keychain.load("not the password", contents) === false);

var not_ready = password_manager.keychain();
assert(not_ready.dump() === null);
should_throw(not_ready.set, "foo", "bar");
should_throw(not_ready.get, "foo");
should_throw(not_ready.remove, "foo");

var empty = password_manager.keychain();
empty.init("nofriendsQQ");
assert(empty.get("foo") === null);
assert(empty.remove("foo") === false);

// should throw when corrupt
var tamper = JSON.parse(contents);
tamper.passwords["foo"] = "bar";

var sneaky = password_manager.keychain();

should_throw(sneaky.load, password, JSON.stringify(tamper), cksum);
should_throw(sneaky.set, "foo", "bar");

// Even if loaded without checksum, tampered entries should not be retrievable
var tampered_key;
for (k in tamper.passwords){
  tampered_key = k;
  tamper.passwords[k][0]++;
  break;
}
sneaky.load(password, JSON.stringify(tamper));
should_throw(sneaky.get, "foo");
should_throw(sneaky.get, tampered_key);

var short_and_long = password_manager.keychain();
short_and_long.init("password");
short_and_long.set("foo.com", "a");
should_throw(short_and_long.set, "bar.com", "foobarbazfoobarbazfoobarbazfoobarbazfoobarbazfoobarbazfoobarbazfoobarbazfoobarbazfoobarbazfoobarbazfoobarbazfoobarbaz");
short_and_long.set("bar.com", "foobarbazfoobarbazfoobarbazfoobarbazfoobarbazfoobarbaz");

console.log("All bonus tests passed.");

/* Helpers */

function should_throw(fn /*, ... */){
  var args = Array.prototype.slice.call(arguments, should_throw.length);
  var threw = false;
  try {
    fn.apply(args);
  } catch(e) {
    threw = true;
  }
  assert(threw);
}
