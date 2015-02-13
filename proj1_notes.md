salt dem passwords

swap attack: salt with url of website?

rollback attack: compute, store hash of all contents

PBKDF2 salt: random bits

store `last_salt`, `next_salt <- SHA(last_salt)`

KDF
- IN: (master password, randombits salt)
- OUT: master key === must be 256 bits

KVstore
- KEY: HMAC(master key, url)
- OR KEY: HMAC( SHA(master key || salt), url)
- VALUE: SHA(master key, password || url || salt)
  + secret key must be 128 bits. just use first half?


Short Answers
----

1. SHA outputs same length
2. Use the URL in the salt -- swap attack will invalidate decryption (note: explicitly check url)
3. Necessary - adversary could change digest to disguise changes
4. idk lol
5. pad with bogus entries?
- orrr something else?

Notes
---

Writing last-salt to disk is okay because it's captured by the digest
