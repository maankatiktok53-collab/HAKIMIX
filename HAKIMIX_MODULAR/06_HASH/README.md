# 06_HASH / hash.py

Aqoonsiga hash-ka **offline** iyo wordlist auditing. Ma jiro online password attack.

Types: MD5, SHA1, SHA256, SHA512, NTLM, bcrypt (+ MD4, LM, SHA224, SHA384). 32-hex wuxuu noqon karaa `md5`, `md4` ama `ntlm`; isticmaal `--hash-type` ama context.

```bash
python3 06_HASH/hash.py localhost -y --hash 5d41402abc4b2a76b9719d911017c592
python3 06_HASH/hash.py localhost -y --hashfile hashes.txt --wordlist rockyou.txt --hash-type ntlm
python3 06_HASH/hash.py localhost -y --hashfile hashes.txt --no-crack
python3 hakimix.py 10.10.11.25 --module hash --yes --hashfile hashes.txt --wordlist rockyou.txt
```

- `hashes.txt`: hal hash line kasta, ama `user:hash`.
- Wordlist waa inaad adigu bixisaa; john/hashcat waxaa lagu wadaa `--pot` gudaha workspace-ka.
- Marka aysan jirin hashfile/wordlist, waa aqoonsi keliya.
- Natiijo: `output/TARGET/hash/hash.json` + `john.pot`/`hashcat.potfile` (marka la sameeyo).

API: `run(target, workspace, config, logger, options) -> envelope`.

Help buuxa: `python3 06_HASH/hash.py --help`.
