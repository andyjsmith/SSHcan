class Algorithms:
	WARN_OPENSSH72_LEGACY = 'disabled (in client) since OpenSSH 7.2, legacy algorithm'
	FAIL_OPENSSH70_LEGACY = 'removed since OpenSSH 7.0, legacy algorithm'
	FAIL_OPENSSH70_WEAK   = 'removed (in server) and disabled (in client) since OpenSSH 7.0, weak algorithm'
	FAIL_OPENSSH70_LOGJAM = 'disabled (in client) since OpenSSH 7.0, logjam attack'
	FAIL_OPENSSH67_UNSAFE = 'removed (in server) since OpenSSH 6.7, unsafe algorithm'
	FAIL_OPENSSH61_REMOVE = 'removed since OpenSSH 6.1, removed from specification'
	FAIL_OPENSSH31_REMOVE = 'removed since OpenSSH 3.1'
	FAIL_DBEAR67_DISABLED = 'disabled since Dropbear SSH 2015.67'
	FAIL_DBEAR53_DISABLED = 'disabled since Dropbear SSH 0.53'
	FAIL_PLAINTEXT        = 'no encryption/integrity'
	WARN_CURVES_WEAK      = 'using weak elliptic curves'
	WARN_RNDSIG_KEY       = 'using weak random number generator could reveal the key'
	WARN_MODULUS_SIZE     = 'using small 1024-bit modulus'
	WARN_MODULUS_CUSTOM   = 'using custom size modulus (possibly weak)'
	WARN_HASH_WEAK        = 'using weak hashing algorithm'
	WARN_CIPHER_MODE      = 'using weak cipher mode'
	WARN_BLOCK_SIZE       = 'using small 64-bit block size'
	WARN_CIPHER_WEAK      = 'using weak cipher'
	WARN_ENCRYPT_AND_MAC  = 'using encrypt-and-MAC mode'
	WARN_TAG_SIZE         = 'using small 64-bit tag size'

	ALGORITHMS = {
		'kex': {
			'diffie-hellman-group1-sha1': [FAIL_OPENSSH67_UNSAFE, FAIL_OPENSSH70_LOGJAM, WARN_MODULUS_SIZE, WARN_HASH_WEAK],
			'diffie-hellman-group14-sha1': [WARN_HASH_WEAK],
			'diffie-hellman-group14-sha256': [],
			'diffie-hellman-group16-sha512': [],
			'diffie-hellman-group18-sha512': [],
			'diffie-hellman-group-exchange-sha1': [FAIL_OPENSSH67_UNSAFE, WARN_HASH_WEAK],
			'diffie-hellman-group-exchange-sha256': [WARN_MODULUS_CUSTOM],
			'ecdh-sha2-nistp256': [WARN_CURVES_WEAK],
			'ecdh-sha2-nistp384': [WARN_CURVES_WEAK],
			'ecdh-sha2-nistp521': [WARN_CURVES_WEAK],
			'curve25519-sha256@libssh.org': [],
			'kexguess2@matt.ucc.asn.au': []
		},
		'key': {
			'rsa-sha2-256': [],
			'rsa-sha2-512': [],
			'ssh-ed25519': [],
			'ssh-ed25519-cert-v01@openssh.com': [],
			'ssh-rsa': [],
			'ssh-dss': [FAIL_OPENSSH70_WEAK, WARN_MODULUS_SIZE, WARN_RNDSIG_KEY],
			'ecdsa-sha2-nistp256': [WARN_CURVES_WEAK, WARN_RNDSIG_KEY],
			'ecdsa-sha2-nistp384': [WARN_CURVES_WEAK, WARN_RNDSIG_KEY],
			'ecdsa-sha2-nistp521': [WARN_CURVES_WEAK, WARN_RNDSIG_KEY],
			'ssh-rsa-cert-v00@openssh.com': [FAIL_OPENSSH70_LEGACY],
			'ssh-dss-cert-v00@openssh.com': [FAIL_OPENSSH70_LEGACY, WARN_MODULUS_SIZE, WARN_RNDSIG_KEY],
			'ssh-rsa-cert-v01@openssh.com': [],
			'ssh-dss-cert-v01@openssh.com': [FAIL_OPENSSH70_WEAK, WARN_MODULUS_SIZE, WARN_RNDSIG_KEY],
			'ecdsa-sha2-nistp256-cert-v01@openssh.com': [WARN_CURVES_WEAK, WARN_RNDSIG_KEY],
			'ecdsa-sha2-nistp384-cert-v01@openssh.com': [WARN_CURVES_WEAK, WARN_RNDSIG_KEY],
			'ecdsa-sha2-nistp521-cert-v01@openssh.com': [WARN_CURVES_WEAK, WARN_RNDSIG_KEY]
		},
		'enc': {
			'none': [FAIL_PLAINTEXT],
			'3des-cbc': [FAIL_OPENSSH67_UNSAFE, WARN_CIPHER_WEAK, WARN_CIPHER_MODE, WARN_BLOCK_SIZE],
			'3des-ctr': [],
			'blowfish-cbc': [FAIL_OPENSSH67_UNSAFE, FAIL_DBEAR53_DISABLED, WARN_OPENSSH72_LEGACY, WARN_CIPHER_MODE, WARN_BLOCK_SIZE],
			'twofish-cbc': [FAIL_DBEAR67_DISABLED, WARN_CIPHER_MODE],
			'twofish128-cbc': [FAIL_DBEAR67_DISABLED, WARN_CIPHER_MODE],
			'twofish256-cbc': [FAIL_DBEAR67_DISABLED, WARN_CIPHER_MODE],
			'twofish128-ctr': [],
			'twofish256-ctr': [],
			'cast128-cbc': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_CIPHER_MODE, WARN_BLOCK_SIZE],
			'arcfour': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_CIPHER_WEAK],
			'arcfour128': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_CIPHER_WEAK],
			'arcfour256': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_CIPHER_WEAK],
			'aes128-cbc': [FAIL_OPENSSH67_UNSAFE, WARN_CIPHER_MODE],
			'aes192-cbc': [FAIL_OPENSSH67_UNSAFE, WARN_CIPHER_MODE],
			'aes256-cbc': [FAIL_OPENSSH67_UNSAFE, WARN_CIPHER_MODE],
			'rijndael128-cbc': [FAIL_OPENSSH31_REMOVE, WARN_CIPHER_MODE],
			'rijndael192-cbc': [FAIL_OPENSSH31_REMOVE, WARN_CIPHER_MODE],
			'rijndael256-cbc': [FAIL_OPENSSH31_REMOVE, WARN_CIPHER_MODE],
			'rijndael-cbc@lysator.liu.se': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_CIPHER_MODE],
			'aes128-ctr': [],
			'aes192-ctr': [],
			'aes256-ctr': [],
			'aes128-gcm@openssh.com': [],
			'aes256-gcm@openssh.com': [],
			'chacha20-poly1305@openssh.com': []
		},
		'mac': {
			'none': [FAIL_PLAINTEXT],
			'hmac-sha1': [WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK],
			'hmac-sha1-96': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK],
			'hmac-sha2-256': [WARN_ENCRYPT_AND_MAC],
			'hmac-sha2-256-96': [FAIL_OPENSSH61_REMOVE, WARN_ENCRYPT_AND_MAC],
			'hmac-sha2-512': [WARN_ENCRYPT_AND_MAC],
			'hmac-sha2-512-96': [FAIL_OPENSSH61_REMOVE, WARN_ENCRYPT_AND_MAC],
			'hmac-md5': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK],
			'hmac-md5-96': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK],
			'hmac-ripemd160': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC],
			'hmac-ripemd160@openssh.com': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC],
			'umac-64@openssh.com': [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE],
			'umac-128@openssh.com': [WARN_ENCRYPT_AND_MAC],
			'hmac-sha1-etm@openssh.com': [WARN_HASH_WEAK],
			'hmac-sha1-96-etm@openssh.com': [FAIL_OPENSSH67_UNSAFE, WARN_HASH_WEAK],
			'hmac-sha2-256-etm@openssh.com': [],
			'hmac-sha2-512-etm@openssh.com': [],
			'hmac-md5-etm@openssh.com': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_HASH_WEAK],
			'hmac-md5-96-etm@openssh.com': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY, WARN_HASH_WEAK],
			'hmac-ripemd160-etm@openssh.com': [FAIL_OPENSSH67_UNSAFE, WARN_OPENSSH72_LEGACY],
			'umac-64-etm@openssh.com': [WARN_TAG_SIZE],
			'umac-128-etm@openssh.com': []
		}
	}