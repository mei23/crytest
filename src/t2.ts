import { inspect } from 'util';
import { genSignature, genSignatureHeader, genSigningString, RequestOptions, SignatureKey, signToRequest, verifySignature } from './http-signature';
import {genDigestHeader, genSignedPost } from './signed-request';
import { genEcKeyPair, genEd25519KeyPair, genEd448KeyPair, genRsaKeyPair } from './keypair';

const data = {
	"id": "https://origin.example.com/notes/71892bbe2438fe6d0d62d7b8",
	"url": "https://origin.example.com/notes/71892bbe2438fe6d0d62d7b8",
	"type": "Note",
	"attributedTo": "https://origin.example.com/users/5dc9a9187ca6e03164b43934",
	"summary": null,
	"content": "<p><span>あいうえおかきくけこ</span></p>",
	"_misskey_content": "あいうえおかきくけこ",
	"published": "2023-07-06T15:07:08.728Z",
	"to": [
		"https://origin.example.com/users/5dc9a9187ca6e03164b43934/followers"
	],
	"cc": [
		"https://www.w3.org/ns/activitystreams#Public"
	],
	"inReplyTo": null,
	"attachment": [],
	"sensitive": false,
	"tag": []
};

async function main() {
	// generate keys
	const rsa2048 = await genRsaKeyPair(2048);
	const rsa4096 = await genRsaKeyPair(4096);
	const p256 = await genEcKeyPair('prime256v1');	// NIST P-256
	const p384 = await genEcKeyPair('secp384r1');	// NIST P-384
	const p512 = await genEcKeyPair('secp521r1');	// NIST P-512
	const ed25519 = await genEd25519KeyPair();
	const ed448 = await genEd448KeyPair();

	const body = JSON.stringify(data);

	const rsa2048Ps = (() => {
		const sp = genSignedPost({ privateKeyPem: rsa2048.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {})
		return buildParsedSignature(sp.signingString, sp.signature, 'rsa-sha256');
	})();

	const rsa4096Ps = (() => {
		const sp = genSignedPost({ privateKeyPem: rsa4096.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {})
		return buildParsedSignature(sp.signingString, sp.signature, 'rsa-sha256');
	})();

	const p256Ps = (() => {
		const sp = genSignedPost({ privateKeyPem: p256.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {})
		return buildParsedSignature(sp.signingString, sp.signature, 'ecdsa-sha256');
	})();

	const p384Ps = (() => {
		const sp = genSignedPost({ privateKeyPem: p384.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {})
		return buildParsedSignature(sp.signingString, sp.signature, 'ecdsa-sha256');
	})();

	const p512Ps = (() => {
		const sp = genSignedPost({ privateKeyPem: p512.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {})
		return buildParsedSignature(sp.signingString, sp.signature, 'ecdsa-sha256');
	})();

	const ed25519Ps = (() => {
		const sp = genSignedPost({ privateKeyPem: ed25519.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {})
		return buildParsedSignature(sp.signingString, sp.signature, 'x');
	})();

	const ed448Ps = (() => {
		const sp = genSignedPost({ privateKeyPem: ed448.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {})
		return buildParsedSignature(sp.signingString, sp.signature, 'x');
	})();


	console.log(verifySignature(ed25519Ps, ed25519.publicKey));

	const marks = {
		'veri rsa2048': () => {
			verifySignature(rsa2048Ps, rsa2048.publicKey);
		},
		'veri rsa4096': () => {
			verifySignature(rsa4096Ps, rsa4096.publicKey);
		},
		'veri p256': () => {
			verifySignature(p256Ps, p256.publicKey);
		},
		'veri p384': () => {
			verifySignature(p384Ps, p384.publicKey);
		},
		'veri p512': () => {
			verifySignature(p512Ps, p512.publicKey);
		},
		'veri ed25519': () => {
			verifySignature(ed25519Ps, ed25519.publicKey);
		},
		'veri ed448': () => {
			verifySignature(ed448Ps, ed448.publicKey);
		},

		'sign rsa2048': () => {
			genSignedPost({ privateKeyPem: rsa2048.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {});
		},
		'sign rsa4096': () => {
			genSignedPost({ privateKeyPem: rsa4096.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {});
		},
		'sign p256': () => {
			genSignedPost({ privateKeyPem: p256.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {});
		},
		'sign p384': () => {
			genSignedPost({ privateKeyPem: p384.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {});
		},
		'sign p512': () => {
			genSignedPost({ privateKeyPem: p512.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {});
		},
		'sign ed25519': () => {
			genSignedPost({ privateKeyPem: ed25519.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {});
		},
		'sign ed448': () => {
			genSignedPost({ privateKeyPem: ed448.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {});
		},


	};

	for (const key of Object.keys(marks)) {
		console.log(key);
		const t0 = performance.now();
		for (let i = 0; i < 1000; i++) marks[key]();
		const t1 = performance.now();
		console.log( t1 - t0 );
	}

	/*
	const t0 = performance.now();
	const p = genSignedPost({ privateKeyPem: rsa2048.privateKey, keyId: 'key1' }, 'https://target.example.com/inbox', body, {});
	const t1 = performance.now();
	console.log( t1 - t0 );
	*/

}

type ParsedSignature = {
	scheme: 'Signature';
	params: {
		keyId: string;
		algorithm: string;	// 'rsa-sha256'
		headers: string[];	//[ '(request-target)', 'date', 'host', 'digest' ],
		signature: string;
	};
	signingString: string;
	algorithm: string;	// 'RSA-SHA256'
	keyId: string;
};

export const buildParsedSignature = (signingString: string, signature: string, algorithm: string) => {
	return {
		scheme: 'Signature',
		params: {
			keyId: 'KeyID',
			algorithm: algorithm,
			headers: [ '(request-target)', 'date', 'host', 'digest' ],
			signature: signature,
		},
		signingString: signingString,
		algorithm: algorithm?.toUpperCase(),
		keyId: 'KeyID',
	} as ParsedSignature;
};

main()
	.then(() => {})
	.catch(e => console.log(e));
