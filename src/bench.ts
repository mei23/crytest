import { verifySignature } from './http-signature';
import { genDigestHeader, createSignedPost } from './signed-request';
import { genEcKeyPair, genEd25519KeyPair, genEd448KeyPair, genRsaKeyPair } from './keypair';
import * as httpSignature from 'http-signature';

const data = {
	'@context': [
		'https://www.w3.org/ns/activitystreams',
		'https://w3id.org/security/v1',
		{
			manuallyApprovesFollowers: 'as:manuallyApprovesFollowers',
			sensitive: 'as:sensitive',
			Hashtag: 'as:Hashtag',
			quoteUrl: 'as:quoteUrl',
			toot: 'http://joinmastodon.org/ns#',
			Emoji: 'toot:Emoji',
			featured: 'toot:featured',
			discoverable: 'toot:discoverable',
			schema: 'http://schema.org#',
			PropertyValue: 'schema:PropertyValue',
			value: 'schema:value',
			misskey: 'https://misskey-hub.net/ns#',
			_misskey_content: 'misskey:_misskey_content',
			_misskey_quote: 'misskey:_misskey_quote',
			_misskey_reaction: 'misskey:_misskey_reaction',
			_misskey_votes: 'misskey:_misskey_votes',
			_misskey_talk: 'misskey:_misskey_talk',
			isCat: 'misskey:isCat',
			vcard: 'http://www.w3.org/2006/vcard/ns#'
		}
	],
	id: 'https://mi12.m213.xyz/notes/9mspkxq26c',
	type: 'Note',
	attributedTo: 'https://mi12.m213.xyz/users/9mr3df4vbf',
	summary: null,
	content: '<p><span>あいうえおかきくけこさしすせそあいうえおかきくけこさしすせそ</span></p>',
	_misskey_content: 'あいうえおかきくけこさしすせそあいうえおかきくけこさしすせそ',
	source: {
		content: 'あいうえおかきくけこさしすせそあいうえおかきくけこさしすせそ',
		mediaType: 'text/x.misskeymarkdown'
	},
	published: '2023-12-03T07:11:48.410Z',
	to: [ 'https://www.w3.org/ns/activitystreams#Public' ],
	cc: [ 'https://mi12.m213.xyz/users/9mr3df4vbf/followers' ],
	inReplyTo: null,
	attachment: [],
	sensitive: false,
	tag: []
};

async function main() {
	const body = JSON.stringify(data);

	// generate keys
	const rsa2048 = await genRsaKeyPair(2048);
	const rsa3072 = await genRsaKeyPair(3072);
	const rsa4096 = await genRsaKeyPair(4096);
	const rsa8192 = await genRsaKeyPair(8192);
	const p256 = await genEcKeyPair('prime256v1');	// NIST P-256
	const p384 = await genEcKeyPair('secp384r1');	// NIST P-384
	const p512 = await genEcKeyPair('secp521r1');	// NIST P-512
	const k256 = await genEcKeyPair('secp256k1');
	const ed25519 = await genEd25519KeyPair();
	const ed448 = await genEd448KeyPair();

	// generate parsedSignatures
	const rsa2048Ps = (() => {
		const sp = createSignedPost({ key: { privateKeyPem: rsa2048.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} })
		return buildParsedSignature(sp.signingString, sp.signature, 'rsa-sha256');
	})();

	const rsa3072Ps = (() => {
		const sp = createSignedPost({ key: { privateKeyPem: rsa3072.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });
		return buildParsedSignature(sp.signingString, sp.signature, 'rsa-sha256');
	})();

	const rsa4096Ps = (() => {
		const sp = createSignedPost({ key: { privateKeyPem: rsa4096.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });
		return buildParsedSignature(sp.signingString, sp.signature, 'rsa-sha256');
	})();

	const rsa8192Ps = (() => {
		const sp = createSignedPost({ key: { privateKeyPem: rsa8192.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });
		return buildParsedSignature(sp.signingString, sp.signature, 'rsa-sha256');
	})();

	const p256Ps = (() => {
		const sp = createSignedPost({ key: { privateKeyPem: p256.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });
		return buildParsedSignature(sp.signingString, sp.signature, 'ecdsa-sha256');
	})();

	const p384Ps = (() => {
		const sp = createSignedPost({ key: { privateKeyPem: p384.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });
		return buildParsedSignature(sp.signingString, sp.signature, 'ecdsa-sha256');
	})();

	const p512Ps = (() => {
		const sp = createSignedPost({ key: { privateKeyPem: p512.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });
		return buildParsedSignature(sp.signingString, sp.signature, 'ecdsa-sha256');
	})();

	const k256Ps = (() => {
		const sp = createSignedPost({ key: { privateKeyPem: k256.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });
		return buildParsedSignature(sp.signingString, sp.signature, 'ecdsa-sha256');
	})();

	const ed25519Ps = (() => {
		const sp = createSignedPost({ key: { privateKeyPem: ed25519.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });
		return buildParsedSignature(sp.signingString, sp.signature, 'ed25519-sha512');
	})();

	const ed448Ps = (() => {
		const sp = createSignedPost({ key: { privateKeyPem: ed448.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });
		return buildParsedSignature(sp.signingString, sp.signature, '');
	})();


	//console.log(verifySignature(ed25519Ps, ed25519.publicKey));

	const marks = {
		'sha256': () => {
			genDigestHeader(body)
		},
		'veri-rsa2048-joyent': () => {
			httpSignature.verifySignature(rsa2048Ps, rsa2048.publicKey);
		},
		'veri-rsa3072-joyent': () => {
			httpSignature.verifySignature(rsa3072Ps, rsa3072.publicKey);
		},
		'veri-rsa4096-joyent': () => {
			httpSignature.verifySignature(rsa4096Ps, rsa4096.publicKey);
		},
		'veri-rsa8192-joyent': () => {
			httpSignature.verifySignature(rsa8192Ps, rsa8192.publicKey);
		},
		'veri-p256-joyent': () => {
			httpSignature.verifySignature(p256Ps, p256.publicKey);
		},
		'veri-p384-joyent': () => {
			httpSignature.verifySignature(p384Ps, p384.publicKey);
		},
		'veri-p512-joyent': () => {
			httpSignature.verifySignature(p512Ps, p512.publicKey);
		},
		'veri-ed25519-joyent': () => {
			httpSignature.verifySignature(ed25519Ps, ed25519.publicKey);
		},

		'veri-rsa2048': () => {
			verifySignature(rsa2048Ps, rsa2048.publicKey);
		},
		'veri-rsa3072': () => {
			verifySignature(rsa3072Ps, rsa3072.publicKey);
		},
		'veri-rsa4096': () => {
			verifySignature(rsa4096Ps, rsa4096.publicKey);
		},
		'veri-rsa8192': () => {
			verifySignature(rsa8192Ps, rsa8192.publicKey);
		},
		'veri-p256': () => {
			verifySignature(p256Ps, p256.publicKey);
		},
		'veri-p384': () => {
			verifySignature(p384Ps, p384.publicKey);
		},
		'veri-p512': () => {
			verifySignature(p512Ps, p512.publicKey);
		},
		'veri-k256': () => {
			verifySignature(k256Ps, k256.publicKey);
		},
		'veri-ed25519': () => {
			verifySignature(ed25519Ps, ed25519.publicKey);
		},
		'veri-ed448': () => {
			verifySignature(ed448Ps, ed448.publicKey);
		},

		'sign-rsa2048': () => {
			createSignedPost({ key: { privateKeyPem: rsa2048.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });;
		},
		'sign-rsa3072': () => {
			createSignedPost({ key: { privateKeyPem: rsa3072.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });;
		},
		/*
		'sign-rsa4096': () => {
			createSignedPost({ key: { privateKeyPem: rsa4096.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });;
		},
		'sign-rsa8192': () => {
			createSignedPost({ key: { privateKeyPem: rsa8192.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });;
		},
		*/
		'sign-k256': () => {
			createSignedPost({ key: { privateKeyPem: k256.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });;
		},
		'sign-p256': () => {
			createSignedPost({ key: { privateKeyPem: p256.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });;
		},
		'sign-p384': () => {
			createSignedPost({ key: { privateKeyPem: p384.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });;
		},
		'sign-p512': () => {
			createSignedPost({ key: { privateKeyPem: p512.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });;
		},
		'sign-ed25519': () => {
			createSignedPost({ key: { privateKeyPem: ed25519.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });;
		},
		'sign-ed448': () => {
			createSignedPost({ key: { privateKeyPem: ed448.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });;
		},


	};

	for (const key of Object.keys(marks)) {
		const t0 = performance.now();
		for (let i = 0; i < 10000; i++) marks[key]();
		const t1 = performance.now();
		console.log(`${key}\t${t1 - t0}`);
	}

	/*
	const t0 = performance.now();
	const p = createSignedPost({ key: { privateKeyPem: rsa2048.privateKey, keyId: 'key1' }, url: 'https://target.example.com/inbox', body, additionalHeaders: {} });;
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
