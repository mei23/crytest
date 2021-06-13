import * as crypto from 'crypto';
const { createSignatureString } = require('http-signature-header');

export type RequestOptions = {
	url: string;
	method: string;
	headers: Record<string, string>;
};

export type SignatureKey = {
	privateKeyPem: string;
	keyId: string;
};

export type SignatureKeyAlgorithm = 'rsa' | 'ecdsa' | 'ed25519' | 'ed448';
export type SignatureHashAlgorithm = 'sha1' | 'sha256' | 'sha512';
export type SignatureAlgorithm = 'rsa-sha1' | 'rsa-sha256' | 'rsa-sha512' | 'ecdsa-sha1' | 'ecdsa-sha256' | 'ecdsa-sha512';

type ParsedSignature = {
	scheme: 'Signature';
	params: {
		keyId: string;
		algorithm?: string;	// 'rsa-sha256'
		headers: string[];	//[ '(request-target)', 'date', 'host', 'digest' ],
		signature: string;
	};
	signingString: string;
	algorithm?: string;	// 'RSA-SHA256'
	keyId: string;
};

export function verifySignature(parsed: ParsedSignature, publicKeyPem: string) {
	let legacyKeyAlg: string | undefined;
	let legacyHashAlg: string | undefined;
	const m = parsed.params.algorithm?.match(/^(rsa|hmac|ecdsa)-(sha(?:1|224|256|384|512))$/);
	if (m) {
		legacyKeyAlg = m[1],
		legacyHashAlg = m[2];
	}

	const k = crypto.createPublicKey(publicKeyPem);

	if (legacyKeyAlg) {
		if (k.asymmetricKeyType === 'rsa' && legacyKeyAlg !== 'rsa') throw 'rsa';
		if (k.asymmetricKeyType === 'ec' && legacyKeyAlg !== 'ecdsa') throw 'ec';
		if (k.asymmetricKeyType === 'ed25519') throw 'ed25519';
		if (k.asymmetricKeyType === 'ed448') throw 'ed448';
	}

	if (k.asymmetricKeyType === 'ed25519' || k.asymmetricKeyType === 'ed448') {
		return crypto.verify(null, Buffer.from(parsed.signingString), publicKeyPem, Buffer.from(parsed.params.signature, 'base64'));
	} else if (k.asymmetricKeyType === 'rsa') {
		return crypto.verify(legacyHashAlg || 'sha256', Buffer.from(parsed.signingString), publicKeyPem, Buffer.from(parsed.params.signature, 'base64'));
	} else if (k.asymmetricKeyType === 'ec') {
		return crypto.verify(legacyHashAlg, Buffer.from(parsed.signingString), publicKeyPem, Buffer.from(parsed.params.signature, 'base64'));
	} else {
		throw 'unsupported';
	}
}

export function signToRequest(requestOptions: RequestOptions, includeHeaders: string[], key: SignatureKey, opts: { hashAlgorithm?: SignatureHashAlgorithm } = {}) {
	const hashAlgorithm = opts?.hashAlgorithm || 'sha256';
	const keyAlgorithm = detectKeyAlgorithm(key.privateKeyPem);

	const signingString =  genSigningString(requestOptions, includeHeaders);
	const signature = genSignature(signingString, key.privateKeyPem,
			(keyAlgorithm === 'ed25519' || keyAlgorithm === 'ed448') ? null : hashAlgorithm);

	let signatureAlgorithm: SignatureAlgorithm | undefined;
	if (keyAlgorithm === 'rsa' || keyAlgorithm === 'ecdsa') {
		signatureAlgorithm = `${keyAlgorithm}-${hashAlgorithm}` as const;
	}

	const signatureHeader = genSignatureHeader(includeHeaders, key.keyId, signature, signatureAlgorithm);

	Object.assign(requestOptions.headers, {
		Signature: signatureHeader
	});

	return {
		signingString,
		signature,
		signatureHeader,
	}
}

export function genSigningString(requestOptions: RequestOptions, includeHeaders: string[]) {
	return createSignatureString({
		includeHeaders,
		requestOptions,
	}) as string;
}

export function genSignature(signingString: string, privateKey: string, hashAlgorithm: SignatureHashAlgorithm | null) {
	const r = crypto.sign(hashAlgorithm, Buffer.from(signingString), privateKey);
	return r.toString('base64');
}

export function genAuthorizationHeader(includeHeaders: string[], keyId: string, signature: string, hashAlgorithm: SignatureAlgorithm | undefined) {
	return `Signature ${genSignatureHeader(includeHeaders, keyId, signature, hashAlgorithm)}`;
}

export function genSignatureHeader(includeHeaders: string[], keyId: string, signature: string, algorithm: SignatureAlgorithm | undefined) {
	if (algorithm) {
		return `keyId="${keyId}",algorithm="${algorithm}",headers="${includeHeaders.join(' ')}",signature="${signature}"`;
	} else {
		return `keyId="${keyId}",headers="${includeHeaders.join(' ')}",signature="${signature}"`;
	}
}

export function detectKeyAlgorithm(privateKey: string): SignatureKeyAlgorithm {
	const keyObject = crypto.createPrivateKey(privateKey);
	if (keyObject.asymmetricKeyType === 'rsa') return 'rsa';
	if (keyObject.asymmetricKeyType === 'ec') return 'ecdsa';
	if (keyObject.asymmetricKeyType === 'ed25519') return 'ed25519';
	if (keyObject.asymmetricKeyType === 'ed448') return 'ed448';
	throw `unsupported keyAlgorithm: ${keyObject.asymmetricKeyType}`;
}
