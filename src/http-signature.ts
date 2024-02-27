/*
 * SPDX-FileCopyrightText: mei23
 * SPDX-License-Identifier: MIT
 */

import * as crypto from 'crypto';

export type Request = {
	url: string;
	method: string;
	headers: Record<string, string>;
};

export type PrivateKey = {
	privateKeyPem: string;
	keyId: string;
};

export type SignatureKeyAlgorithm = 'rsa' | 'ecdsa' | 'ed25519' | 'ed448';

export type SignatureHashAlgorithm = 'sha1' | 'sha256' | 'sha384' | 'sha512';
// sign専用
export type SignatureAlgorithm = 'rsa-sha1' | 'rsa-sha256' | 'rsa-sha384' | 'rsa-sha512' | 'ecdsa-sha1' | 'ecdsa-sha256' | 'ecdsa-sha384' | 'ecdsa-sha512' | 'ed25519-sha512' | 'ed25519' | 'ed448';

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
	const publicKey = crypto.createPublicKey(publicKeyPem);
	const detected = detectAlgorithm(parsed.params.algorithm, publicKey);
	return crypto.verify(detected.hashAlg, Buffer.from(parsed.signingString), publicKey, Buffer.from(parsed.params.signature, 'base64'));
}

/**
 * ヘッダーのアルゴリズムから鍵とハッシュアルゴリズムを認識する
 * @param algorithm ヘッダーのアルゴリズム
 * @param key 実際公開鍵 (ヘッダーで明示されていない場合のヒント)
 */
export function detectAlgorithm(algorithm: string | undefined, publicKey?: crypto.KeyObject ): { keyAlg: SignatureKeyAlgorithm, hashAlg: SignatureHashAlgorithm | null } {
	// ed25519
	if (algorithm === 'ed25519' || algorithm === 'ed25519-sha512') {	// ed25519-sha512 はjoyent実装が使うかも
		return {
			keyAlg: 'ed25519',
			hashAlg: null,	// ハッシュ関数は固定
		}
	}

	// ed448
	if (algorithm === 'ed448') {
		return {
			keyAlg: 'ed448',
			hashAlg: null,	// ハッシュ関数は固定
		}
	}

	// rsa, ecdsa
	const m = algorithm?.match(/^(rsa|ecdsa)-(sha(?:256|384|512))$/);
	if (m) {
		return {
			keyAlg: m[1] as SignatureKeyAlgorithm,
			hashAlg: m[2] as SignatureHashAlgorithm,
		}
	}

	// RFC 9421
	if (algorithm === 'rsa-v1_5-sha256') return { keyAlg: 'rsa', hashAlg: 'sha256' }
	if (algorithm === 'ecdsa-p256-sha256') return { keyAlg: 'ecdsa', hashAlg: 'sha256' }
	if (algorithm === 'ecdsa-p384-sha384') return { keyAlg: 'ecdsa', hashAlg: 'sha384' }

	// バグ (Crystal版pub-relay) や 中途仕様のhs2019を実装したもののため
	if (algorithm == null || algorithm === 'hs2019') {
		if (publicKey.asymmetricKeyType === 'ed25519') return { keyAlg: 'ed25519', hashAlg: null }
		if (publicKey.asymmetricKeyType === 'ed448') return { keyAlg: 'ed448', hashAlg: null }
		if (publicKey.asymmetricKeyType === 'ec') return { keyAlg: 'ecdsa', hashAlg: 'sha256' }
		if (publicKey.asymmetricKeyType === 'rsa') return { keyAlg: 'rsa', hashAlg: 'sha256' }
	}

	throw new Error('Unsupported algorithm');
}

export function signToRequest(request: Request, key: PrivateKey, includeHeaders: string[], opts: { hashAlgorithm?: SignatureHashAlgorithm } = {}) {
	const hashAlgorithm = opts?.hashAlgorithm || 'sha256';
	const keyAlgorithm = detectKeyAlgorithm(key.privateKeyPem);

	const signingString = genSigningString(request, includeHeaders);
	const signature = genSignature(signingString, key.privateKeyPem,
			(keyAlgorithm === 'ed25519' || keyAlgorithm === 'ed448') ? null : hashAlgorithm);

	let signatureAlgorithm: SignatureAlgorithm;
	if (keyAlgorithm === 'rsa' || keyAlgorithm === 'ecdsa') {
		signatureAlgorithm = `${keyAlgorithm}-${hashAlgorithm}`;
	}

	// TODO: -sha512付けたくないがjoyentが認識しない
	if (keyAlgorithm === 'ed25519') {
		signatureAlgorithm = `${keyAlgorithm}-sha512`;
	}

	if (keyAlgorithm === 'ed448') {
		signatureAlgorithm = keyAlgorithm;
	}

	const signatureHeader = genSignatureHeader(includeHeaders, key.keyId, signature, signatureAlgorithm);

	Object.assign(request.headers, {
		Signature: signatureHeader
	});

	return {
		signingString,
		signature,
		signatureHeader,
	}
}

export function genSigningString(request: Request, includeHeaders: string[]) {
	request.headers = lcObjectKey(request.headers);

	const results: string[] = [];

	for (const key of includeHeaders.map(x => x.toLowerCase())) {
		if (key === '(request-target)') {
			results.push(`(request-target): ${request.method.toLowerCase()} ${new URL(request.url).pathname}`);
		} else {
			results.push(`${key}: ${request.headers[key]}`);
		}
	}

	return results.join('\n');
}

function lcObjectKey(src: Record<string, string>) {
	const dst: Record<string, string> = {};
	for (const key of Object.keys(src).filter(x => x != '__proto__' && typeof src[x] === 'string')) dst[key.toLowerCase()] = src[key];
	return dst;
}

export function genSignature(signingString: string, privateKey: string, hashAlgorithm: SignatureHashAlgorithm | null) {
	const r = crypto.sign(hashAlgorithm, Buffer.from(signingString), privateKey);
	return r.toString('base64');
}

export function genAuthorizationHeader(includeHeaders: string[], keyId: string, signature: string, hashAlgorithm: SignatureAlgorithm | undefined) {
	return `Signature ${genSignatureHeader(includeHeaders, keyId, signature, hashAlgorithm)}`;
}

export function genSignatureHeader(includeHeaders: string[], keyId: string, signature: string, algorithm: SignatureAlgorithm) {
	return `keyId="${keyId}",algorithm="${algorithm}",headers="${includeHeaders.join(' ')}",signature="${signature}"`;
}

export function detectKeyAlgorithm(privateKey: string): SignatureKeyAlgorithm {
	const keyObject = crypto.createPrivateKey(privateKey);
	if (keyObject.asymmetricKeyType === 'rsa') return 'rsa';
	if (keyObject.asymmetricKeyType === 'ec') return 'ecdsa';
	if (keyObject.asymmetricKeyType === 'ed25519') return 'ed25519';
	if (keyObject.asymmetricKeyType === 'ed448') return 'ed448';
	throw `unsupported keyAlgorithm: ${keyObject.asymmetricKeyType}`;
}
