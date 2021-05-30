import * as crypto from 'crypto';
const { createSignatureString } = require('http-signature-header');

export class HttpSignatureSigner {
	private privateKey: string;
	private keyId: string;
	public hashAlgorithm: SignatureHashAlgorithm = 'sha256';

	constructor(privateKey: string, keyId: string) {
		this.privateKey = privateKey;
		this.keyId = keyId;
	}

	public signToRequest(requestOptions: HttpRequestOptions, includeHeaders: string[]) {
		const signingString = genSigningString(requestOptions, includeHeaders);
		const signature = genSignature(signingString, this.privateKey, this.hashAlgorithm);
		const signatureHeader = genSignatureHeader(includeHeaders, this.keyId, signature, this.hashAlgorithm);
		Object.assign(requestOptions.headers, {
			signature: signatureHeader
		});

		return {
			signingString,
			signature,
			signatureHeader,
		}
	}
}

export type HttpRequestOptions = {
	url: string;
	method: string;
	headers: Record<string, string>;
};

export type SignatureOptions = {
	hashAlgorithm?: SignatureHashAlgorithm;
};

export type DigestHashAlgorithm = 'sha256' | 'sha512';
export type SignatureHashAlgorithm = 'sha256' | 'sha384' | 'sha512';

export function genDigestHeader(body: string, hashAlgorithm: DigestHashAlgorithm = 'sha256') {
	const hash = crypto.createHash(hashAlgorithm);
	hash.update(body);
	const digest = hash.digest('base64');
	return `${hashAlgorithm === 'sha256' ? 'SHA-256' : 'SHA-512'}=${digest}`;
}

export function genSigningString(requestOptions: HttpRequestOptions, includeHeaders: string[]) {
	return createSignatureString({
		includeHeaders,
		requestOptions,
	}) as string;
}

export function genSignature(signingString: string, privateKey: string, hashAlgorithm: SignatureHashAlgorithm = 'sha256') {
	// TODO: privateKeyは本当にRSA?

	const sign = crypto.createSign(hashAlgorithm);
	sign.update(signingString);
	sign.end();

	return sign.sign(privateKey, 'base64');
}

export function genAuthorizationHeader(includeHeaders: string[], keyId: string, signature: string, hashAlgorithm: SignatureHashAlgorithm = 'sha256') {
	return `Signature ${genSignatureHeader(includeHeaders, keyId, signature, hashAlgorithm)}`;
}

export function genSignatureHeader(includeHeaders: string[], keyId: string, signature: string, hashAlgorithm: SignatureHashAlgorithm = 'sha256') {
	return `keyId="${keyId}",algorithm="rsa-${hashAlgorithm}",headers="${includeHeaders.join(' ')}",signature="${signature}"`;
}
