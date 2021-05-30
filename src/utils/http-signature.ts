import * as crypto from 'crypto';
const { createSignatureString } = require('http-signature-header');

export class HttpSignatureSigner {
	private privateKey: string;
	private keyId: string;
	private hashAlgorithm: SignatureHashAlgorithm = 'sha256';

	constructor(privateKey: string, keyId: string) {
		this.privateKey = privateKey;
		this.keyId = keyId;
	}

	public signToRequest(requestOptions: HttpRequestOptions, includeHeaders: string[]) {
		const signingString = genSigningString(requestOptions, includeHeaders);
		const signature = genSignature(signingString, this.privateKey, { hashAlgorithm: this.hashAlgorithm });
		const signatureHeader = genSignatureHeader(includeHeaders, this.keyId, signature);
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

export type SignatureHashAlgorithm = 'sha256';	// TODO

export function genSigningString(requestOptions: HttpRequestOptions, includeHeaders: string[]) {
	return createSignatureString({
		includeHeaders,
		requestOptions,
	}) as string;
}

export function genSignature(signingString: string, privateKey: string, signatureOptions?: SignatureOptions) {
	const hashAlgorithm = signatureOptions?.hashAlgorithm || 'sha256';
	// TODO: privateKeyは本当にRSA?

	const sign = crypto.createSign(hashAlgorithm);
	sign.update(signingString);
	sign.end();
	return sign.sign(privateKey, 'base64');
}

export function genAuthorizationHeader(includeHeaders: string[], keyId: string, signature: string) {
	return `Signature ${genSignatureHeader(includeHeaders, keyId, signature)}`;
}

export function genSignatureHeader(includeHeaders: string[], keyId: string, signature: string) {
	return `keyId="${keyId}",algorithm="${'rsa-sha256'}",headers="${includeHeaders.join(' ')}",signature="${signature}"`;
}
