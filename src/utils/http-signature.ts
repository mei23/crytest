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

export type SignatureHashAlgorithm = 'sha256' | 'sha384' | 'sha512';

export class HttpSignature {
	private key: SignatureKey;
	public hashAlgorithm: SignatureHashAlgorithm = 'sha256';

	constructor(key: SignatureKey) {
		this.key = key;
	}

	public signToRequest(requestOptions: RequestOptions, includeHeaders: string[]) {
		const signingString = HttpSignature.genSigningString(requestOptions, includeHeaders);
		const signature = HttpSignature.genSignature(signingString, this.key.privateKeyPem, this.hashAlgorithm);
		const signatureHeader = HttpSignature.genSignatureHeader(includeHeaders, this.key.keyId, signature, this.hashAlgorithm);
		Object.assign(requestOptions.headers, {
			Signature: signatureHeader
		});

		return {
			signingString,
			signature,
			signatureHeader,
		}
	}

	public static genSigningString(requestOptions: RequestOptions, includeHeaders: string[]) {
		return createSignatureString({
			includeHeaders,
			requestOptions,
		}) as string;
	}
	
	public static genSignature(signingString: string, privateKey: string, hashAlgorithm: SignatureHashAlgorithm = 'sha256') {
		// TODO: privateKeyは本当にRSA?
		const sign = crypto.createSign(hashAlgorithm);
		sign.update(signingString);
		sign.end();
	
		return sign.sign(privateKey, 'base64');
	}
	
	public static genAuthorizationHeader(includeHeaders: string[], keyId: string, signature: string, hashAlgorithm: SignatureHashAlgorithm = 'sha256') {
		return `Signature ${HttpSignature.genSignatureHeader(includeHeaders, keyId, signature, hashAlgorithm)}`;
	}
	
	public static  genSignatureHeader(includeHeaders: string[], keyId: string, signature: string, hashAlgorithm: SignatureHashAlgorithm = 'sha256') {
		return `keyId="${keyId}",algorithm="rsa-${hashAlgorithm}",headers="${includeHeaders.join(' ')}",signature="${signature}"`;
	}
	
}
