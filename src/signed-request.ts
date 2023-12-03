import * as crypto from 'crypto';
import { Request, PrivateKey, signToRequest } from './http-signature';

export function genSignedPost(key: PrivateKey, url: string, body: string, headers: Record<string, string>) {
	const u = new URL(url);

	const request: Request = {
		url: u.href,
		method: 'POST',
		headers:  Object.assign({
			'Date': new Date().toUTCString(),
			'Host': u.hostname,
			'Content-Type': 'application/activity+json',
			'Digest': genDigestHeader(body),
		}, headers),
	};

	const result = signToRequest(request, key, ['(request-target)', 'date', 'host', 'digest']);

	return {
		request,
		signingString: result.signingString,
		signature: result.signature,
		signatureHeader: result.signatureHeader,
	};
}

export function genSignedGet(key: PrivateKey, url: string, headers: Record<string, string>) {
	const u = new URL(url);

	const request: Request = {
		url: u.href,
		method: 'GET',
		headers:  Object.assign({
			'Accept': 'application/activity+json, application/ld+json',
			'Date': new Date().toUTCString(),
			'Host': u.hostname,
		}, headers),
	};

	const result = signToRequest(request, key, ['(request-target)', 'date', 'host', 'accept']);

	return {
		request,
		signingString: result.signingString,
		signature: result.signature,
		signatureHeader: result.signatureHeader,
	};
}

export function genDigestHeader(body: string, hashAlgorithm: 'sha256' | 'sha512' = 'sha256') {
	const hash = crypto.createHash(hashAlgorithm);
	hash.update(body);
	const digest = hash.digest('base64');
	return `${hashAlgorithm === 'sha256' ? 'SHA-256' : 'SHA-512'}=${digest}`;
}
