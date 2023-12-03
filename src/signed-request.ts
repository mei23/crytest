import * as crypto from 'crypto';
import { Request, PrivateKey, signToRequest } from './http-signature';

export function createSignedPost(args: { key: PrivateKey, url: string, body: string, additionalHeaders: Record<string, string> }) {
	const u = new URL(args.url);

	const request: Request = {
		url: u.href,
		method: 'POST',
		headers:  objectAssignWithLcKey({
			'Date': new Date().toUTCString(),
			'Host': u.hostname,
			'Content-Type': 'application/activity+json',
			'Digest': genDigestHeader(args.body),
		}, args.additionalHeaders),
	};

	const result = signToRequest(request, args.key, ['(request-target)', 'date', 'host', 'digest']);

	return {
		request,
		signingString: result.signingString,
		signature: result.signature,
		signatureHeader: result.signatureHeader,
	};
}

export function createSignedGet(args: { key: PrivateKey, url: string, additionalHeaders: Record<string, string> }) {
	const u = new URL(args.url);

	const request: Request = {
		url: u.href,
		method: 'GET',
		headers:  objectAssignWithLcKey({
			'Accept': 'application/activity+json, application/ld+json',
			'Date': new Date().toUTCString(),
			'Host': u.hostname,
		}, args.additionalHeaders),
	};

	const result = signToRequest(request, args.key, ['(request-target)', 'date', 'host', 'accept']);

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

function lcObjectKey(src: Record<string, string>) {
	const dst: Record<string, string> = {};
	for (const key of Object.keys(src).filter(x => x != '__proto__' && typeof src[x] === 'string')) dst[key.toLowerCase()] = src[key];
	return dst;
}

function objectAssignWithLcKey(a: Record<string, string>, b: Record<string, string>) {
	return Object.assign(lcObjectKey(a), lcObjectKey(b));
}
