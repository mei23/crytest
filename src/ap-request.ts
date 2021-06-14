import * as crypto from 'crypto';

type Request = {
	url: string;
	method: string;
	headers: Record<string, string>;
};

type PrivateKey = {
	privateKeyPem: string;
	keyId: string;
};

export function createSignedPost(key: PrivateKey, url: string, body: string, headers: Record<string, string>) {
	const u = new URL(url);
	const digestHeader = `SHA-256=${crypto.createHash('sha256').update(body).digest('base64')}`;

	const request: Request = {
		url: u.href,
		method: 'POST',
		headers:  Object.assign({
			'Date': new Date().toUTCString(),
			'Host': u.hostname,
			'Content-Type': 'application/activity+json',
			'Digest': digestHeader,
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

export function createSignedGet(key: PrivateKey, url: string, headers: Record<string, string>) {
	const u = new URL(url);

	const request: Request = {
		url: u.href,
		method: 'GET',
		headers:  Object.assign({
			'Accept': 'application/activity+json, application/ld+json',
			'Date': new Date().toUTCString(),
			'Host': new URL(url).hostname,
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

function signToRequest(request: Request, key: PrivateKey, includeHeaders: string[]) {
	const signingString = genSigningString(request, includeHeaders);
	const signature = crypto.sign('sha256', Buffer.from(signingString), key.privateKeyPem).toString('base64');
	const signatureHeader = `keyId="${key.keyId}",algorithm="rsa-sha256",headers="${includeHeaders.join(' ')}",signature="${signature}"`;

	Object.assign(request.headers, {
		Signature: signatureHeader
	});

	return {
		request,
		signingString,
		signature,
		signatureHeader,
	};
}

function genSigningString(request: Request, includeHeaders: string[]) {
	const lcObjectKey = (src: Record<string, string>) => {
		const dst: Record<string, string> = {};
		for (const key of Object.keys(src).filter(x => x != '__proto__')) dst[key.toLowerCase()] = src[key];
		return dst;
	}

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
