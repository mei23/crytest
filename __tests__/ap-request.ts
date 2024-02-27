import { genRsaKeyPair } from '../src/keypair';
import { createSignedPost, createSignedGet } from '../src/portable/ap-request';
import { buildParsedSignature } from './utils';
import * as httpSignature from '@peertube/http-signature';

describe('ap-request', () => {
	it('createSignedPost with verify', async () => {
		const keypair = await genRsaKeyPair();
		const key = { keyId: 'x', 'privateKeyPem': keypair.privateKey };
		const url = 'https://example.com/inbox';
		const activity = { a: 1 };
		const body = JSON.stringify(activity);
		const headers = {
			'User-Agent': 'UA'
		};

		const req = createSignedPost({ key, url, body, additionalHeaders: headers });

		const parsed = buildParsedSignature(req.signingString, req.signature, 'rsa-sha256');

		const result = httpSignature.verifySignature(parsed, keypair.publicKey);
		expect(result).toBe(true);
	});

	it('createSignedGet with verify', async () => {
		const keypair = await genRsaKeyPair();
		const key = { keyId: 'x', 'privateKeyPem': keypair.privateKey };
		const url = 'https://example.com/outbox';
		const headers = {
			'User-Agent': 'UA'
		};

		const req = createSignedGet({ key, url, additionalHeaders: headers });

		const parsed = buildParsedSignature(req.signingString, req.signature, 'rsa-sha256');

		const result = httpSignature.verifySignature(parsed, keypair.publicKey);
		expect(result).toBe(true);
	});
});
