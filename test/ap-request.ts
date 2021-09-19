import * as assert from 'assert';
import { genRsaKeyPair } from '../src/keypair';
import { createSignedPost, createSignedGet } from '../src/ap-request';
import { buildParsedSignature } from './utils';
import * as httpSignature from 'http-signature';

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

		const rsult = createSignedPost({ key, url, body, additionalHeaders: headers });

		const parsed = buildParsedSignature(rsult.signingString, rsult.signature, 'rsa-sha256');

		const result = httpSignature.verifySignature(parsed, keypair.publicKey);
		assert.deepStrictEqual(result, true);
	});

	it('createSignedGet with verify', async () => {
		const keypair = await genRsaKeyPair();
		const key = { keyId: 'x', 'privateKeyPem': keypair.privateKey };
		const url = 'https://example.com/inbox';
		const headers = {
			'User-Agent': 'UA'
		};

		const rsult = createSignedGet({ key, url, additionalHeaders: headers });

		const parsed = buildParsedSignature(rsult.signingString, rsult.signature, 'rsa-sha256');

		const result = httpSignature.verifySignature(parsed, keypair.publicKey);
		assert.deepStrictEqual(result, true);
	});
});
