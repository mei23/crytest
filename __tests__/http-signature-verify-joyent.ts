import { genSignature } from '../src/http-signature';
import { genRsaKeyPair, genEcKeyPair, genEd25519KeyPair, genEd448KeyPair } from '../src/keypair';
import * as httpSignature from '@peertube/http-signature';
import { buildParsedSignature } from './utils';

describe('HTTP Signature verify by joyent', () => {
	it('rsa-sha256', async () => {
		const keyPair = await genRsaKeyPair();
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, 'sha256');
		const parsed = buildParsedSignature(signingString, signature, 'rsa-sha256');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	it('rsa-sha512', async () => {
		const keyPair = await genRsaKeyPair();
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, 'sha512');
		const parsed = buildParsedSignature(signingString, signature, 'rsa-sha512');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	it('ecdsa-sha256 prime256v1', async () => {
		const keyPair = await genEcKeyPair('prime256v1');
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, 'sha256');
		const parsed = buildParsedSignature(signingString, signature, 'ecdsa-sha256');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	it('ecdsa-sha512 secp521r1', async () => {
		const keyPair = await genEcKeyPair('secp521r1');
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, 'sha512');
		const parsed = buildParsedSignature(signingString, signature, 'ecdsa-sha512');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	it('ed25519-sha512', async () => {
		const keyPair = await genEd25519KeyPair();
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, null);
		const parsed = buildParsedSignature(signingString, signature, 'ed25519-sha512');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	/*
	it('ed25519', async () => {
		const keyPair = await genEd25519KeyPair();
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, null);
		const parsed = buildParsedSignature(signingString, signature, 'ed25519');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});
	*/

	it('hs2019 (rsa-sha256)', async () => {
		const keyPair = await genRsaKeyPair();
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, 'sha256');
		const parsed = buildParsedSignature(signingString, signature, 'hs2019');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	it('hs2019 (ecdsa-sha256 prime256v1)', async () => {
		const keyPair = await genEcKeyPair('prime256v1');
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, 'sha256');
		const parsed = buildParsedSignature(signingString, signature, 'hs2019');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	it('hs2019 (ed25519-sha512)', async () => {
		const keyPair = await genEd25519KeyPair();
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, null);
		const parsed = buildParsedSignature(signingString, signature, 'hs2019');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});
});
