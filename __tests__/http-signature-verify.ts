import { genSignature, verifySignature } from '../src/http-signature';
import { genRsaKeyPair, genEcKeyPair, genEd25519KeyPair, genEd448KeyPair } from '../src/keypair';
import { buildParsedSignature } from './utils';

describe('HTTP Signature verify', () => {
	it('rsa-sha256', async () => {
		const keyPair = await genRsaKeyPair();
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, 'sha256');
		const parsed = buildParsedSignature(signingString, signature, 'rsa-sha256');
		const result = verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	it('rsa-sha256 algorithm omited', async () => {
		const keyPair = await genRsaKeyPair();
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, 'sha256');
		const parsed = buildParsedSignature(signingString, signature, undefined);
		const result = verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	it('ecdsa-sha256 prime256v1', async () => {
		const keyPair = await genEcKeyPair('prime256v1');
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, 'sha512');
		const parsed = buildParsedSignature(signingString, signature, 'ecdsa-sha512');
		const result = verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	it('ecdsa-sha512 secp521r1', async () => {
		const keyPair = await genEcKeyPair('secp521r1');
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, 'sha512');
		const parsed = buildParsedSignature(signingString, signature, 'ecdsa-sha512');
		const result = verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	it('ed25519', async () => {
		const keyPair = await genEd25519KeyPair();
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, null);
		const parsed = buildParsedSignature(signingString, signature, 'ed25519');
		const result = verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});

	it('ed448', async () => {
		const keyPair = await genEd448KeyPair();
		const signingString = 'foo';
		const signature = genSignature(signingString, keyPair.privateKey, null);
		const parsed = buildParsedSignature(signingString, signature, 'ed448');
		const result = verifySignature(parsed, keyPair.publicKey);
		expect(result).toBe(true);
	});
});
