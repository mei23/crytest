import * as assert from 'assert';
import { HttpSignature, verifySignature } from '../src/http-signature';
import { genRsaKeyPair, genEcKeyPair, genEd25519KeyPair, genEd448KeyPair } from '../src/keypair';

type ParsedSignature = {
	scheme: 'Signature';
	params: {
		keyId: string;
		algorithm: string;	// 'rsa-sha256'
		headers: string[];	//[ '(request-target)', 'date', 'host', 'digest' ],
		signature: string;
	};
	signingString: string;
	algorithm: string;	// 'RSA-SHA256'
	keyId: string;
};

const buildParsedSignature = (signingString: string, signature: string, algorithm: string) => {
	return {
		scheme: 'Signature',
		params: {
			keyId: 'KeyID',
			algorithm: algorithm,
			headers: [ '(request-target)', 'date', 'host', 'digest' ],
			signature: signature,
		},
		signingString: signingString,
		algorithm: algorithm?.toUpperCase(),
		keyId: 'KeyID',
	} as ParsedSignature;
};

describe('HTTP Signature verify', () => {
	it('rsa-sha256 2048', async () => {
		const keyPair = await genRsaKeyPair(2048);
		const signingString = 'foo';
		const signature = HttpSignature.genSignature(signingString, keyPair.privateKey, 'sha256');
		const parsed = buildParsedSignature(signingString, signature, 'rsa-sha256');
		const result = verifySignature(parsed, keyPair.publicKey);
		assert.deepStrictEqual(result, true);
	});

	it('rsa-sha256 2048 2', async () => {
		const keyPair = await genRsaKeyPair(2048);
		const signingString = 'foo';
		const signature = HttpSignature.genSignature(signingString, keyPair.privateKey, 'sha256');
		const parsed = buildParsedSignature(signingString, signature, undefined);
		const result = verifySignature(parsed, keyPair.publicKey);
		assert.deepStrictEqual(result, true);
	});

	it('ecdsa-sha512', async () => {
		const keyPair = await genEcKeyPair();
		const signingString = 'foo';
		const signature = HttpSignature.genSignature(signingString, keyPair.privateKey, 'sha512');
		const parsed = buildParsedSignature(signingString, signature, 'ecdsa-sha512');
		const result = verifySignature(parsed, keyPair.publicKey);
		assert.deepStrictEqual(result, true);
	});

	it('ed25519', async () => {
		const keyPair = await genEd25519KeyPair();
		const signingString = 'foo';
		const signature = HttpSignature.genSignature(signingString, keyPair.privateKey, null);
		const parsed = buildParsedSignature(signingString, signature, undefined);
		const result = verifySignature(parsed, keyPair.publicKey);
		assert.deepStrictEqual(result, true);
	});

	it('ed448', async () => {
		const keyPair = await genEd448KeyPair();
		const signingString = 'foo';
		const signature = HttpSignature.genSignature(signingString, keyPair.privateKey, null);
		const parsed = buildParsedSignature(signingString, signature, undefined);
		const result = verifySignature(parsed, keyPair.publicKey);
		assert.deepStrictEqual(result, true);
	});
});
