import * as crypto from 'crypto';
import * as util from 'util';

const generateKeyPair = util.promisify(crypto.generateKeyPair);

export async function genRsaKeyPair(modulusLength = 2048) {
	return await generateKeyPair('rsa', {
		modulusLength,
		publicKeyEncoding: {
			type: 'spki',
			format: 'pem'
		},
		privateKeyEncoding: {
			type: 'pkcs8',
			format: 'pem',
			cipher: undefined,
			passphrase: undefined
		}
	});
}

export type EcCurves = 'prime256v1' | 'secp384r1' | 'secp521r1' | 'curve25519';

export async function genEcKeyPair(namedCurve: EcCurves = 'prime256v1') {
	return await generateKeyPair('ec', {
		namedCurve,
		publicKeyEncoding: {
			type: 'spki',
			format: 'pem'
		},
		privateKeyEncoding: {
			type: 'pkcs8',
			format: 'pem',
			cipher: undefined,
			passphrase: undefined
		}
	});
}

/**
 * PKCS1形式かもしれない公開キーをSPKI形式に統一して出力する
 */
export function toSpkiPublicKey(publicKey: string) {
	return crypto.createPublicKey(publicKey).export({
		type: 'spki',
		format: 'pem'
	});
}
