import { inspect } from 'util';
import { RequestOptions, genSigningString, genSignature, genSignatureHeader, HttpSignatureSigner } from './utils/http-signature';
import { genRsaKeyPair } from './utils/keypair';

async function main() {
	const keypair = await genRsaKeyPair();

	const requestOptions: RequestOptions = {
		url: 'https://host2.test/inbox',
		method: 'POST',
		headers: {
			host: 'host2.test',
			date: new Date().toUTCString(),
			digest: 'x',
		}
	};

	const includeHeaders = ['(request-target)', 'host', 'date', 'digest'];
	const signingString = genSigningString(requestOptions, includeHeaders);

	const signature = genSignature(signingString, keypair.privateKey);
	//const authorizationHeader = genAuthorizationHeader(includeHeaders, 'x1', signature);
	const signatureHeader = genSignatureHeader(includeHeaders, 'x1', signature);

	console.log(inspect({
		privateKey: keypair.privateKey,
		publicKey: keypair.publicKey,
		signingString,
		signature,
		signatureHeader,
	}));

	const sn = new HttpSignatureSigner({ privateKeyPem: keypair.privateKey, keyId: 'key1' });
	const re = sn.signToRequest(requestOptions, includeHeaders);
	console.log(inspect(requestOptions));
	console.log(inspect(re));
}

main()
	.then(() => {})
	.catch(e => console.log(e));
