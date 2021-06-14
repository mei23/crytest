import * as assert from 'assert';
import { genAuthorizationHeader, genSignature, genSignatureHeader, genSigningString } from '../src/http-signature';

describe('HTTP Signature', () => {
	it('genSigningString', () => {
		const signingString = genSigningString({
			url: 'https://host1.example.com/path',
			method: 'GET',
			headers: {
				Accept: '*/*',
				Host: 'host1.example.com',
				Date: 'Fri, 11 Jun 2021 16:15:11 GMT',
			}
		}, ['(request-target)', 'date', 'host', 'accept'])

		assert.strictEqual(
			signingString,
			'(request-target): get /path\n' +
			'date: Fri, 11 Jun 2021 16:15:11 GMT\n' +
			'host: host1.example.com\n' +
			'accept: */*'
		);
	});

	it('genSignature', () => {
		const privateKey = '-----BEGIN PRIVATE KEY-----\n' +
			'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDC+Ie3GY5D1TNU\n' +
			'v/PLweQUcqT16XNkI+WiZAFYiwLUvz3S23boJwgsNDEjKiaVhkeGRiYueMSlvDTW\n' +
			'BNYdtkqctpfq1w16FOB78R7CpYxcFxp1yqb9naypwx8J1TJi2Zc/mRbB8SpOr1Fj\n' +
			'TeIKKSm1IEx/kplEctw0OmT714Gm8gSMkxMRtEZdRsIokmTyzGoGXSHzsBPDgnFr\n' +
			'lDE789opcH1yto4ni2zn0WtNrIgF4uoQmessczuVlTMPX7HEgrvzAuh5fKRPodhF\n' +
			'5y6fPMwZSL3dEkfAeeWOsYG5vykRibJrag4JFBzHwkkGhSRtSRWpMcfuyejJgq2S\n' +
			'd2Qrgog1AgMBAAECggEAMBZkQsDG2ewnsOt3EfZMbs6n6Q8fKr+/z4Gi41fF5vsU\n' +
			'IIGInlGiLmThCa9HvPFVisSafjPDLK1yyqZ+uO1REb3nUkCgTk//3hHmaFO0frIk\n' +
			'EJFfBoZxI53AdghjWQYZy9HSTxtQN//9ruRyr9bfNpE0zPI3Yy6BKVCNv5+zlp0E\n' +
			'JTS3qphWIMXMmxKDw4vQLw1zD8udiq7WuWsNYUSSZsrq+GPsBS2QB6cYHRhIoFAu\n' +
			'r3/07s9Px1xt7n7B14QfGVSZ/gqBoP5toeAl7L6UqYmZ//4k5Okx6JzwsrswPYm8\n' +
			'eVQPvSPtz0laAXkYY4/A2L0CcBNFIuoclMvKsXWKsQKBgQDs4gyEKSGijVHWXcYe\n' +
			'yuYaU/rmlGhWqoUzSQ7bP87FcqQxPE1HMx6NXOIpxF14RcMjgCVAzLK//xB7RCb/\n' +
			'o1z0t9MDXQ0lgyd5OJQacGEJXUk6/rFRdoSaoeXCK9m4b3C2EsZRKcjbqlQ4LOYj\n' +
			'6w1IMHL/NiqviZ9JLy/iyJ2UYwKBgQDStJWvaxM68w3cAQo/2fwr6/GPm91J040G\n' +
			'wyZkbH98zyrJ+XxGnuB4EmRlIu2JoLB8AW5zR0tu4CDrkX+EOkRFl79EqlVF+yqi\n' +
			'c8w1XVmNhJgA6UXVfPxX4huc1+RAqk1IEKouwffGWpOcvzfWbvkGShb7McjjoNOg\n' +
			'NUfkw4AYhwKBgCyEHo4HnMaLgEGkxcKrpqpz9ca3RRRkXzvQEvao+xaoAKswBeXH\n' +
			'eYpfVjE7McWUdqOJRXb0APOL33EK0blg3esvUHxlVD8kcpqZQ1vkmpfD7CsmCfSh\n' +
			'LTJSEnd2/idm6euNg69lBtYhIEqeRXGijpBuam4Do+nxFvoN4BXiVZq5AoGBAM9q\n' +
			'mVc/boS/Mst58p78dPK/puGZq3K7X75iaO6+p5kzTonYoG/cgldws4ejpHWwy0qn\n' +
			'FhVA/46772w1pHOD8CUZxl1P1/W11DhrCYEWzcsz1XZALFCGYtoYaNoy5CyL+NuS\n' +
			'HBU/OCv4igrpaYwbXeTFFm5ciccaUHkLOiSGFxkNAoGAXEe/NS6Md6sVOl3GoQce\n' +
			'IOZCNO2RoGhzgiRQWcYKltxmmRGqz8f0mgef9BMGERcP/BLjD9Ltw+6nkqO3t14M\n' +
			'r3/AYXSNHNSTsOCJFaE5wyNaWRuyjOxDHWCPzKUpBkd0u6x7/mU9ZYsKJmON9rY+\n' +
			'J9HgWyymBJcN4rTR/lGbS0I=\n' +
			'-----END PRIVATE KEY-----\n';

		const signature = genSignature('abc', privateKey, 'sha256');

		assert.strictEqual(
			signature,
			'uoSHT+Vhfu4ChwY6t9dDx92daPTKxxPaTCYoPpGFhAqmUcxvImWKfetfkBLDCrXManpqz/4k6AXLtHekYXD0/MYadNG5tJCu27EHvMt0sfOv/LiYL2VBfeDJ3i+r/tMAkM/YFf8cg93TnAi70wwTifQ/fdPcvPCNrouMlSm4MDrhf56X0gIc7jNRYuVswjXpfxt+js+mfsaJUzVIFaVFemNFTaveeS+6F7z7nu4eSfxjeyLXpaJYsQS5tGaVAgk2RJEiD4PG2zGkwNA3iJKLd7Z1t9N74/8AHwVMD9HNqc/Zjd4HZt33i+GrlJbqxv+ZHPCddl4/7x5PgwmOVfdI4Q=='
		);
	});

	it('genAuthorizationHeader', () => {
		const header = genAuthorizationHeader(['foo', 'bar'], 'KeyIdaaa', 'Signature', 'rsa-sha256');

		assert.strictEqual(
			header,
			'Signature keyId="KeyIdaaa",algorithm="rsa-sha256",headers="foo bar",signature="Signature"'
		);
	});

	it('genSignatureHeader', () => {
		const header = genSignatureHeader(['foo', 'bar'], 'KeyIdaaa', 'Signature', 'rsa-sha256');

		assert.strictEqual(
			header,
			'keyId="KeyIdaaa",algorithm="rsa-sha256",headers="foo bar",signature="Signature"'
		);
	});

	it('genSignatureHeader algorithm omited', () => {
		const header = genSignatureHeader(['foo', 'bar'], 'KeyIdaaa', 'Signature', undefined);

		assert.strictEqual(
			header,
			'keyId="KeyIdaaa",headers="foo bar",signature="Signature"'
		);
	});
});
