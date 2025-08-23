import {exec} from "child_process";
import {readdir, mkdtemp, readFile, rmdir, mkdir} from "fs/promises";
import {writeFileSync} from "fs";
import {extname, join} from "path";
import {createHash, createPrivateKey, createPublicKey, createSecretKey, randomUUID, KeyObject} from "crypto";
import {tmpdir} from "os";

export type OpenSSLVersion = {
    major: number,
    minor: number,
    patch: number
    release_date: string,
    lib: {
        major: number,
        minor: number,
        patch: number,
        release_date: string,
    }
}

export type OpenSSLBuffer = {
    get sha1(): string;
    get sha256(): string;
    get md5(): string;
    get isChain(): boolean
    get type(): string
    get mimeType(): string
    get certificates(): string[],
    get data(): string;
    toObject(): KeyObject;
} & Buffer

export class OpenSSLError extends Error {

    private static Messages = {
        NOT_INSTALLED: `
\x1b[41mOpenSSL isn't correctly installed or is not configured correctly.\x1b[0m
Check: Make sure if you open a \x1b[4mnew\x1b[0m terminal and type 'openssl version' that you get output that looks something like 'OpenSSL 3.4.1 11 Feb 2025 (Library: OpenSSL 3.4.1 11 Feb 2025)'
If you dont have OpenSSL installed, you have two options:
    1. Compile and install from source (https://github.com/openssl/openssl/blob/master/INSTALL.md)
    2. Install from a precompile binary (https://github.com/openssl/openssl/wiki/Binaries)
`
    }

    constructor(public readonly stderr: string, public readonly execArgs: string[], public readonly processError: Error) {
        super(stderr);
    }



    static NOT_INSTALLED(err: Error) {
        console.error(this.Messages.NOT_INSTALLED, '\n', err);
    }

}

function mergeToInterleavedArray(jsonArray: (string[] | any)[]): (string | any)[] {
    const result: (string | Buffer)[] = [];

    // Extract the string template
    if (Array.isArray(jsonArray[0])) {
        const strings = jsonArray[0] as string[];
        let bufferIndex = 1;

        for (const str of strings) {
            result.push(str);

            // Insert buffers between strings where appropriate
            if (bufferIndex < jsonArray.length) {
                const item = jsonArray[bufferIndex];
                result.push(item);
                bufferIndex++;
            }
        }
    }

    return result;
}

function OpenSSLPromise(input: Promise<OpenSSLBuffer[] & { args: any[] }>) {
    return Object.assign(input, {
        one: () => input.then((r) => r[0])
    })
}

export class OpenSSL {

    private static HELPERS = Object.seal({
        bufferSymbol: Symbol('OpenSSL::Buffer'),
        versionRegex: /^OpenSSL\s+(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)\s+(?<release_date>\d{1,2}\s+[A-Za-z]+\s+\d{4})\s+\(Library:\s+OpenSSL\s+(?<lib_major>\d+)\.(?<lib_minor>\d+)\.(?<lib_patch>\d+)\s+(?<lib_release_date>\d{1,2}\s+[A-Za-z]+\s+\d{4})\)$/gm,
        /**
         * @see https://pki-tutorial.readthedocs.io/en/latest/mime.html#mime-types
         */
        mime_types: {
            '.p8': 'application/pkcs8',
            '.key': 'application/pkcs8',
            '.p10': 'application/pkcs10',
            '.csr': 'application/pkcs10',
            '.cer': 'application/pkix-cert',
            '.pkix.crl': 'application/pkix-crl',
            '.p7c': 'application/pkcs7-mime',

            '.ca.crt': 'application/x-x509-ca-cert',
            '.crt': 'application/x-x509-user-cert',
            '.crl': 'application/x-pkcs7-crl',

            '.pem': 'application/x-pem-file',
            '.p12': 'application/x-pkcs12',
            '.pfx': 'application/x-pkcs12',

            '.p7b': 'application/x-pkcs7-certificates',
            '.spc': 'application/x-pkcs7-certificates',
            '.p7r': 'application/x-pkcs7-certreqresp'
        },
        tempDir: (prefix: string) => {
            const path = join(tmpdir(), `${prefix}-${randomUUID()}`);
            return mkdir(path, {recursive: true}).then(() => path, () => mkdtemp(prefix));
        }
    })

    public static readonly BufferSymbol = Symbol('OpenSSL::Buffer')

    private static VERSION: OpenSSLVersion;

    public static get version() {
        return this.VERSION;
    }

    public static get mime_types() {
        return this.HELPERS.mime_types;
    }

    public static PROXY = new Proxy(
        new (class extends Function {
        }),
        {
            apply: (_, __, argArray) => OpenSSL.exec(argArray),
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            get: (_, prop, __) => {
                if (prop in OpenSSL && OpenSSL[prop as keyof OpenSSL]) {
                    return OpenSSL[prop as keyof OpenSSL];
                } else {
                    throw 'Unable to determine target property'
                }
            }
        }
    )

    public static exec(args: any[], workdir: string | Promise<string> = OpenSSL.HELPERS.tempDir('openssl')) {
        return OpenSSLPromise(new Promise<OpenSSLBuffer[] & { args: any[] }>(async (resolve, reject) => {
            const cwd = await workdir;
            const output: OpenSSLBuffer[] = [];
            if (args.some((item) => typeof item !== 'string')) args = mergeToInterleavedArray(args)
            const execArgs = await Promise.all(args.map(async (arg, index) => {
                if (arg instanceof Promise) arg = await arg;
                if (Array.isArray(arg) && arg.length === 1) arg = arg[0];
                if (typeof arg === 'string') {
                    return arg;
                } else if (arg instanceof Buffer) {
                    const path = `./__${index}.raw`;
                    writeFileSync(join(cwd, `__${index}.raw`), arg)
                    return path;
                }
                return arg?.toString() as string
            }));
            exec(['openssl', ' ', ...execArgs].join(''), {cwd, encoding: 'utf-8'}, async (error, stdout, stderr) => {
                if (stdout && stdout.length > 0) output.push(this.TransformBuffer(Buffer.from(stdout)));
                if (error) reject(new OpenSSLError(stderr, execArgs, error));
            })
                .on('close', async () => {
                    const filePaths = await readdir(cwd).then((files) => files.filter((file) => !file.startsWith("__")).map((file) => join(cwd, file)), () => []);
                    for (const filePath of filePaths) {
                        const data = await readFile(filePath).catch(() => null);
                        if (data) {
                            const file_type = extname(filePath)
                            let mime_type = 'application/octet-stream'
                            if (file_type in OpenSSL.HELPERS.mime_types) mime_type = OpenSSL.HELPERS.mime_types[file_type as keyof typeof OpenSSL.HELPERS.mime_types]
                            output.push(this.TransformBuffer(data, mime_type))
                        }
                    }
                    const out = Object.assign(output, {args})
                    return rmdir(cwd).then(() => resolve(out), () => resolve(out))
                })
        }))
    }


    public static init() {
        return new Promise<string>((resolve, reject) =>
            exec('openssl version', {encoding: 'utf-8'}, (err, stdout) => {
                if (err) return reject(err);
                resolve(stdout);
            })
        ).then(
            (v) => {
                const version = OpenSSL.HELPERS.versionRegex.exec(v);
                OpenSSL.VERSION = {
                    major: parseInt(version?.groups?.['major'] ?? '-1'),
                    minor: parseInt(version?.groups?.['minor'] ?? '-1'),
                    patch: parseInt(version?.groups?.['patch'] ?? '-1'),
                    release_date: version?.groups?.['release_date'] ?? '',
                    lib: {
                        major: parseInt(version?.groups?.['lib_major'] ?? '-1'),
                        minor: parseInt(version?.groups?.['lib_minor'] ?? '-1'),
                        patch: parseInt(version?.groups?.['lib_patch'] ?? '-1'),
                        release_date: version?.groups?.['lib_release_date'] ?? '',
                    }
                }
            },
            (reason) => {
                if (reason.message.includes("not recognized")) {
                    OpenSSLError.NOT_INSTALLED(reason)
                } else {
                    console.error(reason);
                }
                process.exit(1);
            }
        )
    }

    public static isOpenSSLBuffer(b: object): b is OpenSSLBuffer {
        return OpenSSL.BufferSymbol in b && b instanceof Buffer
    }
    public static isOpenSSLError(obj: any): obj is OpenSSLError {
        return obj instanceof OpenSSLError;
    }

    public static TransformBuffer(b: Buffer, mimeType: string = 'application/octet-stream'): OpenSSLBuffer {
        const pemAnalyses = this.AnalysePEM(b.toString('utf-8'))
        return Object.assign(b, {
            get sha1() {
                return createHash('sha1').update(b).digest().toString('base64url');
            },
            get md5() {
                return createHash('md5').update(b).digest().toString('base64url');
            },
            get sha256() {
                return createHash('sha256').update(b).digest().toString('base64url');
            },
            get data() {
                return b.toString('utf-8')
                    .replace(/(\r\n|\r)/g, '\n')
                    .replace(/-----BEGIN [A-Z\x20]{1,48}-----\n?/, '')
                    .replace(/-----END [A-Z\x20]{1,48}-----\n?/, '');
            },
            toObject(): KeyObject {
                if (pemAnalyses.type === 'CERTIFICATE' || pemAnalyses.type === 'PUBLIC KEY') {
                    return createPublicKey(b);
                } else if (pemAnalyses.type == 'PRIVATE KEY') {
                    return createPrivateKey(b);
                } else {
                    return createSecretKey(b);
                }
            },
            ...pemAnalyses,
            mimeType,
            [OpenSSL.BufferSymbol]: true,
        }) as unknown as OpenSSLBuffer
    }

    public static AnalysePEM(data: Buffer | string) {
        const pemContent: string = data.toString('utf-8')
        // Regex to extract the PEM type
        const typeMatch = pemContent.match(/(?<=-----BEGIN )[A-Z ]+(?=-----)/);
        const pemType = typeMatch ? typeMatch[0] : "Unknown";

        // Regex to find all certificate blocks
        const certificateBlocks = pemContent.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
        const isChain = certificateBlocks.length > 1;

        return {
            type: pemType,
            isChain: isChain,
            certificates: isChain ? certificateBlocks : [],
        };
    }

}

await OpenSSL.init()

export type MagicTemplateFunction<R> = (strings: TemplateStringsArray, ...values: any[]) => R
export type OpenSSLProxyOperator =
    MagicTemplateFunction<ReturnType<typeof OpenSSL['exec']>>
    & { get version(): OpenSSLVersion }

export const openssl = OpenSSL.PROXY as OpenSSLProxyOperator;
