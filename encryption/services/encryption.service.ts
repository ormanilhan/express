import * as _ from "lodash";
import crypto from "msrcrypto";

export class EncryptionService {
    public RSAPasswordEncryptionEnabled: boolean;
    public rsaEncryptAlgorithm = { name: "RSA-OAEP", hash: { name: "SHA-256" } };
    public publicKeyHandles: string;
    public RSAPublicKeyModulus: string;
    public RSAPublicKeyExponent: string;
    public publicKey: any;

    constructor(rsaPublicKeyModulus: string, rsaPublicKeyExponent: string) {
        this.RSAPasswordEncryptionEnabled = true;
        this.RSAPublicKeyModulus = rsaPublicKeyModulus;
        this.RSAPublicKeyExponent = rsaPublicKeyExponent;

        this.publicKey = {
            kty: "RSA",
            ext: true,
            n: this.RSAPublicKeyModulus,
            e: this.RSAPublicKeyExponent
        };
        crypto.subtle.forceSync = true;
    }

    public encrypt(rawInput: string): Promise<string> {
        const promise: Promise<string> = new Promise<string>((resolve, reject) => {
            crypto.subtle
                .importKey("jwk", this.publicKey, this.rsaEncryptAlgorithm, true, [
                    "encrypt"
                ])
                .then((publickey: string) => {
                    this.publicKeyHandles = publickey;
                    if (this.RSAPasswordEncryptionEnabled && !_.isEmpty(rawInput)) {
                        let input: any = rawInput;
                        if (typeof input != "string" && input && input.toString()) {
                            input = input.toString();
                        }
                        if (this.IsEncrypted(rawInput)) {
                            resolve(rawInput);
                        } else {
                            let plainTextBytes = this.toSupportedArray(rawInput);

                            crypto.subtle
                                .encrypt(
                                    this.rsaEncryptAlgorithm,
                                    this.publicKeyHandles,
                                    plainTextBytes
                                )
                                .then((encrypted: any) => {
                                    let encryptedBytes = this.toSupportedArray(encrypted);
                                    let encryptedText = crypto.toBase64(encryptedBytes, false);
                                    resolve(encryptedText);
                                });
                        }
                    } else {
                        resolve(rawInput);
                    }
                });
        });
        return promise;
    }

    public IsEncrypted(input: string): boolean {
        return input.length > 128 && input.lastIndexOf("=") === input.length - 1;
    }

    public toSupportedArray(data: any) {
        // does this browser support Typed Arrays?
        var typedArraySupport = typeof Uint8Array !== "undefined";

        // get the data type of the parameter
        var dataType = Object.prototype.toString.call(data);
        dataType = dataType.substring(8, dataType.length - 1);

        // determine the type
        switch (dataType) {
            // Regular JavaScript Array. Convert to Uint8Array if supported
            // else do nothing and return the array
            case "Array":
                return typedArraySupport ? new Uint8Array(data) : data;

            // ArrayBuffer. IE11 Web Crypto API returns ArrayBuffers that you have to convert
            // to Typed Arrays. Convert to a Uint8Arrays and return;
            case "ArrayBuffer":
                return new Uint8Array(data);

            // Already Uint8Array. Obviously there is support.
            case "Uint8Array":
                return data;

            case "Uint16Array":
            case "Uint32Array":
                return new Uint8Array(data);

            // String. Convert the string to a byte array using Typed Arrays if
            // supported.
            case "String":
                var newArray = typedArraySupport
                    ? new Uint8Array(data.length)
                    : new Array(data.length);
                for (var i = 0; i < data.length; i += 1) {
                    newArray[i] = data.charCodeAt(i);
                }
                return newArray;

            // Some other type. Just return the data unchanged.
            default:
                throw new Error("toSupportedArray : unsupported data type " + dataType);
        }
    }
}

