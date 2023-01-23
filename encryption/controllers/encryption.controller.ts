import express from 'express';
import { EncryptionService } from '../services/encryption.service';
import debug from 'debug';

const log: debug.IDebugger = debug('app:encrypt-controller');
class EncryptionController {

    async encrypt(req: express.Request, res: express.Response) {
        var encryptionService = new EncryptionService(req.body.rsaPublicKeyModulus, req.body.rsaPublicKeyExponent);
        encryptionService.encrypt(req.body.pureText).then((result) => {
            log(result);
            res.status(201).send({ encryptedValue: result });
        }, (error) => {
            log(error);
            res.status(400).send({ error: error });
        });

    }
}

export default new EncryptionController();