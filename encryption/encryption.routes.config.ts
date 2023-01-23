import { CommonRoutesConfig } from '../common/common.routes.config';
import EncryptionController from './controllers/encryption.controller';
import express from 'express';

export class EncryptionRoutes extends CommonRoutesConfig {
    constructor(app: express.Application) {
        super(app, 'EncryptionRoutes');
    }

    configureRoutes() {
        this.app.route(`/encryption`)
            .post(EncryptionController.encrypt);
        return this.app;
    }
}