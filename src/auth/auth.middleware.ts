import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';
import { AuthService } from './auth.service';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
    constructor(private authService: AuthService) {}
    use(req: Request, _res: Response, next: NextFunction) {
        // Perform authentication logic here (e.g., verify JWT token)
        const authUser = this.authService.verifyJwtToken(req);
        // Replace it with actual user data
        req.user = authUser;
        next();
    }
}
