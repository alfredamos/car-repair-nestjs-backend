import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';
import { AuthService } from './auth.service';
import { isPublicRoute } from '../utils/publicRoute.util';


@Injectable()
export class AuthMiddleware implements NestMiddleware {
    constructor(private authService: AuthService) {}
    use(req: Request, _res: Response, next: NextFunction) {
        //----> public routes send the payload to the next middleware.
        if(isPublicRoute(req)) return next();

        //----> private routes send an error if the user is not authenticated.
        const session = this.authService.getSession(req);

        if(!session) throw new UnauthorizedException("You are not authenticated!");

        //----> Go on to the next middleware.
        next();
    }
}
