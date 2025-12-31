import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { Request } from 'express';
import { UserInfo } from '../models/userInfo.model';
import { AuthService } from './auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(private authService: AuthService) {
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                (request: Request) => {
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
                    return request?.cookies?.accessToken; // Extract from 'jwt' cookie
                },
            ]),
            ignoreExpiration: false,
            secretOrKey: process.env.JWT_TOKEN_KEY!,
        });
    }

    async validate(payload: UserInfo) {
        //----> Get the current user.
        const user = await this.authService.getCurrentUser(payload.id);
        //----> Check for authentic user.
        if (!user)
            throw new UnauthorizedException(
                'Access denied',
            );

        //----> Send back the response.
        return user;
    }
}
