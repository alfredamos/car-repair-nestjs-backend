import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private reflector: Reflector,
    private readonly authService: AuthService,
  ) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    //----> Get the request object.
    const req: Request = context.switchToHttp().getRequest<Request>(); //----> Retrieve all objects on request object.

    //----> Retrieve the token from the cookie on headers.
    const token = req.headers.cookie
      ? req.headers.cookie.substring(12).split(';')[0]
      : '';

    //----> Check for empty token.
    if (!token) {
      throw new UnauthorizedException(
        'Authentication token not found in cookies.',
      );
    }

    //----> Check for valid token.
    try {
      req.user = this.authService.verifyJwtToken(req); // Attach user to the request
    } catch {
      throw new UnauthorizedException('Invalid or expired token.'); //----> Invalid token.
    }

    //----> Valid token
    return true;
  }
}
