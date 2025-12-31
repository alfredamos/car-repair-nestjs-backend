import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Request } from 'express';
import { Role } from '../generated/prisma/enums';
import { AuthService } from '../auth/auth.service';

export class SameUserIdOrAdminGuard implements CanActivate {
  constructor(private authService: AuthService){}
  canActivate(context: ExecutionContext): boolean {
    //----> Get the request object.
    const req: Request = context.switchToHttp().getRequest<Request>(); //----> Retrieve all objects on request object.

    //----> get the user id from param.
    const session = this.authService.getSession(req);
    const userIdFromParam = req.params.userId;

    //----> Get the user id from the user object on request object.
    const userIdFromContext = session.id;
    const role = session.role;

    //----> Check for same user via equality of the two user-ids.
    const sameUser = this.isSameUser(userIdFromContext, userIdFromParam);

    //----> Check for admin privilege.
    const isAdmin = role === Role.Admin;

    console.log('In same-user-or-admin-guard, sameUser : ', sameUser);
    console.log('In same-user-or-admin-guard, isAdmin : ', isAdmin);
    console.log(
      'In same-user-or-admin-guard, userIdFromParam : ',
      userIdFromParam,
    );
    console.log(
      'In same-user-or-admin-guard, userIdFromContext : ',
      userIdFromContext,
    );

    if (!sameUser && !isAdmin) {
      throw new ForbiddenException(
        "You don't have permission to view or perform this action!",
      );
    }

    //----> Not same user and not admin.
    return !(!sameUser && !isAdmin);
  }

  private isSameUser(userIdOne: string, userIdTwo: string) {
    return userIdOne?.normalize() === userIdTwo?.normalize();
  }
}
