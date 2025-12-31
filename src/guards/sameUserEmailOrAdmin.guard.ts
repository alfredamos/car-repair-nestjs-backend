import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Request } from 'express';
import { Role } from '../generated/prisma/enums';

export class SameUserEmailOrAdminGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    //----> Get the request object.
    const req: Request = context.switchToHttp().getRequest<Request>(); //----> Retrieve all objects on request object.

    //----> get the user id from param.
    const emailFromParam = req.params.email;

    //----> Get the user id from the user object on request object.
    const tokenJwt = req.user;
    const emailFromContext = tokenJwt?.email as string;
    const role = tokenJwt?.role;
    console.log('In same-user-email, role : ', role);
    //----> Check for same user via equality of the two user-ids.
    const sameUser = this.isSameUser(emailFromContext, emailFromParam);

    //----> Check for admin privilege.
    const isAdmin = role === Role.Admin;

    console.log('In same-user-or-admin-guard, sameUser : ', sameUser);
    console.log('In same-user-or-admin-guard, isAdmin : ', isAdmin);
    console.log(
      'In same-user-or-admin-guard, emailFromParam : ',
      emailFromParam,
    );
    console.log(
      'In same-user-or-admin-guard, emailFromContext : ',
      emailFromContext,
    );

    if (!sameUser && !isAdmin) {
      throw new ForbiddenException(
        "You don't have permission to view or perform this action!",
      );
    }

    //----> Not same user and not admin.
    return !(!sameUser && !isAdmin);
  }

  private isSameUser(emailOne: string, emailTwo: string) {
    return emailOne?.normalize() === emailTwo?.normalize();
  }
}
