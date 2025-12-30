/* eslint-disable prettier/prettier */
import { Reflector } from '@nestjs/core';
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { UserInfo } from '../models/userInfo.model';
import { Role } from '../generated/prisma/enums';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getClass(),
      context.getHandler(),
    ]);

    //----> Public resources.
    if (isPublic) return true;

    //----> Get the role of the user.
    const roles = this.reflector.get<string[]>('roles', context.getHandler());

    //----> Check for the existence of role.
    if (!roles) return false;

    //----> Get the request object.
    const request : Request = context.switchToHttp().getRequest();

    //----> Get the user from the request object.
    const user = request.user as UserInfo;
    
    if (!user){
      throw new UnauthorizedException('Invalid or expired token.');
    }

    //----> Check if the user has the right role.
    const correctRole = this.matchRoles(roles, user.role);

    //----> Wrong role.
    if (!correctRole) {
      throw new ForbiddenException('You are not permitted to view or perform this action.');
    }

    //----> Check if the roles matches those who are permitted to view or use the available resources.
    return correctRole;
  }

  matchRoles(roles: string[], role: Role): boolean {
    return roles.includes(role); //----> Check that role is one of the valid ones accepted.
  }
}
