import { Role } from '../generated/prisma/client';

export class UserInfo {
    id: string = "";
    name: string = "";
    email: string = "";
    role: Role = Role.User;
}
