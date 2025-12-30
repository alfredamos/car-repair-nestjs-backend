import {Role} from "../generated/prisma/enums";

export class TokenJwt {
    id!: string;
    name!: string;
    role!: Role;
    email!: string;
}