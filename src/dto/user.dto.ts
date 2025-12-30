import {Role, Gender} from "../generated/prisma/enums";
import {User} from "../generated/prisma/client";

export class UserDto {
    id: string;
    name: string;
    email: string;
    role: Role;
    image: string;
    phone: string;
    gender: Gender;
}

export function toUserDto(user: User) :UserDto {
    return {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        image: user.image,
        phone: user.phone,
        gender: user.gender,

    }
}