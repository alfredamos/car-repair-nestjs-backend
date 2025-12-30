import { SignupUserDto } from "../auth/dto/signupUserDto";
import {Role, User} from "../generated/prisma/client";
import { v4 as uuidv4 } from 'uuid';


export function fromSignupToUser(signup: SignupUserDto): User {
    return {
        id: uuidv4(),
        email: signup.email,
        password: signup.password,
        name: signup.name,
        role: Role.User,
        image: signup.image,
        phone: signup.phone,
        gender: signup.gender,
        createdAt: new Date(),
        updatedAt: new Date(),
    }
}