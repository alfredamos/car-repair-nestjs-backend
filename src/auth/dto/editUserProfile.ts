import {IsEmail, IsEnum, IsNotEmpty, IsString} from "class-validator";
import {Gender, Role} from "@prisma/client";

export class EditUserProfile {
    @IsNotEmpty()
    @IsString()
    name: string;

    @IsNotEmpty()
    @IsString()
    @IsEmail()
    email: string;

    @IsNotEmpty()
    @IsString()
    image: string;

    @IsNotEmpty()
    @IsString()
    phone: string;

    @IsNotEmpty()
    @IsEnum(Gender)
    gender: Gender;

    @IsNotEmpty()
    @IsString()
    password: string;

    // @IsNotEmpty()
    // @IsEnum(Role)
    // role: Role;
}