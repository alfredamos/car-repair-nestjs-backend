import { IsEmail, IsEnum, IsNotEmpty, IsOptional, IsString } from "class-validator";
import { Gender } from "../../generated/prisma/enums";

export class CustomerDto {
  @IsString()
  @IsOptional()
  id: string;

  @IsNotEmpty()
  @IsString()
  address: string;

  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  phone: string;

  @IsNotEmpty()
  @IsString()
  image: string;

  @IsEnum(Gender)
  gender: Gender;

  @IsNotEmpty()
  @IsString()
  dateOfBirth: string;

  @IsOptional()
  active: boolean;

  @IsNotEmpty()
  @IsString()
  notes: string;

  @IsOptional()
  userId: string;
}