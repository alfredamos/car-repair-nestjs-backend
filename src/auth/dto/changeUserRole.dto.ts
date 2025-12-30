import { IsEmail, IsEnum, IsNotEmpty, IsString } from 'class-validator';
import { Role } from '../../generated/prisma/enums';

export class ChangeUserRoleDto {
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  email: string;

  @IsEnum(Role)
  role: Role;
}
