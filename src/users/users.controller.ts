import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Roles } from '../decorators/role.decorator';
import { SameUserEmailOrAdminGuard } from '../guards/sameUserEmailOrAdmin.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Roles('Admin')
  @Get()
  async getAllUsers() {
    return this.usersService.getAllUsers();
  }

  @Roles('Admin')
  @Get(':id')
  async getUserById(@Param('id') id: string) {
    return this.usersService.getUserById(id);
  }

  @Roles('Admin', 'User')
  @UseGuards(SameUserEmailOrAdminGuard)
  @Get('get-user-by-email/:email')
  async getUserByEmail(@Param('email') email: string) {
    return this.usersService.getUserByEmail(email);
  }
}
