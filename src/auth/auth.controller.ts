import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Res,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { StatusCodes } from 'http-status-codes';
import { Roles } from '../decorators/role.decorator';
import { IsPublic } from '../decorators/is-public.decorator';
import { ResponseMessage } from '../utils/responseMessage.util';
import {type Request, type Response} from "express";
import { ChangeUserPasswordDto } from './dto/changeUserPasswordDto';
import { EditUserProfile } from './dto/editUserProfile';
import { LoginUserDto } from './dto/loginUserDto';
import { SignupUserDto } from './dto/signupUserDto';
import { CurrentUser } from '../decorators/user.decorator';
import { UserInfo } from '../models/userInfo.model';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Roles('Admin', 'User')
  @Patch('/change-password')
  async changeUserPassword(@Body() changePasswordDto: ChangeUserPasswordDto) {
    return await this.authService.changeUserPassword(changePasswordDto);
  }

  @Roles('Admin', 'User')
  @Patch('/edit-profile')
  async editUserProfile(@Body() editUserProfile: EditUserProfile) {
    return await this.authService.editUserProfile(editUserProfile);
  }

  @IsPublic()
  @Post('/login')
  async loginUser(
    @Body() loginDto: LoginUserDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    //----> Get token.
    const accessToken = await this.authService.loginUser(loginDto, res);

    //----> Send back access-token;
    res.status(StatusCodes.OK).json(accessToken);
  }

  @IsPublic()
  @Post('/logout')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    //----> Get the current access-token.
    //req.res?.cookie()
    const accessToken = req.headers.cookie
      ? req.headers.cookie.substring(12).split(';')[0]
      : '';

    //----> Logout user.
    await this.authService.logoutUser(req, res);

    //----> send back the response.
    res
      .status(StatusCodes.OK)
      .json(
        new ResponseMessage(
          'Logout is successful!',
          'successful',
          StatusCodes.OK,
        ),
      );
  }

  @Roles('Admin', 'User')
  @Get('/me')
  async getCurrentUser(@CurrentUser() user: UserInfo) {
    //----> Get the user-id from the user payload.
    const id = user.id;

    //----> Get the current user from the database,
    return await this.authService.getCurrentUser(id);
  }

  @IsPublic()
  @Post('/signup')
  async signupUser(@Body() signupDto: SignupUserDto) {
    return await this.authService.signupUser(signupDto);
  }

  @IsPublic()
  @Post('/refresh')
  async refreshUserToken(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.headers.cookie
      ? req.headers.cookie.substring(13).split(';')[0]
      : '';

    const accessToken = await this.authService.refreshUserToken(
      refreshToken,
      res,
    );

    //----> Send back access-token;
    res.status(StatusCodes.OK).json(accessToken);
  }
}
