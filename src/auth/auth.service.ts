import { BadRequestException, Injectable,  Req, Res, UnauthorizedException } from '@nestjs/common';
import { LoginUserDto } from './dto/loginUserDto';
import { ChangeUserPasswordDto } from './dto/changeUserPasswordDto';
import * as bcrypt from "bcryptjs";
import { JwtService } from '@nestjs/jwt';
import { TokensService } from '../tokens/tokens.service';
import { StatusCodes } from 'http-status-codes';
import { ChangeUserRoleDto } from './dto/changeUserRole.dto';
import { EditUserProfile } from './dto/editUserProfile';
import { Request, Response } from 'express';
import { SignupUserDto } from './dto/signupUserDto';
import { PrismaService } from '../services/prisma/prisma.service';
import { ResponseMessage } from '../utils/responseMessage.util';
import { toUserDto } from '../dto/user.dto';
import { TokenJwt } from '../utils/tokenJwt.util';
import { Role, TokenType } from '../generated/prisma/enums';
import { CookieParam } from '../utils/CookieParam.util';
import { UserSession } from '../types/express';
import { fromSignupToUser } from '../utils/fromSignupToUser.util';
import { Token } from '../generated/prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly tokenService: TokensService,
  ) {}
  async changeUserPassword(changePassword: ChangeUserPasswordDto) {
    console.log('In changeUserPassword, payload : ', changePassword);
    //----> Destructure the changePassword object
    const { email, confirmPassword, password, newPassword } = changePassword;

    //----> Check for match password.
    if (!this.checkForMatchPassword(newPassword, confirmPassword)) {
      throw new BadRequestException('Passwords do not match');
    }

    //----> Check for null user.
    const user = await this.getUserByEmail(email);
    //----> Validate password.
    if (!(await this.validatePassword(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials!');
    }

    //----> Hash the new password.
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    //----> Update the user password.
    await this.prisma.user.update({
      where: { id: user.id },
      data: { ...user, password: hashedPassword },
    });

    //----> Send back feedback.
    return new ResponseMessage(
      'Password changed successfully!',
      'success',
      StatusCodes.OK,
    );
  }

  async changeUserRole(changeRole: ChangeUserRoleDto) {
    //----> Destructure the changeRole object
    const { email, role } = changeRole;

    //----> Check for null user.
    const userToChangeRole = await this.getUserByEmail(email);

    //----> Save the user role.
    await this.prisma.user.update({
      where: { id: userToChangeRole.id },
      data: { ...userToChangeRole, role },
    });

    //----> Send back feedback.
    return new ResponseMessage(
      'User role is changed successfully!',
      'success',
      StatusCodes.OK,
    );
  }

  async editUserProfile(editProfile: EditUserProfile) {
    //----> Destructure the editProfile object
    const { email, password } = editProfile;

    //----> Check for null user.
    const userToEditProfile = await this.getUserByEmail(email);

    //----> Validate password.
    if (!(await this.validatePassword(password, userToEditProfile.password))) {
      throw new UnauthorizedException('Invalid credentials!');
    }

    //----> Update the user profile.
    await this.prisma.user.update({
      where: { email },
      data: {
        ...editProfile,
        role: userToEditProfile.role,
        password: userToEditProfile.password,
      },
    });

    //----> Send back feedback.
    return new ResponseMessage(
      'User profile is edited successfully!',
      'success',
      StatusCodes.OK,
    );
  }

  async getCurrentUser(email: string) {
    const user = await this.getUserByEmail(email);
    return toUserDto(user);
  }

  async loginUser(loginUser: LoginUserDto, res: Response) {
    //----> Destructure the loginUser object
    const { email, password } = loginUser;

    //----> Check for null user.
    const user = await this.getUserByEmail(email);

    //----> Validate password.
    if (!(await this.validatePassword(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials!');
    }

    //----> generate tokens, sessions and set them in cookies.
    const tokenJwt: TokenJwt = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role as Role,
    };
    return this.generateTokensAndSetCookies(tokenJwt, res);
  }
  async logoutUser(req: Request, res: Response) {
    // //----> Get session object and revoked valid token object.
    // const session = this.getSession(req);
    // await tokenModel.revokedTokensByUserId(session.id);
    const sessionString = req.cookies[CookieParam.sessionName];

    //----> Check for undefined session-string.
    if (!sessionString) {
      throw new UnauthorizedException('You have already logged out!');
    }

    //----> Parse the session object.
    const session = JSON.parse(sessionString) as UserSession;

    //----> Check for null session.
    if (!session) {
      throw new UnauthorizedException('You have already logged out!');
    }

    //----> Invalidate last valid token object.
    await this.tokenService.revokedTokensByUserId(session.id);

    //----> Delete accessToken, refreshToken and session from cookies.
    this.deleteCookie(
      res,
      CookieParam.accessTokenName,
      CookieParam.accessTokenPath,
    );
    this.deleteCookie(
      res,
      CookieParam.refreshTokenName,
      CookieParam.refreshTokenPath,
    );
    this.deleteCookie(res, CookieParam.sessionName, CookieParam.sessionPath);

    //----> Send back feedback.
    return new ResponseMessage(
      'User logged out successfully!',
      'success',
      StatusCodes.OK,
    );
  }
  async refreshUserToken(refreshToken: string, res: Response) {
    //----> Validate refresh token.
    const tokenJwt = this.validateUserToken(refreshToken);

    //----> generate tokens, sessions and set them in cookies.
    return this.generateTokensAndSetCookies(tokenJwt, res);
  }

  async signupUser(signup: SignupUserDto) {
    //----> Destructure the signup object
    const { email, password, confirmPassword } = signup;

    //----> Check for password match.
    if (!this.checkForMatchPassword(password, confirmPassword)) {
      throw new UnauthorizedException('Passwords do not match!');
    }

    //----> Check for existing user.
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new UnauthorizedException('Invalid credentials!');
    }

    //----> Hash the password.
    signup.password = await bcrypt.hash(password, 12);

    //----> make a new user.
    const user = fromSignupToUser(signup);
    const newUser = await this.prisma.user.create({ data: { ...user } });

    //----> Send back feedback.
    return new ResponseMessage(
      'User signed up successfully!',
      'success',
      StatusCodes.CREATED,
    );
  }

  verifyJwtToken(@Req() req: Request) {
    //----> Get access-token
    const accessToken = this.getAccessToken(req);

    //----> Verify token

    const jwtToken = this.validateUserToken(accessToken) as TokenJwt;

    //----> Get the role, name, and id of user from the token object.
    const role = jwtToken?.role;
    const name = jwtToken?.name;
    const id = jwtToken?.id;
    const email = jwtToken?.email;

    //----> Send back the results.
    return { id, role, name, email };
  }

  validateUserToken(token: string) {
    //----> Check for empty token.
    if (!token) {
      throw new UnauthorizedException('Invalid credentials!');
    }

    //----> Verify the jwt-token
    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return this.jwtService?.verify(token, {
        secret: process.env.JWT_TOKEN_KEY,
      });
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (err: any) {
      throw new UnauthorizedException('Invalid credentials!');
    }
  }

  getToken(cookieName: string, req: Request) {
    const token = req.cookies[cookieName] as string;
    //----> Check for null accessToken.
    if (!token) {
      throw new UnauthorizedException('You are not logged in!');
    }

    //----> Return accessToken.
    return token;
  }

  getRefreshToken(req: Request) {
    return this.getToken(CookieParam.refreshTokenName, req);
  }

  getSession(req: Request) {
    //----> Retrieve the accessToken from the cookie.
    const accessToken = this.getAccessToken(req);

    //----> Check for null accessToken.
    if (!accessToken) {
      throw new UnauthorizedException('You are not logged in, please login!');
    }

    //----> Validate accessToken.
    const tokenJwt = this.validateUserToken(accessToken);
    req.user = tokenJwt;

    //----> Create a session object and return it.
    return this.makeSession(tokenJwt, accessToken);
  }

  private checkForMatchPassword(passwordOne: string, passwordTwo: string) {
    return passwordOne === passwordTwo;
  }

  private async validatePassword(rawPassword: string, encodedPassword: string) {
    return bcrypt.compare(rawPassword, encodedPassword);
  }

  private async getUserByEmail(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    console.log("In get-user-by-email")
    //----> Check for null user.
    if (!user) {
      throw new UnauthorizedException('Invalid credentials!');
    }

    //----> Return user.
    return user;
  }

  private async generateTokensAndSetCookies(user: TokenJwt, res: Response) {
    //----> Invalidate last valid token object.
    await this.tokenService.revokedTokensByUserId(user.id);

    //----> Generate access-token and store it in a cookie.
    const accessToken = await this.generateToken(
      user.id,
      user.name,
      user.email,
      user.role,
      CookieParam.accessTokenExpiresIn,
    );
    this.setCookie(
      res,
      accessToken,
      CookieParam.accessTokenName,
      CookieParam.accessTokenPath,
      CookieParam.accessTokenMaxAge,
    );

    //----> Generate refresh-token and store it in a cookie.
    const refreshToken = await this.generateToken(
      user.id,
      user.name,
      user.email,
      user.role,
      CookieParam.refreshTokenExpiresIn,
    );
    this.setCookie(
      res,
      refreshToken,
      CookieParam.refreshTokenName,
      CookieParam.refreshTokenPath,
      CookieParam.refreshTokenMaxAge,
    );

    //----> Set a session object in the response.
    this.setSession(user, res);

    //----> Make a token object and store it in the db.

    const token = this.makeNewToken(accessToken, refreshToken, user.id);
    await this.tokenService.createToken(token);

    //----> Return the session object.
    return this.makeSession(user, accessToken);
  }

  private setCookie(
    res: Response,
    token: string,
    cookieName: string,
    cookiePath: string,
    cookieMaxAge: number,
  ) {
    res.cookie(cookieName, token, {
      httpOnly: true,
      path: cookiePath,
      maxAge: cookieMaxAge,
      secure: process.env.NODE_ENV === 'production',
    });
  }

  private generateToken = (
    id: string,
    name: string,
    email: string,
    role: Role,
    expiresIn: number,
  ) => {
    return this.jwtService.sign(
      {
        id,
        name,
        email,
        role,
      },
      { expiresIn },
    );
  };

  private deleteCookie(res: Response, cookieName: string, cookiePath: string) {
    res.clearCookie(cookieName, {
      path: cookiePath,
      secure: false,
      httpOnly: true,
    });
  }

  private makeNewToken(
    accessToken: string,
    refreshToken: string,
    userId: string,
  ): Token {
    return {
      id: undefined as unknown as string,
      accessToken,
      refreshToken,
      expired: false,
      revoked: false,
      tokenType: TokenType.Bearer,
      userId,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  private makeSession(user: TokenJwt, accessToken: string): UserSession {
    const isLoggedIn = !!user && !!accessToken;
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      accessToken,
      isLoggedIn,
      isAdmin: user.role === Role.Admin,
    };
  }

  private getAccessToken(req: Request): string {
    //----> Retrieve the accessToken from the cookie.
    return this.getToken(CookieParam.accessTokenName, req);
  }

  private setSession(tokenJwt: TokenJwt, res: Response) {
    //----> Make a session object.
    const session = this.makeSession(tokenJwt, '');

    //----> Set the session cookie.
    this.setCookie(
      res,
      JSON.stringify(session),
      CookieParam.sessionName,
      CookieParam.sessionPath,
      CookieParam.sessionMaxAge,
    );
  }
}
