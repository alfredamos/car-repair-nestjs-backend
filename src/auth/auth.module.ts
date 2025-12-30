import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { PrismaService } from '../services/prisma/prisma.service';
import {TokensService} from '../tokens/tokens.service';
import {JwtAuthGuard} from '../guards/jwt-auth.guard';


@Module({
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, PrismaService, TokensService, JwtAuthGuard],
  imports: [
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_TOKEN_KEY!,
      signOptions: { expiresIn: 24 * 60 * 60 * 1000 },
    }),
  ],

  exports: [AuthService],
})
export class AuthModule {}
