import { Module } from '@nestjs/common';
import { TicketsService } from './tickets.service';
import { TicketsController } from './tickets.controller';
import { PrismaService } from '../services/prisma/prisma.service';
import { AuthService } from '../auth/auth.service';
import { SameUserEmailOrAdminGuard } from '../guards/sameUserEmailOrAdmin.guard';
import { AuthModule } from '../auth/auth.module';
import { JwtService } from '@nestjs/jwt';

@Module({
  controllers: [TicketsController],
  providers: [TicketsService, PrismaService],
})
export class TicketsModule {}
