import { Module } from '@nestjs/common';
import { TokensService } from './tokens.service';
import { TokensController } from './tokens.controller';
import { PrismaService } from '../services/prisma/prisma.service';

@Module({
  controllers: [TokensController],
  providers: [TokensService, PrismaService],
})
export class TokensModule {}
