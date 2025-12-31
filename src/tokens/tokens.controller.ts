import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { TokensService } from './tokens.service';
import { Roles } from '../decorators/role.decorator';

@Controller('tokens')
export class TokensController {
  constructor(private readonly tokensService: TokensService) {}

  @Roles('Admin')
  @Delete('all/delete-all')
  async deleteAllInvalidTokens() {
    return this.tokensService.deleteAllInvalidTokens();
  }

  @Roles('Admin')
  @Delete('delete-by-user-id/:userId')
  async deleteInvalidTokensByUserId(@Param('userId') userId: string) {
    return this.tokensService.deleteAllInvalidTokens();
  }
}
