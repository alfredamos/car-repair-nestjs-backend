import {Injectable, NotFoundException} from '@nestjs/common';
import {PrismaService} from "../services/prisma/prisma.service";
import {Token} from "@prisma/client";
import {TokenQueryCondition} from "../utils/TokenQueryCondition";
import {ResponseMessage} from "../utils/responseMessage.util";
import {StatusCodes} from "http-status-codes";

@Injectable()
export class TokensService {
    constructor(private readonly prisma: PrismaService) {}

    async createToken(token: Token): Promise<Token> {
        //----> Insert the new token into the db.
        return this.prisma.token.create({
            data: {...token}
        })
    }

    async deleteAllInvalidTokens() {
        //----> Retrieve invalid tokens.
        const queryCondition: TokenQueryCondition = {
            expired: true,
            revoked: true,
        }
        //----> Delete invalid tokens.
        return this.deleteInvalidTokens(queryCondition)
    }

    async deleteInvalidTokensbyUserId(userId: string) {
        //----> Retrieve invalid tokens.
        const queryCondition: TokenQueryCondition = {
            userId,
            expired: true,
            revoked: true,
        }
        //----> Delete invalid tokens.
        return this.deleteInvalidTokens(queryCondition)
    }

    async findTokenByAccessToken(accessToken: string) {
        //----> Retrieve the token with the given access token.
        const token = await this.prisma.token.findUnique({
            where: {accessToken},
        });

        //----> Check for null value.
        if (!token){
            throw new NotFoundException(`Token with access token: ${accessToken} not found in db!`);
        }

        //----> Send back response.
        return token;
    }

    async findValidTokensByUserId(userId: string): Promise<Token[]> {
        //----> Retrieve valid tokens.
        const queryCondition : TokenQueryCondition = {
            userId,
            expired: false,
            revoked: false,
        }
        //----> Send back results.
        return this.findInvalidOrValidTokens(queryCondition);
    }

    async revokedTokensByUserId(userId: string) {
        //----> Retrieve valid tokens.
        const validTokens = await this.findValidTokensByUserId(userId);

        //----> Invalidate tokens and save them in db.
        await this.saveAll(validTokens);

        //----> Send back response.
        return new ResponseMessage("All tokens have been revoked", "success", StatusCodes.OK);
    }

    private async deleteInvalidTokens(queryCondition: TokenQueryCondition) {
        //----> Retrieve invalid tokens.
        const invalidTokens = await this.findInvalidOrValidTokens(queryCondition);

        //----> Collect all invalid tokens ids in a map.
        const invalidTokensIds = invalidTokens.map((token) => token.id);

        //----> Delete all invalid tokens with the given query condition.
        const deletedTokens = await this.prisma.token.deleteMany({
            where: {
                id: {
                    in: invalidTokensIds,
                }
            }
        })

        //----> Check for bad request.
        if (!deletedTokens.count) {
            throw new NotFoundException("No tokens found.");
        }

        //----> Send back response.
        return new ResponseMessage("All Tokens have been deleted successfully!", "success", StatusCodes.OK);
    }

    private async findInvalidOrValidTokens(queryCondition: TokenQueryCondition){
        //----> Retrieve the tokens that match the given query condition.
        return this.prisma.token.findMany({
            where: {...queryCondition}
        })
    }

    private async saveAll(tokens: Token[]){
        const modifiedTokens = tokens.map(async (token) => {
            token.expired = true;
            token.revoked = true;
            return this.prisma.token.update({
                where: {id: token.id},
                data: {...token}
            })
        })

        //----> Send back results.
        return Promise.all(modifiedTokens)
    }


}
