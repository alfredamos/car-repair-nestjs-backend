export class CookieParam {
    static accessTokenName: string = "accessToken";
    static accessTokenPath: string = "/";
    static accessTokenExpiresIn: number = 24 * 60 * 60 * 1000;
    static accessTokenMaxAge: number = 24 * 60 * 60 * 1000;
    static refreshTokenName: string = "refreshToken";
    static refreshTokenPath: string = "/api/auth/refresh";
    static refreshTokenExpiresIn: number = 7 * 24 * 60 * 60 * 1000;
    static refreshTokenMaxAge: number = 24 * 60 * 60 * 1000;
    static sessionName: string = "session";
    static sessionPath: string = "/";
    static sessionExpiresIn: number = 7 * 24 * 60 * 60 * 1000;
    static sessionMaxAge: number = 7 * 24 * 60 * 60 * 1000;
}