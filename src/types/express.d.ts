// src/types/express.d.ts
import { UserInfo } from '../models/userInfo.model';

declare global {
    namespace Express {
        interface Request {
            // Replace 'any' with your User interface/type
            user: UserInfo | null;
        }
    }
}

type UserSession = {
    id: string;
    name: string;
    email: string;
    role: Role;
    accessToken: string;
    isLoggedIn: boolean;
    isAdmin: boolean;
}