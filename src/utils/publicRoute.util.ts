import {Request} from "express";

const routes = [
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/signup",
    "/api/auth/refresh",
]

export function isPublicRoute(req: Request){
    return routes.includes(req.url);
}