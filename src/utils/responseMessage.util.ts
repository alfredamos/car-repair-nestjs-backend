import {StatusCodes} from "http-status-codes";

export class ResponseMessage{
    constructor(public message: string, public status: string, public statusCode: StatusCodes) {
    }
}