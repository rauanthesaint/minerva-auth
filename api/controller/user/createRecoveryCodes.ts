import pool from 'api/database/config'
import { cookieOptions } from 'api/utils/cookieOptions'
import encrypt from 'api/utils/encrypt'
import { BadRequestError, InternalServerError } from 'api/utils/server-errors'
import { Request, Response } from 'express'
import { createToken } from 'api/utils/token'

import {sha256} from 'js-sha256'
// Notes: Добавить валидацию данных

export default async function createUser(
    request: Request,
    response: Response
): Promise<void> {
    try {
        const { email, time } = request.body
        if (!email || !time) return BadRequestError(response)
        
        const src = email + time

        const hash = sha256(src)
        if (!hash) return InternalServerError(response)
       
       
        // Implement recording to the db and sending via email
    } catch (error) {
        return InternalServerError(response, error)
    }
}
