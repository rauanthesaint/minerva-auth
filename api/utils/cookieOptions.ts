import { MAX_AGE } from './token'

export const cookieOptions = {
    path: '/',
    maxAge: MAX_AGE * 1000,
    httpOnly: true,
}
