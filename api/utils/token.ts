import jwt from 'jsonwebtoken'
import { ConfigService } from '../config/config.class'

export const MAX_AGE: number = 30 * 3600 * 24 // 30 days
const configService: ConfigService = new ConfigService()
export const createToken = (id: string) => {
    return jwt.sign({ id }, configService.get('JWT_SECRET'), {
        expiresIn: MAX_AGE,
    })
}

export const decodeToken = (token: string): string => {
    if (!token) throw new Error('Token is undefined')
    const decodedToken = jwt.decode(token)
    let id: string | undefined
    if (
        decodedToken &&
        typeof decodedToken !== 'string' &&
        decodedToken !== null
    ) {
        id = decodedToken.id as string
    } else id = ''
    return id
}
