import { HTTP_STATUS } from 'api/shared/constants/http-status.constants'
import { Request, Response } from 'express'

export default class AuthController {
    async unauthorizeUser(request: Request, response: Response): Promise<any> {
        console.log('Clearing cookies')
        response.clearCookie('token')
        console.log('Cookies cleared')
        return response.status(HTTP_STATUS.SUCCESS.OK).json({
            message: 'Cookie is clean',
        })
    }
}
