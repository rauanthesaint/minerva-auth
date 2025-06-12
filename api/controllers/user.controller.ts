import UserService from 'api/services/user.service'
import { HTTP_STATUS } from 'api/shared/constants/http-status.constants'
import {
    createToken,
    decodeToken,
    tokenOptions,
} from 'api/shared/utils/jwt.util'
import { Request, Response } from 'express'

export default class UserController {
    constructor(private userService: UserService) {}

    async authenticateUser(request: Request, response: Response): Promise<any> {
        try {
            const data = request.body
            const result = await this.userService.authenticateUser(data)
            if (!result.success) {
                return response.status(result.statusCode).json({
                    message: result.statusCode,
                })
            }
            const id = result.data.id

            const token = createToken(id)
            if (!token) {
                return response
                    .status(HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR)
                    .json({
                        success: false,
                        message: 'Failed to generate token',
                    })
            }

            response.cookie('token', token, tokenOptions)

            return response.status(result.statusCode).json({
                data: result.data,
            })
        } catch (error) {
            return response
                .status(HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR)
                .json({
                    success: false,
                    message: 'Internal server error',
                    statusCode: HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR,
                })
        }
    }

    createUser = async (request: Request, response: Response): Promise<any> => {
        try {
            const data = request.body
            const result = await this.userService.createUser(data)

            if (!result.success) {
                return response.status(result.statusCode).json({
                    message: result.message,
                })
            }

            const id = result.data.id
            const token = createToken(id)
            response.cookie('token', token, tokenOptions)
            return response.status(result.statusCode).json({
                // message: result.message,
                data: result.data,
            })
        } catch (error) {
            return response.status(
                HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR
            )
        }
    }

    getUser = async (request: Request, response: Response): Promise<any> => {
        try {
            const token = request.cookies['token']
            if (!token) {
                console.error('No token')
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED)
                    .json({
                        message: 'Unauthorized access',
                    })
            }
            const id = decodeToken(token)
            const result = await this.userService.getUser(id)
            if (!result.success) {
                return response.status(result.statusCode)
            }

            return response.status(result.statusCode).json({
                // message: result.message,
                data: result.data,
            })
        } catch (error) {
            return response.status(
                HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR
            )
        }
    }
}
