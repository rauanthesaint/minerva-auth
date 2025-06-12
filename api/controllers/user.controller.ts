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
                    success: false,
                    message: 'Authentication failed',
                    statusCode: result.statusCode,
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
                success: true,
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
                    success: false,
                    message: 'Failed to create user',
                    statusCode: result.statusCode,
                })
            }

            // Теперь result.data содержит { user, verification }
            const userId = result.data.user.id
            const token = createToken(userId)

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
                success: true,
                data: result.data, // Включает информацию о пользователе и OTP
                message: 'User created successfully. Verification email sent.',
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

    getUser = async (request: Request, response: Response): Promise<any> => {
        try {
            const token = request.cookies['token']

            if (!token) {
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED)
                    .json({
                        success: false,
                        message: 'Unauthorized access - No token provided',
                    })
            }

            const id = decodeToken(token)
            if (!id) {
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED)
                    .json({
                        success: false,
                        message: 'Invalid token',
                    })
            }

            const result = await this.userService.getUser(id)

            if (!result.success) {
                return response.status(result.statusCode).json({
                    success: false,
                    message: 'Failed to get user',
                    statusCode: result.statusCode,
                })
            }

            return response.status(result.statusCode).json({
                success: true,
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

    // ========== НОВЫЕ МЕТОДЫ ДЛЯ РАБОТЫ С OTP ==========

    sendVerificationOTP = async (
        request: Request,
        response: Response
    ): Promise<any> => {
        try {
            const token = request.cookies['token']

            if (!token) {
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED)
                    .json({
                        success: false,
                        message: 'Unauthorized access',
                    })
            }

            const userId = decodeToken(token)
            if (!userId) {
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED)
                    .json({
                        success: false,
                        message: 'Invalid token',
                    })
            }

            const result = await this.userService.sendVerificationOTP(
                parseInt(userId)
            )

            if (!result.success) {
                return response.status(result.statusCode).json({
                    success: false,
                    message: 'Failed to send verification OTP',
                    data: result.data,
                    statusCode: result.statusCode,
                })
            }

            return response.status(result.statusCode).json({
                success: true,
                data: result.data,
                message: 'Verification OTP sent successfully',
            })
        } catch (error) {
            return response
                .status(HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR)
                .json({
                    success: false,
                    message: 'Internal server error',
                })
        }
    }

    verifyEmail = async (
        request: Request,
        response: Response
    ): Promise<any> => {
        try {
            const { code } = request.body
            const token = request.cookies['token']

            if (!token) {
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED)
                    .json({
                        success: false,
                        message: 'Unauthorized access',
                    })
            }

            if (!code) {
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST)
                    .json({
                        success: false,
                        message: 'Verification code is required',
                    })
            }

            const userId = decodeToken(token)
            if (!userId) {
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED)
                    .json({
                        success: false,
                        message: 'Invalid token',
                    })
            }

            const result = await this.userService.verifyEmail(
                parseInt(userId),
                code
            )

            if (!result.success) {
                return response.status(result.statusCode).json({
                    success: false,
                    message:
                        result.data?.message || 'Email verification failed',
                    statusCode: result.statusCode,
                })
            }

            return response.status(result.statusCode).json({
                success: true,
                data: result.data,
            })
        } catch (error) {
            return response
                .status(HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR)
                .json({
                    success: false,
                    message: 'Internal server error',
                })
        }
    }

    requestPasswordReset = async (
        request: Request,
        response: Response
    ): Promise<any> => {
        try {
            const { email } = request.body

            if (!email) {
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST)
                    .json({
                        success: false,
                        message: 'Email is required',
                    })
            }

            const result = await this.userService.requestPasswordReset(email)

            // Всегда возвращаем успех для безопасности (не раскрываем существование email)
            return response.status(result.statusCode).json({
                success: true,
                message:
                    result.data?.message ||
                    'If email exists, reset code has been sent',
            })
        } catch (error) {
            return response
                .status(HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR)
                .json({
                    success: false,
                    message: 'Internal server error',
                })
        }
    }

    resetPassword = async (
        request: Request,
        response: Response
    ): Promise<any> => {
        try {
            const { email, code, newPassword } = request.body

            if (!email || !code || !newPassword) {
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST)
                    .json({
                        success: false,
                        message: 'Email, code, and new password are required',
                    })
            }

            const result = await this.userService.resetPassword(
                email,
                code,
                newPassword
            )

            if (!result.success) {
                return response.status(result.statusCode).json({
                    success: false,
                    message: result.data?.message || 'Password reset failed',
                    statusCode: result.statusCode,
                })
            }

            return response.status(result.statusCode).json({
                success: true,
                data: result.data,
            })
        } catch (error) {
            return response
                .status(HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR)
                .json({
                    success: false,
                    message: 'Internal server error',
                })
        }
    }

    getUserStats = async (
        request: Request,
        response: Response
    ): Promise<any> => {
        try {
            const token = request.cookies['token']

            if (!token) {
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED)
                    .json({
                        success: false,
                        message: 'Unauthorized access',
                    })
            }

            const userId = decodeToken(token)
            if (!userId) {
                return response
                    .status(HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED)
                    .json({
                        success: false,
                        message: 'Invalid token',
                    })
            }

            const result = await this.userService.getUserStats(parseInt(userId))

            if (!result.success) {
                return response.status(result.statusCode).json({
                    success: false,
                    message: 'Failed to get user stats',
                    statusCode: result.statusCode,
                })
            }

            return response.status(result.statusCode).json({
                success: true,
                data: result.data,
            })
        } catch (error) {
            return response
                .status(HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR)
                .json({
                    success: false,
                    message: 'Internal server error',
                })
        }
    }

    // ========== UTILITY METHODS ==========

    logout = async (request: Request, response: Response): Promise<any> => {
        try {
            // Очищаем токен
            response.clearCookie('token', {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                path: '/',
            })

            return response.status(HTTP_STATUS.SUCCESS.OK).json({
                success: true,
                message: 'Logged out successfully',
            })
        } catch (error) {
            return response
                .status(HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR)
                .json({
                    success: false,
                    message: 'Internal server error',
                })
        }
    }
}
