import { Result } from 'api/domain/entities/result.entity'
import { IUserRepository } from 'api/domain/interfaces/repositories/userRepository.interface'
import { HTTP_STATUS } from 'api/shared/constants/http-status.constants'
import Logger from 'api/shared/utils/logger.util'
import {
    isEmailValid,
    isNameValid,
    isPasswordValid,
} from 'api/shared/utils/validators.util'
import encrypt from 'api/shared/utils/encrypt.util'
import bcrypt from 'bcrypt'
import { generateOTP } from 'api/shared/utils/one-time-password'

export default class UserService {
    constructor(private userRepository: IUserRepository) {}

    async authenticateUser(data: {
        password: string
        email: string
    }): Promise<Result> {
        const { password, email } = data
        if (!password || !email) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST
            Logger.error(
                UserService.name,
                'Failed to authenticate user -> one of the fields undefined',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }

        if (!isEmailValid(email)) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST
            Logger.error(
                UserService.name,
                'Failed to authenticate user -> email is not valid',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }

        if (!isPasswordValid(password)) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST
            Logger.error(
                UserService.name,
                'Failed to authenticate user -> password is not valid',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }

        const user = await this.userRepository.findByEmail(email)

        if (!user) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.CONFLICT
            Logger.error(
                UserService.name,
                'Failed to authenticate user -> invalid name or password',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }

        try {
            const isValid = await bcrypt.compare(password, user.password)
            if (!isValid) {
                const statusCode = HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED // ИСПРАВЛЕНО: CONFLICT -> UNAUTHORIZED
                Logger.error(
                    UserService.name,
                    'Failed to authenticate user -> invalid email or password',
                    statusCode
                )
                return {
                    success: false,
                    statusCode,
                }
            }

            const OTP = generateOTP()
            const otp_hash = await encrypt(OTP)

            const { password: excludedPassword, ...rest } = user
            return {
                success: true,
                statusCode: HTTP_STATUS.SUCCESS.OK,
                data: rest,
            }
        } catch (error) {
            const statusCode = HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR
            Logger.error(
                UserService.name,
                'Failed to authenticate user -> server error',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }
    }

    async getUser(id: string): Promise<Result> {
        if (!id) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST
            Logger.error(
                UserService.name,
                'Failed to get user -> invalid id',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }

        const result = await this.userRepository.findById(Number.parseInt(id))

        if (!result) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.NOT_FOUND
            Logger.error(
                UserService.name,
                'Failed to get user -> user is not found ',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }
        const { password, ...rest } = result

        const statusCode = HTTP_STATUS.SUCCESS.OK
        return {
            success: true,
            statusCode,
            data: rest,
        }
    }

    async createUser(data: {
        email: string
        password: string
        name: string
    }): Promise<Result> {
        const { email, password, name } = data
        if (!email || !password || !name) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST
            Logger.error(
                UserService.name,
                'Failed to create user -> one of the fields undefined',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }

        if (!isEmailValid(email)) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST
            Logger.error(
                UserService.name,
                'Failed to create user -> email is not valid',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }

        if (!isPasswordValid(password)) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST
            Logger.error(
                UserService.name,
                'Failed to create user -> password is not valid',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }

        if (!isNameValid(name)) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST
            Logger.error(
                UserService.name,
                'Failed to create user -> name is not valid',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }

        const existingUser = await this.userRepository.findByEmail(email)

        if (existingUser) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.CONFLICT
            Logger.error(
                UserService.name,
                'Failed to create user -> invalid email or password',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }
        try {
            const hash = await encrypt(password)
            if (!hash) {
                const statusCode =
                    HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR
                Logger.error(
                    UserService.name,
                    'failed to create user -> password not encrypted',
                    statusCode
                )
                return {
                    success: false,
                    statusCode,
                }
            }

            const user = await this.userRepository.createUser({
                password: hash,
                email: email,
                name: name,
            })

            const { password: excludedPassword, ...rest } = user

            return {
                success: true,
                statusCode: HTTP_STATUS.SUCCESS.CREATED,
                data: rest,
            }
        } catch (error) {
            const statusCode = HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR
            Logger.error(
                UserService.name,
                'Failed to create user -> server error',
                statusCode
            )
            return {
                success: false,
                statusCode,
            }
        }
    }
}
