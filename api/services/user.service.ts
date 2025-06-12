import { Result } from 'api/domain/entities/result.entity'
import { IUserRepository } from 'api/domain/interfaces/repositories/userRepository.interface'
import { OTPType } from 'api/domain/entities/user.entity'
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
import { sendMail } from 'api/shared/utils/mail-service'

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
            const statusCode = HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED
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

        try {
            const isValid = await bcrypt.compare(password, user.password)
            if (!isValid) {
                const statusCode = HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED
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
                'Failed to get user -> user is not found',
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

        // Используем новый метод existsByEmail для проверки
        const userExists = await this.userRepository.existsByEmail(email)
        if (userExists) {
            const statusCode = HTTP_STATUS.CLIENT_ERROR.CONFLICT
            Logger.error(
                UserService.name,
                'Failed to create user -> email already exists',
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
                    'Failed to create user -> password not encrypted',
                    statusCode
                )
                return {
                    success: false,
                    statusCode,
                }
            }

            // Используем новый метод createUserWithVerification
            const { user, otp } =
                await this.userRepository.createUserWithVerification({
                    password: hash,
                    email: email,
                    name: name,
                })

            const emailSubject = 'Email Verification - Minerva Auth'
            const emailText = `
Hello ${user.name},

Welcome to Minerva Auth! Please verify your email address using the code below:

Verification Code: ${otp.code}

This code will expire in 10 minutes.

If you didn't create this account, please ignore this email.

Best regards,
Minerva Auth Team
            `

            // Отправляем email
            sendMail(user.email, emailText, emailSubject)

            const { password: excludedPassword, ...rest } = user

            // Возвращаем данные пользователя и информацию об OTP
            return {
                success: true,
                statusCode: HTTP_STATUS.SUCCESS.CREATED,
                data: {
                    user: rest,
                    verification: {
                        otp_sent: true,
                        expires_at: otp.expires_at,
                        email: otp.email,
                    },
                },
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

    // ========== НОВЫЕ МЕТОДЫ ДЛЯ РАБОТЫ С OTP ==========

    async sendVerificationOTP(userId: number): Promise<Result> {
        try {
            const user = await this.userRepository.findById(userId)
            if (!user) {
                return {
                    success: false,
                    statusCode: HTTP_STATUS.CLIENT_ERROR.NOT_FOUND,
                }
            }

            // Проверяем, можно ли отправить OTP
            const canSend = await this.userRepository.canSendOTP(
                userId,
                OTPType.EMAIL_VERIFICATION
            )
            if (!canSend.canSend) {
                return {
                    success: false,
                    statusCode: HTTP_STATUS.CLIENT_ERROR.TOO_MANY_REQUESTS,
                    data: {
                        reason: canSend.reason,
                        nextAllowedAt: canSend.nextAllowedAt,
                    },
                }
            }

            const code = generateOTP()
            const expiresAt = new Date(Date.now() + 10 * 60 * 1000) // 10 минут

            const otp = await this.userRepository.createOTP({
                user_id: userId,
                code,
                type: OTPType.EMAIL_VERIFICATION,
                email: user.email,
                expires_at: expiresAt,
                max_attempts: 3,
            })

            const emailSubject = 'Email Verification Code - Minerva Auth'
            const emailText = `
Hello ${user.name},

Your email verification code is: ${code}

This code will expire in 10 minutes.

If you didn't request this verification, please ignore this email.

Best regards,
Minerva Auth Team
            `

            sendMail(user.email, emailText, emailSubject)

            return {
                success: true,
                statusCode: HTTP_STATUS.SUCCESS.OK,
                data: {
                    otp_sent: true,
                    expires_at: otp.expires_at,
                    email: user.email,
                },
            }
        } catch (error) {
            Logger.error(
                UserService.name,
                'Failed to send verification OTP',
                500
            )
            return {
                success: false,
                statusCode: HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR,
            }
        }
    }

    async verifyEmail(userId: number, code: string): Promise<Result> {
        try {
            const result = await this.userRepository.confirmEmailWithOTP(
                userId,
                code
            )

            if (!result.success) {
                return {
                    success: false,
                    statusCode: HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST,
                    data: { message: result.message },
                }
            }

            const { password, ...userData } = result.user!
            return {
                success: true,
                statusCode: HTTP_STATUS.SUCCESS.OK,
                data: {
                    user: userData,
                    message: result.message,
                },
            }
        } catch (error) {
            Logger.error(UserService.name, 'Failed to verify email', 500)
            return {
                success: false,
                statusCode: HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR,
            }
        }
    }

    async requestPasswordReset(email: string): Promise<Result> {
        try {
            const user = await this.userRepository.findByEmail(email)
            if (!user) {
                // Не раскрываем информацию о существовании пользователя
                return {
                    success: true,
                    statusCode: HTTP_STATUS.SUCCESS.OK,
                    data: {
                        message: 'If email exists, reset code has been sent',
                    },
                }
            }

            const canSend = await this.userRepository.canSendOTP(
                user.id,
                OTPType.PASSWORD_RESET
            )
            if (!canSend.canSend) {
                return {
                    success: false,
                    statusCode: HTTP_STATUS.CLIENT_ERROR.TOO_MANY_REQUESTS,
                    data: {
                        reason: canSend.reason,
                        nextAllowedAt: canSend.nextAllowedAt,
                    },
                }
            }

            const code = generateOTP()
            const expiresAt = new Date(Date.now() + 15 * 60 * 1000) // 15 минут для сброса пароля

            await this.userRepository.createOTP({
                user_id: user.id,
                code,
                type: OTPType.PASSWORD_RESET,
                email: user.email,
                expires_at: expiresAt,
                max_attempts: 3,
            })

            // ОТПРАВЛЯЕМ EMAIL С КОДОМ ДЛЯ СБРОСА ПАРОЛЯ
            const emailSubject = 'Password Reset Code - Minerva Auth'
            const emailText = `
Hello ${user.name},

You requested a password reset for your Minerva Auth account.

Your password reset code is: ${code}

This code will expire in 15 minutes.

If you didn't request a password reset, please ignore this email and your password will remain unchanged.

For security reasons, please do not share this code with anyone.

Best regards,
Minerva Auth Team
            `

            sendMail(user.email, emailText, emailSubject)

            return {
                success: true,
                statusCode: HTTP_STATUS.SUCCESS.OK,
                data: { message: 'If email exists, reset code has been sent' },
            }
        } catch (error) {
            Logger.error(
                UserService.name,
                'Failed to request password reset',
                500
            )
            return {
                success: false,
                statusCode: HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR,
            }
        }
    }

    private async sendPasswordResetConfirmation(
        email: string,
        name: string
    ): Promise<void> {
        const emailSubject = 'Password Successfully Changed - Minerva Auth'
        const emailText = `
Hello ${name},

Your password has been successfully changed for your Minerva Auth account.

If you didn't make this change, please contact our support team immediately.

Best regards,
Minerva Auth Team
        `

        sendMail(email, emailText, emailSubject)
    }

    async resetPassword(
        email: string,
        code: string,
        newPassword: string
    ): Promise<Result> {
        try {
            if (!isPasswordValid(newPassword)) {
                return {
                    success: false,
                    statusCode: HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST,
                    data: { message: 'Invalid password format' },
                }
            }

            const hashedPassword = await encrypt(newPassword)
            if (!hashedPassword) {
                return {
                    success: false,
                    statusCode: HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR,
                    data: { message: 'Failed to encrypt password' },
                }
            }

            const result = await this.userRepository.resetPasswordWithOTP(
                email,
                code,
                hashedPassword
            )

            if (!result.success) {
                return {
                    success: false,
                    statusCode: HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST,
                    data: { message: result.message },
                }
            }

            // ОТПРАВЛЯЕМ ПОДТВЕРЖДЕНИЕ О СМЕНЕ ПАРОЛЯ
            await this.sendPasswordResetConfirmation(
                result.user!.email,
                result.user!.name
            )

            const { password, ...userData } = result.user!
            return {
                success: true,
                statusCode: HTTP_STATUS.SUCCESS.OK,
                data: {
                    user: userData,
                    message: result.message,
                },
            }
        } catch (error) {
            Logger.error(UserService.name, 'Failed to reset password', 500)
            return {
                success: false,
                statusCode: HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR,
            }
        }
    }

    async getUserStats(userId: number): Promise<Result> {
        try {
            const stats = await this.userRepository.getUserStats(userId)
            return {
                success: true,
                statusCode: HTTP_STATUS.SUCCESS.OK,
                data: stats,
            }
        } catch (error) {
            Logger.error(UserService.name, 'Failed to get user stats', 500)
            return {
                success: false,
                statusCode: HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR,
            }
        }
    }
}
