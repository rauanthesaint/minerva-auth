import {
    ActiveOTP,
    CreateOTP,
    OTP,
    OTPType,
    User,
    UserRequiredFields,
    VerifyOTPRequest,
} from 'api/domain/entities/user.entity'

export interface IUserRepository {
    createUser(user: UserRequiredFields): Promise<User>
    findByEmail(email: string): Promise<User | null>
    findById(id: number): Promise<User | null>
    // // ========== OTP METHODS ==========

    // // Создание и управление OTP
    // createOTP(otp: CreateOTP): Promise<OTP>
    // findActiveOTP(
    //     userId: number,
    //     code: string,
    //     type: OTPType
    // ): Promise<ActiveOTP | null>
    // findOTPById(id: number): Promise<OTP | null>

    // // Проверка и использование OTP
    // verifyOTP(request: VerifyOTPRequest): Promise<{
    //     isValid: boolean
    //     otp?: ActiveOTP
    //     attemptsLeft?: number
    // }>
    // markOTPAsUsed(id: number): Promise<boolean>
    // incrementOTPAttempts(id: number): Promise<number> // возвращает текущее количество попыток

    // // Очистка и управление OTP
    // invalidateUserOTPs(userId: number, type?: OTPType): Promise<number> // возвращает количество инвалидированных
    // cleanupExpiredOTPs(): Promise<number> // возвращает количество удаленных
    // deleteOTP(id: number): Promise<boolean>

    // // Получение OTP для пользователя
    // getUserOTPs(
    //     userId: number,
    //     type?: OTPType,
    //     includeExpired?: boolean
    // ): Promise<OTP[]>
    // getActiveOTPsForUser(userId: number): Promise<OTP[]>

    // // Статистика и лимиты
    // getOTPCountForUser(
    //     userId: number,
    //     type: OTPType,
    //     timeframe?: Date
    // ): Promise<number>
    // canSendOTP(
    //     userId: number,
    //     type: OTPType
    // ): Promise<{
    //     canSend: boolean
    //     reason?: string
    //     nextAllowedAt?: Date
    // }>

    // // ========== COMBINED METHODS ==========

    // // Методы, объединяющие работу с пользователями и OTP
    // findUserWithActiveOTP(
    //     userId: number,
    //     type: OTPType
    // ): Promise<{
    //     user: User | null
    //     otp: OTP | null
    // }>

    // // Создание пользователя с автоматической отправкой OTP
    // createUserWithVerification(user: UserRequiredFields): Promise<{
    //     user: User
    //     otp: OTP
    // }>

    // // Подтверждение email через OTP
    // confirmEmailWithOTP(
    //     userId: number,
    //     code: string
    // ): Promise<{
    //     success: boolean
    //     user?: User
    //     message: string
    // }>

    // // Сброс пароля через OTP
    // resetPasswordWithOTP(
    //     email: string,
    //     code: string,
    //     newPassword: string
    // ): Promise<{
    //     success: boolean
    //     user?: User
    //     message: string
    // }>

    // // ========== UTILITY METHODS ==========

    // // Статистика
    // getUserStats(userId: number): Promise<{
    //     totalOTPsSent: number
    //     totalOTPsVerified: number
    //     lastLoginAt?: Date
    //     accountCreatedAt: Date
    //     emailVerified: boolean
    // }>

    // // Безопасность
    // getUserSecurityInfo(userId: number): Promise<{
    //     failedLoginAttempts: number
    //     lastFailedLoginAt?: Date
    //     accountLocked: boolean
    //     lockExpiresAt?: Date
    // }>

    // // Очистка данных
    // cleanupUserData(userId: number): Promise<{
    //     otpsRemoved: number
    //     userDeleted: boolean
    // }>
}
