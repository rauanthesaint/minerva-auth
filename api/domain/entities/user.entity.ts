export type User = {
    id: number // SERIAL
    created_at: Date // default NOW
    updated_at: Date // default NOW
} & UserRequiredFields

export interface UserRequiredFields {
    email: string
    password: string
    name: string
}

// Основной интерфейс OTP
export interface OTP {
    id: number
    user_id: number
    code: string
    type: OTPType
    email: string
    phone?: string | null
    expires_at: Date
    is_used: boolean
    attempts: number
    max_attempts: number
    created_at: Date
    updated_at: Date
}

// Обязательные поля для создания OTP
export interface OTPRequiredFields {
    user_id: number
    code: string
    type: OTPType
    email: string
    expires_at: Date
}

// Необязательные поля для создания OTP
export interface OTPOptionalFields {
    phone?: string
    max_attempts?: number
}

// Полные поля для создания OTP
export type CreateOTPFields = OTPRequiredFields & OTPOptionalFields

// Тип для создания OTP (без автогенерируемых полей)
export type CreateOTP = Omit<
    OTP,
    'id' | 'is_used' | 'attempts' | 'created_at' | 'updated_at'
> & {
    max_attempts?: number
}

// Enum для типов OTP
export enum OTPType {
    EMAIL_VERIFICATION = 'email_verification',
    PASSWORD_RESET = 'password_reset',
    LOGIN_2FA = 'login_2fa',
    PHONE_VERIFICATION = 'phone_verification',
    ACCOUNT_RECOVERY = 'account_recovery',
    TRANSACTION_CONFIRM = 'transaction_confirm',
}

// Альтернативный способ через union type
export type OTPTypeUnion =
    | 'email_verification'
    | 'password_reset'
    | 'login_2fa'
    | 'phone_verification'
    | 'account_recovery'
    | 'transaction_confirm'

// Интерфейс для проверки OTP
export interface VerifyOTPRequest {
    user_id: number
    code: string
    type: OTPType
}

// Интерфейс для создания OTP запроса
export interface CreateOTPRequest {
    user_id: number
    type: OTPType
    email: string
    phone?: string
    expires_minutes?: number // по умолчанию 10 минут
}

// Ответ при создании OTP
export interface CreateOTPResponse {
    success: boolean
    otp_id?: number
    expires_at?: Date
    message?: string
}

// Ответ при проверке OTP
export interface VerifyOTPResponse {
    success: boolean
    is_valid: boolean
    message: string
    attempts_left?: number
    expires_at?: Date
}

// Интерфейс для активного OTP (из базы)
export interface ActiveOTP {
    id: number
    user_id: number
    code: string
    type: OTPType
    email: string
    expires_at: Date
    attempts: number
    max_attempts: number
}

// Статистика OTP для пользователя
export interface OTPStats {
    user_id: number
    total_sent: number
    total_verified: number
    active_codes: number
    last_sent_at?: Date
    last_verified_at?: Date
}

// Конфигурация OTP
export interface OTPConfig {
    code_length: number // обычно 6
    expires_minutes: number // обычно 10
    max_attempts: number // обычно 3
    resend_cooldown_seconds: number // обычно 60
    max_per_day: number // лимит отправки в день
}

// Дефолтная конфигурация
export const DEFAULT_OTP_CONFIG: OTPConfig = {
    code_length: 6,
    expires_minutes: 10,
    max_attempts: 3,
    resend_cooldown_seconds: 60,
    max_per_day: 10,
}

// Утилитарные типы
export type OTPWithUser = OTP & {
    user: Pick<User, 'id' | 'email' | 'name'>
}

export type OTPHistory = Pick<
    OTP,
    'id' | 'type' | 'created_at' | 'is_used' | 'attempts'
>

// Тип для обновления OTP
export type UpdateOTP = Partial<
    Pick<OTP, 'is_used' | 'attempts' | 'updated_at'>
>

// Примеры использования:

// Создание нового OTP
// const newOTP: CreateOTP = {
//     user_id: 1,
//     code: '123456',
//     type: OTPType.EMAIL_VERIFICATION,
//     email: 'user@example.com',
//     expires_at: new Date(Date.now() + 10 * 60 * 1000)
// }

// Запрос на создание OTP
// const createRequest: CreateOTPRequest = {
//     user_id: 1,
//     type: OTPType.PASSWORD_RESET,
//     email: 'user@example.com',
//     expires_minutes: 15
// }

// Проверка OTP
// const verifyRequest: VerifyOTPRequest = {
//     user_id: 1,
//     code: '123456',
//     type: OTPType.EMAIL_VERIFICATION
// }
