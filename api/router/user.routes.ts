import { Router } from 'express'
import UserService from 'api/services/user.service'
import UserController from 'api/controllers/user.controller'

export const userRoutes = (userService: UserService): Router => {
    const router = Router()
    const controller = new UserController(userService)

    // ========== АУТЕНТИФИКАЦИЯ И РЕГИСТРАЦИЯ ==========

    // Регистрация пользователя (создает пользователя + отправляет OTP)
    router.post('/user', controller.createUser.bind(controller))

    // Аутентификация (логин)
    router.post('/auth', controller.authenticateUser.bind(controller))

    // Выход из системы
    router.post('/logout', controller.logout.bind(controller))

    // ========== РАБОТА С ПРОФИЛЕМ ==========

    // Получение информации о пользователе
    router.get('/user', controller.getUser.bind(controller))

    // Статистика пользователя
    router.get('/user/stats', controller.getUserStats.bind(controller))

    // ========== OTP И ВЕРИФИКАЦИЯ ==========

    // Отправка OTP для верификации email
    router.post(
        '/user/send-verification',
        controller.sendVerificationOTP.bind(controller)
    )

    // Подтверждение email через OTP
    router.post('/user/verify-email', controller.verifyEmail.bind(controller))

    // ========== СБРОС ПАРОЛЯ ==========

    // Запрос на сброс пароля (отправляет OTP на email)
    router.post(
        '/user/request-password-reset',
        controller.requestPasswordReset.bind(controller)
    )

    // Сброс пароля через OTP
    router.post(
        '/user/reset-password',
        controller.resetPassword.bind(controller)
    )

    // ========== АЛЬТЕРНАТИВНЫЙ СИНТАКСИС (рекомендуемый) ==========

    // Если предпочитаете arrow функции вместо .bind():
    /*
    // Аутентификация и регистрация
    router.post('/user', (req, res) => controller.createUser(req, res))
    router.post('/auth', (req, res) => controller.authenticateUser(req, res))
    router.post('/logout', (req, res) => controller.logout(req, res))
    
    // Профиль
    router.get('/user', (req, res) => controller.getUser(req, res))
    router.get('/user/stats', (req, res) => controller.getUserStats(req, res))
    
    // OTP и верификация
    router.post('/user/send-verification', (req, res) => controller.sendVerificationOTP(req, res))
    router.post('/user/verify-email', (req, res) => controller.verifyEmail(req, res))
    
    // Сброс пароля
    router.post('/user/request-password-reset', (req, res) => controller.requestPasswordReset(req, res))
    router.post('/user/reset-password', (req, res) => controller.resetPassword(req, res))
    */

    return router
}
