import { Router } from 'express'
import AuthController from 'api/controllers/auth.controller'

export const authRoutes = (): Router => {
    const router = Router()
    const controller = new AuthController()

    router.post('/unauth', controller.unauthorizeUser)

    return router
}
