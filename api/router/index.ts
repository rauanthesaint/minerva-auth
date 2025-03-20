import {
    getUserData,
    createUser,
    ejectUser,
    authUser,
    compareOtp,
} from 'api/controller/user'
import { Router } from 'express'

const router: Router = Router()
router.get('/user', getUserData)
router.post('/user', createUser)
router.post('/user/auth', authUser)
router.post('/user/eject', ejectUser)
router.post('/otp-verification', compareOtp)

export default router

// mJSnt9Q6x0e5nGzwhXeF
