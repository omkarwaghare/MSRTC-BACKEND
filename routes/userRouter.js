// External Module
const express = require('express');

// Local Modules
const userController = require('../controllers/userController');

const userRouter = express.Router();

userRouter.post('/send-otp', userController.sendVerificationOTP);
userRouter.post('/verify-otp', userController.addNewUser)
userRouter.post('/login', userController.userLogin);
userRouter.post('/upload-profile', userController.uploadImage)
userRouter.post('/add-profile', userController.addUserProfile)
userRouter.get('/get-bus-routes', userController.getBusRoutes);
userRouter.get('/get-bus-stops/:routeId', userController.getBusStops);
userRouter.get('/get-institutes', userController.getInstitutes);
userRouter.post('/apply-student-pass', userController.userPassApplication);

//! Returns user pass data 
userRouter.get('/get-application-data', userController.sendPassData);

//! Sends payment order info to the user
userRouter.post('/get-payment-info', userController.paymentInfo);

//! Verifies payment and update the database
userRouter.post('/verify-payment', userController.verifyPayment);

//! Store data in punch data in database
userRouter.post('/add-going-punch-data', userController.addGoingPunchData)

//! Adds punch data while going  
userRouter.post('/add-returning-punch-data', userController.addReturningPunchData)

userRouter.get('/get-validation-date', userController.getValidationDates)


module.exports = userRouter;