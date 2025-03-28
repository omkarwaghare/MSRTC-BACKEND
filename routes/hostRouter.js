// External Modules
const express = require('express')
const multer = require('multer')
const upload = multer()

// Local Modules
const hostController = require('../controllers/hostController')

const hostRouter = express.Router();

//! Handling of GET and POST request for Login page
hostRouter.get('/login', hostController.getLoginPage)
hostRouter.post('/login', hostController.postLogin)

//! Handles the GET request for Logout
hostRouter.get('/logout', hostController.getLogout)

//! Handling of GET and POST request for OTP page
hostRouter.get('/otp-verification', hostController.getOTPPage)
hostRouter.post('/otp-verification', hostController.postOTP)

//! Handling of GET request for Home page
hostRouter.get('/home', hostController.getHome)

//! Handling of GET request for View All Routes page
hostRouter.get('/manage-routes/all-routes', hostController.getAllRoutes)

//! Handling of GET and POST request for Add Route page
hostRouter.get('/manage-routes/add-route', hostController.getAddRoute)
hostRouter.post('/manage-routes/add-route', upload.single('file'), hostController.postAddRoute)

//! Handling of GET request for to view all stops on a bus route
hostRouter.get('/manage-routes/view-route/:routeId', hostController.getViewRoute)

//! Handling of GET and POST request for Edit Route page
hostRouter.get('/manage-routes/edit-route/:routeId', hostController.getEditRoute)
hostRouter.post('/manage-routes/edit-route', upload.single("file"), hostController.postEditRoute)

//! Handling of GET and POST request to view all institutes 
hostRouter.get('/manage-institutes/all-institutes', hostController.getAllInstitute)

//! Handling of GET and POST request for Add Institute page
hostRouter.get('/manage-institutes/add-institute', hostController.getAddInstitute)
hostRouter.post('/manage-institutes/add-institute', hostController.postAddInstitute)

//! Handling of GET and POST request for Edit Institute page
hostRouter.get('/manage-institutes/edit-institute/:instituteId', hostController.getEditInstitute)
hostRouter.post('/manage-institutes/edit-institute', hostController.postEditInstitute)

//! Handling of GET request for Add Pass Rate page
hostRouter.get('/manage-passrates/add-pass-rate', hostController.getAddPassRate)
hostRouter.post('/manage-passrates/add-pass-rate', hostController.postAddPassRate)

//! Handling for the GET and POST request for Edit Passrate Page 
hostRouter.get('/manage-passrates/edit-pass-rate/:passrateId', hostController.getEditPassRate)
hostRouter.post('/manage-passrates/edit-pass-rate', hostController.postEditPassRate)

//! Handling of GET request for View Pass Rates Page 
hostRouter.get('/manage-passrates/all-pass-rates', hostController.getAllPassRates)

//! Handling for the GET and POST request for gracedate Page 
hostRouter.get('/manage-students', hostController.getManageStudents)

hostRouter.post('/manage-students/pass-validity-period', hostController.savePassValidityDates)

hostRouter.post('/manage-students/disable-accounts', hostController.disableAllPasses)

module.exports = hostRouter