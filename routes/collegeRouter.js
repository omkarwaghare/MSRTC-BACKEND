// External Module
const express = require('express');

// Local Modules
const collegeController = require('../controllers/collegeController');

const collegeRouter = express.Router();

//! Handles GET and POST request for login page 
collegeRouter.get('/login', collegeController.getLoginPage);
collegeRouter.post('/login', collegeController.postLogin);

//! Handling of GET and POST request for OTP page
collegeRouter.get('/otp-verification', collegeController.getOTPPage)
collegeRouter.post('/otp-verification', collegeController.postOTP)

//! Handles GET request for College Authority Home page 
collegeRouter.get('/home', collegeController.getHomePage);

//! Handles GET and POST request for College Authority Home page 
collegeRouter.get('/manage-applications', collegeController.getManageApplications);

//! Fetch and send list of pending applications to the institute  
collegeRouter.get('/manage-applications/get-pending-applications', collegeController.getPendingApplications);

//! Handles GET request for View Application page 
collegeRouter.get('/manage-applications/view-application/:studentId', collegeController.getApplication);

//! Handles POST request for Approve or Reject Pass Application
collegeRouter.post('/manage-applications/view-application/approve-reject-application', collegeController.applicationApproveReject);


//! Handles logout functionality.
collegeRouter.get('/logout', collegeController.getLogout);

module.exports = collegeRouter;