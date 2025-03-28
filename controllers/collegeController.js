// Local Modules
const College = require("../models/colleges");
const sendMail = require("../Emails/sendMail");
const { response } = require("express");
const OTPClass = require('../models/otp')

//! Handle GET request for login page
exports.getLoginPage = (req, res, next) => {
    res.render('login', { pageTitle: 'MSRTC College Authority Login', submitOn: '/college/login', responseMessage: '' });
}

//! Handles College Authoriy login process and sends an OTP to email
exports.postLogin = async (req, res, next) => {
    const { emailId, password } = req.body;

    const trimmedEmailId = emailId.trim()
    const trimmedPassword = password.trim()
    try {
        // Gets the admin credential document else null
        const doesCollegeExists = await College.findCollege(trimmedEmailId);

        if (doesCollegeExists === null) {
            const message = `Wrong email address provided : ${trimmedEmailId}`
            return res.status(401).render('login', { pageTitle: 'College Authority Login', submitOn: '/college/login', responseMessage: message })
        }

        // Verifies the password with the hashed password in the database
        const doesPasswordMatch = await College.comparePassword(trimmedPassword, doesCollegeExists.password.trim())

        if (!doesPasswordMatch) {
            return res.status(401).render('login', { pageTitle: 'College Authority Login', submitOn: '/college/login', responseMessage: 'Password does not match.' })
        }

        // Checks whether the OTP is already sent to the user and is still valid
        const isOTPAlreadySent = await OTPClass.checkExistingOTP(emailId);
        if (isOTPAlreadySent) {
            return res.status(201).render('otp-verification', { pageTitle: 'College Authority Login', submitOn: '/college/otp-verification', responseMessage: 'OTP is already sent to you via email', emailId: emailId })
        }

        // Generate an OTP 
        const OTP = await OTPClass.generateOTP(trimmedEmailId)


        if (!OTP) {
            return res.status(500).render('login', { pageTitle: 'College Authority Login', submitOn: '/college/login', responseMessage: 'OTP generation failed. Please try again.' })
        }

        // Waits to send mail to the user on email
        await sendMail(trimmedEmailId, OTP);
        return res.status(201).render('otp-verification', { pageTitle: 'OTP Verification', submitOn: '/college/otp-verification', responseMessage: '', emailId: emailId })


    } catch (error) {
        console.log(error.message)
        return res.status(500).render('login', { pageTitle: 'College Authority Login', submitOn: '/college/login', responseMessage: 'Server failed to process your request.' })
    }
}

//! Send OTP-Verification page to the college authority
exports.getOTPPage = (req, res, next) => {
    res.render('otp-verification', { pageTitle: 'OTP Verification', submitOn: '/college/otp-verification', responseMessage: '' });
}

//! Verify the OTP from college authority. If correct sets an token in http cookies and redirects to the college/home page
exports.postOTP = async (req, res, next) => {
    const { emailId, OTP } = req.body;

    const OTPMatched = await OTPClass.verifyOTP(emailId, OTP);

    if (!OTPMatched) {
        return res.status(500).render('otp-verification', { pageTitle: 'OTP Verification', submitOn: '/college/otp-verification', responseMessage: 'OTP does not match.', emailId })
    }

    const collegeInfo = await College.findCollege(emailId);

    const token = College.generateToken(collegeInfo._id, emailId, 'user');

    const OTPRemoved = OTPClass.removeOTP(emailId);

    if (OTPRemoved) {
        res.cookie("authCollegeToken", token, {
            httpOnly: true,
            secure: false,
        });

        return res.redirect(`/college/home`);
    }

    res.render('login', { pageTitle: 'MSRTC College Authority Login', submitOn: '/college/login', responseMessage: 'Server unable verify your OTP. Please try again' });

}

//! Send Home page to the college Authority on GET request
exports.getHomePage = (req, res, next) => {
    const token = req.cookies.authCollegeToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'College Authority Login', submitOn: '/college/login', responseMessage: 'Token not available.' })
    }

    res.render('college/college-home', { pageTitle: 'Home' });
}

//! Send Applications Page to the college Authority on GET request
exports.getManageApplications = async (req, res, next) => {
    const token = req.cookies.authCollegeToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'College Authority Login', submitOn: '/college/login', responseMessage: 'Token not available.' })
    }

    res.render('college/manage-application', { pageTitle: 'Applications', responseMessage: '' });
}

//! Send pending applications list to the authority 
exports.getPendingApplications = async (req, res, next) => {
    const token = req.cookies.authCollegeToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'College Authority Login', submitOn: '/college/login', responseMessage: 'Token not available.' })
    }

    const response = await College.getPendingPassApplications(token);
    if (response.status === 401) {
        res.clearCookie('authCollegeToken', {
            httpOnly: true,
            secure: false,
        });
        return res.status(302).render('login', { pageTitle: 'College Authority Login', submitOn: '/college/login', responseMessage: 'Invalid Token.' })
    }

    return res.json(response.pendingApplications)
}

//! Send View Application Page to the college Authority on GET request
exports.getApplication = async (req, res, next) => {
    const token = req.cookies.authCollegeToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'College Authority Login', submitOn: '/college/login', responseMessage: 'Token not available.' })
    }

    const studentId = req.params.studentId;

    res.render('college/view-application', { pageTitle: 'Student Pass Application', responseMessage: '', studentId });
}


//! Handles pass application approve or reject request
exports.applicationApproveReject = async (req, res, next) => {
    const token = req.cookies.authCollegeToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'College Authority Login', submitOn: '/college/login', responseMessage: 'Token not available.' })
    }

    const isValidCollege = await College.collegeValidation(token);
    if (!isValidCollege) {
        return res.status(302).render('login', { pageTitle: 'College Authority Login', submitOn: '/college/login', responseMessage: 'Unauthorized Access : You are not authorized to make modification in system.' })
    }

    const { studentId, action } = req.body;
    const response = await College.approveRejectApplication(studentId, action)


    res.redirect('/college/manage-applications');

}


//! Send Applications Page to the college Authority on GET request
exports.getLogout = (req, res, next) => {
    res.clearCookie('authCollegeToken', {
        httpOnly: true,
        secure: false,
    });

    res.redirect('/college/login')
}
