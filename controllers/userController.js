// External Module
const ImageKit = require("imagekit");
const Razorpay = require("razorpay");
const crypto = require('crypto')
const OTPClass = require('../models/otp')

require('dotenv').config()

const imagekit = new ImageKit({
    publicKey: process.env.PUBLIC_KEY,
    privateKey: process.env.PRIVATE_KEY,
    urlEndpoint: "https://ik.imagekit.io/omkarwaghare"
});

// Initialize Razorpay
const razorpay = new Razorpay({
    key_id: process.env.KEY_ID,
    key_secret: process.env.KEY_SECRET
});

const SECRET_KEY = process.env.KEY_SECRET

const sendMail = require('../Emails/sendMail')
const user = require('../models/users');

//! This follwoing code send an OTP to user
exports.sendVerificationOTP = async (req, res, next) => {
    const { contactNo, emailId } = req.body;
    try {

        // if the email id is not available
        if (!emailId) {
            return res.status(400).json({ message: 'Email ID is required' })
        }

        // Check whether user already present in database
        const userExists = await user.checkExistingUsers(contactNo, emailId);
        if (userExists) return res.status(409).json({ message: 'User with same email or contact number already exist in database' })

        // checks whether OTP is still valid and exists in the database
        const OTPExist = await OTPClass.checkExistingOTP(emailId);
        if (OTPExist) return res.status(201).json({ message: 'OTP is already sent to you via email. Please check your mailbox' })

        // Waits for server to  genrate the OTP and save in Database
        const OTP = await OTPClass.generateOTP(emailId.trim());
        if (!OTP) {
            throw new Error('OTP generation failed. Please try again');
        }

        // Waits for server to send the OTP to user via email 
        await sendMail(emailId.trim(), OTP);
        return res.status(200).json({ message: `We have sent an OTP on your email. Please submit your OTP` })

    } catch (error) {
        return res.status(500).json({ message: 'Unable to send OTP. Please try again.' })
    }
}


//! The following code adds a new user before which it verify the OTP sent by user
exports.addNewUser = async (req, res, next) => {

    try {
        const { name, contactNo, emailId, birthdate, password, userOTP } = req.body;

        // checks whether all fields are present or not
        if (!name || !contactNo || !emailId || !birthdate || !password || !userOTP) {
            return res.status(400).json({ message: 'All fields are madatory' });
        }

        // Verifies the OTP sent by the user
        const validOTP = await OTPClass.verifyOTP(emailId, userOTP);

        if (!validOTP) {
            return res.status(406).json({ message: "OTP does not match" });
        }

        // verifies whether the user with same email and contact no exists or not
        const userExists = await user.checkExistingUsers(contactNo, emailId);
        if (userExists) return res.status(409).json({ message: 'Your account is already created.' })

        // Wait for server to add user in database
        try {
            const removeOTP = OTPClass.removeOTP(emailId);
            if (removeOTP) {
                const userInfo = await user.addUser(name, contactNo, emailId, birthdate, password);
                return res.status(201).json({ message: 'Account Created Successfully', userInfo });
            } else {
                return res.status(500).json({ message: 'Server is unable to verify your OTP' });

            }
        } catch (error) {
            return res.status(500).json({ message: error.message, error: error.message });
        }

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
}


//! This is for user login 

exports.userLogin = async (req, res, next) => {

    try {
        const { emailId, password } = req.body;

        // checks whether all fields are present or not
        if (!emailId || !password) {
            return res.status(400).json({ message: 'All fields are madatory' });
        }

        // if user exits then receives encrypted password else receive null
        const userExist = await user.findUser(emailId)

        if (userExist === null) {
            return res.status(404).json({ message: 'User does not exist ..!' })
        }

        const isPasswordCorrect = await user.comparePassword(password.trim(), userExist.password)

        if (!isPasswordCorrect) {
            return res.status(401).json({ message: 'Invalid Password..!' })
        }

        const token = user.generateToken(userExist._id.toString());

        const userInfo = {
            ...userExist,
            token: token
        };

        const passInfo = await user.findUserPassData(token);

        const punchInfo = await user.findPassPunchData(token)

        return res.status(201).json({ userInfo, passInfo, punchInfo })

    } catch (error) {
        res.status(500).json({ message: error.message });
    }

}

//! Uploads image to the Imagekit.io and returns the image URL to the user  
exports.uploadImage = async (req, res, next) => {
    const { image } = req.body;

    try {
        const result = await imagekit.upload({
            file: image,
            fileName: `user_${Date.now()}.jpg`,
            folder: "/user_images"
        });

        res.json({ imageURL: result.url });
    } catch (error) {
        res.status(500).json({ message: "Failed to upload image" });
    }

}

//! The following code is to add users profile image.

exports.addUserProfile = async (req, res, next) => {
    const { imageURL, token } = req.body;

    const profileURLAdded = await user.addProfileURL(imageURL, token)
    return profileURLAdded ? res.status(201).json({ message: 'Profile Picture Added Successfully' }) : res.status(500).json({ message: 'Image Upload Failed..Please Try Again.' })

}
exports.addUserProfile = async (req, res, next) => {
    const { imageURL, token } = req.body;

    const profileURLAdded = await user.addProfileURL(imageURL, token)
    return profileURLAdded ? res.status(201).json({ message: 'Profile Picture Added Successfully' }) : res.status(500).json({ message: 'Image Upload Failed..Please Try Again.' })

}

//! The following code is to get all the bus routes to the app UI
exports.getBusRoutes = async (req, res, next) => {
    const busRoutes = await user.sendBusRoutes()
    return res.status(201).json(busRoutes)
}

//! The following code is to get all the stops of a particular bus route to the app UI
exports.getBusStops = async (req, res, next) => {
    const routeId = req.params.routeId;

    const busStops = await user.sendBusStops(routeId)
    return res.status(201).json(busStops)
}

//! The following code is to get all the institutes to the app UI
exports.getInstitutes = async (req, res, next) => {
    const busStops = await user.sendInstitutes();
    return res.status(201).json(busStops)
}

//! Adds user application in the database 
exports.userPassApplication = async (req, res, next) => {

    const { userInfo, token } = req.body;

    const applicationSent = await user.addUserPassApplication(userInfo, token)
    return applicationSent ? res.status(201).json({ message: 'Application submitted Successfully' }) : res.status(500).json({ message: 'Application Submission Failed..Please Try Again.' })
}

//! Finds and send the user's pass data to the user 
exports.sendPassData = async (req, res, next) => {
    const token = req.headers.authorization;

    const userData = await user.findUserPassData(token)

    return userData ? res.status(201).json({ message: 'Got your request', userData }) : res.status(500).json({ message: 'Unable to find your application' })

}

//! Issues pass 
exports.paymentInfo = async (req, res, next) => {
    try {
        const { token } = req.body;

        const studentId = await user.verifyToken(token);

        if (!studentId) {
            res.status(404).json({ success: false });
        }

        const userInfo = await user.findUserById(studentId.trim())
        if (!userInfo) {
            res.status(404).json({ success: false });
        }

        const passRateInfo = await user.findPassRate(userInfo.travelPoints)

        const amount = Number(passRateInfo.passrate) * 100; // Replace this with actual logic from your DB

        const options = {
            amount: amount,
            currency: "INR",
            receipt: `receipt_${studentId}`,
            payment_capture: 1
        };

        const order = await razorpay.orders.create(options);
        res.status(201).json({ success: true, order });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
}

//! Verifies the payment from the user 
exports.verifyPayment = async (req, res, next) => {

    try {
        const { studentId, order_id, payment_id, signature } = req.body;

        // Verify Signature (Extra Security)
        const body = order_id + "|" + payment_id;
        const expectedSignature = crypto
            .createHmac("sha256", SECRET_KEY)
            .update(body.toString())
            .digest("hex");

        if (expectedSignature !== signature) {
            return res.status(400).json({ success: false, message: "Invalid Signature" });
        }

        // Fetch payment from Razorpay API
        const payment = await razorpay.payments.fetch(payment_id);
        if (payment.status !== "captured") {
            return res.status(400).json({ success: false, message: "Payment not captured" });
        }

        const dataToInsert = {
            studentId,
            order_id,
            payment_id,
            amount: payment.amount / 100,
            currency: payment.currency,
            status: payment.status,
        }
        const result = await user.updateStudentPassData(studentId, dataToInsert)

        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, message: "Verification failed", error });
    }
}

//! Adds user data while going in the database
exports.addGoingPunchData = async (req, res, next) => {
    const token = req.headers.authorization;

    const result = await user.addsGoingPassPunchData(token)

    return res.status(result.status).json(result)
}

//! Adds user data while returning in the database
exports.addReturningPunchData = async (req, res, next) => {
    const token = req.headers.authorization;

    const result = await user.addsReturningPassPunchData(token)

    return res.status(result.status).json(result)
}


exports.getValidationDates = async (req, res, next) => {
    const token = req.headers.authorization;

    const result = await user.getValidationDatesForPass(token)

    return res.status(result.status).json(result)
}
