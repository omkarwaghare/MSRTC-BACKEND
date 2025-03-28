// External Modules
const bcrypt = require('bcrypt');

// Local Modules
const { getDb } = require('../utils/databaseUtil');

module.exports = class OTPClass {
    //! Hashes the OTP 
    static async hashOTP(OTP) {
        const saltRounds = 10;
        const hashedOTP = await bcrypt.hash(OTP, saltRounds);
        return hashedOTP;
    };

    //! Compare the OTP entered by the user with the hash code in the database.
    static async compareOTP(enteredOTP, hashedOTP) {
        return await bcrypt.compare(enteredOTP, hashedOTP);
    };


    //! Verifies the OTP entered by user with the OTP send by server.

    static async verifyOTP(emailId, userOTP) {
        const db = getDb();
        const OTPInfo = await db.collection('otp').findOne({
            'emailId': emailId,
        });

        const isOTPCorrect = await this.compareOTP(userOTP, OTPInfo.OTP)

        return isOTPCorrect;

    }

    //! Generates an OTP and send to user via email and save OTP in database. 
    static async generateOTP(emailId) {

        let OTP = '';

        for (let i = 0; i < 6; i++) {
            OTP += Math.trunc(Math.random() * 10)
        }

        const hashedOTP = await this.hashOTP(OTP);

        const db = getDb();
        const otpStored = await db.collection('otp').insertOne({
            'emailId': emailId,
            'OTP': hashedOTP,
            'createdAt': new Date()
        });

        if (otpStored) {
            return OTP;
        }
    }

    //! Checks whether OTP is already sent to specified email and OTP still valid

    static async checkExistingOTP(emailId) {
        const db = getDb();

        const OTPExists = await db.collection('otp').countDocuments({
            emailId: emailId,
        });

        return OTPExists > 0;
    }

    //! Remove the OTP from the Database once verification is completed 

    static async removeOTP(emailId) {
        const db = getDb();
        const OTPRemoved = await db.collection('otp').findOneAndDelete({
            'emailId': emailId,
        });

        return OTPRemoved;

    }

}