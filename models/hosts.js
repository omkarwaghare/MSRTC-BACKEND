// External Modules
const bcrypt = require('bcrypt');

// Local Modules
const { getDb } = require('../utils/databaseUtil');
const jwt = require('jsonwebtoken');
const { ObjectId } = require('mongodb');

require('dotenv').config()

const SECRET_KEY = process.env.SECRET_KEY

module.exports = class Host {


    //! Generates and return a token for authentication.
    static generateToken(emailId, role) {

        const payload = {
            emailId: emailId,
            role: role
        };

        return jwt.sign(payload, SECRET_KEY);
    }

    //! This code verifies the token sent by the user

    static async verifyToken(token) {
        return jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) {
                return null;
            } else {
                return decoded
            }
        });
    }




    //! This block of code find as user in database for login by email id and return user info

    static async findAdmin(emailId) {
        const db = getDb();
        const userExist = await db.collection('admins').find({
            'emailId': emailId,
            'role': 'admin'
        }).next();

        return userExist ? userExist : null
    }


    //! Checks whether OTP is already sent to specified email and OTP still valid

    static async checkExistingOTP(emailId) {
        const db = getDb();

        const OTPExists = await db.collection('otp').countDocuments({
            emailId: emailId,
        });

        return OTPExists > 0;
    }


    //! Hashes password and return hashed password

    static async hashPassword(password) {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        return hashedPassword;
    };


    //! Compare the password entered by the user with the hash code in the database

    static async comparePassword(enteredPassword, hashedPassword) {
        return await bcrypt.compare(enteredPassword, hashedPassword);
    };

    //! Validates the admin by checking token and database admin credentials 
    static async adminValidation(token) {

        const isValidToken = await this.verifyToken(token)

        const { emailId } = isValidToken

        const db = getDb();
        // checks the admin is real or not
        const admin = await db.collection('admins').findOne({ emailId });

        if (!admin || admin.role !== 'admin') {
            return false
        }

        return true;
    }

    //! add a new route in the data database
    static async addRoute(dataToInsert, token) {
        const db = getDb();

        try {

            const routeExistCount = await db.collection('routes').countDocuments({
                routeName: dataToInsert.routeName
            });

            if (routeExistCount > 0) {
                return { status: 409, message: 'Route already exists in the database' };
            }

            const result = await db.collection('routes').insertOne(dataToInsert);
            return { status: 201, message: 'Route added successfully', data: result };

        } catch (error) {
            return { status: 500, message: 'Server failed to add new route', error: error.message };
        }
    }

    //! Finds the Route data from by using routeId
    static async getRouteDataFromId(routeId) {
        try {
            const db = getDb();
            return await db.collection('routes').find({ _id: new ObjectId(String(routeId)) }).next();

        } catch (error) {
            console.log('Error while fetching the routes data from the database')
        }
    }

    //! Returns all routes in the database
    static async getRoutesData() {
        try {
            const db = getDb();
            return await db.collection('routes').find({}, { projection: { _id: 1, routeName: 1 } }).toArray();

        } catch (error) {
            console.log('Error while fetching the routes data from the database')
        }
    }

    //! Edit route details in the database 
    static async editRoute(routeId, dataToBeUpdated, token) {
        // 
        const db = getDb();

        try {

            const routeExistCount = await db.collection('routes').countDocuments({
                _id: new ObjectId(String(routeId))
            });

            if (routeExistCount === 0) {
                return { status: 409, message: 'Route does not exist in the database' };
            }

            const result = await db.collection('routes').updateOne({ _id: new ObjectId(String(routeId)) }, { $set: dataToBeUpdated });
            return { status: 201, message: 'Route updated successfully', data: result };

        } catch (error) {
            return { status: 500, message: 'Server failed to update route', error: error.message };
        }
    }

    //! Returns all institutes data to the page 
    static async getInstituteData() {
        try {
            const db = getDb();
            return await db.collection('institutes').find().toArray();

        } catch (error) {
            console.log('Error while fetching the routes data from the database')
        }
    }

    //! Adds a new institute in the database
    static async addInstitute(dataToInsert) {
        const db = getDb();

        try {
            const emailIdExists = await db.collection('institutes').countDocuments({
                instituteEmailId: dataToInsert.instituteEmailId
            });

            if (emailIdExists > 0) {
                return { status: 409, message: 'Institute with same emailId already exists in the database' };
            }

            const result = await db.collection('institutes').insertOne(dataToInsert);
            return { status: 201, message: 'Institute added successfully', data: result };

        } catch (error) {
            console.log(error.message)
            return { status: 500, message: 'Server failed to add new institute', error: error.message };
        }
    }

    //! Finds the institute data from by using instituteId
    static async getInstituteDataFromId(instituteId) {
        try {
            const db = getDb();
            return await db.collection('institutes').find({ _id: new ObjectId(String(instituteId)) }).next();

        } catch (error) {
            console.log('Error while fetching the institute data from the database')
        }
    }

    //! Edits the info of institute 
    static async editInstitute(instituteId, dataToBeUpdate) {
        const db = getDb();

        try {
            const result = await db.collection('institutes').updateOne({ _id: new ObjectId(String(instituteId)) }, { $set: dataToBeUpdate });
            return { status: 201, message: 'Institute updated successfully', data: result };

        } catch (error) {
            console.log(error.message)
            return { status: 500, message: 'Server failed to add new institute', error: error.message };
        }
    }

    //! Adds a new pass rate in the database
    static async addPassRate(dataToInsert) {
        const db = getDb();

        try {
            const pointExist = await db.collection('passrates').countDocuments({
                travellingPoints: dataToInsert.travellingPoints
            });

            if (pointExist > 0) {
                return { status: 409, message: 'Passrate for given travelling points already exists in the database' };
            }

            const result = await db.collection('passrates').insertOne(dataToInsert);
            return { status: 201, message: 'New passrate added successfully', data: result };

        } catch (error) {
            console.log(error.message)
            return { status: 500, message: 'Server failed to add new passrate', error: error.message };
        }
    }

    //! Returns passrates data to the page 
    static async getPassRates() {
        try {
            const db = getDb();
            return await db.collection('passrates').find().toArray();

        } catch (error) {
            console.log('Error while fetching the passrates data from the database')
        }
    }

    //! Returns the pass rate data of a specific id
    static async getPassDataFromId(passrateId) {
        try {
            const db = getDb();
            return await db.collection('passrates').find({ _id: new ObjectId(String(passrateId)) }).next();

        } catch (error) {

            console.log('Error while fetching the pass data from the database')
        }
    }

    //! Edits pass rate
    static async editPassRate(passrateId, dataToBeUpdate) {
        const db = getDb();

        try {
            const result = await db.collection('passrates').updateOne({ _id: new ObjectId(String(passrateId)) }, { $set: dataToBeUpdate });
            return { status: 201, message: 'Passrate updated successfully', data: result };

        } catch (error) {
            console.log(error.message)
            return { status: 500, message: 'Server failed to add new institute', error: error.message };
        }
    }

    //! return gracedata to admin
    static async getValidityDates() {
        const db = getDb();
        try {
            const passvalidationdates = await db.collection('passvalidationdates').findOne({});
            const noOfActivePasses = await db.collection('studentpasses').countDocuments({ collegeRemark: 'approved' })
            return { passvalidationdates, noOfActivePasses }
        } catch (error) {
            console.log(error)
        }
    }

    //! sets gracedata to admin
    static async setValidityDates(deactivationDate, reactivationDate) {
        const db = getDb()
        try {
            const doesValidityDatesSaved = await db.collection('passvalidationdates').insertOne({
                deactivationDate: new Date(deactivationDate).toISOString(),
                reactivationDate: new Date(reactivationDate).toISOString(),
            });

            //! check whether gracedata is updated or not
            if (doesValidityDatesSaved) {
                return { success: true, message: 'Both dates added successfully' };
            } else {
                return { success: false, message: 'No records were inserted' };
            }
        } catch (error) {
            console.log(error.message, error)
            return { success: false, message: 'An error occurred while inserting dates' };
        }
    }

    //! Disable all approved student passes 
    static async disableAllStudentPasses() {
        const db = getDb();

        try {
            const studentApprovedPassUpdateResult = await db.collection('studentpasses').updateMany({ collegeRemark: 'approved' }, { $set: { collegeRemark: 'disabled' } })
            const studentPendingPassUpdateResult = await db.collection('studentpasses').updateMany({ collegeRemark: 'pending' }, { $set: { collegeRemark: 'rejected' } })

            //! check whether all passes are updated or not
            if (studentApprovedPassUpdateResult.modifiedCount > 0 || studentPendingPassUpdateResult > 0) {
                return { success: true, message: 'All student passes disabled successfully' };
            } else {
                return { success: false, message: 'No records were updated' };
            }
        } catch (error) {
            console.log(error.message, error)
            return { success: false, message: 'An error occurred while deactivating passes' };
        }
    }
}

