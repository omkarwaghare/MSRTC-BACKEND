//External Modules
const multer = require("multer");
const ExcelJS = require("exceljs");
const { compare } = require("bcrypt");
const OTPClass = require('../models/otp')


// Local Modules
const Host = require("../models/hosts");
const sendMail = require("../Emails/sendMail");

const upload = multer({ storage: multer.memoryStorage() });

//! Sends login page to MSRTC Admin
exports.getLoginPage = (req, res, next) => {
    res.render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: '' });
}

//! Handles Admin login process and sends an OTP to email
exports.postLogin = async (req, res, next) => {
    const { emailId, password } = req.body;

    const trimmedEmailId = emailId.trim()
    const trimmedPassword = password.trim()
    try {
        // Gets the admin credential document else null
        const doesAdminExist = await Host.findAdmin(trimmedEmailId);

        if (doesAdminExist === null) {
            const message = `Wrong email address provided : ${trimmedEmailId}`
            return res.status(401).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: message })
        }

        // Verifies the password with the hashed password in the database
        const doesPasswordMatch = await Host.comparePassword(trimmedPassword, doesAdminExist.password.trim())

        if (!doesPasswordMatch) {
            return res.status(401).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Password does not match.' })
        }

        // Checks whether the OTP is already sent to the user and is still valid
        const isOTPAlreadySent = await OTPClass.checkExistingOTP(emailId);
        if (isOTPAlreadySent) {
            return res.status(201).render('otp-verification', { pageTitle: 'OTP Verification', submitOn: '/host/otp-verification', responseMessage: 'OTP is already sent to you via email', emailId: emailId })
        }

        // Generate an OTP 
        const OTP = await OTPClass.generateOTP(trimmedEmailId)


        if (!OTP) {
            return res.status(500).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'OTP generation failed. Please try again.' })
        }

        // Waits to send mail to the user on email
        await sendMail(trimmedEmailId, OTP);
        return res.status(201).render('otp-verification', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/otp-verification', responseMessage: '', emailId: emailId })


    } catch (error) {
        console.log(error.message)
        return res.status(500).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Server failed to process your request.' })
    }
}

//! Logout user from the session
exports.getLogout = (req, res, next) => {
    res.clearCookie('authToken', {
        httpOnly: true,
        secure: false,
    });

    res.redirect('/host/login')
}

//! Send OTP-Verification page to the Admin
exports.getOTPPage = (req, res, next) => {
    res.render('otp-verification', { pageTitle: 'OTP Verification', submitOn: '/host/otp-verification', responseMessage: '' });
}

//! Verify the OTP from Admin. If correct sets an token in http cookies and redirects to the host/home page
exports.postOTP = async (req, res, next) => {
    const { emailId, OTP } = req.body;

    const OTPMatched = await OTPClass.verifyOTP(emailId, OTP);

    if (!OTPMatched) {
        return res.status(500).render('otp-verification', { pageTitle: 'OTP Veriification', submitOn: '/host/otp-verification', responseMessage: 'OTP does not match.', emailId })
    }

    const token = Host.generateToken(emailId, 'admin');

    const OTPRemoved = OTPClass.removeOTP(emailId);

    if (OTPRemoved) {
        res.cookie("authToken", token, {
            httpOnly: true,
            secure: false,
        });

        return res.redirect(`/host/home`);
    }

    return res.status(500).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Server failed to verify your OTP.' })

}

//! Returns Admin Home Page but before which it checks for the token in cookies. If there is no cookies then redirects the user to login page
exports.getHome = (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    res.render('host/host-home', { pageTitle: 'Home' });
}

//! Returns Routes page to admin but before which it checks for the token in cookies. If there is no cookies then redirects the user to login page
exports.getAllRoutes = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const routesData = await Host.getRoutesData();

    res.render('host/manage-routes', { pageTitle: 'Manage Routes', routesData })
}

//! Returns add-route page to the admin is token is available in the cookies
exports.getAddRoute = (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    res.render('host/add-update-route', { pageTitle: 'Add New Route', responseMessage: '', submitOn: '/host/manage-routes/add-route', editing: false, routeId: '', routeName: '' })
}

//! Gets the edit route page
exports.getEditRoute = (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const routeId = req.params.routeId;
    const routeName = req.query.routeName
    const editing = req.query.editing === 'true';

    res.render('host/add-update-route', { pageTitle: 'Add New Route', responseMessage: '', submitOn: '/host/manage-routes/edit-route', editing, routeId, routeName })

}

exports.getViewRoute = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const routeId = req.params.routeId;

    const routeData = await Host.getRouteDataFromId(routeId.trim())

    res.render('host/view-route', { pageTitle: 'View Route', routeData })

}

//! Extract the excel file data from the file and return the data  
const extractDataFromExcel = (worksheet) => {
    // check whether the excel file has exactly two columns or not.
    const headerRow = worksheet.getRow(1);
    const columnCount = headerRow.cellCount;

    if (columnCount !== 3) {
        throw new Error("Invalid file format. The file must contain exactly 3 columns.");
    }

    const sheetData = [];
    let stopNumber = 1;
    worksheet.eachRow((row, rowNumber) => {
        if (rowNumber > 1) {
            const cleanedRow = row.values.filter(cell => cell !== undefined);
            const rowValue = {
                'stopSequence': stopNumber,
                'stop': cleanedRow[0],
                'goingPoint': cleanedRow[1],
                'returningPoint': cleanedRow[2],
            }
            sheetData.push(rowValue);
            stopNumber++;
        }
    });

    return sheetData;
}

//! Handles the routes excel file and extract data from it then saves the data in the database
exports.postAddRoute = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }
    try {
        const { routeName } = req.body;

        if (!req.file) {
            return res.status(400).json({ message: "No file uploaded" });
        }

        const isValidAdmin = await Host.adminValidation(token);
        if (!isValidAdmin) {
            return res.status(403).json({ message: "Unauthorized: Only valid admins can add routes" });
        }

        // Read the file buffer
        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.load(req.file.buffer);

        const worksheet = workbook.worksheets[0];

        let sheetData;

        // Handling of excel sheet data extraction
        try {
            sheetData = extractDataFromExcel(worksheet);
        } catch (error) {
            return res.status(400).render('host/add-update-route', { pageTitle: 'Add New Route', submitOn: '/host/manage-routes/add-route', editing: false, routeId: '', routeName: '', responseMessage: error.message });
        }

        const dataToInsert = {
            'routeName': routeName,
            'stops': sheetData
        }

        const result = await Host.addRoute(dataToInsert)
        res.status(result.status).render('host/add-update-route', { pageTitle: 'Add New Route', submitOn: '/host/manage-routes/add-route', editing: false, routeId: '', routeName: '', responseMessage: result.message })

    } catch (error) {
        console.error("Error processing file:", error);
        res.status(500).json({ message: "Error processing file" });
    }
}

//! Handles the POST Edit route request
exports.postEditRoute = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    try {
        const { routeName, routeId } = req.body;

        const trimmedRouteId = routeId.trim();
        const trimmedRouteName = routeName.trim();

        if (!req.file) {
            return res.status(400).json({ message: "No file uploaded" });
        }

        const isValidAdmin = await Host.adminValidation(token);
        if (!isValidAdmin) {
            return res.status(403).json({ message: "Unauthorized: Only valid admins can update routes" });
        }

        // Read the file buffer
        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.load(req.file.buffer);

        const worksheet = workbook.worksheets[0];

        let sheetData;

        // Handling of excel sheet data extraction
        try {
            sheetData = extractDataFromExcel(worksheet);
        } catch (error) {
            return res.status(400).json({ message: error.message });
        }

        const dataToBeUpdate = {
            'routeName': trimmedRouteName,
            'stops': sheetData
        }

        const result = await Host.editRoute(trimmedRouteId, dataToBeUpdate)
        res.status(result.status).render('host/add-update-route', { pageTitle: 'Edit Route', responseMessage: result.message, submitOn: '/host/manage-routes/edit-route', editing: true, routeId: trimmedRouteId, routeName: trimmedRouteName })

    } catch (error) {
        console.error("Error processing file:", error);
        res.status(500).json({ message: "Error processing file" });
    }
}

//! Gets add institute page
exports.getAddInstitute = (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    res.render('host/add-update-institute', { pageTitle: 'Add Institute', submitOn: '/host/manage-institutes/add-institute', editing: false, responseMessage: '', instituteName: '', instituteEmailId: '' })
}

//! Handles the institute insert operation on POST method
exports.postAddInstitute = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    try {
        const { instituteName, instituteEmailId, password } = req.body;

        const trimmedInstituteName = instituteName.trim();
        const trimmedInstituteEmailId = instituteEmailId.trim();
        const trimmedPassword = password.trim();

        const isValidAdmin = await Host.adminValidation(token);
        if (!isValidAdmin) {
            return res.status(403).json({ message: "Unauthorized: Only valid admins can add institute" });
        }

        const hashedPassword = await Host.hashPassword(trimmedPassword)

        const dataToInsert = {
            'instituteName': trimmedInstituteName,
            'instituteEmailId': trimmedInstituteEmailId,
            'password': hashedPassword
        }

        const result = await Host.addInstitute(dataToInsert)
        res.status(result.status).render('host/add-update-institute', { pageTitle: 'Add Institute', submitOn: '/host/manage-institutes/add-institute', editing: false, responseMessage: result.message, instituteName: '', instituteEmailId: '' })

    } catch (error) {
        console.error("Error processing file:", error);
        res.status(500).json({ message: "Error processing file" });
    }

}


//! Gets the institutes in database
exports.getAllInstitute = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const institutesData = await Host.getInstituteData();
    res.render('host/manage-institute', { pageTitle: 'Manage Institutes', institutesData })
}


//! Gets edit page for the institute
exports.getEditInstitute = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const instituteId = req.params.instituteId;

    const institute = await Host.getInstituteDataFromId(instituteId.trim())

    res.render('host/add-update-institute', { pageTitle: 'Edit Institute', submitOn: '/host/manage-institutes/edit-institute', editing: true, responseMessage: '', instituteName: institute.instituteName, instituteEmailId: institute.instituteEmailId, instituteId: institute._id })

}

//! Handles the update request for institute info 
exports.postEditInstitute = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    try {
        const { instituteId, instituteName, instituteEmailId } = req.body;

        const isValidAdmin = await Host.adminValidation(token);
        if (!isValidAdmin) {
            return res.status(403).json({ message: "Unauthorized: Only valid admins can update institutes" });
        }

        const dataToBeUpdate = {
            'instituteName': instituteName.trim(),
            'instituteEmailId': instituteEmailId.trim(),
        }
        const result = await Host.editInstitute(instituteId.trim(), dataToBeUpdate)
        res.status(result.status).render('host/add-update-institute', { pageTitle: 'Edit Route', responseMessage: result.message, submitOn: '/host/manage-institutes/edit-institute', editing: true, instituteId: instituteId.trim(), instituteName, instituteEmailId })

    } catch (error) {
        console.log(error.message)
        res.status(500).json({ message: "Error processing request" });
    }
}

//! Handles the GET request for the Add Pass Rates 
exports.getAddPassRate = (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    res.render('host/add-update-pass-rate', { pageTitle: 'Add Pass Rate', submitOn: '/host/manage-passrates/add-pass-rate', editing: false, responseMessage: '', })

}

exports.postAddPassRate = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const isValidAdmin = await Host.adminValidation(token);
    if (!isValidAdmin) {
        return res.status(403).json({ message: "Unauthorized: Only valid admins can add pass rates" });
    }


    const dataToInsert = {
        'travellingPoints': req.body.point,
        'passrate': req.body.passrate
    }

    const result = await Host.addPassRate(dataToInsert)

    res.status(result.status).render('host/add-update-pass-rate', { pageTitle: 'Add Pass Rate', submitOn: '/host/manage-passrates/add-pass-rate', editing: false, responseMessage: result.message })

}

//! Handles the GET request for View All Pass Rates 
exports.getAllPassRates = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const passRateData = await Host.getPassRates();
    res.render('host/manage-pass-rates', { pageTitle: 'Manage Pass Rates', passRateData })

}


exports.getEditPassRate = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const passrateId = req.params.passrateId;

    const passData = await Host.getPassDataFromId(passrateId);

    res.render('host/add-update-pass-rate', { pageTitle: 'Edit Passrate', submitOn: '/host/manage-passrates/edit-pass-rate', editing: true, responseMessage: '', passrateId: passrateId, travellingPoints: passData.travellingPoints, passrate: passData.passrate })

}


exports.postEditPassRate = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const isValidAdmin = await Host.adminValidation(token);
    if (!isValidAdmin) {
        return res.status(403).json({ message: "Unauthorized: Only valid admins can update pass rate" });
    }

    const { passrateId, point, passrate } = req.body;

    const dataToBeUpdate = {
        'travellingPoints': point,
        'passrate': passrate
    }

    const result = await Host.editPassRate(passrateId, dataToBeUpdate)

    res.status(result.status).render('host/add-update-pass-rate', { pageTitle: 'Edit Pass Rate', submitOn: '/host/manage-passrates/edit-pass-rate', editing: true, responseMessage: result.message, passrateId, travellingPoints: point, passrate })

}

//! Get Manage Students 
exports.getManageStudents = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const isValidAdmin = await Host.adminValidation(token);
    if (!isValidAdmin) {
        return res.status(403).json({ message: "Unauthorized: Only valid admins can access students page" });
    }

    try {
        //* Fetches validity dates
        const { passvalidationdates, noOfActivePasses } = await Host.getValidityDates();


        if (passvalidationdates && noOfActivePasses === 0) {
            return res.render('host/manage-student-pass', {
                pageTitle: 'Manage Pass Validation Date',
                reactivationDate: passvalidationdates.reactivationDate.split('T')[0],
                form: 'form3'
            });
        }


        //* If dates are found
        else if (passvalidationdates) {
            return res.render('host/manage-student-pass', {
                pageTitle: 'Manage Pass Validation Date',
                deactivationDate: passvalidationdates.deactivationDate.split('T')[0],
                reactivationDate: passvalidationdates.reactivationDate.split('T')[0],
                form: 'form2'
            });
        }


        //* If dates are not found or dates are not set by admin yet
        else if (!passvalidationdates) {
            return res.render('host/manage-student-pass', {
                pageTitle: 'Manage Pass Validation Date',
                message: '',
                form: 'form1'
            });
        }


    }
    catch (error) {
        return res.status(500).render('host/manage-student-pass', {
            pageTitle: 'Manage Pass Validation Date',
            graceDate: '',
            message: '',
            form: 'form1'
        });
    }

}

//! Sets the gracedate from admin 
exports.savePassValidityDates = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const isValidAdmin = await Host.adminValidation(token);
    if (!isValidAdmin) {
        return res.status(403).json({ message: "Unauthorized: Only valid admins can set grace date" });
    }

    const { deactivationDate, reactivationDate } = req.body;

    const result = await Host.setValidityDates(deactivationDate, reactivationDate);

    if (result.success) {
        return res.status(201).redirect('/host/manage-students')
    } else {
        return res.status(500).render('host/manage-student-pass', { pageTitle: 'Manage Pass Validation Date', message: result.message, form: 'form1' })
    }
}


exports.disableAllPasses = async (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(302).render('login', { pageTitle: 'MSRTC Admin Login', submitOn: '/host/login', responseMessage: 'Token not available.' })
    }

    const isValidAdmin = await Host.adminValidation(token);
    if (!isValidAdmin) {
        return res.status(403).json({ message: "Unauthorized: Only valid admins can update routes" });
    }

    const result = await Host.disableAllStudentPasses();
    if (result.success) {
        return res.status(201).redirect('/host/manage-students')
    } else {
        return res.status(500).render('host/manage-student-pass', { pageTitle: 'Manage Pass Validation Date', graceDate: '', message: result.message, form: 'form2' })

    }
}
