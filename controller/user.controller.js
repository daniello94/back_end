const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const crypto = require('crypto');

const User = require('../models/Users');
const BigBoss = require('../models/BigBoss');
const Boss = require('../models/Boss');
const TeamManager = require('../models/TeamMenager');
const Employee = require('../models/Employee');
const Admin = require("../models/Admin");
const Company = require("../models/Company");
const Project = require("../models/Project");
const UsedToken = require("../models/usedTokenSchema");

exports.checkEmailExistence = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Brak adresu e-mail' });
        }
        const user = await User.findOne({ email: email });

        if (user) {
            return res.status(200).json({ message: 'Adres e-mail istnieje w bazie danych', exists: true });
        } else {
            return res.status(404).json({ message: 'Adres e-mail nie istnieje w bazie danych', exists: false });
        }

    } catch (error) {
        console.error("Błąd podczas sprawdzania adresu e-mail:", error);
        res.status(500).json({ message: 'Błąd serwera podczas sprawdzania adresu e-mail', error: error.message });
    }
};


function generateVerificationToken() {
    return crypto.randomBytes(16).toString('hex');
}

async function sendVerificationEmail(userEmail, verificationToken) {
    let transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.ADDRESS_EMAIL,
            pass: process.env.EMAIL_PASSWORD
        },
        tls: {
            rejectUnauthorized: false
        }
    });

    const verificationLink = `http://localhost:5173/verify?token=${verificationToken}`;
    let mailContent = `<p>Witaj ${userEmail},</p>`;
    mailContent += `<p>Aby zweryfikować swoje konto, kliknij w poniższy link: <a href="${verificationLink}">${verificationLink}</a></p>`;
    mailContent += `<p>Pozdrawiamy,<br>Zespół</p>`;

    const mailOptions = {
        from: process.env.ADDRESS_EMAIL,
        to: userEmail,
        subject: 'Weryfikacja konta',
        html: mailContent
    };

    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error(`Błąd podczas wysyłania e-maila: ${error}`);
    }
}
async function sendActivationEmailWithCredentials(userEmail, verificationToken, password) {
    let transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.ADDRESS_EMAIL,
            pass: process.env.EMAIL_PASSWORD
        },
        tls: {
            rejectUnauthorized: false
        }
    });

    const activationLink = `http://localhost:5173/verify?token=${verificationToken}`;
    let mailContent = `<p>Witaj ${userEmail},</p>`;
    mailContent += `<p>Aby aktywować swoje konto, kliknij w poniższy link: <a href="${activationLink}">${activationLink}</a></p>`;

    mailContent += `<p><strong>Twoje dane logowania:</strong></p>`;
    mailContent += `<p>Email: <strong>${userEmail}</strong></p>`;
    mailContent += `<p>Hasło: <strong>${password}</strong></p>`;
    mailContent += `<p>Zalecamy zmianę hasła po pierwszym logowaniu.</p>`;

    mailContent += `<p>Pozdrawiamy,<br>Zespół</p>`;

    const mailOptions = {
        from: process.env.ADDRESS_EMAIL,
        to: userEmail,
        subject: "Aktywacja konta i dane logowania",
        html: mailContent
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log("E-mail aktywacyjny z danymi logowania został wysłany.");
    } catch (error) {
        console.error(`Błąd podczas wysyłania e-maila: ${error}`);
    }
}

exports.createBigBoss = async (req, res) => {
    try {
        const { role, email, password, ...rest } = req.body;
        if (!role || role.toLowerCase() !== 'big_boss') {
            return res.status(400).json({ message: 'Nie można utworzyć innej roli niż BigBoss.' });
        }
        if (!email) {
            return res.status(400).json({ message: 'Email jest wymagany do utworzenia konta BigBoss' });
        }

        const verificationToken = generateVerificationToken();

        const bigBoss = new BigBoss({
            email,
            password,
            verificationToken,
            ...rest
        });

        await bigBoss.save();
        await sendVerificationEmail(email, verificationToken);

        res.status(201).json({
            message: 'BigBoss utworzony pomyślnie. Wysłano e-mail weryfikacyjny.',
            bigBoss
        });
    } catch (error) {
        console.error('Błąd podczas tworzenia BigBossa:', error);
        res.status(500).json({
            message: 'Błąd podczas tworzenia BigBossa',
            error: error.message
        });
    }
};

exports.verifyUser = async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) {
            return res.status(400).json({ message: 'Brak tokenu weryfikacyjnego' });
        }

        const user = await User.findOne({ verificationToken: token });

        if (!user) {
            return res.status(400).json({ message: 'Nieprawidłowy token weryfikacyjny' });
        }
        if (new Date() > user.tokenUsedAt) {
            user.verificationToken = null;
        }

        user.isVerified = true;
        user.tokenUsedAt = new Date();
        await user.save();

        res.status(200).json({ message: 'Konto zostało zweryfikowane pomyślnie' });
    } catch (error) {
        console.error('Błąd podczas weryfikacji użytkownika:', error);
        res.status(500).json({ message: 'Błąd serwera podczas weryfikacji użytkownika', error: error.message });
    }
};

exports.createUser = async (req, res) => {
    try {
        const { role, bigBossEmail, ...rest } = req.body;
        const normalizedRole = role ? role.toLowerCase() : null;
        const reqUser = req.user;

        if (!["big_boss", "boss", "team_manager", "employee"].includes(normalizedRole)) {
            return res.status(400).json({ message: "Nieprawidłowa rola użytkownika" });
        }

        if (["boss", "team_manager", "employee"].includes(normalizedRole)) {
            if (!reqUser || reqUser.__t !== "BigBoss") {
                return res.status(403).json({ message: "Tylko zalogowany BigBoss może tworzyć te konta." });
            }

            if (!bigBossEmail) {
                return res.status(400).json({ message: "Wymagane jest podanie emaila Big Bossa." });
            }

            const bigBoss = await BigBoss.findOne({ email: bigBossEmail });
            if (!bigBoss) {
                return res.status(404).json({ message: "BigBoss nie został znaleziony." });
            }

            if (!bigBoss.idCompany) {
                return res.status(400).json({ message: "BigBoss nie ma przypisanego idCompany." });
            }

            rest.idCompany = bigBoss.idCompany;
        }

        const verificationToken = crypto.randomBytes(16).toString("hex");
        rest.verificationToken = verificationToken;

        let generatedPassword = null;
        if (["boss", "team_manager", "employee"].includes(normalizedRole)) {
            generatedPassword = crypto.randomBytes(8).toString("hex");
            rest.password = generatedPassword;
        }

        let user;
        switch (normalizedRole) {
            case "big_boss":
                user = new BigBoss(rest);
                break;
            case "boss":
                user = new Boss(rest);
                break;
            case "team_manager":
                user = new TeamManager(rest);
                break;
            case "employee":
                user = new Employee(rest);
                break;
        }

        await user.save();

        if (["boss", "team_manager", "employee"].includes(normalizedRole)) {
            const company = await Company.findById(rest.idCompany);
            if (!company) {
                return res.status(404).json({ message: "Firma nie została znaleziona." });
            }

            company.employees.push(user._id);
            await company.save();
        }

        if (normalizedRole === "big_boss") {
            await sendVerificationEmail(user.email, verificationToken);
        } else {
            await sendActivationEmailWithCredentials(user.email, verificationToken, generatedPassword);
        }

        return res.status(201).json({
            message: "Użytkownik utworzony pomyślnie. Wysłano e-mail aktywacyjny.",
            user
        });

    } catch (error) {
        console.error("Błąd podczas tworzenia użytkownika:", error);
        res.status(500).json({ message: "Błąd podczas tworzenia użytkownika", error: error.message });
    }
};

exports.deleteUser = async (req, res) => {
    try {
        const { userId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ message: 'Nieprawidłowe ID użytkownika' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie został znaleziony' });
        }

        if (user.__t === 'BigBoss') {
            return res.status(403).json({ message: 'Usunięcie Big Bossa jest dozwolone tylko przez Administratora' });
        }

        await Project.updateMany(
            { employeesProject: userId },
            { $pull: { employeesProject: userId } }
        );

        if (user.idCompany) {
            await Company.findByIdAndUpdate(user.idCompany, {
                $pull: { employees: userId }
            });
        }

        await User.findByIdAndDelete(userId);

        res.status(200).json({ message: 'Użytkownik usunięty pomyślnie wraz z jego referencjami w projektach i firmie.' });

    } catch (error) {
        console.error("Błąd podczas usuwania użytkownika:", error);
        res.status(500).json({ message: 'Błąd podczas usuwania użytkownika', error: error.message });
    }
};
exports.updateUser = async (req, res) => {
    try {
        const { userId } = req.params;
        const updates = req.body;

        let user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie został znaleziony' });
        }
        if (updates.idCompany) {
            user.idCompany = updates.idCompany;
        }

        Object.keys(updates).forEach(key => {
            if (key !== 'idCompany') {
                user[key] = updates[key];
            }
        });
        await user.save();

        res.status(200).json({ message: 'Użytkownik zaktualizowany pomyślnie', user });

    } catch (error) {
        res.status(500).json({ message: 'Błąd podczas aktualizacji użytkownika', error: error.message });
    }
};
exports.addPlaceWork = async (req, res) => {
    try {
        const { userId, year, month, day, project } = req.body;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie został znaleziony' });
        }

        let dayRecord = user.placeWork.find(record => record.year === year && record.month === month && record.day === day);
        if (dayRecord) {
            dayRecord.projects.push(project);
        } else {
            user.placeWork.push({
                year: year,
                month: month,
                day: day,
                projects: [project]
            });
        }
        await user.save();

        const projectRecord = await Project.findById(project.projectId);
        if (!projectRecord) {
            return res.status(404).json({ message: 'Projekt nie został znaleziony' });
        }
        let projectDayRecord = projectRecord.timeWorks.find(record => record.year === year && record.month === month && record.day === day);

        if (projectDayRecord) {
            let employeeTimeRecord = projectDayRecord.employeeTimeRecords.find(record => record.employee.toString() === userId);
            if (employeeTimeRecord) {
                employeeTimeRecord.time += project.time;
            } else {
                projectDayRecord.employeeTimeRecords.push({
                    employee: userId,
                    time: project.time
                });
            }
        } else {
            projectRecord.timeWorks.push({
                year: year,
                month: month,
                day: day,
                employeeTimeRecords: [{
                    employee: userId,
                    time: project.time
                }]
            });
        }

        await projectRecord.save();

        res.status(200).json({ message: 'Miejsce pracy zostało dodane pomyślnie', user });
    } catch (error) {
        console.error("Error during addPlaceWork:", error);
        res.status(500).json({ message: 'Błąd podczas dodawania miejsca pracy', error: error.message });
    }
};

exports.getUserById = async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie został znaleziony' });
        }

        res.status(200).json({ message: 'Użytkownik został znaleziony', user });
    } catch (error) {
        res.status(500).json({ message: 'Błąd podczas pobierania użytkownika', error: error.message });
    }
};

exports.getUsersByRole = async (req, res) => {
    try {
        const { role, companyId, sortKey = "userName", sortOrder = "asc" } = req.query;

        if (!companyId) {
            return res.status(400).json({ message: "Brak identyfikatora firmy" });
        }

        let discriminatorRole;
        switch (role.toLowerCase()) {
            case "big_boss":
                discriminatorRole = "BigBoss";
                break;
            case "boss":
                discriminatorRole = "Boss";
                break;
            case "team_manager":
                discriminatorRole = "TeamManager";
                break;
            case "employee":
                discriminatorRole = "Employee";
                break;
            default:
                return res.status(400).json({ message: "Nieprawidłowa rola użytkownika" });
        }

        const sortConfig = {};
        sortConfig[sortKey] = sortOrder === "asc" ? 1 : -1;

        const users = await User.find({ __t: discriminatorRole, idCompany: companyId }).sort(sortConfig);

        if (users.length === 0) {
            return res.status(200).json({ message: "Brak użytkowników o wskazanej roli w tej firmie", users: [] });
        }

        res.status(200).json({ message: `Lista użytkowników o roli ${role} w firmie ${companyId}`, users });
    } catch (error) {
        res.status(500).json({ message: "Błąd podczas pobierania użytkowników", error: error.message });
    }
};

exports.loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Nieprawidłowy e-mail lub hasło' });
        }
        if (!user.isVerified) {
            return res.status(403).json({ message: 'Konto nie zostało zweryfikowane. Sprawdź swoją skrzynkę e-mail.' });
        }

        if (user.statusUser) {
            return res.status(403).json({ message: 'Konto użytkownika zostało zablokowane, nie można się zalogować' });
        }

        if (user.idCompany) {
            const company = await Company.findById(user.idCompany);
            if (company && company.statusCompany) {
                return res.status(403).json({ message: 'Konto firmy zostało zablokowane, nie można się zalogować' });
            }
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Nieprawidłowy e-mail lub hasło' });
        }

        const token = user.generateAuthToken();

        res.cookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            maxAge: 24 * 60 * 60 * 1000,
        });

        res.status(200).json({
            message: 'Zalogowano pomyślnie',
            user: {
                id: user._id,
                userName: user.userName,
                lastName: user.userLastName,
                email: user.email,
                role: user.__t,
                firstLogin: user.firstLogin,
                idCompany: user.idCompany
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera podczas logowania', error: error.message });
    }
};

exports.checkSession = (req, res) => {
    if (!req.user) {
        return res.status(401).json({ message: 'Sesja wygasła lub użytkownik nie jest zalogowany.' });
    }

    res.status(200).json({
        message: "Sesja jest aktywna.",
        user: {
            id: req.user._id,
            userName: req.user.userName,
            role: req.user.__t,
            firstLogin: req.user.firstLogin,
            email: req.user.email,
            lastName: req.user.userLastName,
            idCompany: req.user.idCompany
        }
    });
};
exports.refreshUser = (req, res) => {
    const oldToken = req.cookies.token;
    if (!oldToken) {
        return res.status(401).json({ message: 'Brak tokena sesji' });
    }
    try {
        const decoded = jwt.verify(oldToken, process.env.JWT_SECRET);
        const newToken = jwt.sign({ _id: decoded._id, role: decoded.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.cookie('token', newToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            maxAge: 24 * 60 * 60 * 1000,
        });
        res.status(200).json({ message: 'Token odświeżony pomyślnie' });
    } catch (err) {
        res.status(401).json({ message: 'Nieprawidłowy token' });
    }
};
exports.logoutUser = (req, res) => {

    res.cookie('token', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        expires: new Date(0)
    });
    res.status(200).json({ message: 'Wylogowano pomyślnie.' });
};

exports.resetPasswordToken = async (req, res) => {
    try {
        const email = req.body.email;
        const user = await User.findOne({ email: email });

        if (!user) {
            return res.status(404).send({ error: 'Nie znaleziono użytkownika z podanym adresem e-mail' });
        }

        const token = user.generateResetPasswordToken()
        user.tokenResetPassword = token;
        user.resetPasswordExpires = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();

        process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.ADDRESS_EMAIL,
                pass: process.env.EMAIL_PASSWORD
            },
            tls: {
                rejectUnauthorized: false
            }
        });

        const resetPasswordLink = `http://localhost:3000/new-password/${token}`;

        const mailOptions = {
            from: process.env.ADDRESS_EMAIL,
            to: email,
            subject: "Resetowanie hasła",
            html: `<p>Otrzymałeś ten e-mail, ponieważ otrzymaliśmy prośbę o resetowanie hasła dla Twojego konta.</p>
                <p>Jeśli to nie Ty wysłałeś prośbę, możesz zignorować ten e-mail.</p>
                <p>Jeśli chcesz zresetować swoje hasło, kliknij
                <a href="${resetPasswordLink}">tutaj</a></p>
                <p>Link będzie ważny przez 24 godziny.</p>`
        };

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.error("Błąd podczas wysyłania e-maila:", err);
                res.status(500).send({ error: 'Wystąpił błąd podczas wysyłania e-maila z linkiem do resetowania hasła.' });
            } else {
                res.send({ success: true, message: 'E-mail z linkiem do resetowania hasła został wysłany.' });
            }
        });
    } catch (error) {
        console.error("Błąd serwera:", error);
        res.status(500).send({ error: 'Wystąpił błąd podczas generowania tokena do resetu hasła.' });
    }
};

exports.resetPassword = async (req, res) => {
    try {
        const token = req.body.token;
        const password = req.body.password;

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (!decoded) {
            console.error("Niepoprawny lub nieczytelny token.");
            return res.status(400).send({ error: "Token nie jest poprawny lub nie można go rozkodować." });
        }

        const usedToken = await UsedToken.findOne({ token });
        if (usedToken) {
            console.error("Token został już wcześniej użyty.");
            return res.status(401).send({ error: "Token jest nieprawidłowy lub już został użyty." });
        }

        const user = await User.findById(decoded.userId);
        if (!user) {
            console.error("Nie znaleziono użytkownika.");
            return res.status(404).send({ error: "Użytkownik nie został znaleziony" });
        }

        if (Date.now() > user.resetPasswordExpires) {
            console.error("Token wygasł dla użytkownika:", user.email);
            return res.status(401).send({ error: "Token wygasł lub jest nieprawidłowy." });
        }

        if (token !== user.tokenResetPassword) {
            console.error("Token nie pasuje dla użytkownika:", user.email);
            return res.status(401).send({ error: "Token jest nieprawidłowy lub już został użyty." });
        }

        user.password = password;

        user.tokenResetPassword = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        const usedTokenEntry = new UsedToken({
            token: token,
            userId: user._id,
            expiresAt: new Date(decoded.exp * 1000)
        });
        await usedTokenEntry.save();

        res.status(200).send("Hasło zostało zresetowane");

    } catch (error) {
        console.error("Błąd podczas resetowania hasła:", error);
        res.status(500).send({ error: "Wystąpił błąd podczas resetowania hasła użytkownika" });
    }
};

exports.toggleUserStatus = async (req, res) => {
    try {
        const { userId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ message: 'Nieprawidłowe ID użytkownika' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie został znaleziony' });
        }

        user.statusUser = !user.statusUser;

        await user.save();

        res.status(200).json({ message: 'Status użytkownika został pomyślnie przełączony', user });
    } catch (error) {
        res.status(500).json({ message: 'Błąd podczas przełączania statusu użytkownika', error: error.message });
    }
};

exports.toggleFirstLogin = async (req, res) => {
    try {
        const { userId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ message: 'Nieprawidłowe ID użytkownika' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie został znaleziony' });
        }

        user.firstLogin = !user.firstLogin;

        await user.save();

        res.status(200).json({ message: 'Status użytkownika został pomyślnie przełączony', user });
    } catch (error) {
        res.status(500).json({ message: 'Błąd podczas przełączania statusu użytkownika', error: error.message });
    }
};


exports.changeUserRole = async (req, res) => {
    const { newRole } = req.body;
    const { userId } = req.params;

    if (!userId || !newRole) {
        return res.status(400).send({ error: "Brak wymaganych danych: userId lub newRole" });
    }

    try {
        let user = await User.findById(userId);
        if (!user) {
            return res.status(404).send({ error: "Użytkownik nie został znaleziony" });
        }

        const userData = user.toObject();
        delete userData.__t;

        let newUser;
        switch (newRole.toLowerCase()) {
            case "boss":
                newUser = new Boss(userData);
                break;
            case "team_manager":
                newUser = new TeamManager(userData);
                break;
            case "employee":
                newUser = new Employee(userData);
                break;
            default:
                return res.status(400).send({ error: "Niepoprawna rola użytkownika" });
        }
        newUser._id = user._id;

        await User.findByIdAndDelete(userId);
        await newUser.save();

        return res.status(200).send({ message: "Rola użytkownika została zmieniona pomyślnie", user: newUser });
    } catch (error) {
        console.error("Błąd podczas zmiany roli użytkownika:", error);
        return res.status(500).send({ error: "Błąd serwera" });
    }
};


