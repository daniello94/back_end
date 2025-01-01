const isRole = (allowedRoles) => (req, res, next) => {
    try {
        const user = req.user;

        if (!user) {
            return res.status(401).json({ message: 'Brak użytkownika w żądaniu.' });
        }

        if (!allowedRoles.includes(user.__t)) {
            return res.status(403).json({ message: 'Brak uprawnień do tej treści.' });
        }

        next();
    } catch (error) {
        console.error('Błąd podczas sprawdzania uprawnień:', error.message);
        res.status(500).json({ message: 'Błąd podczas sprawdzania uprawnień', error: error.message });
    }
};

module.exports = isRole;
