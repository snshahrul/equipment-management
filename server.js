const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

const app = express();
const PORT = 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'sn-consultancy-secret-key-2024';

let db;

async function initDatabase() {
    db = await open({
        filename: './sn_consultancy.db',
        driver: sqlite3.Database
    });

    await db.exec(`
        CREATE TABLE IF NOT EXISTS Users (
            UserId INTEGER PRIMARY KEY AUTOINCREMENT,
            Email TEXT UNIQUE NOT NULL,
            PasswordHash TEXT NOT NULL,
            FullName TEXT NOT NULL,
            Role TEXT DEFAULT 'engineer',
            IsActive INTEGER DEFAULT 1,
            CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS Assets (
            AssetId INTEGER PRIMARY KEY AUTOINCREMENT,
            AssetTag TEXT UNIQUE NOT NULL,
            AssetName TEXT NOT NULL,
            AssetType TEXT,
            Status TEXT DEFAULT 'operational',
            HealthPercentage REAL DEFAULT 100,
            RemainingLifeDays INTEGER DEFAULT 365,
            Manufacturer TEXT,
            DesignPressurePsig REAL,
            DesignTemperatureF REAL,
            InstallDate TEXT,
            DesignLifeYears INTEGER DEFAULT 25,
            CorrosionRateMmPerYear REAL DEFAULT 0.1,
            OperationalCycles INTEGER DEFAULT 0,
            CreatedBy INTEGER,
            CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            UpdatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS Inspections (
            InspectionId INTEGER PRIMARY KEY AUTOINCREMENT,
            AssetId INTEGER,
            InspectionDate TEXT,
            InspectionType TEXT,
            Findings TEXT,
            RiskScore INTEGER,
            InspectorName TEXT,
            NextInspectionDate TEXT,
            CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (AssetId) REFERENCES Assets(AssetId)
        );

        CREATE TABLE IF NOT EXISTS Documents (
            DocumentId INTEGER PRIMARY KEY AUTOINCREMENT,
            AssetId INTEGER,
            DocumentName TEXT,
            DocumentType TEXT,
            FileName TEXT,
            FilePath TEXT,
            FileSizeBytes INTEGER,
            UploadedBy INTEGER,
            UploadedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (AssetId) REFERENCES Assets(AssetId)
        );
    `);

    // Migrate existing plaintext passwords to bcrypt hashes
    const users = await db.all('SELECT * FROM Users');
    for (const user of users) {
        if (!user.PasswordHash.startsWith('$2')) {
            const salt = await bcrypt.genSalt(10);
            const hash = await bcrypt.hash(user.PasswordHash, salt);
            await db.run('UPDATE Users SET PasswordHash = ? WHERE UserId = ?', [hash, user.UserId]);
            console.log(`Upgraded password hash for user: ${user.Email}`);
        }
    }

    // Seed default users if none exist
    const admin = await db.get('SELECT * FROM Users WHERE Email = ?', 'admin@snconsultancy.com');
    if (!admin) {
        const salt = await bcrypt.genSalt(10);
        const users = [
            { email: 'admin@snconsultancy.com', password: 'Admin123!', name: 'System Administrator', role: 'admin' },
            { email: 'manager@snconsultancy.com', password: 'pass123', name: 'Asset Manager', role: 'manager' },
            { email: 'engineer@snconsultancy.com', password: 'pass123', name: 'Senior Engineer', role: 'engineer' },
            { email: 'supervisor@snconsultancy.com', password: 'pass123', name: 'Site Supervisor', role: 'supervisor' }
        ];
        for (const u of users) {
            const hash = await bcrypt.hash(u.password, salt);
            await db.run('INSERT INTO Users (Email, PasswordHash, FullName, Role) VALUES (?, ?, ?, ?)',
                [u.email, hash, u.name, u.role]);
        }
        console.log('Default users created with hashed passwords');
    }

    // Seed sample assets if none exist
    const assetCount = await db.get('SELECT COUNT(*) as count FROM Assets');
    if (assetCount.count === 0) {
        await db.run(`
            INSERT INTO Assets (AssetTag, AssetName, AssetType, Status, HealthPercentage, RemainingLifeDays, Manufacturer)
            VALUES
            ('B-101', 'Boiler B-101', 'boiler', 'operational', 85, 187, 'Foster Wheeler'),
            ('V-202', 'Pressure Vessel V-202', 'vessel', 'caution', 62, 94, 'Mitsubishi'),
            ('B-102', 'Boiler B-102', 'boiler', 'critical', 35, 45, 'Babcock'),
            ('H-305', 'Heat Exchanger H-305', 'exchanger', 'operational', 92, 312, 'Alfa Laval')
        `);
        console.log('Sample assets created');
    }

    console.log('SQLite database initialized');
}

// ============ MIDDLEWARE ============
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage: storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ============ AUTH MIDDLEWARE ============
async function authenticate(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// ============ AUTH ROUTES ============
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const user = await db.get('SELECT * FROM Users WHERE Email = ?', email.toLowerCase().trim());

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const validPassword = await bcrypt.compare(password, user.PasswordHash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { userId: user.UserId, email: user.Email, role: user.Role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.UserId,
                name: user.FullName,
                email: user.Email,
                role: user.Role
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============ ASSETS ROUTES ============
app.post('/api/assets', authenticate, async (req, res) => {
    const { assetTag, assetName, assetType, manufacturer, installDate, designLifeYears, healthPercentage } = req.body;
    try {
        const result = await db.run(`
            INSERT INTO Assets (AssetTag, AssetName, AssetType, Manufacturer, InstallDate, DesignLifeYears, HealthPercentage, CreatedBy)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [assetTag, assetName, assetType, manufacturer, installDate, designLifeYears || 25, healthPercentage || 100, req.user.userId]);
        const asset = await db.get('SELECT * FROM Assets WHERE AssetId = ?', result.lastID);
        res.json(asset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/assets', authenticate, async (req, res) => {
    try {
        const assets = await db.all('SELECT * FROM Assets ORDER BY AssetName');
        res.json(assets);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/assets/:id', authenticate, async (req, res) => {
    try {
        const asset = await db.get('SELECT * FROM Assets WHERE AssetId = ?', req.params.id);
        res.json(asset || null);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ INSPECTIONS ROUTES ============
app.get('/api/inspections', authenticate, async (req, res) => {
    try {
        const inspections = await db.all(`
            SELECT i.*, a.AssetName FROM Inspections i
            JOIN Assets a ON i.AssetId = a.AssetId
            ORDER BY i.InspectionDate DESC
        `);
        res.json(inspections);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/inspections', authenticate, async (req, res) => {
    const { assetId, inspectionDate, inspectionType, findings, riskScore, inspectorName, nextInspectionDate } = req.body;
    try {
        await db.run(`
            INSERT INTO Inspections (AssetId, InspectionDate, InspectionType, Findings, RiskScore, InspectorName, NextInspectionDate)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [assetId, inspectionDate, inspectionType, findings, riskScore, inspectorName, nextInspectionDate]);
        res.json({ message: 'Inspection recorded' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ DOCUMENTS ROUTES ============
app.get('/api/documents', authenticate, async (req, res) => {
    try {
        const documents = await db.all(`
            SELECT d.*, a.AssetName FROM Documents d
            JOIN Assets a ON d.AssetId = a.AssetId
            ORDER BY d.UploadedAt DESC
        `);
        res.json(documents);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/documents/upload', authenticate, upload.single('file'), async (req, res) => {
    const { assetId, documentName, documentType, fileName } = req.body;
    try {
        const fName = fileName || req.file?.originalname || 'document.pdf';
        await db.run(`
            INSERT INTO Documents (AssetId, DocumentName, DocumentType, FileName, FilePath, FileSizeBytes, UploadedBy)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [assetId, documentName, documentType, fName, req.file?.path || '', req.file?.size || 0, req.user.userId]);
        res.json({ message: 'Document uploaded' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ DASHBOARD STATS ============
app.get('/api/dashboard/stats', authenticate, async (req, res) => {
    try {
        const totalAssets = await db.get('SELECT COUNT(*) as count FROM Assets');
        const atRisk = await db.get("SELECT COUNT(*) as count FROM Assets WHERE Status IN ('caution', 'critical')");
        const critical = await db.get("SELECT COUNT(*) as count FROM Assets WHERE Status = 'critical'");
        const avgHealth = await db.get('SELECT AVG(HealthPercentage) as avg FROM Assets');
        const totalInspections = await db.get('SELECT COUNT(*) as count FROM Inspections');

        res.json({
            totalAssets: totalAssets.count,
            atRisk: atRisk.count,
            critical: critical.count,
            avgHealth: Math.round(avgHealth.avg || 0),
            totalInspections: totalInspections.count
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ TEST ROUTE ============
app.get('/api/health', async (req, res) => {
    res.json({ status: 'ok', message: 'SQLite database connected', timestamp: new Date().toISOString() });
});

// ============ START SERVER ============
async function start() {
    await initDatabase();
    app.listen(PORT, () => {
        console.log(`\n========================================`);
        console.log(`SN Consultancy Backend Server`);
        console.log(`========================================`);
        console.log(`Server running on: http://localhost:${PORT}`);
        console.log(`API endpoint: http://localhost:${PORT}/api`);
        console.log(`========================================\n`);
    });
}

start();
