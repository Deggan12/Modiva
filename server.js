const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

const connectionString = process.env.MYSQL_URL || process.env.DATABASE_URL;

if (connectionString) {
  console.log('Using connection string (MYSQL_URL)');
  var db = mysql.createConnection(connectionString);
} else {
  const dbHost = process.env.MYSQLHOST;
  const dbUser = process.env.MYSQLUSER;
  const dbPassword = process.env.MYSQLPASSWORD;
  const dbName = process.env.MYSQLDATABASE;
  const dbPort = process.env.MYSQLPORT || 3306;

  console.log('Using individual MySQL vars:', {
    host: dbHost,
    user: dbUser,
    database: dbName,
    port: dbPort,
    hasPassword: !!dbPassword
  });

  if (!dbHost || !dbUser || !dbName) {
    console.error('Missing MySQL connection info');
    process.exit(1);
  }

  var db = mysql.createConnection({
    host: dbHost,
    user: dbUser,
    password: dbPassword,
    database: dbName,
    port: dbPort,
  });
}

db.connect((err) => {
  if (err) {
    console.error('MySQL connection failed:', err.message);
    console.error('Full error:', err);
    process.exit(1);
  }
  console.log('MySQL connected successfully');
});

app.get('/', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'Modiva API is running',
    timestamp: new Date().toISOString()
  });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = './uploads/documents';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|jpg|jpeg|png/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error('Format de fichier non supporté'));
    }
  }
});

function assignServicesToUser(userId) {
  const getHandicaps = 'SELECT handicap_type_id FROM user_handicaps WHERE user_id = ?';

  db.query(getHandicaps, [userId], (err, handicaps) => {
    if (err) {
      console.error('Erreur getHandicaps:', err);
      return;
    }

    handicaps.forEach((h) => {
      const getServices = 'SELECT accommodation_id FROM handicap_services WHERE handicap_type_id = ?';

      db.query(getServices, [h.handicap_type_id], (err, services) => {
        if (err) {
          console.error('Erreur getServices:', err);
          return;
        }

        if (services.length > 0) {
          const insertLinks = 'INSERT INTO user_accommodation_link (user_id, accommodation_id) VALUES ?';
          const values = services.map((s) => [userId, s.accommodation_id]);

          db.query(insertLinks, [values], (err) => {
            if (err) console.error('Erreur insertLinks:', err);
          });
        }
      });
    });
  });
}

app.get('/api/admin/pending-users', (req, res) => {
  const query = `
    SELECT id, prenom, nom, email, proof_document, status, created_at
    FROM user_info
    WHERE status = 'pending'
    ORDER BY created_at DESC
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching pending users:', err);
      return res.status(500).json({ message: 'Erreur serveur', error: err.message });
    }
    console.log(`Found ${results.length} pending users`);
    res.json(results);
  });
});

app.post('/api/validation/valider/:userId', (req, res) => {
  const userId = req.params.userId;
  const { approuve } = req.body;
  const newStatus = approuve ? 'approved' : 'rejected';

  console.log(`Validating user ${userId}: ${newStatus}`);

  const updateUser = 'UPDATE user_info SET status = ? WHERE id = ?';
  db.query(updateUser, [newStatus, userId], (err, result) => {
    if (err) {
      console.error('Erreur update user:', err);
      return res.status(500).json({ message: 'Erreur lors de la validation' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Utilisateur introuvable' });
    }

    if (!approuve) {
      return res.json({ message: 'Utilisateur rejeté avec succès' });
    }

    assignServicesToUser(userId);

    const checkRFID = 'SELECT * FROM rfid WHERE user_id = ? LIMIT 1';
    db.query(checkRFID, [userId], (err, existing) => {
      if (err) {
        console.error('Erreur checkRFID:', err);
        return res.status(500).json({ message: 'Erreur vérification RFID' });
      }

      if (existing.length > 0) {
        return res.json({
          message: `Utilisateur approuvé (RFID: ${existing[0].rfid_tag})`
        });
      }

      const findRFID = 'SELECT id, rfid_tag FROM rfid WHERE user_id IS NULL LIMIT 1';
      db.query(findRFID, (err, rfidResults) => {
        if (err) {
          console.error('Erreur findRFID:', err);
          return res.status(500).json({ message: 'Erreur recherche RFID' });
        }

        if (rfidResults.length === 0) {
          return res.json({
            message: 'Utilisateur approuvé (aucun RFID disponible)'
          });
        }

        const rfid = rfidResults[0];
        const assignRFID = 'UPDATE rfid SET user_id = ? WHERE id = ?';
        db.query(assignRFID, [userId, rfid.id], (err2) => {
          if (err2) {
            console.error('Erreur assignRFID:', err2);
            return res.status(500).json({ message: 'Erreur assignation RFID' });
          }

          res.json({
            message: `Utilisateur approuvé et RFID ${rfid.rfid_tag} assigné`,
            assigned_rfid: rfid.rfid_tag
          });
        });
      });
    });
  });
});

app.get('/api/verify/:numeroCompte', (req, res) => {
  const numeroCompte = req.params.numeroCompte;

  const userQuery = `
    SELECT id, prenom, nom, email, numero_de_compte, status
    FROM user_info
    WHERE numero_de_compte = ?
  `;

  db.query(userQuery, [numeroCompte], (err, userResults) => {
    if (err) {
      console.error('Erreur verify user:', err);
      return res.status(500).json({ message: 'Erreur serveur' });
    }

    if (userResults.length === 0) {
      return res.status(404).json({ message: 'Numéro de compte introuvable' });
    }

    const user = userResults[0];

    if (user.status !== 'approved') {
      return res.status(403).json({ 
        message: 'Ce compte n\'est pas encore validé',
        status: user.status 
      });
    }

    const servicesQuery = `
      SELECT DISTINCT a.service_name, a.service_description, a.province
      FROM user_accommodation_link ual
      JOIN accommodation_info a ON ual.accommodation_id = a.accommodation_id
      WHERE ual.user_id = ?
      ORDER BY a.service_name
    `;

    db.query(servicesQuery, [user.id], (err2, services) => {
      if (err2) {
        console.error('Erreur verify services:', err2);
        return res.status(500).json({ message: 'Erreur serveur' });
      }

      res.json({
        user: {
          firstName: user.prenom,
          lastName: user.nom,
          email: user.email,
          numeroCompte: user.numero_de_compte
        },
        services: services
      });
    });
  });
});

app.post('/api/inscription', upload.single('proofDocument'), async (req, res) => {
  try {
    const { prenom, nom, email, adresse, password, handicapTypes } = req.body;

    if (!prenom || !nom || !email || !password || !handicapTypes) {
      return res.status(400).json({ message: 'Tous les champs sont requis' });
    }
    if (!req.file) {
      return res.status(400).json({ message: 'Document médical requis' });
    }

    const checkEmail = 'SELECT id FROM user_info WHERE email = ?';
    db.query(checkEmail, [email], async (err, results) => {
      if (err) return res.status(500).json({ message: 'Erreur serveur' });
      if (results.length > 0) {
        return res.status(400).json({ message: 'Cet email est déjà utilisé' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const numeroCompte = 'ACC' + Date.now().toString().slice(-9);

      const insertUser = `
        INSERT INTO user_info (email, password, prenom, nom, adresse, numero_de_compte, proof_document, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
      `;
      
      db.query(insertUser, [email, hashedPassword, prenom, nom, adresse, numeroCompte, req.file.filename], (err2, result) => {
        if (err2) {
          console.error('Insert user error:', err2);
          return res.status(500).json({ message: 'Erreur lors de l\'inscription' });
        }

        const userId = result.insertId;

        let raw = handicapTypes;
        let ids = [];
        if (Array.isArray(raw)) {
          ids = raw;
        } else if (typeof raw === 'string') {
          try {
            const j = JSON.parse(raw);
            ids = Array.isArray(j) ? j : [j];
          } catch {
            ids = raw.includes(',') ? raw.split(',') : [raw];
          }
        } else if (raw != null) {
          ids = [raw];
        }
        ids = ids.map(v => parseInt(String(v).trim(), 10)).filter(Number.isFinite);

        if (ids.length > 0) {
          const insertHandicaps = 'INSERT INTO user_handicaps (user_id, handicap_type_id) VALUES ?';
          const values = ids.map(id => [userId, id]);
          db.query(insertHandicaps, [values], (err3) => {
            if (err3) console.error('Erreur insertHandicaps:', err3);
            return res.status(201).json({
              message: 'Inscription réussie! Votre document sera vérifié.',
              numeroCompte,
              userId
            });
          });
        } else {
          return res.status(201).json({
            message: 'Inscription réussie! Votre document sera vérifié.',
            numeroCompte,
            userId
          });
        }
      });
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email et mot de passe requis' });
  }

  const query = 'SELECT * FROM user_info WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Erreur serveur' });
    if (results.length === 0) return res.status(401).json({ message: 'Email ou mot de passe incorrect' });

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Email ou mot de passe incorrect' });

    if (user.status === 'pending') {
      return res.status(403).json({ message: 'Votre compte est en attente de validation', statut: 'pending' });
    }
    if (user.status === 'rejected') {
      return res.status(403).json({ message: 'Votre demande a été rejetée', statut: 'rejected' });
    }

    res.json({ message: 'Connexion réussie', userId: user.id, numeroCompte: user.numero_de_compte, statut: user.status });
  });
});

app.get('/api/user/:id', (req, res) => {
  const userId = req.params.id;
  const query = `
    SELECT 
      prenom AS first_name,
      nom AS last_name,
      email,
      adresse AS address,
      numero_de_compte
    FROM user_info 
    WHERE id = ?
  `;
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Erreur MySQL:', err);
      return res.status(500).json({ message: 'Erreur serveur' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }
    res.json(results[0]);
  });
});

app.get('/api/user/:id/services', (req, res) => {
  const userId = req.params.id;

  const query = `
    SELECT DISTINCT a.service_name, a.service_description, a.province
    FROM user_accommodation_link ual
    JOIN accommodation_info a ON ual.accommodation_id = a.accommodation_id
    WHERE ual.user_id = ?
    ORDER BY a.service_name
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Erreur services:', err);
      return res.status(500).json({ message: 'Erreur serveur' });
    }

    res.json(results);
  });
});

app.get('/api/cities/:province', (req, res) => {
  const province = req.params.province;
  
  const query = 'SELECT DISTINCT city FROM government_locations WHERE province = ? ORDER BY city';
  db.query(query, [province], (err, results) => {
    if (err) {
      console.error('Error fetching cities:', err);
      return res.status(500).json({ message: 'Erreur serveur' });
    }
    
    const cities = results.map(row => row.city);
    res.json(cities);
  });
});

app.get('/api/locations/:province/:city', (req, res) => {
  const { province, city } = req.params;
  
  const query = `
    SELECT location_id, location_name, address, phone_number, postal_code, city, province
    FROM government_locations 
    WHERE province = ? AND city = ?
    ORDER BY location_name
  `;
  
  db.query(query, [province, city], (err, results) => {
    if (err) {
      console.error('Error fetching locations:', err);
      return res.status(500).json({ message: 'Erreur serveur' });
    }
    
    res.json(results);
  });
});

app.post('/api/appointments', (req, res) => {
  const { userId, locationId, appointmentDate, appointmentTime, appointmentType, notes } = req.body;
  
  if (!userId || !locationId || !appointmentDate || !appointmentTime || !appointmentType) {
    return res.status(400).json({ message: 'Tous les champs requis sont manquants' });
  }
  
  const query = `
    INSERT INTO card_appointments (user_id, location_id, appointment_date, appointment_time, appointment_type, notes)
    VALUES (?, ?, ?, ?, ?, ?)
  `;
  
  db.query(query, [userId, locationId, appointmentDate, appointmentTime, appointmentType, notes], (err, result) => {
    if (err) {
      console.error('Error creating appointment:', err);
      return res.status(500).json({ message: 'Erreur lors de la création du rendez-vous' });
    }
    
    res.status(201).json({
      message: 'Rendez-vous créé avec succès',
      appointmentId: result.insertId
    });
  });
});

app.get('/api/user/:id/appointments', (req, res) => {
  const userId = req.params.id;
  
  const query = `
    SELECT 
      ca.appointment_id,
      ca.appointment_date,
      ca.appointment_time,
      ca.status,
      ca.appointment_type,
      ca.notes,
      gl.location_name,
      gl.address,
      gl.city,
      gl.province,
      gl.phone_number
    FROM card_appointments ca
    JOIN government_locations gl ON ca.location_id = gl.location_id
    WHERE ca.user_id = ?
    ORDER BY ca.appointment_date DESC, ca.appointment_time DESC
  `;
  
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching appointments:', err);
      return res.status(500).json({ message: 'Erreur serveur' });
    }
    
    res.json(results);
  });
});

app.put('/api/appointments/:id/cancel', (req, res) => {
  const appointmentId = req.params.id;
  
  const query = 'UPDATE card_appointments SET status = "annule" WHERE appointment_id = ?';
  
  db.query(query, [appointmentId], (err, result) => {
    if (err) {
      console.error('Error canceling appointment:', err);
      return res.status(500).json({ message: 'Erreur lors de l\'annulation' });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Rendez-vous introuvable' });
    }
    
    res.json({ message: 'Rendez-vous annulé avec succès' });
  });
});

app.post('/scan', (req, res) => {
  const { uid } = req.body;
  if (!uid) return res.status(400).json({ access: "DENIED", reason: "No UID" });

  const query = `
    SELECT u.prenom, u.nom, u.status
    FROM rfid r
    JOIN user_info u ON u.id = r.user_id
    WHERE r.rfid_tag = ?
  `;

  db.query(query, [uid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ access: "DENIED", reason: "DB error" });
    }

    if (results.length === 0) {
      return res.status(200).json({ access: "DENIED", reason: "Unknown card" });
    }

    const user = results[0];
    if (user.status !== 'approved') {
      return res.status(200).json({ access: "DENIED", name: `${user.prenom} ${user.nom}`, reason: "Not approved" });
    }

    db.query("UPDATE rfid SET last_scan = NOW() WHERE rfid_tag = ?", [uid]);

    res.status(200).json({
      access: "GRANTED",
      name: `${user.prenom} ${user.nom}`,
      disability_category: "N/A"
    });
  });
});

app.get('/debug/db-test', (req, res) => {
  db.query('SELECT 1 AS ok', (err, result) => {
    if (err) {
      console.error('DB connection failed:', err);
      return res.status(500).json({ connected: false, error: err.message });
    }
    console.log('DB test success:', result);
    res.json({ connected: true, result });
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
  console.log(`API: https://modiva-production.up.railway.app`);
});